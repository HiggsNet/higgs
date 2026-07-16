# Phase 5 Route Announcement Record 设计

## 1. Record Key 规范

每一条路由宣告使用独立的 record key，格式为：

```
routes/announcements/<normalized_prefix>
```

其中 `<normalized_prefix>` 是将 CIDR 前缀**规范化（canonicalized）**后，把 `/` 替换为 `_` 的结果。

规范化规则：
- 先用 `netip.ParsePrefix` 解析 CIDR，再取 `Masked()` 得到网络地址。
- 例如 `10.0.1.1/24` 必须规范为 `10.0.1.0/24`，key 为 `routes/announcements/10.0.1.0_24`。
- IPv6 地址中的冒号 `:` 保留，仅替换掩码分隔符 `/`，例如 `2001:db8::/32` 规范为 `2001:db8::_32`。

| 前缀 | 规范化后 | Record Key |
|------|---------|-----------|
| `10.0.1.0/24` | `10.0.1.0/24` | `routes/announcements/10.0.1.0_24` |
| `10.0.1.1/24` | `10.0.1.0/24` | `routes/announcements/10.0.1.0_24` |
| `2001:db8::/32` | `2001:db8::/32` | `routes/announcements/2001:db8::_32` |

**设计理由：**
- per-prefix 独立 record：变更一条前缀只 bump 该 key 的 version，不影响其他
- key 中编码了前缀，审计时可以看到 "node-a 在 key `routes/announcements/10.0.1.0_24` 的 version 3 中宣告了该前缀"
- 前缀规范化存储，便于按 zone 扫描 active records 时重建完整的宣告列表

## 2. Record Type

```
route.announcement
```

（新增到 `docs/design.md` 第二节“Record 内置类型列表”中）

## 3. Record Value JSON Schema

```json
{
  "version": 1,
  "prefix": "10.0.1.0/24",
  "active": true
}
```

字段说明：

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `version` | int | 是 | schema version，当前固定为 `1` |
| `prefix` | string | 是 | CIDR 前缀，必须与 key 中编码的前缀一致；写入前应做 canonicalization |
| `active` | bool | 是 | `true`=宣告该前缀，`false`=撤回该前缀 |

## 4. 撤回语义

由于 record 模型不支持显式删除，采用 **`active: false` 标记撤回**：

- 节点宣告 `10.0.1.0/24`：发 version=1，`active: true`
- 节点撤回 `10.0.1.0/24`：发 version=2，`active: false`（同一 key，更高 version）
- Route authorization 层**只使用 `active=true` 且签名有效的 record**，`active=false` 视为不存在
- 后续如需再次宣告同一前缀：发 version=3，`active: true`

**Version 增长场景：**
```
version=1: {"active": true,  "prefix": "10.0.1.0/24"}   ← 宣告
version=2: {"active": false, "prefix": "10.0.1.0/24"}   ← 撤回
version=3: {"active": true,  "prefix": "10.0.1.0/24"}   ← 重新宣告
version=4: {"active": true,  "prefix": "10.0.2.0/24"}   ← 换了个前缀（key 相同则报错：prefix 不匹配）
```

**前缀变更时**：这是设计上需要着重考虑的边界场景。同一个 key 代表同一个前缀的声明历史，因此：
- 如果新 record 的 `prefix` 与 key 编码的前缀不一致，拒绝并输出 `route_announcement_key_mismatch`。
- 如果新 record 的 `prefix` 与当前 active record 的 `prefix` 不一致（即使与 key 一致），也拒绝，防止 key 被误用或历史前缀被悄悄替换。
- 节点如需修改前缀，必须先对旧 key 发一条 `active:false` 撤回，再在新 key 下发宣告。

**`active:false` 历史保留：**
- 撤回记录会进入该 key 的 `RecordHistory`，受全局 `MaxRecordHistoryPerKey`（默认 128）限制。
- Route authorization 层只使用每个 key 的最新 `active=true` record；`active=false` 及更旧版本不参与路由决策。
- 如果某前缀频繁 flapping，历史版本会快速填满保留窗口；后续可考虑 archive/compaction 策略，但 Phase 5 先依赖 bounded history。

## 5. 与 `ipam/assignments/*` 的关系

### 5.1 层级关系

`ipam/pools/*`、`ipam/assignments/*` 与 `routes/announcements/*` 对 `<prefix>` 采用同一套规范化与 key 编码规则（`/` 替换为 `_`）：

```
ipam/pools/10.0.1.0_24      ← catofes. 持有者授权：这个池可分给子 Zone
ipam/assignments/10.0.1.0_24 ← catofes. 持有者签名：把这个池分给 pek.catofes.
routes/announcements/10.0.1.0_24 ← pek.catofes. 持有者签名：我宣告这个前缀可达
```

**校验链：**
1. `routes/announcements/10.0.1.0_24` 由 `pek.catofes.` 签名 → 验证通过
2. 查找 `10.0.1.0/24` 的 assignment：在 `pek.catofes.` 及其祖先 Zone 中 fallback 查找 `ipam/assignments/10.0.1.0_24`
3. 找到的 assignment 必须满足：
   - `assigned_to` 字段指向 `pek.catofes.` 或其祖先
   - assignment 未被撤销且签名有效
4. 通过 → `10.0.1.0/24` 进入 `pek.catofes.` 的 authorized route set

### 5.2 允许的声明模式

| 场景 | 是否允许 | 说明 |
|------|---------|------|
| assignment 在 zone 自身 | ✅ | 典型场景：被上级分配后自己宣告 |
| assignment 在父 zone | ✅ | 父 zone 持有者可宣告被分配的子前缀（如父 zone 作为 aggregate 点） |
| assignment 在子 zone | ❌ | 父 zone 不能代为宣告子 zone 被分配的前缀（必须由子 zone 自己签名宣告） |
| 无 assignment | ⚠️ Phase 5 拒绝，Phase 7 可加 `route.export_static` 本地 override |
| 宣告的前缀比 assignment 更具体 | ✅ | `ipam/assignments` 写了 `10.0.0.0/16`，宣告 `10.0.1.0/24` 可以 |
| 宣告的前缀比 assignment 更宽泛 | ❌ | assignment 是 `/24`，宣告 `/16` 不可 |

### 5.3 重叠前缀与跨 Zone 冲突

Route record 本身只负责“谁宣告了什么”；重叠前缀的裁决由上层 `AuthorizedRouteSet` 统一处理：

- **更具体优先**：如果父 Zone 宣告 `10.0.0.0/16`，子 Zone 宣告 `10.0.1.0/24`，且子 Zone 被授权，则更具体前缀有效。
- **禁止无授权关系 Zone 同告**：两个没有父子/授权关系的 Zone 同时宣告同一前缀（或互相重叠且互不包含）时，全部拒绝，并输出 `route_overlap_unauthorized`。
- **聚合点例外**：父 Zone 可作为 aggregate 点宣告已被分配给子 Zone 的更大前缀，只要父 Zone 持有该 assignment 或具有显式聚合授权。
- **撤销传播**：父 Zone 或任何祖先 Zone 的 delegation 被撤销后，该子树发布的所有 announcement 立即从 `AuthorizedRouteSet` 中剔除，历史记录仅用于审计。

## 6. Go 数据结构

```go
// pkg/routing/records.go

import (
    "encoding/json"
    "fmt"
    "net/netip"
    "strings"

    "github.com/Catofes/higgs/pkg/core/zone"
)

const (
    RecordTypeRouteAnnouncement = "route.announcement"
    RecordKeyPrefixRoutes       = "routes/announcements/"
)

type RouteAnnouncementRecord struct {
    Version    int    `json:"version"`              // schema version, 1
    Prefix     string `json:"prefix"`               // canonical CIDR prefix
    Active     bool   `json:"active"`               // true=announced, false=withdrawn
    Controller string `json:"controller,omitempty"` // "auto" only for config-managed records
}

// Validate checks the route announcement schema and prefix.
func (r RouteAnnouncementRecord) Validate(owner zone.ZonePath) error {
    if r.Version != 1 {
        return fmt.Errorf("unsupported route announcement schema version: %d", r.Version)
    }
    if _, err := CanonicalizePrefix(r.Prefix); err != nil {
        return fmt.Errorf("invalid prefix %q: %w", r.Prefix, err)
    }
    return nil
}

// CanonicalizePrefix parses a CIDR and returns its canonical form (masked network address).
// This ensures 10.0.1.1/24 and 10.0.1.0/24 map to the same key and prefix field.
func CanonicalizePrefix(prefix string) (string, error) {
    p, err := netip.ParsePrefix(prefix)
    if err != nil {
        return "", err
    }
    return p.Masked().String(), nil
}

// NormalizeRouteAnnouncementKey returns the stable record key for a prefix.
// The prefix is first canonicalized; then '/' is replaced by '_'.
func NormalizeRouteAnnouncementKey(prefix string) (string, error) {
    canonical, err := CanonicalizePrefix(prefix)
    if err != nil {
        return "", err
    }
    normalized := strings.ReplaceAll(canonical, "/", "_")
    return RecordKeyPrefixRoutes + normalized, nil
}

// ParseRouteAnnouncementRecord parses a signed zone.Record into a RouteAnnouncementRecord.
// It enforces that record.Key, ann.Prefix and the canonical prefix all agree.
func ParseRouteAnnouncementRecord(record *zone.Record) (*RouteAnnouncementRecord, error) {
    if record == nil {
        return nil, fmt.Errorf("route announcement record is nil")
    }
    if record.Type != RecordTypeRouteAnnouncement {
        return nil, fmt.Errorf("expected record type %s, got %s", RecordTypeRouteAnnouncement, record.Type)
    }
    var ann RouteAnnouncementRecord
    if err := json.Unmarshal(record.Value, &ann); err != nil {
        return nil, fmt.Errorf("unmarshal route announcement: %w", err)
    }
    if ann.Prefix == "" {
        return nil, fmt.Errorf("route announcement prefix is empty")
    }
    canonical, err := CanonicalizePrefix(ann.Prefix)
    if err != nil {
        return nil, fmt.Errorf("invalid route announcement prefix %q: %w", ann.Prefix, err)
    }
    expectedKey, err := NormalizeRouteAnnouncementKey(ann.Prefix)
    if err != nil {
        return nil, err
    }
    if record.Key != expectedKey {
        return nil, fmt.Errorf("route_announcement_key_mismatch: record key %q does not match prefix key %q", record.Key, expectedKey)
    }
    ann.Prefix = canonical
    return &ann, nil
}

// ValidateRouteAnnouncementAgainstHistory rejects prefix changes on the same key.
// Callers should pass the current active record for the same zone+key, if any.
func ValidateRouteAnnouncementAgainstHistory(ann *RouteAnnouncementRecord, current *zone.Record) error {
    if current == nil {
        return nil
    }
    currentAnn, err := ParseRouteAnnouncementRecord(current)
    if err != nil {
        // Current active is unparseable; treat as conflict to force correction.
        return fmt.Errorf("route_announcement_history_invalid: %w", err)
    }
    if currentAnn.Prefix != ann.Prefix {
        return fmt.Errorf("route_announcement_key_mismatch: key %q previously announced %s, cannot change to %s; withdraw and re-announce under new key", current.Key, currentAnn.Prefix, ann.Prefix)
    }
    return nil
}
```

## 7. 与现有 Record 模型的兼容性

- Record Key 使用 `routes/announcements/<prefix>` 格式，不与现有 `ipsec/*` 等 key 冲突
- Record Type `route.announcement` 是新增类型
- 签名机制完全复用 `higgs.record.v1` domain separator
- 版本链 per-zone-per-key，撤回就是版本++的 `active:false`

## 8. CLI 与易用性

为避免管理员手工构造 key/type/prefix 三者不一致，建议新增专用 CLI：

```bash
# 宣告前缀（自动规范化 CIDR、构造 key、选择 type）
higgs route announce <zone> <prefix>

# 撤回前缀（对同一 key 发一条 active=false 的更高版本 record）
higgs route withdraw <zone> <prefix>
```

实现要点：
- 调用 `CanonicalizePrefix` 得到规范前缀。
- 调用 `NormalizeRouteAnnouncementKey` 生成 key。
- 通过现有 `putRecord` 路径写入；daemon 运行时走 control socket，否则直接写 DB。
- 写入前检查本 Zone authority 是否具备通用 `write` capability。

## 9. 前置依赖与实现顺序

Route announcement 不能独立闭环，必须依赖 IPAM assignment 记录：

1. **先实现 `ipam/pools/*` 与 `ipam/assignments/*` 的 record schema 和解析**。
   - `ipam/pools/<prefix>`：声明某 Zone 有权分配该前缀。
   - `ipam/assignments/<prefix>`：把前缀分配给具体 Zone，含 `assigned_to` 字段。
2. **再实现 `pkg/routing/records.go`**：route announcement 解析、校验、key 规范化。
3. **再实现 `AuthorizedRouteSet`**：输入 verified active state + revocation set，输出 per-zone allowed/announced prefixes 和 import/export whitelist。
4. **最后接入 BIRD Babel adapter**：在 XFRM link `up`/`dual_running` 时动态管理接口、filter、路由表。

## 10. 待验证边界

- IPv6 key 含冒号，需验证 bbolt 存储、MessagePack gossip、Merkle hash、CLI 输出均无特殊字符问题。
- CIDR canonicalization 后，确保 `10.0.1.1/24` 与 `10.0.1.0/24` 不会形成重复 record。
- `active:false` 撤回后， gossip digest 中该 key 仍贡献 hash；远端应能正确识别最新 active=false 并剔除路由。
- 同 key 前缀变更在历史版本校验中被拒绝。

## 11. 变更记录（待确认后合并到 design.md / todo.md）

本文件为 Phase 5 设计补充。确认后将：
- 在 `docs/design.md` 第二节“Record 内置类型列表”中加入 `route.announcement`，并补充 key 规范化说明。
- 在 `docs/design.md` 的 IPAM/路由映射章节中补充 `ipam/pools/*`、`ipam/assignments/*`、`routes/announcements/*` 三层语义。
- `route.announcement` 使用通用 `PermWrite`，无需单独的 route capability。
- 实现代码放在 `pkg/routing/` 下：
  - 新建 `pkg/routing/records.go`：route announcement schema、解析、校验、key 规范化。
  - 后续新建 `pkg/routing/authorization.go`：`AuthorizedRouteSet`、assignment/announcement 校验、重叠前缀裁决。
  - 后续扩展 `pkg/routing/bird/`：消费 authorized route set，管理 BIRD Babel interface/filter/route table。
- 在 `app/higgs/cmd.go` 中新增 `route` 子命令：`higgs route announce` / `higgs route withdraw`。
- 在 `todo.md` Phase 5 章节中拆出可执行任务：
  - 5.2.1 定义 `ipam/pools/*` 与 `ipam/assignments/*` record schema。
  - 5.2.2 实现 route announcement record 解析与校验。
  - 5.2.3 实现 `AuthorizedRouteSet` 与重叠前缀裁决。
  - 5.2.4 接入 BIRD Babel import/export filter。
