# BIRD Babel Backend 设计参考

> 文档状态: Phase 5 设计参考
> 更新日期: 2026-06-13
> BIRD 版本: 2.x/3.x 主线源码 (GitHub CZ-NIC/bird master)
> 调研方式: 官方文档 + 源码分析

## 结论先行

**Higgs Phase 5 默认采用 BIRD 跑 Babel protocol。**

相比 babeld，BIRD 在 Higgs 场景下有几个显著优势：

- ✅ **interface pattern 自动发现**：配置 `interface "hgs*" { ... }` 后，只要 Higgs 创建/删除以 `hgs` 开头的 XFRM 接口，BIRD 会自动开始/停止在该接口上跑 Babel，不需要 Higgs 逐条发送 `interface`/`flush interface` 命令。
- ✅ **平滑配置重载**：`birdc configure` / `birdc configure soft` + `reload in/out` 可以在不重启 daemon 的情况下更新 filter，避免 babeld SIGHUP 实际等价于进程重启的问题。
- ✅ **filter 语言更强大**：支持基于 `ifname`、`net`、`source`、`from`、`babel_metric` 等的过滤，天然可按 peer interface 做 whitelist。
- ✅ **多 routing table**：原生支持多 table + kernel table 同步，适合 Higgs 每 overlay 独立 table 的设计。
- ✅ **IPv4/IPv6 双栈**：同一 BIRD 实例内同时支持，无需像 babeld 那样为不同 AF 分别处理。
- ✅ **认证配置直接**：per-interface HMAC 密码直接在配置里声明，不需要运行时注入 key。

代价是 BIRD 更大更复杂，Higgs 需要维护 `bird.conf` 生成器和 `birdc` CLI client。

## 关键能力逐项（BIRD 作为 Phase 5 后端）

| 能力 | BIRD (2.x/3.x) | 说明 |
|------|---------------|------|
| Babel protocol | ✅ 原生实现 | BIRD 2.x 起支持 Babel |
| 动态接口发现 | ✅ **interface pattern 自动匹配** | BIRD 监听内核接口事件，自动增删 |
| filter 修改 | ⚠️ 需 `birdc configure` 重载 | `configure soft` + `reload in/out` 可减少协议重启 |
| routing table 切换 | ⚠️ 重载配置，必要时重启相关 protocol | 比 babeld 灵活，但仍非完全动态 |
| 多 routing table | ✅ 多 table + pipe + kernel sync | 适合 Higgs 每 overlay 独立 table |
| 认证 | ✅ per-interface password/HMAC | BIRD 配置即可，无需运行时命令 |
| 控制接口 | ✅ `birdc` / stable CLI | 成熟，但 Higgs 需解析文本输出 |
| IPv4+IPv6 | ✅ 同一实例双 channel | BIRD 2.x 起同时支持 |

## BIRD 的动态接口机制（源码确认）

BIRD 的 Babel 协议实现了 `if_notify` hook：

```c
static void
babel_if_notify(struct proto *P, unsigned flags, struct iface *iface)
{
  ...
  if (flags & (IF_CHANGE_UPDOWN | IF_CHANGE_LLV6))
  {
    if (ifa)
      babel_remove_iface(p, ifa);

    if (!(iface->flags & IF_UP))
      return;

    if (!iface->llv6)
      return;

    struct babel_iface_config *ic =
      (void *) iface_patt_find(&cf->iface_list, iface, NULL);

    if (ic && iface_is_valid(p, iface))
      babel_add_iface(p, iface, ic);
  }
  ...
}
```

要点：
- `protocol device {}` 负责扫描内核接口变化并发送 `IF_CHANGE_CREATE` / `IF_CHANGE_UP` / `IF_CHANGE_DOWN` 事件。
- Babel 收到事件后，用 `iface_patt_find()` 匹配配置里的 interface pattern（支持 `*` 通配）。
- 匹配成功且接口 up、有 link-local 地址、支持组播，就自动 `babel_add_iface()`；接口 down 则 `babel_remove_iface()` 并 flush 邻居/路由。

这意味着 Higgs 的 IPsec reconcile 只需要做它本来该做的事：创建/删除/上/下 XFRM 接口。BIRD 会自动感知并启用/停用 Babel，不需要 Higgs 再维护一个 "已加入 BIRD 的接口集合"。

## 网络命名空间启动模型

BIRD **没有内置的 namespace 切换能力**，配置里也没有 `namespace` 之类的指令可以让一个 BIRD 进程同时管理多个 netns 的接口。要让 BIRD 的数据面落在目标 netns，必须**把 BIRD 进程本身启动在目标 netns 内**。

推荐做法：

```bash
# named netns
ip netns add h2
ip netns exec h2 bird -c /run/higgs/bird-ipsec-main.conf -s /run/higgs/bird-ipsec-main.ctl

# 或 systemd service
NetworkNamespacePath=/run/netns/h2
ExecStart=/usr/sbin/bird -f -c /run/higgs/bird-ipsec-main.conf -s /run/higgs/bird-ipsec-main.ctl
```

要点：

- BIRD 启动后通过 netlink 看到的接口、地址、路由都是它所在 netns 的，因此 BIRD daemon 必须与对应 XFRM interface 处于同一 netns。
- `birdc` 通过 Unix domain socket 与 BIRD 通信；socket 是文件系统对象，可以在不同 netns 间访问（只要 mount namespace 共享路径），但 BIRD 回复的 `show interfaces` / `show route` 等状态反映的是 BIRD 自身 netns 的数据。
- 每个 `LinkGroupSpec.NetNS` / overlay data-plane 必须启动**独立的 BIRD 实例**和**独立的 control socket**，不同 netns 不能共享同一个 BIRD 实例或 socket。
- Higgs daemon 的 BIRD Process Manager 负责：创建/确保目标 named netns、生成 `bird.conf`、在目标 netns 内 `exec` BIRD、维护 pid/control socket 路径、退出时按 ownership 清理。
- netns 切换需要 `CAP_SYS_ADMIN` / root 或 privileged container；XFRM/link 操作需要 `CAP_NET_ADMIN`。preflight 必须在启动 BIRD 前检查这些权限。

## Higgs 配置模型

### `overlays[].routing` 配置段

```yaml
overlays:
  - id: ipsec-main
    name: ipsec-main
    provider: strongswan
    # ... existing overlay fields ...
    routing:
      enabled: true              # false 时禁用该 overlay 路由
      protocol: bird             # Phase 5 仅支持 bird
      mode: managed              # managed | external | disabled
      netns: h2                  # 默认继承 LinkGroupSpec.NetNS
      control_socket: /run/higgs/bird-ipsec-main.ctl
      pid_file: /run/higgs/bird-ipsec-main.pid
      router_id: 1.2.3.4         # 可选，默认从 local zone + trusted root + overlay id 确定性派生
      table: main                # kernel routing table；独立 netns 时默认 main 即可
      # table_name: higgs_100    # BIRD 内部 table 名；非 main table 时才需要
      # priority: 100            # ip rule 优先级；仅在非 main table 或共享 netns 策略路由时生效
      metric_base: 100           # 正常接口的 Babel metric
      metric_staged: 200         # staged generation 接口的 metric
      metric_draining: 500       # draining 旧 generation 接口的 metric
      export_static: []          # 本地静态前缀 override，Phase 5 先不支持
      device_scan_time: 5        # protocol device 扫描周期（秒）
      auth:                      # 可选 HMAC 认证
        enabled: false
        algorithm: hmac sha256
        password: "base64-or-hex-key"
        key_id: 1
```

### 字段说明

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `enabled` | bool | 是 | 是否在该 overlay 上启用路由 |
| `protocol` | string | 是 | 固定为 `bird` |
| `mode` | string | 是 | `managed`（Higgs 启动监管）/ `external`（连接已有 BIRD）/ `disabled` |
| `netns` | string | 否 | BIRD daemon 运行的 netns，默认继承 LinkGroup |
| `control_socket` | string | 是 | birdc UNIX control socket 路径 |
| `pid_file` | string | 是 | BIRD pid 文件路径 |
| `router_id` | string | 否 | 仅迁移/恢复时覆盖；默认从 `local zone + trusted root + overlay id` 确定性派生 64-bit id，持久化后不再变化 |
| `table` | int/string | 否 | kernel routing table id 或名称；默认 `main`（即该 netns 的 main table） |
| `table_name` | string | 否 | BIRD 内部 table 名；使用非 main table 时才需要 |
| `priority` | int | 否 | `ip rule` 优先级；仅在非 main table 或共享 netns 策略路由时生效 |
| `metric_base` | int | 否 | 默认 Babel metric |
| `metric_staged` | int | 否 | staged generation 接口 metric |
| `metric_draining` | int | 否 | draining generation 接口 metric |
| `device_scan_time` | int | 否 | `protocol device` 扫描周期 |
| `auth` | object | 否 | HMAC 认证配置 |

## BIRD 配置模板

Higgs 为每个启用 routing 的 overlay 生成一份 `bird.conf`：

```bird
# Higgs-generated BIRD config for overlay ipsec-main
# Do not edit manually; use Higgs control interface instead.

log syslog all;
# debug protocols all;

router id 1.2.3.4;

# Listen on birdc control socket
listen "unix" "/run/higgs/bird-ipsec-main.ctl";

# Scan kernel interfaces for pattern matching
protocol device {
    scan time 5;
}

# Per-overlay internal routing tables
ipv4 table higgs_100;
ipv6 table higgs_100;

# Sync with kernel table 100
protocol kernel higgs_kern_100 {
    ipv4 { table higgs_100; export all; };
    ipv6 { table higgs_100; export all; };
    kernel table 100;
}

# Import filter: only accept prefixes authorized for the peer interface
filter higgs_import_100 {
    if net = 0.0.0.0/0 then reject;
    if net ~ [ 10.0.0.0/8+ ] then accept;   # example authorized aggregate
    if source ~ [ RTS_BABEL ] then {
        # additional per-peer whitelist logic generated by Higgs
        accept;
    }
    reject;
}

# Export filter: only announce local authorized prefixes
filter higgs_export_100 {
    if source ~ [ RTS_STATIC, RTS_INHERIT ] then accept;
    reject;
}

# Babel protocol instance
protocol babel higgs_babel_100 {
    ipv4 {
        table higgs_100;
        import filter higgs_import_100;
        export filter higgs_export_100;
    };
    ipv6 {
        table higgs_100;
        import filter higgs_import_100;
        export filter higgs_export_100;
    };

    interface "hgs*" {
        type tunnel;
        rxcost 96;
        hello interval 4;
        update interval 4;
        # authentication mac;
        # password "..." { algorithm hmac sha256; id 1; };
    };
}
```

说明：
- `listen "unix"` 让 birdc 通过 Unix domain socket 连接。
- `protocol device` 扫描接口变化，触发 interface pattern 匹配。
- `protocol kernel` 把 BIRD 内部 table 同步到指定的 kernel table。
- `protocol babel` 绑定到所有 `hgs*` 接口；Higgs 的 XFRM 接口名带 `hgs` 前缀。
- filter 由 Higgs 根据 `AuthorizedRouteSet` 生成，变化时通过 `birdc configure` 重载。

## Filter 更新流程

当 route authorization 计算出新的 per-peer whitelist 后：

1. Higgs 重写 `bird.conf` 中相关 filter 定义。
2. 执行 `birdc -s /run/higgs/bird-ipsec-main.ctl configure soft`。
3. BIRD 以 soft 方式应用新配置：已接受的路由继续传播，新路由按新 filter 处理。
4. 再执行 `birdc reload in higgs_babel_100` / `birdc reload out higgs_babel_100` 让现有路由重新过 filter。
5. 观测 `show route` / `show protocols`，确认未授权路由已从 kernel table 移除。

如果 filter 变化涉及 routing table 结构（如新增 overlay table），则使用普通 `birdc configure` 而不是 `configure soft`，BIRD 会按需重启相关 protocol。

## 推荐架构

```
┌─────────────────────────────────────────────┐
│                  Higgs daemon                │
├─────────────────────────────────────────────┤
│  IPsec Reconciler                            │
│  ├── 创建/删除 XFRM interface (prefix hgs*)   │
│  └── 分配 link-local / tunnel address        │
├─────────────────────────────────────────────┤
│  Route Authorization                         │
│  ├── 扫描 active state 中 verified           │
│  │   route announcements                     │
│  ├── 校验 assignment chain                   │
│  └── 生成 authorized prefix set              │
├─────────────────────────────────────────────┤
│  BIRD Config Generator                       │
│  ├── 每 overlay 生成一份 bird.conf           │
│  ├── ipv4/ipv6 table + kernel sync           │
│  ├── babel protocol + interface "hgs*"       │
│  ├── import/export filter (精确或宽松)        │
│  └── password / authentication               │
├─────────────────────────────────────────────┤
│  BIRD Process Manager                        │
│  ├── 确保 netns 存在                          │
│  ├── 启动: ip netns exec <ns> bird -c ...    │
│  ├── filter 变更: 重写 conf + birdc configure│
│  ├── 监控: birdc show status / protocols / route│
│  ├── 崩溃恢复: 同 router-id 重新拉起          │
│  └── 退出: birdc down / SIGTERM + 清理 socket │
├─────────────────────────────────────────────┤
│  Route Auditor (kernel layer, 可选)          │
│  ├── 如果 BIRD filter 足够精确可弱化         │
│  └── 否则仍周期性清理未授权 learned route    │
└─────────────────────────────────────────────┘
```

## 与 IPsec staged rotate 的协作

- 新 XFRM interface（如 `hgsxxxx-staged`）创建后，BIRD 的 `protocol device` 会在扫描周期内发现它。
- 如果 staged interface 也匹配 `hgs*` pattern，它会自动加入 Babel；Higgs 通过 BIRD filter 或接口参数控制其 metric（`metric_base` / `metric_staged` / `metric_draining`）。
- 只有观测到新 Babel neighbor 与关键路由收敛后，Higgs 才向 IPsec reconcile 提供 `RotateCutoverReady=true`。
- 旧 interface 进入 draining 期间提高 metric，保留作为退路；最终被删除时 BIRD 自动 retract 相关路由。

## BIRD 生命周期设计

### managed 模式

Higgs daemon 作为 BIRD 的父进程/监管者：

1. **启动 / 领养**
   - 确保目标 named netns 已存在（Higgs 创建或复用）。
   - 将 `router-id`、interface pattern、filter、table、metric 等渲染为 `/run/higgs/bird-<overlay>.conf`。
   - 启动前检查 pidfile：若已存在且进程仍在运行、router-id/table 匹配，则直接 adopt（发送 `birdc configure` 同步最新 conf），避免重复启动。
   - 否则在该 netns 内执行：
     ```bash
     ip netns exec <ns> bird -c /run/higgs/bird-<overlay>.conf \
                             -s /run/higgs/bird-<overlay>.ctl \
                             -P /run/higgs/bird-<overlay>.pid
     ```
   - 等待 control socket 出现，执行 `birdc -s ... show status` 确认可用。

2. **配置热重载**
   - 仅 filter / per-interface metric / auth 变化：重写 conf → `birdc -s ... configure soft` → `birdc reload in <proto>` / `reload out <proto>`。
   - table / channel / interface pattern 结构变化：普通 `birdc configure`（会按需重启相关 protocol）。
   - 重载失败时回退到上一次成功配置，并记录 error；不直接 kill BIRD。

3. **优雅退出**
   - daemon shutdown 时先 `birdc -s ... down`（或 SIGTERM），等待进程退出。
   - 删除 Higgs-owned 的 pid、control socket、conf 文件（带 owner token 校验）。

4. **崩溃恢复**
   - daemon 事件循环中周期性 `waitpid(NO HANG)` 或 `show status` 探测。
   - BIRD 异常退出后，用同一份持久化 router-id 和 conf 重新拉起；连续崩溃进入指数 backoff。
   - **不要启用 BIRD 的 `randomize router id`**：Higgs 已经保证 router-id 持久稳定，随机化会导致序列号问题变成 router-id 抖动问题。

### external 模式

- Higgs 不启动/不停止 BIRD，只通过 control socket 执行 `configure`/`show`。
- 启动 reconcile 时校验 router-id、table、netns、socket 权限、interface pattern 是否匹配 Higgs 期望。
- control socket 丢失或 `show status` 失败时标记 `degraded`，记录 error，不主动重启。

## 通过 `higgs` 命令 dump BIRD 路由状态

CLI 通过 daemon control socket 请求 BIRD 快照，避免用户手动进 netns 执行 `birdc`：

```bash
# 每个 overlay 的 BIRD 实例状态
higgs debug babel [overlay-id]

# Higgs 授权路由集 + BIRD 实际学到/安装的路由
higgs debug routes

# 单条前缀的完整证据链
higgs debug route <prefix>
```

daemon 侧的 birdc client 执行以下命令并解析为结构化数据：

| 用途 | birdc 命令 | 输出字段 |
|------|-----------|---------|
| daemon 健康 | `show status` | version, router id, uptime, last reconfig |
| 协议状态 | `show protocols all <proto>` | name, proto, table, state, info, uptime |
| 接口/邻居 | `show interfaces` / `show protocols all <proto>` | interface, neighbor, address, babel metric |
| 学习路由 | `show route all` | prefix, from, via, interface, metric, source |
| 按协议过滤 | `show route protocol <proto>` | 同上，限定来源 |
| 按前缀 | `show route for <prefix> all` | 该前缀的多条路径 |

解析策略：

- birdc 输出是文本表格，按固定列对齐；Higgs 用正则/列解析，并在解析失败时返回原始文本 + `parse_warning`。
- 建议将最近一次解析结果落盘到 `state.BirdObservedState`，供 `debug babel` 离线使用。
- 命令执行带超时（如 5s），超时时返回部分缓存数据并标记 `stale`。

## BIRD tunnel 模式与选路

BIRD Babel 为 tunnel 接口提供专用模式：

```bird
protocol babel higgs_babel_main {
    ipv4 { ... };
    ipv6 { ... };
    ecmp on limit 16;          # 可选：等 metric 多路径

    interface "hgs*" {
        type tunnel;
        rxcost 96;             # 基础 cost，影响邻居选路
        hello interval 4 s;
        update interval 4 s;
        rtt cost 96;           # RTT 度量权重
        rtt min 10 ms;
        rtt max 120 ms;
        ecmp weight 1;         # ECMP 时权重
    };
}
```

要点：

- `type tunnel` 等价于 wired + 开启 RTT-based metric，默认 `rxcost 96`。
- Babel 到同一前缀的多条路径按综合 metric 排序；**metric 最小者进入 FIB**。
- 若开启 `ecmp on [limit N]` 且多条路径 metric 相等，BIRD 会生成多下一跳 ECMP 路由；`ecmp weight` 可调整流量比例。
- Higgs 可用不同 `rxcost` / `rtt cost` 区分 staged/draining 接口：
  - `metric_base` → 正常接口 `rxcost 96`
  - `metric_staged` → staged 接口 `rxcost 200`
  - `metric_draining` → draining 接口 `rxcost 500`
- 这意味着 BIRD 本身就能做 **active/backup 选路** 和 **多路径负载均衡**，不需要 Higgs 再写 kernel route 去干预 next-hop。

## 风险与待验证项

- [x] BIRD 在目标 netns 中启动并监听 UNIX control socket 的具体命令和权限模型。
- [ ] `birdc configure soft` + `reload in/out` 在 filter 变化时的实际收敛时间和路由中断窗口。
- [ ] interface pattern `hgs*` 在新接口创建后多久触发 Babel，是否稳定。
- [ ] 接口删除时 BIRD 是否正确发送 wildcard retraction，邻居多久感知。
- [ ] BIRD 的 Babel 实现与 babeld 的互操作性（如果网络中混跑）。
- [ ] BIRD 二进制在 NixOS / target 容器镜像中的体积和依赖。
- [ ] birdc 文本输出的解析稳定性（考虑使用稳定 CLI 输出格式）。
- [ ] BIRD Babel `ecmp on` 在 tunnel/RTT metric 场景下是否按预期生成 ECMP，以及 kernel 对 IPv6/IPv4 ECMP 的支持边界。

## 参考

- BIRD User's Guide: https://bird.nic.cz/doc/
- BIRD Babel config grammar: `proto/babel/config.Y`
- BIRD Babel interface notify: `proto/babel/babel.c` (`babel_if_notify`)
- BIRD interface pattern matching: `nest/iface.c` (`iface_patt_match`)
- BIRD CLI configure/reload: `nest/config.Y`, 官方 Remote control 章节
- babeld 历史调研：`docs/babeld-control-protocol-findings.md`
