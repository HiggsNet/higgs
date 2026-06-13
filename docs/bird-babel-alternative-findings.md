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
      router_id: 1.2.3.4         # 可选，默认从本地 zone + overlay id 确定性派生
      table: 100                 # kernel table id 或名称
      table_name: higgs_100      # BIRD 内部 table 名，可选
      priority: 100              # ip rule priority
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
| `router_id` | string | 否 | 覆盖默认 router-id |
| `table` | int/string | 是 | kernel routing table id 或名称 |
| `table_name` | string | 否 | BIRD 内部 table 名 |
| `priority` | int | 否 | `ip rule` 优先级 |
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
│  ├── 启动: bird -c <conf> -s <ctl>           │
│  ├── filter 变更: 重写 conf + birdc configure│
│  ├── 监控: birdc show protocols / show route │
│  └── 退出: birdc down / SIGTERM              │
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

## 风险与待验证项

- [ ] BIRD 在目标 netns 中启动并监听 UNIX control socket 的具体命令和权限模型。
- [ ] `birdc configure soft` + `reload in/out` 在 filter 变化时的实际收敛时间和路由中断窗口。
- [ ] interface pattern `hgs*` 在新接口创建后多久触发 Babel，是否稳定。
- [ ] 接口删除时 BIRD 是否正确发送 wildcard retraction，邻居多久感知。
- [ ] BIRD 的 Babel 实现与 babeld 的互操作性（如果网络中混跑）。
- [ ] BIRD 二进制在 NixOS / target 容器镜像中的体积和依赖。
- [ ] birdc 文本输出的解析稳定性（考虑使用稳定 CLI 输出格式）。

## 参考

- BIRD User's Guide: https://bird.nic.cz/doc/
- BIRD Babel config grammar: `proto/babel/config.Y`
- BIRD Babel interface notify: `proto/babel/babel.c` (`babel_if_notify`)
- BIRD interface pattern matching: `nest/iface.c` (`iface_patt_match`)
- BIRD CLI configure/reload: `nest/config.Y`, 官方 Remote control 章节
- babeld 历史调研：`docs/babeld-control-protocol-findings.md`
