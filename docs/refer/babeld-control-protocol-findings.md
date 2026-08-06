# babeld Control Protocol 调研结论（修正版）

> **历史参考文档**
>
> Photon Phase 5 已决定采用 **BIRD** 作为默认 Babel 路由后端。本文档保留为 babeld 能力调研记录，不再作为项目主实现路径参考。

> 调研日期: 2026-06-13
> babeld 版本: 1.13.1 (NixOS 24.11)
> 调研环境: Linux 6.17, 本机直接测试

## 核心发现

### 1. 控制 socket 有两种模式，不是只有只读模式

| 启动参数 | 配置文件等价项 | 模式 | 说明 |
|---------|--------------|------|------|
| `-g port` / `-g /path` | `local-port` / `local-path` | 只读 | 仅允许 `dump` / `monitor` / `unmonitor` / `quit` |
| `-G port` / `-G /path` | `local-port-readwrite` / `local-path-readwrite` | 读写 | 允许运行时修改部分配置 |

**之前结论的错误**：把 `-g` 只读模式的行为当成了整个 control protocol 的能力，得出了 "control socket 只读" 的错误结论。实际上 `-G` 读写模式存在，且可以动态增删接口。

### 2. 动态增删接口的命令是 `interface <name>`，不是 `add_interface`

之前测试使用的 `add_interface` 是**不存在的命令**，返回 `bad` 是因为命令名错误，而不是因为协议不支持动态加接口。

实测（`-G` 读写 socket）：

```
$ { echo "interface dummy0"; echo "dump"; echo "quit"; } | socat - UNIX-CONNECT:/tmp/babeld.ctl
BABEL 1.0
version babeld-1.13.1
host road
my-id be:24:11:ff:fe:97:0f:60
ok
ok                       <-- interface dummy0 成功
add interface lo up false
add interface dummy0 up false
...
ok
```

`flush interface <name>` 同样可以动态移除接口：

```
$ { echo "flush interface dummy0"; echo "quit"; } | socat - UNIX-CONNECT:/tmp/babeld.ctl
BABEL 1.0
...
ok
```

### 3. 命令矩阵（babeld 1.13.1, `-G` 读写模式, 运行时）

| 命令/指令 | 是否支持 | 响应 | 说明 |
|----------|---------|------|------|
| `dump` | ✅ | 输出全部状态后 `ok` | 只读/读写模式都支持 |
| `monitor` / `unmonitor` | ✅ | 开启/关闭事件流 | 只读/读写模式都支持 |
| `quit` | ✅ | 关闭连接 | 只读/读写模式都支持 |
| `interface <name> [params...]` | ✅ | `ok` | **运行时动态添加接口** |
| `default [params...]` | ✅ | `ok` | 运行时修改默认接口参数 |
| `flush interface <name>` | ✅ | `ok` / `no` | **运行时动态移除接口** |
| `key id ... type ... value ...` | ✅ | `ok` | 运行时添加 HMAC key |
| `link-detect {true\|false}` | ✅ | `ok` | 运行时修改 |
| `log-file <path>` | ✅ | `ok` | 运行时修改并重新打开 |
| `smoothing-half-life <sec>` | ✅ | `ok` | 运行时修改 |
| `reopen-logfile` | ✅ | `ok` | 运行时重新打开日志 |
| `in ...` / `out ...` | ❌ | `bad` | filter 只能在配置初始化阶段设置 |
| `redistribute ...` / `install ...` | ❌ | `bad` | 同上 |
| `export-table <table>` | ❌ | `bad` | 只能在配置初始化阶段设置 |
| `import-table <table>` | ❌ | `bad` | 同上 |
| `local-port*` / `local-path*` | ❌ | `bad` | 只能在配置初始化阶段设置 |
| `add_interface` | ❌ | `bad` | 命令名不存在 |

### 4. 运行时 vs 初始化阶段的能力边界

源码层面（`configuration.c` 的 `parse_config_line`）可以清楚看到边界：

- `config_finalised && !local_server_write`：在只读模式下，除 `dump`/`monitor`/`unmonitor`/`quit` 外的所有指令都被拒绝。
- `in`/`out`/`redistribute`/`install` filter：源码中明确有 `if(config_finalised) goto fail;`，所以**运行时再也无法新增或修改 filter**。
- `interface`/`default`/`flush interface`/`key`：没有 `config_finalised` 限制，可以在 `-G` 读写模式下运行时执行。
- `parse_option()`：运行时只允许 `link-detect`、`log-file`、`smoothing-half-life`。

### 5. dump 输出格式

```
BABEL 1.0
version babeld-1.13.1
host road
my-id be:24:11:ff:fe:97:0f:60
ok
add interface lo up false
add interface dummy0 up false
add xroute 10.16.255.8/32-0.0.0.0/0 prefix 10.16.255.8/32 from 0.0.0.0/0 metric 0
...
ok
```

格式与之前记录一致，仍然是非正式 API，版本间可能变化。

## 对 Photon Phase 5 的影响（修正）

### 影响 1: 接口可以动态管理，不必依赖 SIGHUP

**之前结论**：managed mode 必须用 SIGHUP reload 来增删接口。  
**修正**：Photon 可以通过 `-G` 读写 control socket 实时增删接口。

```
# 添加 IPsec link 对应的接口
interface phxxxxx type tunnel

# 移除已下线的接口
flush interface phxxxxx
```

这样 Photon IPsec reconcile 后，可以直接把 up 的 tunnel 接口动态加入 babeld，不需要重写配置文件 + SIGHUP。

### 影响 2: filter 仍然只能静态声明

`in`/`out`/`redistribute`/`install` filter 无法在运行时修改。所以之前设计的 "双层过滤" 方案依然成立：

- babeld 侧使用宽松的静态 filter（例如 `in if phxxxxx allow`）
- Photon 在 kernel route table 层面做授权过滤，定期清理未授权路由

### 影响 3: xroute（export 前缀集）仍然无法动态调整 filter

由于 `redistribute` filter 只能在初始化阶段设置，export 前缀集的变化有两种应对方式：

1. **broad filter + kernel 路由控制**：配置 `redistribute local allow` 等宽松规则，Photon 通过控制 kernel route table 中实际存在哪些本地路由来决定哪些前缀被宣告。
2. **配置文件重写 + SIGHUP**：如果 export set 变化频繁且需要精确控制，仍需要 reload。

### 影响 4: routing table 仍然只能在启动时指定

`export-table`（`-t`）和 `import-table`（`-T`）无法在运行时修改。每个 overlay 的独立 table 必须在启动时确定。

### 影响 5: HMAC key 可以运行时注入

如果后续需要 per-link HMAC 认证，key 可以通过 `-G` socket 动态添加（`key id ... type ... value ...`），不需要重启。

## 推荐架构变更（修正）

基于修正后的结论，Phase 5 推荐采用 **control socket 动态接口 + 静态 filter + kernel auditor** 的混合模式：

```
┌─────────────────────────────────────────────┐
│                  Photon daemon                │
├─────────────────────────────────────────────┤
│  IPsec Reconciler                            │
│  ├── 发现 up/down 的 IPsec tunnel 接口        │
│  └── 通过 -G control socket 增删 babeld 接口  │
├─────────────────────────────────────────────┤
│  Route Authorization                         │
│  ├── 扫描 active state 中 verified           │
│  │   route announcements                     │
│  ├── 校验 assignment chain                   │
│  └── 生成 authorized prefix set              │
├─────────────────────────────────────────────┤
│  babeld Config Generator (启动时一次性)       │
│  ├── 根据 LinkGroupSpec.Routing 生成配置      │
│  ├── routing-table <table>                   │
│  ├── 宽松 import filter (e.g. in if ... allow)│
│  ├── 宽松 redistribute filter               │
│  └── 通过 -c/-C 传给 babeld                 │
├─────────────────────────────────────────────┤
│  babeld Process Manager                      │
│  ├── 启动: 在目标 netns 中用 -G <path> 启动   │
│  ├── 监控: 连接 control socket 做 monitor     │
│  ├── 接口变更: 通过 -G socket 发 interface/flush│
│  └── 退出: 发送 SIGTERM                      │
├─────────────────────────────────────────────┤
│  Route Auditor (kernel layer)                │
│  ├── 周期性扫描 overlay route table          │
│  ├── 删除未在 authorized set 中的 learned    │
│  ├── 检测 policy violation 的 peer           │
│  └── suppress 重复 detection/cleanup         │
└─────────────────────────────────────────────┘
```

### 与旧架构的主要区别

1. **接口管理从 "配置文件 + SIGHUP" 改为 "-G control socket 实时指令"**。
2. **babeld 启动配置只需写一次**，包含宽松 filter 和 routing table；后续接口变化走 control socket。
3. **SIGHUP 降级为备用手段**：仅在需要修改 filter / routing table / redistribute 规则时才使用。

### 需要补充验证的清单

- [ ] `interface` 动态添加后立即开始发送 Hello，邻居建立时间
- [ ] `flush interface` 是否会正确发送 retraction，邻居多久感知
- [ ] 频繁 `interface` / `flush interface` 是否稳定（内存、fd 泄漏）
- [ ] 多客户端同时连接 `-G` socket 时的行为与并发安全
- [ ] `-G` socket 的权限模型（任何能写 socket 的用户都可改配置）

## 参考

- `babeld(8)` LOCAL CONFIGURATION INTERFACE 章节
- babeld 1.13.1 源码：`configuration.c` 的 `parse_config_line()` / `parse_option()`
- babeld 1.13.1 源码：`local.c` 的 `local_read()`
