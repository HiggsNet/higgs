# Photon Windows 设计

> 状态：实现中  
> 首个目标：Windows 11 amd64 prototype  
> 对应任务：[todo.md Phase 10](../../todo.md#phase-10-photon-windows当前新主线)

## 1. 产品边界

Photon Windows 是一个独立的 Windows 叶子客户端，程序入口为
`app/photon-windows`，发布产物为 `photon-windows.exe`。它不是现有 Linux
`photon daemon` 的 Windows 交叉编译版本，也不尝试在 Windows 上模拟 StrongSwan、
XFRM、BIRD 或 network namespace。

第一版固定以下边界：

- outbound-only IKEv2 initiator；
- 一个 active Photon gateway；
- 用户态 ESP tunnel mode；
- 内嵌 Babel leaf 和用户态 source-specific route table；
- Wintun 承接 Windows TCP/IP stack 的 L3 packet；
- split tunnel，只向 Windows 安装稳定 Photon aggregate route；
- 不做 transit、IKE responder、lite-to-lite、full tunnel、GUI 或 auto-update。

Photon Android 是后续独立产品。两个产品可以复用 portable core，但 Windows Service、
Wintun、IP Helper、named pipe 和 Event Log 不进入 Android 依赖图。

## 2. 数据流

```text
Windows applications / TCP-IP stack
                |
                v
             Wintun
                |
                v
       portable packet engine
                |
                v
   SADR lookup (source, destination)
                |
                v
       selected gateway / ESP SA
                |
                v
   shared UDP socket (IKE + ESP demux)
                |
                v
      Photon StrongSwan/BIRD gateway
```

Babel control packet 不通过 Wintun。portable core 为每个已建立 ESP peer 构造标准
IPv6 link-local UDP/6696 packet，直接交给该 peer 的 ESP send path；收到 ESP plaintext
时也先识别 Babel control packet，再决定是否写入 Wintun。

这样可以避免把 Babel multicast membership、link-local scope 和 UDP/6696 socket 暴露给
Windows 虚拟接口，同时保证业务 packet 仍使用 Windows 自带 TCP/IP stack。

## 3. 信任边界

Photon Windows 继续消费 Photon 的可信事实层：

- Zone authority 与 delegation chain；
- signed record、revocation 和有效期；
- IPAM pool/assignment；
- route announcement authorization；
- transport key、profile、address、port 和 overlay intent。

静态 gateway address 只能作为 bootstrap hint。IKE responder identity 必须匹配已验证的
transport record，Babel route 必须在写入 SADR table 前通过 `AuthorizedRouteSet`。

首版尚需完成 Babel 64-bit Router ID 到 verified Zone 的端到端 origin binding。在该绑定
完成前，prototype 只连接一个显式选择的可信 gateway；它能阻止未授权 prefix，却不能完全
阻止这个已认证 gateway 冒充另一个已授权 route origin。因此该阶段必须标记为
experimental，不能作为 production security boundary 发布。

### 3.1 本机私钥模型

Photon Windows 沿用 Photon Linux 的管理员责任模型。root、Zone identity 和 transport 的
Ed25519/private key material 可以作为普通原始字节直接保存在同一个 bbolt
RuntimeStateStore 中，不强制 DPAPI、CNG、NCrypt 或 non-exportable key。

本项目不宣称抵御已经取得本机 Administrators/SYSTEM 权限的攻击者；数据库文件、备份、磁盘和
主机访问控制由管理员负责。安装器可以设置合理 ACL，但 ACL/磁盘加密不是 Photon 协议正确性的
前置条件。程序仍必须避免把私钥写入日志、IPC、Observer、gossip、crash diagnostics 或导出的
Zone snapshot；这是防止意外远程泄漏，不是把进程内 Store 当作不可信边界。

公共 Store 直接根据当前 authority 从同一事务 candidate 选择授权私钥并调用公共 Ed25519
sign/verify。Windows 与 Linux 不维护两套 signer/key-store adapter，也不为硬件不可导出密钥改变
state transaction 语义。未来若需要平台加固，只能作为兼容相同持久化和签名语义的可选扩展。

### 3.2 Verified state 与 Gossip runtime 边界

`VerifiedState` 只保存会影响信任结论的事实：managed Zone、已验证 Network、完整 Ed25519
`trusted_root_public_key` pin 以及本机
raw private key。它不包含 peer session 或同步统计。

Gossip 状态分成两类：session phase、round/catalog cursor、timer generation、chunk assembly、repair
cache 和在途 object-pull 是协议正确性所需的活状态，只存在于 Engine/HostRuntime 内存，重启后重新同步；
backoff、最近 endpoint、observed grace、relay suppression 和 rejected digest TTL 是可丢失的
`GossipCheckpoint`，丢失最多带来额外重试或重新发现，不能改变验签、授权与最终收敛。attempt/error、
hint/responder、datagram/object-pull 等纯统计进入有界 observability/metrics，不进入公共持久状态。

公共状态只保留一个 `VerifiedRevision`，仅在已验证 Network 内容发生变化时推进。
`GossipCheckpoint` 没有独立 revision；checkpoint-only 保存不会让下游 controller 误以为可信事实变化。
平台 runtime checkpoint 也不反向修改 verified，只记录它所基于的 `SourceVerifiedRevision`。平台
RuntimeStateStore 可在一次 bbolt transaction 中原子保存这些逻辑分区，但不会创建第二个 DB handle、
writer goroutine 或 event loop。

公共 bbolt schema 由 `pkg/core/state` 固定为 `photon:common-state` 根 bucket，其下分别保存 schema/revision、
verified payload 与 gossip checkpoint。codec 只接收平台 RuntimeStateStore 已打开的 `*bolt.Tx`，不打开、
提交或关闭数据库；Linux/Windows 因而可以在同一个 `Update` 中组合自己的 runtime bucket。写入只检查
verified payload 变化是否恰好推进一次 `VerifiedRevision`，checkpoint 变化不参与版本竞争；最终
commit/rollback 仍由平台唯一 writer 决定。
schema、revision 或 verified payload 损坏时 fail closed；checkpoint JSON 损坏时加载空 checkpoint 并返回
discard report，重启后的重新发现与同步负责恢复效率提示。

`TrustedRootPublicKey` 是本机 trust-anchor pin，不是可由 gossip 更新的普通 verified 字段。当前协议没有定义
root-key rotation，因此在线 Store/codec 拒绝修改 pin，远端 root snapshot 也不得替换既有 root authority；
它只能在 authority 完全相同时更新由该 authority 验证的 root Zone 内容。未来若增加 root rotation，必须
先定义由旧 trust anchor 授权的新 pin 迁移协议，不能复用普通 snapshot apply。

Linux 旧 `_meta/cli_state` 与 `zone:*` 迁移也只接收唯一 RuntimeStateStore 提供的事务：同一事务写完公共
state bucket 和 `photon:linux-runtime` bucket 后删除旧表示，失败整体回滚，新旧表示同时存在则拒绝启动。
迁移函数在整体切换在线 writer 前保持未接线状态，不能让旧保存路径与新 bucket 同时写入。

Linux 已增加未接入在线路径的 RuntimeStateStore owner，用来验证最终 handle 生命周期和事务组合：它持有唯一
bbolt handle，首次加载在同一事务内迁移并读取完整 aggregate，公共 Repository 写入和 Linux runtime 聚合写入
均复用该 handle。字节完全相同的提交回滚为空操作；公共状态校验或提交失败会连同同事务的平台 payload 一起
回滚。第二个进程/handle 必须在有界超时后因文件锁冲突失败，Close 错误必须返回给生命周期 owner。E 阶段会
整体替换现有 Linux loader/writer，替换完成前两套路径不会同时在线。

## 4. 代码边界

```text
app/photon-windows
  CLI/version and Windows composition root

internal/photonclient
  portable contracts, lifecycle and packet runtime
  ike / esp / babel / sadr / transport / trust

internal/photonwindows
  SCM service, Wintun, IP Helper, named pipe, Event Log

pkg/core + pkg/crypto + pkg/routing + pkg/transport/ipsec
  reusable Photon verified facts and transport record model
```

Gossip 不做 Windows 分支。`pkg/core/state` 统一拥有 verified snapshot、zone digest、catalog DTO/
root/diff/projection 和 `ApplySnapshot`；`pkg/core/gossip` 直接引用这些 DTO，统一拥有 wire message、
依赖实际 wire-size 的 catalog page 装箱、object-pull、chunk 与 quota。Linux daemon 与 Photon Windows
直接链接同一组公共包，Windows 只注入 datagram/network adapter；不得复制协议源码到
`internal/photonwindows`，也不得引入 Windows 专属 snapshot 或“精简 gossip”语义。
每 peer 无 I/O 的同步 FSM 也位于 `pkg/core/gossip`；Linux daemon 和 Photon Windows 直接
引用公共事件、action 与状态机，不在各自入口保留类型别名或转发函数。
有界 packet receive loop 同样位于 `pkg/core/gossip`，只依赖 `PacketReceiver` 的
`Receive/Close` capability。Linux `Transport` 与未来 Windows adapter 共用该 loop；默认
队列为 64，backpressure 会暂停下一次 receive，不创建 per-packet goroutine。stop 拥有并
关闭 receiver，以解除不感知 context 的阻塞读取。
active-session/unsolicited packet classifier 也位于同一 `pkg/core/gossip`；它只按已验证
message 的 `PeerID` 查询当前 `SyncSession` map，不解释 message type。Linux 与 Windows 的
executor 分别处理 responder、状态提交和平台日志，不能把这些副作用放回 classifier。
同步事件的稳定诊断名和 peer ID 提取也由公共包提供，executor 不重复维护 event type switch。
在 classifier 之后，共享 inbound planner 统一解释 message type，产出有序的 session-event、
Ping/fetch responder、announce、chunk 或 NACK action。它固定 active/unsolicited policy 和
nil payload 的 fail-closed 行为；Linux/Windows executor 只执行 action 所需的平台副作用。
Read-only fetch 分类与 Ping response message planning 同样共享：公共逻辑固定 responder 标签、
catalog-root equality，以及 Pong 后按需请求 catalog page 的顺序；executor 负责读取本地 summary、
观测和实际发送。
`gossip.Engine` 是同步 FSM/session registry：拥有 per-peer session 与 pending announce hint，但不拥有
event queue、timer 资源、数据库或平台副作用。公共 `host.Runtime` 拥有 bounded event queue 和单
heap/wakeup Scheduler；timer policy/期限仍由 gossip session action 决定，Scheduler 只统一执行
replace/cancel、generation stale 防护、背压和 stop。Linux daemon 与 Photon Windows 都把共享 receive
loop 产出的 verified packet 注入同一 HostRuntime，再按相同顺序执行 Engine 返回的 action。
send action 到 wire message 的映射由 gossip 唯一实现；HostRuntime 的公共 action plan 固定
apply -> outbound -> object-pull -> timer -> backoff/persistence 分相和 persistence scope 合并。
平台 controller 只执行各相，不得再次按具体 gossip action 类型建立 switch。

因此平台注入边界不只有 UDP：至少还包括 timer clock、verified state projection、snapshot
apply/object-pull completion，以及 send/persistence/log effect executor。公共 gossip 不 bind socket、
不打开数据库，也不创建平台资源；协议 timer/receive goroutine 只依赖注入的 capability，具体 UDP
adapter 不泄漏进状态机。
UDP object chunk assembly、quiet-period NACK 和 sent-chunk repair cache 也复用
`pkg/core/gossip` 的同一实现。共享策略固定 object/hash/metadata 校验、per-peer inflight、
repair rounds、NACK index、TTL 和内存 byte 上限；Linux/Windows executor 只负责实际发送
NACK/chunk 以及将完整对象交回 `state.ApplySnapshot`。
Datagram announce planning、wire-size/MTU budget 计算和 zone snapshot chunk packing 也位于
gossip。它直接使用 state 的 `ZoneRoot`，统一排序、oversized 分类、object/root hash 与 chunk metadata；平台 executor
只提供随机 transfer ID，并承担 sent cache、UDP send 和日志副作用。

portable core 不得：

- 创建 Wintun/TUN；
- bind 系统 UDP socket；
- 修改 OS address、route、metric 或 DNS；
- 安装/控制 Windows Service；
- 读取 Windows registry；
- 监听 Unix signal。

平台 adapter 创建资源并通过窄接口转移给 runtime。首批接口位于
`internal/photonclient/contracts.go`，测试替身位于
`internal/photonclient/testkit`。
本机 identity 私钥随 verified/local state snapshot 提供，不是独立平台 resource capability。

## 5. 生命周期

`Runtime.Start` 只有在配置和全部 injected resources 验证通过、workload 的同步启动完成后
才进入 `running`。关键后台 loop 意外退出时 runtime 进入 `failed`，不能继续报告 ready。

正常停止顺序：

1. cancel runtime context，停止接收新的 Wintun packet；
2. workload 撤销用户态 route、停止 peer 并清理 SA；
3. 关闭共享 UDP transport；
4. 关闭 Wintun session/device；
5. 关闭 network/state observer；
6. 等待 workload 完整退出并报告最终状态。

Windows address/route 的 ownership 和回滚属于 `internal/photonwindows`，不由 portable
runtime 猜测。service crash 后下一次启动只能 adopt 带匹配 owner/generation 的资源。

## 6. 当前首个切口

当前实现只建立不会锁死后续协议选择的基础：

- 可交叉编译的 `photon-windows.exe` 命令骨架；
- portable platform contracts；
- runtime 状态与资源关闭语义；
- system/manual clock；
- memory tunnel 和 memory datagram transport；
- Photon Windows schema v1 与离线 `config validate`；
- 预置 bbolt state 经共享 `state.Snapshot`/`ApplySnapshot` 重建为 verified static source；
- Linux unit tests 与 Windows amd64 compile guard。

Wintun、IP Helper、SCM、IKE/ESP/Babel 实现分别在后续窄切口加入。未实现的命令不得伪造
connected/ready 状态。
