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

Gossip 不做 Windows 分支。Linux daemon 与 Photon Windows 直接链接同一个
`pkg/core/gossip`，共享 wire message、catalog、object-pull、chunk、quota、`Snapshot` 和
`ApplySnapshot`。Windows 只注入 datagram/network adapter；不得复制一份协议源码到
`internal/photonwindows`，也不得引入 Windows 专属 snapshot 或“精简 gossip”语义。
每 peer 无 I/O 的同步 FSM 也位于 `pkg/core/gossip`；Linux daemon 通过兼容别名执行其
action，Photon Windows 后续直接调用同一状态机。
有界 packet receive loop 同样位于 `pkg/core/gossip`，只依赖 `PacketReceiver` 的
`Receive/Close` capability。Linux `Transport` 与未来 Windows adapter 共用该 loop；默认
队列为 64，backpressure 会暂停下一次 receive，不创建 per-packet goroutine。stop 拥有并
关闭 receiver，以解除不感知 context 的阻塞读取。
active-session/unsolicited packet classifier 也位于同一 `pkg/core/gossip`；它只按已验证
message 的 `PeerID` 查询当前 `SyncSession` map，不解释 message type。Linux 与 Windows 的
executor 分别处理 responder、状态提交和平台日志，不能把这些副作用放回 classifier。
UDP object chunk assembly、quiet-period NACK 和 sent-chunk repair cache 也复用
`pkg/core/gossip` 的同一实现。共享策略固定 object/hash/metadata 校验、per-peer inflight、
repair rounds、NACK index、TTL 和内存 byte 上限；Linux/Windows executor 只负责实际发送
NACK/chunk 以及将完整对象交回 `ApplySnapshot`。

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
- 预置 bbolt state 经共享 `gossip.Snapshot`/`ApplySnapshot` 重建为 verified static source；
- Linux unit tests 与 Windows amd64 compile guard。

Wintun、IP Helper、SCM、IKE/ESP/Babel 实现分别在后续窄切口加入。未实现的命令不得伪造
connected/ready 状态。
