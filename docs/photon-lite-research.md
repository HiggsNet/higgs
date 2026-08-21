# Photon Lite 跨平台实现调研

> 状态：调研草案  
> 日期：2026-08-21  
> 参考项目：[NickCao/ranet-lite](https://github.com/NickCao/ranet-lite)  
> 调研快照：[ranet-lite `24a24a2`](https://github.com/NickCao/ranet-lite/commit/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5)

## 1. 背景与目标

Photon 当前的数据面依赖 Linux、StrongSwan/XFRM 和 BIRD/Babel。未来设想的
`photon-lite` 希望能运行在 Windows 和 Android 上，因此不能直接依赖现有 Linux
数据面，需要考虑：

- 用户态 IKEv2 initiator；
- 用户态 ESP encap/decap；
- 内嵌 Babel speaker 和用户态路由选择；
- Windows Wintun、Android `VpnService` 等平台 TUN 接入；
- 移动网络切换、NAT、后台生命周期和 Android 耗电；
- 保留 Photon 的 Zone、签名、IPAM、route authorization 和 gossip 信任模型。

本调研主要分析 `ranet-lite` 有哪些设计和实现可以借鉴，以及哪些部分不能直接用于
Photon。

## 2. 总体结论

`ranet-lite` 很适合作为协议原型和实现素材，但不适合直接 fork 成
`photon-lite`。它最值得借鉴的决策是主动缩小 lite 节点的职责：

- 节点永远是 leaf/stub，不承担 transit；
- 只实现 IKEv2 initiator，由完整 StrongSwan 节点充当 responder；
- ESP、Babel 和下一跳选择全部在用户态完成；
- 使用一个 TUN、一个共享 UDP Hub 和少量上游 peer；
- Babel 控制包直接作为 ESP 内层 IPv6 包处理，不依赖平台上的 babeld、组播接口或
  kernel route protocol。

建议把这些限制直接作为 `photon-lite v1` 的产品边界：

```text
outbound-only leaf
  + one active Photon gateway
  + optional cold/low-frequency standby gateway
  + no transit
  + no lite-to-lite IKE
```

不建议为 v1 重写完整 babeld 或完整 IKEv2 responder。完整 Photon 节点继续负责
responder、transit、路由汇聚和网络控制。

## 3. ranet-lite 项目状态

本次检查基于 master 的 `24a24a2`。项目在 2026-08-17 开始提交，2026-08-19
为当前最新提交，在很短时间内积累了 108 个 commit 和约 11.3k 行 Go 代码。

本地验证结果：

- `go test ./...` 通过；
- `go test -race ./...` 通过；
- Android/ARM64 standalone binary 可以交叉编译，带调试信息约 7.5 MiB；
- Windows 核心包可以交叉编译；最终命令目前因 Unix 专用的
  `syscall.SIGUSR1` 编译失败，使用 build tag 拆分即可解决；
- 仓库当前没有 CI、fuzz target 和正式 release/tag；
- StrongSwan、BIRD 和真实 TUN 的协议互操作主要通过 standalone test 程序和手工测试
  验证。

因此，当前代码是质量较好的快速原型，但提交历史很短，仍应经过独立安全审计、fuzz、
互操作矩阵和长期运行测试后才能进入生产安全边界。

项目说明及明确限制见
[ranet-lite README](https://github.com/NickCao/ranet-lite/blob/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/README.md)。

## 4. 架构概览

ranet-lite 的核心数据流如下：

```text
Host TCP/IP stack
        |
        v
       TUN
        |
        v
SADR (source, destination) route lookup
        |
        v
per-peer userspace ESP SA
        |
        v
shared UDP Hub
  |- non-ESP marker -> IKE SPI demux
  `- ESP packet     -> ESP SPI demux
        |
        v
StrongSwan/XFRM/BIRD peer
```

内嵌 Babel 不通过本机 TUN 发送控制流量。它为每个 ESP peer 构造一份标准 IPv6
link-local UDP/Babel 包，直接调用该 peer 的发送函数；收到 ESP 明文后也先检查是否为
Babel 包，再决定交给 TUN。这种设计非常适合 Android/Windows，因为核心无需在平台
虚拟接口上处理组播 membership、scope ID 和 UDP 6696 绑定。

相关实现：

- [IKEv2](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/ike)
- [ESP](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/esp)
- [Babel speaker](https://github.com/NickCao/ranet-lite/blob/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/babel/speaker.go)
- [SADR table](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/sadr)
- [UDP mux](https://github.com/NickCao/ranet-lite/blob/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/transport/mux.go)
- [TUN pipeline](https://github.com/NickCao/ranet-lite/blob/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/netstack/mesh.go)

## 5. 可借鉴模块

| 模块 | 借鉴价值 | Photon Lite 建议 |
|---|---:|---|
| 用户态 ESP | 高 | 移植 AEAD、SPI、sequence、padding、anti-replay、rekey overlap |
| SADR route table | 高 | 可评估直接复用根目录公开包 `sadr` |
| 单 UDP Hub + SPI demux | 高 | 保留；减少 socket、NAT mapping 和 radio 活跃次数 |
| Babel leaf speaker | 高 | 借用 wire codec 和 direct-per-peer I/O，补 Photon authorization 和低功耗调度 |
| IKEv2 initiator | 中高 | 借用 parser、crypto 和 rekey 状态机，适配 Photon identity/profile |
| TUN packet pipeline | 中 | 借用有序并行处理；TUN 的创建和所有权必须重构 |
| registry/config | 低 | ranet 静态 registry 不适合 Photon，应替换为 verified Zone state |

### 5.1 ESP

ESP 实现的优点包括：

- AES-GCM 和 ChaCha20-Poly1305；
- tunnel mode IPv4/IPv6；
- outbound sequence/IV 原子分配；
- inbound anti-replay window；
- 严格检查 SPI、padding、Next Header 和内层 IP 长度；
- Child SA rekey 时允许新旧 inbound SA 短暂重叠；
- 并行加解密，同时保持交付顺序。

当前不支持 ESN，必须在 32-bit sequence 空间耗尽前 rekey。对 lite 节点通常足够，
但需要增加长时间高吞吐测试和 sequence exhaustion 测试。

### 5.2 SADR

路由表直接以 `(source prefix, destination prefix)` 为键，并按“destination longest
match 优先、同 destination specificity 下 source longest match”执行 lookup。它比把
source-specific route 近似成普通 destination route 更适合 Photon。

`sadr` 和 `esp` 位于 Go module 根目录，可以被其他 module import。IKE、Babel、
transport 和 netstack 位于 Go `internal/` 下，Photon 不能直接 import；需要：

1. 让上游抽取公共 library；或
2. 在保留 MIT notice 的前提下 fork/copy；或
3. 只参考协议实现重新实现。

### 5.3 UDP Hub

一个共享 UDP socket 同时承载多个 peer 的 IKE 和 ESP：

- IKE 使用四字节 non-ESP marker，并按 initiator SPI 分流；
- ESP 使用包首 inbound SPI 分流；
- peer 共享同一本地端口；
- Linux 下可以利用 WireGuard Go socket backend 的 batch I/O。

这一点对移动端尤其重要。若每个 peer 各自维护 UDP socket、DPD、NAT keepalive 和
timer，会直接放大后台功耗。

### 5.4 Babel leaf speaker

当前 speaker 支持 Hello、IHU、Update、AckReq/Ack、RTT extension 和 SADR Update，
只宣告本地 originate prefix，不向其他 peer 重宣告 learned route。

适合借鉴的不是“完整 babeld”，而是：

- 标准 Babel wire format；
- per-peer point-to-point neighbor state；
- Babel control packet 直接注入 ESP；
- learned route 直接写入用户态 route table；
- triggered update 和 periodic expiry；
- leaf-only、不宣称本机不具备的 forwarding 能力。

Photon Lite 还需要增加：

- 稳定、可从 Zone/netns 派生的 Router ID；
- route authorization hook；
- originate sequence 持久化/递增；
- 更完整的 Route Request/Seqno Request 处理；
- mobile-aware interval 和 timer coalescing；
- peer/link 状态变化触发的立即收敛，而不是只等 Hello timeout。

## 6. 与 Photon 信任模型的差异

ranet-lite 读取静态 `registry.json`，验证 IKE peer identity，但 Babel 路由本身没有
Photon 的 Zone/IPAM/route announcement 授权。

Photon Lite 必须继续复用现有可信事实层：

- Zone store 和 delegation chain；
- signed record 验证；
- IPAM pool/assignment；
- route announcement authorization；
- transport key、profile、addresses、ports 和 overlay intent；
- gossip/object pull 或其 lite 版本。

建议在 Babel 安装 route 前增加窄接口：

```go
type RouteAuthorizer interface {
    Allow(routerID [8]byte, source, destination netip.Prefix) bool
}
```

它由 Photon verified active state 和 `AuthorizedRouteSet` 驱动。Babel 只负责选择下一跳
和 metric，不能决定一个前缀是否有资格进入数据面。

需要进一步研究如何把 Babel origin Router ID 与 verified Zone/netns 稳定映射，以及如何
处理恶意 authenticated peer 伪造其他 origin Router ID 的问题。现有 Babel/ESP link
authentication 并不等同于端到端 route-origin authentication。

## 7. IKEv2 范围与互操作

ranet-lite 的 IKEv2 是 modern-crypto-only initiator：

- raw Ed25519 public-key authentication；
- RFC 7427 Digital Signature / RFC 8420 EdDSA；
- X25519、P-256、P-384；
- AES-GCM、ChaCha20-Poly1305；
- SHA-256/384 PRF；
- forced UDP encapsulation；
- full-range IPv4/IPv6 traffic selectors；
- local/peer initiated Child SA 和 IKE SA rekey；
- DPD、delete 和 simultaneous rekey collision handling。

明确不支持：

- initial responder role；
- MOBIKE；
- certificates、EAP；
- IKE fragmentation；
- legacy CBC/MODP/SHA-1 profile。

Photon 适配至少需要：

- 使用 Photon Zone/FQDN identity，而不是 ranet 的 organization/common-name/serial ASN.1
  DN；
- 消费 Photon `ipsec/transport-key`，默认 Ed25519，并决定是否支持 ECDSA P-256；
- 消费 Photon peer addresses/ports/current generation 和 overlay intent；
- 与现有 StrongSwan responder 配置做双向 interop test；
- 网络变化时 teardown/reconnect，第一版不必先实现 MOBIKE；
- 允许平台注入/rebind 已经 `protect()` 的 UDP transport。

现有 Photon StrongSwan driver 已经使用 `encap=yes`、`mobike=no` 和 route-based broad
traffic selector，整体模型与 ranet-lite 接近，见
[`pkg/transport/ipsec/strongswan.go`](../pkg/transport/ipsec/strongswan.go)。

## 8. 平台抽象

portable core 不应自行创建 TUN、bind socket、配置 route 或监听 Unix signal。建议边界：

```go
type TunnelDevice interface {
    ReadBatch(buffers [][]byte, sizes []int) (int, error)
    WriteBatch(buffers [][]byte) (int, error)
    MTU() int
    Close() error
}

type DatagramTransport interface {
    Send(peer PeerEndpoint, packets [][]byte) error
    Receive() (PeerEndpoint, []byte, error)
    Rebind(NetworkHandle) error
    Close() error
}

type NetworkObserver interface {
    Changes() <-chan NetworkChange
}

type SecureKeyStore interface {
    LoadOrCreateIdentity(...) (Signer, error)
}
```

目标依赖方向：

```text
Android VpnService / Windows Service + Wintun
                    |
                    v
              platform adapter
                    |
                    v
  Photon verified state + IKE + ESP + Babel leaf + SADR
                    |
                    v
          one protected shared UDP transport
```

平台层拥有资源，Go 核心只消费抽象。这样可以在 unprivileged unit test 中使用 memory TUN
和 fake datagram transport。

## 9. Windows

Windows 并非没有 native IKEv2/IPsec。系统内置 VPN client，也可以通过 Windows
Filtering Platform 配置 IPsec：

- [Windows VPN connection types](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-connection-type)
- [VPNv2 CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/vpnv2-csp)
- [WFP IPsec configuration](https://learn.microsoft.com/en-us/windows/win32/fwp/ipsec-configuration)

但 native VPN profile 面向单 gateway，认证和算法 profile 也不匹配 Photon 当前 raw
Ed25519、多 peer、用户态 Babel/SADR 和自定义端口语义。因此，从统一 portable core 的角度，
用户态 IKEv2+ESP 仍然合理。

推荐 Windows 实现：

- 使用 [Wintun](https://github.com/WireGuard/wintun) 提供 L3 adapter；
- Windows Service 承载 Go core；
- 用 IP Helper API 管理 interface address、route 和 metric，避免依赖 `netsh`；
- GUI 通过窄 IPC 与 service 通信；
- 平台文件处理 service control、shutdown、route cleanup 和日志；
- 打包 Wintun DLL/driver，明确管理员权限、升级和卸载策略；
- 后续考虑 DNS/NRPT、firewall/kill switch 和 Modern Standby。

ranet-lite 已依赖 WireGuard Go TUN backend，Windows 核心包能够交叉编译；当前 main 的
`SIGUSR1` 只是平台拆分问题。因此 Windows 是最快可以验证协议和数据面的第一平台。

## 10. Android

Android 上不应让 Go core 调用 Linux `tun.CreateTUN`。普通 App 必须由 Kotlin/Java
`VpnService`：

1. 请求 VPN 用户授权；
2. 创建 underlay UDP socket；
3. 调用 `VpnService.protect()`，避免 socket 流量重新进入 VPN；
4. 用 `VpnService.Builder` 配置 address、route、DNS、MTU 和 app allow/deny list；
5. 调用 `establish()` 获得 TUN `ParcelFileDescriptor`；
6. 把 TUN FD 和受保护的 UDP transport 交给 native core；
7. 以 foreground service 运行，并支持 always-on 生命周期。

官方开发流程见 [Android VPN guide](https://developer.android.com/develop/connectivity/vpn) 和
[`VpnService`](https://developer.android.com/reference/android/net/VpnService)。

关键问题：

- 一个 user/profile 同时只能有一个 active VPN service；
- TUN address/route/app list 属于 `Builder.establish()` 时的 interface 配置，频繁动态变化
  可能要求重新建立 TUN，影响现有 flow；
- 应优先向 TUN 安装稳定 Photon/IPAM aggregate route，而不是每条 Babel learned route；
- `ConnectivityManager` network callback 应触发 UDP rebind 和 IKE reconnect；
- 设置并更新 underlying network；
- 必须处理 `onRevoke()`、always-on boot、app upgrade 和厂商后台限制；
- 私钥建议用 Android Keystore 中的 wrapping key 加密存储，而不是直接明文落盘；
- 第一版可在网络切换时重连，不必立即实现 MOBIKE。

Android 的 `Ikev2VpnProfile` 是可评估的 gateway-only 备选，但认证主要是证书、PSK、
EAP，且无法提供 Photon 所需的用户态多 peer/Babel packet pipeline：

- [`Ikev2VpnProfile.Builder`](https://developer.android.com/reference/android/net/Ikev2VpnProfile.Builder.html)
- [`IpSecManager`](https://developer.android.com/reference/android/net/IpSecManager)

如果未来产品允许退化成“一个 native IKE gateway + 稳定静态 aggregate route”，可以把
它作为低维护、低功耗模式或基准实现。

## 11. Android 耗电分析

ranet-lite 当前默认：

| 活动 | 默认周期 | 每 peer 理论调度/包数量 |
|---|---:|---:|
| IKE receive poll | 100 ms | 最多 864,000 timeout/day/session |
| DPD | 10 s idle | 最多 8,640 probe/day/session |
| Babel Hello/IHU | 20 s | 4,320 send/day/peer |
| Babel Update timer | 80 s | 1,080 timer/day；无 originate 时不一定发包 |

这些数字不等于同数量的硬件 wakeup，实际 authenticated ESP 流量也会抑制 DPD；但它们
说明当前调度是 server/desktop profile，不适合直接用于手机。

Photon 当前 BIRD 默认 Hello 4 秒、Update 16 秒，见
[`pkg/routing/bird/generator.go`](../pkg/routing/bird/generator.go)。即使 lite 自己使用 20 秒
Hello，网关仍可能每 4 秒向手机发一个 Babel Hello，相当于每 peer 每天 21,600 个入站
控制包。Android 优化必须同时修改 lite client 和 Photon gateway 的 per-link Babel profile。

Android Doze 会限制网络和 CPU、忽略普通 wake lock 并延迟 job/alarm。不能假设
foreground/always-on VPN 自动消除 Doze 影响：

- [Doze and App Standby](https://developer.android.com/training/monitoring-device-state/doze-standby)
- [Foreground service overview](https://developer.android.com/develop/background-work/services)

### 11.1 低功耗原则

- 移除 100 ms polling，使用真正阻塞/event-driven receive；
- 所有 peer、IKE、Babel、gossip 共用一个 deadline heap/timer scheduler；
- 默认仅一个 active gateway；standby cold 或低频探测；
- DPD、Babel Hello 和 NAT keepalive 合并为同一次发送机会；
- 有 authenticated ESP 流量时不额外发送 DPD/keepalive；
- mobile profile 的 DPD 建议从 60–120 秒起测，而不是固定 10 秒；
- 为 lite link 配置较长的 gateway-side Babel Hello，例如从 30–60 秒起测；
- 网络 callback、socket error 和 IKE state 负责快速故障感知，不依赖短 Hello timeout；
- Android crypto worker 默认 1–2 个，按吞吐/充电状态自适应，不按 `NumCPU()` 开 8–16
  个 worker；
- 避免 per-packet goroutine，使用固定 worker 和 batch；
- gossip digest、repair 和 record publish 批量执行；
- 不长期持有 wake lock；允许 Doze 后恢复；
- 根据 underlying link MTU 动态选择 TUN MTU，至少保证 IPv6 1280；
- 按 Wi-Fi、cellular、charging、screen-off 和 Doze 使用不同 profile。

### 11.2 测量方案

不能仅比较网络字节数。应记录：

- CPU wakeups、timer wakeups；
- WLAN/cellular radio active 时间；
- userspace wake lock；
- 控制包数、数据包数和 reconnect 次数；
- 空闲电量差；
- Wi-Fi/cellular handoff 恢复时延；
- active throughput 下 CPU、功耗和 packet loss。

建议在真机做以下 A/B：

```text
no VPN baseline
Android native IKEv2 baseline
photon-lite: current ranet-lite timers
photon-lite: event-driven + mobile intervals
photon-lite: 1 active peer vs 2 active peers
Wi-Fi idle / LTE idle / Doze / active throughput
```

优先使用 Android Power Profiler/System Trace；Pixel 6+ 可以观察 CPU、WLAN 和 cellular
power rails：

- [Power Profiler](https://developer.android.com/studio/profile/power-profiler)
- [Batterystats](https://developer.android.com/topic/performance/power/setup-battery-historian)

具体功耗验收线应在最小 Android prototype 后，根据 native IKEv2/WireGuard 和 no-VPN
baseline 制定，而不是提前凭估计固定。

## 12. 推荐实施路线

### Phase 0：冻结 lite 契约

- outbound-only leaf；
- 一个 active gateway，可选一个 standby；
- 不做 transit；
- 不做 lite-to-lite；
- 只支持 Photon verified records；
- 明确 split-tunnel aggregate 和 full-tunnel 两种 route 模式；
- 决定是否保留 native IKE gateway-only mode。

### Phase 1：抽取 portable core

- TUN、datagram、clock、key store、network observer 接口化；
- 移植/重写 ESP、SADR、IKE initiator、Babel leaf；
- 接入 Photon Zone store、verification、authorized route set 和 transport records；
- 使用 memory TUN/fake socket 做无特权端到端测试；
- 增加 parser fuzz、RFC vectors 和 malformed packet corpus。

### Phase 2：Windows prototype

- Wintun adapter；
- Windows Service；
- address/route/metric 管理；
- 与 Photon StrongSwan/BIRD gateway 完成 IPv4/IPv6 interop；
- 验证 rekey、loss/reorder、MTU、restart/adopt 和 cleanup。

### Phase 3：Android vertical slice

- Kotlin `VpnService` lifecycle；
- TUN FD 和 protected UDP transport 注入 Go core；
- foreground/always-on；
- stable aggregate route；
- Wi-Fi/cellular callback 与重连；
- Doze、app kill、reboot、upgrade 和 permission revoke 测试。

Android vertical slice 应尽早开始功耗测量，不要等所有协议功能完成后再处理耗电。

### Phase 4：生产化

- timer coalescing 和 adaptive keepalive；
- gateway-side mobile Babel profile；
- control-plane batching；
- packet buffer/pool 和 worker 调优；
- DNS、firewall、kill switch 和泄漏测试；
- 强制 revocation 和 route authorization；
- 长期 soak、互操作矩阵和外部安全审计。

## 13. 测试与安全门槛

用户态 IKE/ESP 属于高风险网络安全边界。进入生产前至少需要：

- `go test -race ./...`；
- IKE、ESP、Babel、SADR parser fuzz；
- RFC/IANA test vectors；
- malformed length、duplicate payload、unknown critical payload、SPI spoof、replay、sequence
  wrap、padding 和 inner-IP validation；
- Child/IKE simultaneous rekey collision；
- packet loss、duplication、reorder、delay 和 MTU black-hole；
- StrongSwan 多版本/多算法 interop；
- BIRD Babel/SADR/RTT interop；
- Wi-Fi、IPv4、IPv6、NAT44、CGNAT、蜂窝和网络切换；
- Android Doze、always-on、reboot、app upgrade 和 OEM background policy；
- Windows service crash/recovery、Wintun upgrade/uninstall 和 route cleanup；
- verified route revocation 后的数据面及时撤回；
- 独立密码学和协议状态机审计。

## 14. 待决策问题

后续进入设计前需要明确：

1. `photon-lite` 是否永远是 leaf，还是未来必须支持 lite-to-lite？
2. 是否允许 Android/Windows native IKE 的 gateway-only mode？
3. Android 是 split tunnel、full tunnel，还是两者都支持？
4. Android TUN 安装 Photon 聚合前缀，还是动态重建精确 routes？
5. standby gateway 是 cold、只保留 IKE，还是同时保留 ESP/Babel？
6. lite 节点是否运行完整 gossip，还是通过 gateway relay signed objects？
7. lite route authorization 如何绑定 Babel Router ID 与 Zone identity？
8. 是否只支持 Ed25519 transport key，还是同时支持 ECDSA P-256？
9. gateway-side mobile Babel/DPD profile 如何通过 signed capability/intent 协商？
10. Android 功耗、恢复时延和 Windows throughput 的验收基线是什么？

## 15. 最终建议

`ranet-lite` 已证明“用户态 IKEv2 initiator + ESP + Babel leaf + SADR + TUN”在工程上可行。
Photon Lite 最应复用的是它的协议切片、单 UDP Hub、per-peer ESP、direct Babel I/O 和
leaf-only 边界。

真正需要重新设计的是：

- Photon Zone/gossip/route authorization 接入；
- TUN、socket、route 和 key store 的平台资源所有权；
- Android event-driven 调度、NAT keepalive、Doze 和 gateway-side Babel interval；
- Windows service、Wintun 和系统 route 生命周期；
- 自研 IKE/ESP 的长期安全验证。

推荐先完成 portable core 边界与 Windows 数据面 prototype，同时尽早建立最小 Android
功耗实验，之后再决定是否扩大 IKE/Babel 功能范围。
