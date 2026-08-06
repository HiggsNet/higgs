# BIRD vs babeld 在 tunnel 模式下测量网络质量的能力对比

> 文档状态：调研结论  
> 更新日期：2026-06-13  
> 调研范围：BIRD 2.16+/3.x、babeld 1.13.x，重点对比两者在 IPsec/XFRM tunnel 场景下的链路质量感知能力。

## 1. 结论先行

BIRD 的 Babel `type tunnel` 与 babeld 的 `type tunnel` **在 RTT 测量原理上基本一致**，都实现了 Babel RTT 扩展（RFC 8967），通过在 Hello/IHU 报文里打时间戳来异步计算 RTT，无需两端时钟同步。

两者都能：

- ✅ **持续测量邻居 RTT**，并把 RTT 映射为路由 metric 的附加 cost。
- ✅ **感知链路是否通断**（BIRD 默认用 wired 的 k-out-of-j Hello 到达率；babeld 同理，也可显式开启 link-quality/ETX）。
- ✅ **把质量信息用于选路**（metric 越高，路径越不被优先采用）。

但两者都**不能完整测量 "tunnel 网络质量"**：

- ❌ 不测带宽/吞吐量。
- ❌ 不测抖动（jitter）的直接统计量，只能间接从 RTT 波动观察。
- ❌ 不测乱序、应用层 QoS、NAT/QoS 降级细节。
- ❌ RTT 基于 Babel 控制面小包，可能与真实业务流质量有偏差。

对 Photon Phase 5 来说，Babel 的 RTT/loss 信号足够做 **路径排序、active/backup 选择、rotate cutover 健康判断**；若需要更细粒度的质量评估（如带宽探测、持续丢包率、RTT 分位数），仍需 Photon 自有的链路健康探测层（见 `todo.md` 6.6 链路健康检测）。

## 2. 核心机制对比

### 2.1 RTT 扩展原理

| 项目 | BIRD | babeld |
|------|------|--------|
| 协议扩展 | Babel RTT extension（RFC 8967） | 同左 |
| 时间戳载体 | Hello / IHU TLV | Hello / IHU |
| 是否需要对端支持 | 需要对端也发送时间戳；否则 metric 可能 stuck 在 65535 | 需要 `enable-timestamps` |
| 是否需时钟同步 | 否，采用异步 RTT 算法 | 否 |

BIRD 源码层面在 `proto/babel/babel.c` 维护每个邻居的 `srtt`（smoothed RTT）；babeld 在相关结构里维护类似指数加权平均。

### 2.2 tunnel 模式默认行为

| 参数 | BIRD `type tunnel` | babeld `type tunnel` |
|------|---------------------|----------------------|
| 基础类型 | wired + RTT metric | 启用 timestamps 的隧道模式 |
| 默认 `rxcost` | 96 | 96 |
| 默认 RTT cost / max-rtt-penalty | `rtt cost 96` | `max-rtt-penalty 96` |
| 默认 `rtt-min` | 10 ms | 10 ms |
| 默认 `rtt-max` | 120 ms | 120 ms |
| 默认 decay | `rtt decay 42` | `rtt-decay 42` |
| 默认 timestamps | `send timestamps yes` | `enable-timestamps true` |
| 邻居存活检测 | wired 式 k-out-of-j（`limit 12/16`） | 同 wired 默认，也可开 ETX |

> 注意：babeld 的 `max-rtt-penalty` 与 BIRD 的 `rtt cost` 语义等价，都是 RTT 达到 `rtt-max` 时加到邻居 cost 上的最大值。

### 2.3 丢包/链路质量测量

| 能力 | BIRD | babeld |
|------|------|--------|
| 基于 Hello 到达率的 up/down | ✅ wired/tunnel 默认 k-out-of-j | ✅ 同左 |
| ETX / packet-loss 质量估计 | ✅ 通过 `link quality yes` 强制开启（2023 年后补丁） | ✅ 通过 `link-quality true` 强制开启（原本为 wireless 设计） |
| 无线 diversity / channel | ❌ 不支持 | ✅ `diversity`、`channel`（主要用于无线干扰避免，对 tunnel 意义有限） |

BIRD 在 2023 年引入了独立的 `link quality` 开关，允许在 tunnel 接口上启用 ETX，这使 BIRD tunnel 模式也能像 babeld 一样把丢包率纳入 metric。

## 3. 可观测性对比

### 3.1 BIRD

```bash
birdc show babel neigh
```

输出示例（来源：社区文档）：

```
IP address                Interface  Metric Routes Hellos Expires Auth  RTT (ms)
fe80::5054:ff:fef0:1110   e1             96      8     16   5.003 No       4.831
```

- `RTT (ms)` 列直接显示平滑后的 RTT。
- `Metric` 列已包含 `rxcost + rtt cost` 后的有效 cost。
- 开启 debug 后日志还会打印每次 RTT sample 与 `Added RTT cost ...`。

### 3.2 babeld

```bash
# 只读 control socket
{ echo "dump"; echo "quit"; } | socat - UNIX-CONNECT:/tmp/babeld.ctl
```

基础 `dump` 输出里 neighbor 行可见：

```
add neighbour ... if <INT> reach ffff ureach 0000 rxcost 96 txcost 96 cost ...
```

- 可看到 `rxcost`、`txcost`、`cost`，但**默认 dump 不直接打印 RTT 数值**。
- OpenWrt 的 ubus `babeld get_neighbours` 会返回 JSON，其中包含 `"rtt"` 字段。
- FRR 的 `show babel neighbor` 会同时显示 `rtt` 和 `rttcost`。

因此，若 Photon 选择 babeld，需要额外解析 ubus/ubus-bindings 或自己 patch 输出才能拿到实时 RTT；BIRD 则通过 `birdc show babel neigh` 原生支持。

## 4. 配置示例

### 4.1 BIRD tunnel 模式（完整质量相关参数）

```bird
protocol babel photon_babel_main {
    ipv4 { ... };
    ipv6 { ... };
    ecmp on limit 16;

    interface "phx*" {
        type tunnel;
        rxcost 96;
        hello interval 4 s;
        update interval 4 s;

        rtt cost 96;        # RTT >= rtt-max 时加 96
        rtt min 10 ms;
        rtt max 120 ms;
        rtt decay 42;       # EMA 衰减因子

        link quality yes;   # 额外启用 ETX 丢包估计（BIRD 2.16+/3.x）
        ecmp weight 1;
    };
}
```

### 4.2 babeld tunnel 模式（完整质量相关参数）

```
default type tunnel

interface phxxxxx
    rxcost 96
    link-quality true
    enable-timestamps true
    rtt-min 10
    rtt-max 120
    rtt-decay 42
    max-rtt-penalty 96
```

## 5. 对 Photon Phase 5 的意义

### 5.1 能做什么

1. **路径质量排序**：同一远端前缀若经多个 XFRM tunnel 学到，BIRD/babeld 会把 RTT 更高或丢包更严重的 tunnel 排在后面。
2. **staged rotate 就绪判断**：Photon 可读取 `birdc show babel neigh` 的 RTT 与 route metric，判断新 staged tunnel 是否已收敛、质量是否优于旧 tunnel，再设置 `RotateCutoverReady=true`。
3. **active/backup 与 ECMP**：BIRD 的 `ecmp on` + `ecmp weight` 可在 metric 相等时生成多下一跳；metric 不等时自动主备。

### 5.2 不能做什么

1. **带宽感知**：RTT 无法区分 10 Mbps 隧道与 1 Gbps 隧道。
2. **业务流质量**：Babel 小包 RTT 与真实 TCP/UDP 业务流在 QoS 队列、分片、NAT 行为上可能不同。
3. **持续丢包统计**：即使开启 ETX，metric 是指数平滑后的单一数值，不如独立 ping probe 能得到 P50/P95/P99 RTT、丢包率、jitter。
4. **方向性质量**：Babel 测量的是本机到邻居的 RTT，若隧道上下行不对称（如某些 NAT/移动网络），只能反映单侧质量。

### 5.3 建议

- **Phase 5 主路径**：继续用 BIRD 的 `type tunnel` + `rtt cost` + `link quality yes`，通过 `birdc show babel neigh` 获取 RTT/metric，作为 cutover 与选路的默认信号。
- **补充探测层**：在 `todo.md` 6.6 "链路健康检测" 中规划的周期性 ICMP/自定义 keepalive 仍然需要，用于：
  - 测量真实业务路径的 RTT 分位数与丢包率；
  - 检测 Babel 控制面小包无法暴露的 QoS 劣化；
  - 在 Babel metric 尚未收敛或 stuck 时提供独立的健康信号。

## 6. 参考

- BIRD User's Guide — Babel section: https://bird.nic.cz/doc/
- BIRD Babel RTT extension 实现讨论: https://bird.network.cz/pipermail/bird-users/2022-April/016080.html
- BIRD `link quality` patch (2023): https://bird.network.cz/pipermail/bird-users/2023-June/017037.html
- babeld(8) manpage: https://www.irif.fr/~jch/software/babel/babeld.html
- RFC 8967: MAC Authentication for Babel; RFC 8966: The Babel Routing Protocol
- Photon 既有文档：`docs/bird-babel-alternative-findings.md`、`docs/babeld-control-protocol-findings.md`
