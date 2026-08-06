# Photon 全量改名实施计划

> **文档状态**：代码改名已完成；待特权数据面 smoke 与外部仓库重命名
> **目标**：将整个项目从 Higgs 一次性、不兼容地改名为 Photon，并统一源码、协议、部署、运行时资源和文档中的命名。
> **兼容性决策**：不提供旧二进制、环境变量、目录、配置、数据、协议或运行时资源的兼容层。

---

## 1. 已冻结决策

1. 产品正式名称为 **Photon**，机器可读名称统一为 `photon`。
2. 主程序为 `photon`，服务渲染程序为 `photon-services`。
3. 默认 network namespace 为 `photon`。
4. XFRM interface 使用 `phx` 前缀，veth 使用 `phv` 前缀。不得使用宽泛的 `ph*` 作为 BIRD 默认匹配规则。
5. `HIGGS_*` 环境变量全部替换为 `PHOTON_*`，不读取旧变量。
6. `/etc/higgs`、`/var/lib/higgs`、`/run/higgs` 等目录全部替换，不做自动迁移或 fallback。
7. 签名域、wire magic、哈希派生域、owner token 和探测 magic 全部改为 Photon；旧身份、签名数据和旧节点不与 Photon 互通。
8. 不保留 `higgs`、`higgsnet`、`higgs-services` 命令、软链接、wrapper 或 systemd alias。
9. 默认部署视为新网络初始化：重新创建 root、身份、delegation、record 和节点加入关系。

Go module 的目标暂按当前 canonical module owner 写为 `github.com/Catofes/photon`。如果仓库在实施前迁移到其他 GitHub owner，必须先冻结最终 URL，再一次性修改 module、源码 import、Nix metadata、安装脚本和文档链接，避免再次重命名。

## 2. 不在本次范围内

- 不借改名重构业务模块、状态模型、CLI 层级或协议结构。
- 不改变路由、授权、同步、IPAM、IPsec、firewall、health 等业务语义。
- 不提供 Higgs 数据库到 Photon 数据库的转换器。
- 不由 Photon 自动识别、adopt 或删除 Higgs 创建的系统资源。
- 不同时处理与改名无关的 roadmap 项目。

除明确的命名变化外，测试输出、API schema 和运行行为应保持当前语义。

## 3. 目标命名表

### 3.1 项目、源码与发布

| 类别 | 当前 | 目标 |
|---|---|---|
| 产品名 | `Higgs` | `Photon` |
| 仓库名 | `higgs` | `photon` |
| Go module | `github.com/Catofes/higgs` | `github.com/Catofes/photon` |
| 主源码目录 | `app/higgs` | `app/photon` |
| 服务源码目录 | `app/higgs-services` | `app/photon-services` |
| 主二进制 | `higgs` / 部署时的 `higgsnet` | `photon` |
| 服务二进制 | `higgs-services` | `photon-services` |
| Docker image | `higgs:<tag>` | `photon:<tag>` |
| Release archive | `higgs-<version>-<os>-<arch>` | `photon-<version>-<os>-<arch>` |
| systemd unit | `higgsnet.service` | `photon.service` |
| Nix package/attr | `higgsnet` / `higgs` | `photon` |
| NixOS option | `services.higgsnet` | `services.photon` |

源码 import alias（例如 `higgscrypto`、`higgsstate`、`higgsservice`）同步改为 `photoncrypto`、`photonstate`、`photonservice`，或在无歧义时直接使用包名。测试 helper、函数名和注释中的 `Higgs` 也应同步修改。

### 3.2 配置、环境变量与文件系统

| 类别 | 当前 | 目标 |
|---|---|---|
| 环境变量前缀 | `HIGGS_*` | `PHOTON_*` |
| 主配置 | `/etc/higgs/config.yaml` | `/etc/photon/config.yaml` |
| 默认数据目录 | `/etc/higgs` | `/etc/photon` |
| 容器数据目录 | `/var/lib/higgs` | `/var/lib/photon` |
| 服务 manifest | `/etc/higgs/service.yaml` | `/etc/photon/service.yaml` |
| 服务输出目录 | `/etc/higgs/services` | `/etc/photon/services` |
| runtime 目录 | `/run/higgs` | `/run/photon` |
| control socket | `/run/higgs/higgs.sock` | `/run/photon/photon.sock` |
| BIRD runtime | `/run/higgs/bird` | `/run/photon/bird` |
| 本地开发目录 | `.higgs` | `.photon` |
| 日志示例 | `/var/log/higgs.log` | `/var/log/photon.log` |
| syslog ident | `higgs` | `photon` |

所有 Makefile、shell script、GitHub Actions、Dockerfile、Nix、VS Code 配置和测试环境变量一起更新。旧变量不存在优先级或 deprecation 行为。

### 3.3 network namespace 与 interface

| 资源 | 当前 | 目标 | 约束 |
|---|---|---|---|
| 默认 netns | `h2` | `photon` | 仅修改 `DefaultNetNSName` 语义及对应配置/测试；不得全局替换 `h2` |
| XFRM interface | `hgs<hex-if-id>` | `phx<hex-if-id>` | 最大 11 字符，低于 Linux `IFNAMSIZ` 的 15 字符可用上限 |
| BIRD XFRM pattern | `hgs*` | `phx*` | 只匹配 XFRM interface |
| netns 侧 veth | `hgv2host` | `phv2host` | 表示从 Photon netns 通往 host |
| host/upstream 侧 veth | `hgv2mesh` | `phv2mesh` | 表示从 host 通往 Photon netns |
| WireGuard device | `hgw*` | `phw*` | 与 XFRM、GRE 和 veth 分离 |
| WG 路径 GRE interface | `hgg*` | `phg*` | 作为 Babel interface |

`phx*` 和 `phv*` 必须保持分离。若配置生成器使用 `ph*`，BIRD 可能把 upstream veth 当成 overlay tunnel interface，改变路由行为。

除命名域变化外，XFRM if_id、地址、端口和接口名仍应保持确定性。因为本次明确不兼容，改名后生成的 link/runtime ID 可以与旧版本不同，但同一 Photon 输入在重启后必须稳定。

### 3.4 运行时资源 owner

| 子系统 | 目标命名 |
|---|---|
| firewall manager/owner | `photon` |
| iptables comment marker | `photon-<scope>` |
| nftables table/chain 前缀 | `photon`，受内核长度限制的派生名使用稳定短前缀和 hash |
| ipset 派生前缀 | 使用 `phs_` 等 Photon 专属短前缀，并保留现有长度上限测试 |
| BIRD protocol | `photon_kern_*`、`photon_babel_*`、`photon_import_*`、`photon_export_*`、`photon_static_*` |
| BIRD internal table | `photon_<sanitized-netns>` |
| BIRD owner manager/token | `photon` / `photon.bird.owner.v1` |
| StrongSwan connection/child | `photon-*` / `photon-child` |
| IPsec resource manager | `photon` |
| Docker network/project | `photon-<id>` / `photon-networks`、`photon-socks5` |

所有 `isHiggs*`、`Higgs-owned`、`Manager == "higgs"`、prefix guard 和 cleanup filter 都必须同步改名。Photon cleanup 只管理 Photon owner，不负责清理旧 Higgs owner。

### 3.5 协议、密码学和稳定派生域

以下标识全部进行不兼容改名，并同步 golden/unit tests：

- `higgs.record.v1` → `photon.record.v1`
- `higgs.delegation.v1` → `photon.delegation.v1`
- `higgs.delegation-revocation.v1` → `photon.delegation-revocation.v1`
- `higgs.authority.v1` → `photon.authority.v1`
- `higgs.gossip.v1` → `photon.gossip.v1`
- `higgs.gossip.m1\n` → `photon.gossip.m1\n`
- `higgs.catalog.v1` → `photon.catalog.v1`
- `higgs.ed25519.private.v1` → `photon.ed25519.private.v1`
- `HIGGS-HC` → `PHOTON-HC`
- `higgs.ipsec.*` → `photon.ipsec.*`
- `higgs.bird.owner.v1` → `photon.bird.owner.v1`

扫描时还要覆盖 transport key、tunnel address、link/runtime/XFRM/owner hash domain，以及可能藏在测试 fixture、protobuf option、诊断文本中的协议字符串。

这一步意味着：

- 旧私钥文件的 type 不再被接受；
- 旧 delegation、record、authority 和 revocation 签名不能通过 Photon 验证；
- Photon 与 Higgs 的 gossip frame、catalog 和 health probe 不互通；
- 旧 IPsec/BIRD owner token 与派生资源不被 Photon adopt。

## 4. 实施顺序

### 阶段 0：冻结基线

- [ ] 确认最终 GitHub owner 和 repository URL（本地实现暂按 `github.com/Catofes/photon`）。
- [x] 确认工作区初始状态，记录当前 commit。
- [x] 在改名前运行 `go test ./...`，确认基线全绿。
- [x] 确认不保留旧生产身份、数据库或现网互通能力。
- [ ] 确认旧部署将单独停机、清理，不依赖 Photon cleanup。

### 阶段 1：源码结构与 Go namespace

- [x] 将 `app/higgs` 改为 `app/photon`。
- [x] 将 `app/higgs-services` 改为 `app/photon-services`。
- [x] 修改 `go.mod` module path 和全部 Go import。
- [x] 修改 import alias、测试 helper、函数/类型名中的 Higgs 品牌命名。
- [x] 更新 Makefile package path 和 build output。
- [x] 运行 `gofmt`、`go test ./...`，确认源码 namespace 可完整构建。

建议把本阶段作为独立提交，避免把机械 import diff 与协议行为变化混在一起。

### 阶段 2：产品入口、配置与发布面

- [x] CLI name、usage、version output、错误提示和 command hint 改为 Photon。
- [x] 二进制、安装/更新脚本、release archive/checksum 改名。
- [x] systemd unit 改为 `photon.service`，更新 environment、runtime directory 和 `ExecStart`。
- [x] Docker image、binary、entrypoint、volume 和默认配置路径改名。
- [x] Nix package、flake output、NixOS option 和 main program 改名。
- [x] `HIGGS_*` 全量替换为 `PHOTON_*`。
- [x] 默认路径、临时目录、日志、socket、service renderer 和 compose 名称改名。
- [x] 更新 README、config example、service example 和安装文档。

### 阶段 3：netns、interface 与系统资源

- [x] `DefaultNetNSName` 从 `h2` 改为 `photon`。
- [x] `StableInterfaceName` 从 `hgs` 改为 `phx`。
- [x] BIRD 默认 interface pattern 从 `hgs*` 改为 `phx*`。
- [x] 默认 upstream veth 改为 `phv2host` / `phv2mesh`。
- [x] firewall、BIRD、IPsec、StrongSwan 和 Docker owner/prefix 全部改名。
- [x] 重命名 resource guard、inspection、adoption、cleanup 相关函数与诊断文本。
- [x] 检查 kernel name 长度约束并运行现有相关测试。
- [x] 运行 routing/firewall/IPsec 的单元、集成和非特权 smoke。
- [ ] 运行 root data-plane smoke（当前环境缺少 root/CAP_NET_ADMIN，preflight 已确认阻塞）。

这里禁止对 `h2` 做全局替换：`h2` 同时是 HTTP/2 服务类型、配置名和测试场景。只修改默认 netns 常量及明确引用该默认值的断言。

### 阶段 4：协议与密码学断代

- [x] 修改签名 domain separator 和 private-key type。
- [x] 修改 gossip wire magic、catalog domain 和 protobuf/module 引用。
- [x] 修改 health UDP magic。
- [x] 修改所有 IPsec 稳定派生 domain。
- [x] 修改 BIRD owner token domain。
- [x] 更新 hash/signature fixture 和 codec negative tests。
- [x] 增加测试证明 Photon 拒绝 Higgs key type、wire frame 和签名数据。
- [x] 运行 join/delegation/revocation、gossip/sync、IPsec rotate/restart 测试。

### 阶段 5：文档、脚本与残留收口

- [x] 将活跃设计文档、roadmap、todo、脚本注释和 Web UI 文案统一为 Photon。
- [x] 重命名 `docs/app-higgs-modularization-design.md` 等带旧项目名的路径及其引用。
- [x] 更新 `.gitignore`、`.dockerignore`、编辑器配置和测试临时目录。
- [x] 删除旧 build artifact，再用 Photon 名称重新构建。
- [x] 执行残留扫描并逐项分类；旧名只保留在本文映射和明确的拒绝旧格式测试中。

建议残留扫描至少包含：

```sh
rg -n -i 'higgs|higgsnet|hgs|hgv|hgw|hgg|HIGGS_' \
  -g '!.git' \
  -g '!docs/photon-renaming-plan.md'
```

对 `h2` 只能通过语义审查确认默认 netns 已清除，不能要求仓库零匹配。

## 5. 验证矩阵

### 5.1 静态与普通测试

- `gofmt` 后无 diff。
- `go test ./...` 全绿。
- `make check` 全绿。
- `go list ./...` 中不存在旧 module/app path。
- release workflow、Docker、Nix 和安装脚本只生成 Photon artifact。
- `photon version` 输出 `photon <version>`。

### 5.2 核心功能 smoke

至少覆盖现有这些测试族：

- root init、keygen、join request/accept、delegate grant/revoke；
- daemon control socket、direct/offline guard；
- multi-node gossip、discovery、bootstrap join、relay、object pull；
- route/IPAM、BIRD reload/failover、firewall reconcile；
- IPsec/XFRM bring-up、restart/adopt、rotate/cutover、revocation cleanup；
- observer、health probe、service publish/withdraw；
- Docker/root/container smoke 中的 namespace 和 interface 实际命名断言。

可复用现有 Make target，但 target 内部的临时目录和环境变量必须已经改成 Photon。涉及真实 BIRD、firewall、XFRM 和 netns 的 root smoke 是本次验收必跑项，不能只以 `go test ./...` 代替。

### 5.3 运行时验收

在干净测试机或隔离容器中验证：

- [ ] 启动后只创建名为 `photon` 的默认 netns。
- [ ] XFRM interface 全部匹配 `phx*`，且不存在 Photon 创建的 `hgs*`。
- [ ] upstream veth 为 `phv2host` / `phv2mesh`。
- [ ] BIRD 只在预期 interface 上建立邻接。
- [ ] nftables/iptables/ipset 中 owner 和前缀均为 Photon。
- [ ] StrongSwan connection/child 和 BIRD protocol/table 均为 Photon 命名。
- [ ] control socket 位于 `/run/photon/photon.sock`。
- [ ] 默认配置、数据、日志和 service artifact 不写入 Higgs 路径。
- [ ] 两个全新 Photon 节点可以完成加入、同步、路由和健康检查。
- [ ] Photon 节点不能读取旧 key type，不能与旧 gossip wire magic 建立会话。

## 6. 部署切换要求

这是一次重置部署，不是滚动升级：

1. 停止并禁用旧 Higgs service，确认旧 daemon 已退出。
2. 在部署 Photon 前单独审计并清理旧 `h2` netns、`hgs*`/`hgv*` interface、Higgs firewall、BIRD 和 StrongSwan 资源。
3. 备份后归档或删除旧配置与数据目录；Photon 不读取这些目录。
4. 安装 `photon` 和 `photon.service`。
5. 重新初始化 root/identity/delegation，建立全新的 Photon 网络。
6. 用运行时验收清单确认没有新进程重新创建旧名称资源。

旧资源清理由操作人员或一次性部署脚本显式完成。不要把旧资源识别逻辑加入 Photon 主程序，否则会重新引入被明确排除的兼容面。

## 7. 主要风险与控制

| 风险 | 控制措施 |
|---|---|
| 对 `h2` 全局替换，破坏 HTTP/2 服务配置 | 只修改 `DefaultNetNSName` 和明确的默认 netns 断言，逐项审查其余 `h2` |
| `ph*` 同时匹配 XFRM 和 veth | XFRM 固定使用 `phx*`，veth 固定使用 `phv*` |
| interface/iptables/ipset 名称超过内核限制 | 保持短前缀，继续使用稳定 hash，并补边界长度测试 |
| owner guard 漏改，导致资源无法 reconcile/cleanup | 对 manager、owner、prefix、adopt、cleanup 做成组扫描和 root smoke |
| 协议字符串漏改，形成半兼容状态 | 集中列出全部 domain/magic，并增加拒绝旧格式的 negative tests |
| module、repo、release URL 不一致 | 阶段 0 冻结 canonical GitHub URL，统一生成和扫描 |
| 机械改名夹带行为重构，难以审查 | 按源码结构、部署面、运行时资源、协议断代分提交 |
| 旧 build artifact 造成误判 | 验收前清理并只生成 Photon 名称 artifact |

## 8. 完成标准

只有同时满足以下条件，改名才算完成：

1. 源码、构建、发布、部署、文档和 Web UI 对外只使用 Photon。
2. 默认 netns 为 `photon`；XFRM 和 veth 分别使用 `phx*`、`phv*`。
3. 所有 Photon runtime resource 都有统一 owner/prefix，并能被 Photon 正确 reconcile 和 cleanup。
4. 签名、wire、catalog、health 和派生 domain 已完成不兼容断代，negative tests 证明旧格式被拒绝。
5. 普通测试、`make check`、核心 smoke 和 root data-plane smoke 全绿。
6. 除本文记录旧名映射外，残留扫描无未经解释的 `Higgs`、`higgs`、`higgsnet`、`HIGGS_`、`hgs`、`hgv`、`hgw`、`hgg`。
7. 在干净环境完成双节点 Photon 网络的初始化、加入、同步、路由与健康验证。

## 9. 建议提交拆分

1. `rename module and app source paths to photon`
2. `rename photon cli packaging config and deployment surfaces`
3. `rename photon netns interfaces and runtime ownership`
4. `switch crypto wire and derivation domains to photon`
5. `rename docs tests and smoke fixtures to photon`

每个提交都应尽可能保持可构建；第 4 个提交是明确的协议断代点。预计集中实施和验证需要约 2–3 个工作日，其中真实数据面 smoke 和残留审查占主要时间。
