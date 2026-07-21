# Observer Web UI 重构设计

> **本文档状态：2026-07（设计定稿，待实施）**
> 针对 `internal/observer/web` 现有静态 UI 的视觉与信息架构重构方案。当前实现行为以 [observer.md](observer.md) 为准；本文只描述 UI 层与事件链路的改造，不改变 observer 的只读定位、REST API 形状与安全模型。
> 任务拆解见 [../../todo.md](../../todo.md) Phase 9。

---

## 目录

1. [背景与问题](#1-背景与问题)
2. [目标与非目标](#2-目标与非目标)
3. [约束](#3-约束)
4. [视觉设计系统](#4-视觉设计系统)
5. [前端架构](#5-前端架构)
6. [页面信息架构](#6-页面信息架构)
7. [事件链路补完（可选）](#7-事件链路补完可选)
8. [阶段划分与验收标准](#8-阶段划分与验收标准)
9. [测试策略](#9-测试策略)

---

## 1. 背景与问题

现有 UI（`internal/observer/web/`：`index.html` 30 行、`style.css` 524 行、`app.js` 1153 行单文件）是 Observer MVP 的配套产物，功能完整但体验粗糙。问题分三层：

### 1.1 视觉层

- 配色是过时的深蓝仪表盘风（`#1a1a2e / #16213e / #0f3460`），边框 `#233` 与底色几乎无区分度，弱化文本 `#888` 对比度不足。
- 无设计系统：字号 11/12/13/14 混用、间距无阶梯、monospace 字体泛滥，整体像未排版的 debug 输出。
- badge / 卡片 / 表格样式各自为政，h2 全部使用 accent 色，视觉层级缺失。

### 1.2 信息架构层

- **Raw JSON 泛滥**：Zones 页平铺 authority / delegations / parent proof / revocations 的 `jsonViewer`；link 与 record 详情内嵌大段 "Raw JSON"。主要内容与调试材料混排。
- **Overview 形同虚设**：6 个数字卡片 + 5 行状态表，回答不了"系统现在健不健康"；错误信息埋在表格行里。
- **Overlay 与 Health 职责重叠**：两页都展示 link 状态 / 健康 / 路由，定位没有区分。
- 实体卡片每张 9~10 个字段平铺，所有信息同等权重，无法扫读。
- 无搜索 / 过滤；时间全部为 `toLocaleString()` 长串，无相对时间；选中态不进 URL，刷新即丢。

### 1.3 交互 / 技术层

- 任何 SSE 事件 → 当前页全量重取 + 全量 `innerHTML` 重建，滚动位置丢失；`foldState` Map 只是对抗全量重绘的补丁。
- Health 页每次刷新对每条 link 各发一个 series 请求，事件频繁时呈 N× 放大。
- 1153 行单文件无模块边界，字符串模板靠手工 `esc()` 纪律防 XSS。
- 事件 payload 全为 nil（observer.md 第 9 节已列为缺口），前端只能整页刷新。

## 2. 目标与非目标

### 2.1 目标

- **视觉**：全部颜色 / 字号 / 间距来自设计 token，无散落硬编码值；正文对比度达到 WCAG AA。
- **信息层级**：每个页面有且只有一个首要问题；Raw JSON 类调试材料一律收入折叠区，默认不占首屏。
- **交互**：SSE 事件只触发受影响数据的重取；重绘不丢滚动 / 输入 / 折叠状态；列表页全部支持文本过滤；选中态可深链。
- **工程**：保持零构建、零运行时依赖、纯 embed；模块拆分后单文件 < ~200 行。

### 2.2 非目标

- 不引入 Node.js 构建链、不引入前端框架运行时依赖。
- 不改变 REST API 的端点与响应形状（第 7 节的事件 payload 增强除外）。
- 不实现写操作、认证、拓扑图、外部 TSDB 集成（仍属 observer.md 第 10 节的远期方向）。

## 3. 约束

- **零构建**：浏览器原生 ES Modules + 多个 CSS 文件直接 `<link>`，`//go:embed web/*` 不需要任何打包步骤。注意 embed pattern 为 `web/*`，新增子目录（`web/src/`、`web/style/`）需把 pattern 改为 `web/* web/*/*` 或 `all:web`。
- **只读与安全模型不变**：`requireGET`、`Provider` 快照语义、无认证 + loopback 默认绑定均不动。
- **静态文件服务**：`HandleStatic` 的 Content-Type 表已覆盖 css/js/svg，ES modules 无需新类型；SPA fallback 行为保持。

## 4. 视觉设计系统

### 4.1 设计 token（`style/tokens.css`）

以中性灰底 + 单一 accent + 语义状态色替换现有深蓝配色：

```css
:root {
    /* 中性色板 */
    --bg-0: #0b0e14;            /* 页面底 */
    --bg-1: #11151d;            /* 侧栏 / 卡片底 */
    --bg-2: #171c26;            /* 嵌套 / 悬浮底 */
    --border: #232a36;
    --text-0: #e6e9ef;          /* 主文本 */
    --text-1: #9aa4b2;          /* 次要文本 */
    --text-2: #6b7482;          /* 弱化文本 */
    --accent: #5b8def;
    /* 语义状态色（badge / 指示灯 / 横幅共用） */
    --ok: #3fb96f;
    --warn: #d9a13b;
    --err: #e05d5d;
    --unknown: #6b7482;
    /* 字号阶梯 */
    --fs-xs: 11px; --fs-sm: 12px; --fs-md: 13px;
    --fs-lg: 15px; --fs-xl: 20px; --fs-num: 26px;
    /* 间距阶梯（4 的倍数） */
    --sp-1: 4px; --sp-2: 8px; --sp-3: 12px;
    --sp-4: 16px; --sp-5: 24px; --sp-6: 32px;
    --radius: 6px;
    --mono: 'SF Mono', 'Monaco', 'Courier New', monospace;
}
```

规则：monospace 只用于 hash / 地址 / ID 等机器标识符，不再整段使用；状态色只经 `.badge`/`.dot`/`.banner` 等语义类引用，页面样式不得直接写颜色字面值。

### 4.2 布局壳

- 侧栏：logo、导航（按 总览 / 网络（Gossip、Zones、Overlay、Routes、BIRD）/ 监控（Health）分组）、底部连接状态指示（Live / Polling / Disconnected 三态，带色点）。
- 内容区：统一页头组件（页面标题 + 一句话说明 + 页面级操作区，如过滤输入框），页头下才是内容。
- 移动端断点保留现有 900px 行为，侧栏折为顶栏。

### 4.3 基础组件

统一重写并收敛到 `style/base.css`：card、stat-card（大数字）、badge（弱化底色、去荧光）、dot（状态点）、table（sticky 表头、行 hover）、kv、code、details/summary 折叠、empty / loading（骨架或旋转指示，替换裸 "Loading..." 文本）/ error 三态、toast 不需要。

## 5. 前端架构

### 5.1 目录结构

```text
internal/observer/web/
  index.html              # 壳 + <script type="module" src="/src/main.js">
  style/
    tokens.css            # 设计 token
    base.css              # reset、布局壳、基础组件
    pages.css             # 页面级样式（超出后再按页拆）
  src/
    main.js               # 入口：router + events 初始化
    api.js                # fetch 封装 + 统一错误
    store.js              # 按 endpoint 的缓存 + 失效 + 订阅
    events.js             # SSE 连接、降级轮询、事件 → store 失效映射
    router.js             # hash 路由，含选中态深链（见 6.7）
    format.js             # esc / relTime / ms / pct / shortHash / copy
    components/
      badge.js card.js table.js kv.js jsonview.js chart.js
    pages/
      overview.js gossip.js zones.js overlay.js health.js routes.js bird.js
```

约定：每个 page 模块导出 `render(container)`；组件是纯函数返回 HTML 字符串，所有动态文本必经 `format.js` 的 `esc()`；`webapp_test.go` 的 token 断言同步改为检查模块化后的关键导出。

### 5.2 数据流与重绘策略

- `store.js` 维护 `Map<endpoint, {data, error, updatedAt}>` 与订阅者列表；`fetch(key)` 去重并发请求。
- `events.js` 建立事件类型 → endpoint 的失效映射（如 `link_updated` → `/links`、`health_updated` → `/health`），SSE 事件只失效对应键并重取，**不再整页刷新**；降级轮询只轮询当前页依赖的键。
- 页面渲染：数据就绪后重绘 `#content` 内部，重绘前记录 `scrollTop` / 活跃输入框 / `<details open>` 状态，重绘后恢复——取代现有 `foldState` 全局补丁（删除）。
- Health 页 sparkline：卡片可见时才懒加载 series（IntersectionObserver 或首屏前 N 条），详情图维持按档位手动加载；消除每次刷新 N× 请求放大。

## 6. 页面信息架构

### 6.1 Overview（仪表盘化）

首要问题：**现在有没有问题？**

1. 顶部全局状态横幅：`All systems normal`（绿）或 `N issues need attention`（红/黄），由 links down、health 非 healthy、reconcile 错误、revoked zone 聚合得出。
2. 问题清单（无问题时不渲染）：每条一行（级别色点 + 对象 + 摘要 + 跳转到对应页深链）。
3. 统计卡：Zones / Peers / Links（up/total）/ Desired Links，大数字 + 次行小字。
4. 节点与 reconcile 摘要 kv 表（peer id、managed zone、listen、last sync / reconcile、snapshot 元数据）。

### 6.2 Overlay 与 Health 职责分离

- **Overlay = 控制面**：planner desired vs actual、IKE/Child SA、reconcile actions/skipped、rotation/takeover。导航文案改为 "Overlay · Control Plane"。
- **Health = 数据面**：探针状态、RTT/loss/jitter、历史曲线。导航文案 "Health · Data Plane"。
- 两页卡片字段按上述边界裁剪，重叠字段（如 interface、endpoint）只在一页作为主体，另一页仅保留跳转链接。

### 6.3 Zones（双栏 + Inspect 折叠）

- 左栏 zone 列表（路径、record 数、状态点），支持文本过滤；右栏选中 zone 详情。
- 详情主体为 Active Records 表格（key/type/version/value 摘要/hash 截断 + 点击复制）。
- authority / parent proof / delegations / revocations / record history / Raw JSON 全部收入 "Inspect" 折叠区；Global Root 从平铺 JSON 改为一行 code + 复制按钮。

### 6.4 Gossip

- peer 卡片只保留：peer_id、source、last sync（相对时间）、failure 数、状态点；点击展开侧详情面板（endpoints 表 + diagnostics kv）。
- diagnostics 中的 `datagram_stats` 等 JSON 字面值格式化为 kv，不再 `JSON.stringify` 直出。

### 6.5 Routes / BIRD

- Routes：Authorization Errors 置顶（非 0 时红色计数），其次 Local Export Set（chip 列表），再 IPAM Pools / Assignments 表格并支持按 zone 过滤。
- BIRD：实例表格 + `last_routing_error` 醒目展示；协议/邻居明细等 `birdc` 深度解析不在本期（observer.md 10.2）。

### 6.6 Health

- 每条 link 一张卡片：状态点 + instance、RTT/loss/jitter 三指标、sparkline；异常（down/degraded/cutover blocking）卡片排前并带色条。
- 详情折叠区含 RTT 历史图（5m/30m/1h/6h/24h 档位，沿用现有 series API）。

### 6.7 全局交互

- 相对时间（`3m ago`，hover 显示绝对时间 title）；hash / 地址点击复制（带 Copied 反馈）。
- 每个列表页页头含文本过滤框；过滤条件与选中态写入 hash（如 `#/zones/example.cn`），可深链、刷新不丢。

## 7. 事件链路补完（可选）

仅当阶段 9.4 纳入本轮时实施；需要动后端广播点，范围超出纯前端。

- **事件 payload**：`daemon.go` 的 `notifyObserver` 调用点携带键（`link_updated` → `{link_id}`、`peer_updated` → `{peer_id}`、`health_updated` → `{link_id}`），前端据此做条目级失效而非整键失效。payload 仍保持轻量，不携带 diff。
- **Events 时间线页**：落地 `event_buffer_seconds`（当前已解析无消费方）：hub 侧加环形缓冲，新端点 `GET /api/v1/events/recent` 或 SSE 连接建立时回放；UI 增加 Events 页展示最近事件流。此子项独立可裁，不做不影响其余阶段。

## 8. 阶段划分与验收标准

| 阶段 | 内容 | 验收 |
|---|---|---|
| 9.1 设计基座 | tokens.css、布局壳、基础组件样式重写 | 全部颜色/字号/间距引用 token；正文对比度 WCAG AA |
| 9.2 模块化 | app.js 拆分为 ES modules；store + 局部失效；删除 foldState 补丁 | 单文件 < ~200 行；SSE 事件只重取受影响键；重绘不丢滚动/折叠/输入 |
| 9.3 页面重构 | 第 6 节逐页落地 | 每页首要问题明确；Raw JSON 全入折叠区；列表页可过滤；选中态可深链 |
| 9.4 事件链路（可选） | 事件 payload；Events 页 | payload 到达前端并触发条目级刷新 |
| 9.5 收口 | 测试与文档 | `internal/observer` 与 `app/higgs` observer 族测试全绿；observer.md 第 6/9 节同步 |

阶段 9.1–9.3 是本设计的主体，按顺序实施；9.4 与 9.5 独立收尾。

## 9. 测试策略

- **Go 侧**：`internal/observer` 现有测试族保持绿色；`webapp_test.go` 按 token 断言的用例（esc token、foldState token）随重构改写为对新模块关键导出与 `esc()` 覆盖的断言；`static_test.go` 覆盖新增子目录文件的 embed 与 Content-Type。
- **JS 侧**：维持零构建原则，不引入 JS 测试框架；以 Go embed 测试 + 手工浏览器验证为准。重构完成后在真实 daemon 上逐页走查第 6 节的验收点。
- **回归基线**：重构前后各 REST 端点响应不变（9.4 除外），`app/higgs/observer_api_*_test.go` 不应需要修改；若必须修改则说明改动越界，需回头审查。
