# 全能节点检测与实用插件集 (Loon & Clash-Client 多端融合版 `v3.0.0`)

[![Version: v3.0.0](https://img.shields.io/badge/Version-v3.0.0-10B981.svg)](./xream-loon-node-info.lpx)
[![Clients: Loon | Clash-Client](https://img.shields.io/badge/Clients-Loon%203.5.1%2B%20%7C%20Clash--Client-3B82F6.svg)](#)
[![Platform: iOS | iPadOS | macOS | tvOS](https://img.shields.io/badge/Platform-iOS%20%7C%20iPadOS%20%7C%20macOS%20%7C%20tvOS-111827.svg)](#)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)

深度融合 [**xream/scripts**](https://github.com/xream/scripts) 与 [**可莉插件仓库 (Kelee)**](https://github.com/luestr/ProxyResource)，基于单一跨端核心引擎（`HostAdapter`）原生支持 **Loon**（零外部控制器一等公民）与 **ProjectClash / Clash-Client**（零切换隧道桥接 + 前后台哈希防连坐隔离），同时提供通用入口脚本适配 Surge / Stash / Shadowrocket / Egern。

---

## ✨ 主插件：全能节点检测套件 (`v3.0.0`)

在节点列表或策略组**长按任意节点**，弹出三大独立深度检测面板（信息正交不重复、深浅色模式自适应排版）：

| 长按菜单项 | 核心检测维度 |
| :--- | :--- |
| 🌐 **节点链路与入口查询** | 展示 **本地直连对比** ➔ **智能 EDNS 中转入口 IP + 省市运营商 + `[ASxxxx]`** ➔ **落地 IPv4/IPv6 双栈** ➔ **10 类零忽悠证据分级拓扑 + 节点名称宣称验伪** ➔ **RIPE RIS 实时全球 BGP 上游骨干评级**（自动穿透 DMIT / Zenlayer / xTom / Misaka / Cera / Kirino 等聚合网关识别 CN2 `AS4809`、CTGNet `AS23764`、联通 `AS9929`·`AS10099`、移动 `CMIN2 AS58807`·`CMI AS58453`、软银·IIJ、国际 Tier-1 及 HKIX/JPIX/SGIX/BBIX）➔ **Cloudflare 边缘机房与 WARP 状态** |
| 🛡️ **节点纯净度深度检测** | 交叉核验 **双 ISP 属性（原生住宅家宽 / 商业政企宽带 / IDC 机房）**、**RIR 注册国 vs 地理国（原生 IP / 广播 IP）**、**BGP 互联评级**，融合 `ipapi.is` + `ProxyCheck` + `ip-score` + `IPPure` **四源风控评分与 40+ RBL 黑名单审计** |
| 🎬 **流媒体与 AI 解锁检测** | 轻量限流并发池（适配 iOS 扩展内存上限与双跳链式节点）实测 **ChatGPT (Web + iOS)**、**Claude**、**Gemini**、**Netflix**、**Disney+**、**YouTube Premium (防送中)**、**TikTok**、**巴哈姆特动画疯** |

> **全端附带能力**：
> - **网络环境切换通知**：开启插件参数「网络环境切换通知」后，采用错峰两阶段轻量探测 + 出口缓存比对，仅在 Wi-Fi / 蜂窝网络切换且实际出口变化时推送结构化通知。
> - **响应式 Web / JSON 诊断面板**：启用 `net-lsp-x.com` MitM 后，浏览器打开 `http://net-lsp-x.com` 即可查看可视化诊断报告（支持 `?node=节点名` 与 `?format=json`）。
> - **Clash-Client 专属模块面板**：模块详情页内置「当前网络出口信息」实时卡片，结合本地 LRU 缓存秒级刷新。

---

## 🎈 一、Loon 原生接入指南（推荐 · 零外部控制器免配置）

> **版本要求**：Loon `3.5.1 (Build 983)` 及以上版本（全面采用官方 v2 `script(...)` 与 `redirect(...)` 语法，多插件 `network-changed` 并行互不抢占）。

### 1. 一键导入主插件
- **方式 A（Safari / 快捷指令一键唤起安装）**：
  ```text
  loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-loon-node-info.lpx
  ```
- **方式 B（手动订阅链接导入）**：打开 **Loon** → **配置** → **插件** → 右上角 **`+`** 粘贴：
  ```text
  https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-loon-node-info.lpx
  ```

### 2. Loon 原生免配置四大架构优势
1. **零外部控制器直取入口**：长按节点触发 `generic` 脚本时，直接从 Loon 原生注入的 `$environment.params.nodeInfo` 提取服务器地址、端口与协议，并读取 `proxyChainInfo` 识别前置代理链——**无需开启任何本地端口或填写控制器密钥**。
2. **智能 EDNS + 原生 DNS 栈 + 离线 MMDB 秒查**：针对机场智能分流域名，自动提取本地直连宽带 `/24` 网段注入阿里 DoH `edns_client_subnet` 精准还原你所在省份真实命中的中转入口 IP 与完整 CNAME 链，配合 Loon `$dns.query` 原生栈与 `$utils.geoip / ipasn / ipaso` 0ms 离线兜底。
3. **原生 `{ node }` 直通隧道零切换**：`$httpClient` 直接指定目标节点出站探测，**不经过 MitM 桥接、绝不临时改动全局分流策略**（仅在需要浏览器访问 `http://net-lsp-x.com` 网页版面板时才需开启 MitM）。
4. **仪表盘即点即测**：在 Loon 仪表盘直接点击运行脚本时，自动探测当前活跃默认出口并弹出富文本卡片。

---

## ⚡ 二、Clash-Client 接入与配置指南

### 1. 导入主模块
打开 **Clash-Client** → **模块** → 点击右上角 **`+`** 粘贴导入（已装旧版用户直接更新模块即可 100% 平滑升级至 `v3.0.0`）：

```text
https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-clash-node-info.plugin
```

> **前后台隔离防护**：针对 Clash-Client `ModuleScriptHost` 按脚本 SHA-256 哈希超时隔离机制，模块自动将前台交互菜单绑定至 `xream-clash-node-info.js`，后台隧道桥接与切网事件绑定至 `xream-clash-node-bg.js`，配合内置软超时看门狗杜绝连坐拉黑。

### 2. 两项推荐配置（仅需设置一次）
1. **开启零切换隧道直测**：在 **模块** 页顶部开启 **「HTTPS 解密」**（点击生成证书即可；仅测节点无需去系统设置安装信任证书），长按节点即可经底层 PacketTunnel 零切换秒测；若未开启，脚本会自动安全降级为临时路由测速并在 `finally` 还原策略。
2. **捕获节点中转入口 IP 与链式拓扑**：前往 **设置 → 客户端设置 → 外部控制器** 选择 **「本机」**（重连一次 VPN 生效），将显示的 **密钥** 粘贴至本模块 **「设置 → 外部控制器密钥」**。

*(注：Surge / Stash / Shadowrocket / Egern 高级用户可直接引用仓库通用单文件产物 [`xream-node-info.js`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-node-info.js)，`HostAdapter` 会自动识别宿主并切换秒/毫秒超时单位与策略头。)*

---

## 🔬 三、新一代「零忽悠证据分级链路拓扑 + 名称验伪 + 双轴 BGP」原理

### 为什么彻底废弃「按节点名称猜 IEPL/IPLC 专线」？
在传统节点检测脚本中，只要满足「国内入口 + 海外落地」且节点名称包含 `IEPL`、`IPLC`、`专线`、`深港`、`沪日` 等字眼，就会直接盖章为「跨境专线加速」。由于代理协议在入口服务器发生 L4/L7 会话终结（Session Termination），客户端侧**在物理原理上不可见「入口机 ➔ 落地机」之间的二层传输介质**——廉价公网端口转发、家宽 NAT 与真物理二层专线在客户端可观测的出入口 IP 上完全可能相同。

`v3.0.0` 彻底将**节点名称从正向分类器中物理隔离（0% 字符串命名依赖）**，建立 **10 类 100% 实测网络证据驱动** 的拓扑分类体系：

### 1. 10 类客观证据驱动链路拓扑表

| 优先级 | 客观实测触发条件（零节点名依赖） | 拓扑类型徽章 (`badge`) | 证据等级 |
| :---: | :--- | :--- | :--- |
| **1** | 客户端显式配置 `dialer-proxy` / `relay` 组 / Loon `proxyChainInfo` | **客户端链式代理** `(+ WARP)` | 100% 配置铁证 |
| **2** | 入口 IP 属 RFC1918 私网 / `100.64.0.0/10` (Tailscale/旁路由) / IPv6 ULA | **局域网 / 组网网关中转** | 100% 协议栈铁证 |
| **3** | **`entranceIP === landingIP`**（出入口同 IP，含双栈匹配） | **单跳直连出境** / **单跳直连 + WARP 出站** | 100% 实测铁证 |
| **4** | 入口归属 `AS13335` (Cloudflare Anycast) | **Cloudflare WARP 隧道** / **Cloudflare CDN 边缘反代** | 100% ASN 铁证 |
| **5** | 境内入口出境，且 DNS `CNAME` 链命中阿里云 `ga.aliyuncs.com` / 腾讯云 `aga` / 华为云 / AWS Global Accelerator 等官方专网加速域 | **云全球加速专网中转 (GA/AGA)** | 100% CNAME 铁证 |
| **6** | 境内入口出境，且入口 ASN 与落地 ASN 同属同一跨国云/骨干集团（阿里 / 腾讯 / 华为 / UCloud / 火山 / AWS / Azure / Zenlayer） | **同云架构跨境中转** | 高置信度同云客观事实 |
| **7** | 境内入口出境，且入口 ASN 命中经核实的**国内多线 BGP 云厂商词典**（阿里 / 腾讯 / 华为 / UCloud / 火山 / 百度 / 京东 / 金山 / 青云 / 网宿） | **国内多线 BGP 云入口中转** | 100% 入口实测 *(不妄断过境黑盒)* |
| **8** | 境内入口出境，入口属三大运营商省网 IDC / 政企 / 宽带（如实展示具体省市 + 运营商 + ASN） | **国内运营商入口中转** | 100% 入口实测 |
| **9** | `entCC === 'CN' && landingCC === 'CN'` 且出入口分离 | **境内内陆中转链路** | 100% 实测铁证 |
| **10** | 海外接入且出入口分离（先判跨国再判 WARP，修复跨洲跳板套 WARP 误判）：<br>• 跨国 + WARP ➔ **海外跨国跳板 + WARP 出站**<br>• 同国 + WARP ➔ **海外入口 + WARP 出站**<br>• 跨国异地 ➔ **海外跨国跳板中转**<br>• 同国同 ASN ➔ **海外同网段多 IP 出站**<br>• 同国异 ASN ➔ **海外同区异网落地链** | 对应右侧 5 种精确海外分离徽章 | 100% 实测铁证 |

### 2. 「只验伪、不采信」节点名称宣称审计 (`detectNameClaimMismatch`)
节点名称**绝不会给线路评级加一分**；但当客观网络铁证 100% 证伪节点名称中的营销标签时，面板将输出客观核验提示：
- 名称含 `IEPL / IPLC / 专线 / 中转`，但实测 `entranceIP === landingIP`（无客户端链）➔ 提示 **「实测出入口同 IP（纯单跳直连）」**。
- 名称含 `IEPL / IPLC / 内网专线 / 深港 / 沪日` 等，但实测入口为 `AS13335` ➔ 提示 **「实测为 Cloudflare Anycast 公共边缘接入」**。
- 名称含 `IEPL / IPLC / 内网专线 / 深港 / 广港 / 沪日 / 沪美 / 京德 / 京日`，但实测首跳入口在境外（`entCC !== 'CN'`）➔ 提示 **「实测首跳直连境外，无境内入口」**。

### 3. 双轴正交 BGP 路由评级（杜绝「落地国际 BGP」与「去程质量」混淆）
- **单跳直连拓扑** → 标签显示为 **`跨境骨干`**：此时跨境去回程质量直接取决于落地机公网 BGP 上游（精准识别电信 `CN2 AS4809` / `CTGNet AS23764`、联通 `AS9929` / `CUG AS10099`、移动 `CMIN2 AS58807` / `CMI AS58453`、日本软银 / IIJ 等精品回国优化 vs 普通国际公网）。
- **国内中转 / 海外跳板拓扑** → 标签自动切换为 **`落地互联`**：第一跳去程看本地宽带与国内入口（多线云 BGP vs 单线省网），RIPE RIS 路由表明确表征**落地机房的国际交换中心（HKIX / JPIX / SGIX / BBIX）与 Tier-1 上游互联能力**，概念严丝合缝。

---

## 🧩 四、精选可莉实用插件双端对照表（Loon `.lpx` vs Clash-Client `.plugin`）

全部实用插件均已针对 **Loon 3.5.1+ 原生 v2 规范**（无 `RULE-SET`、无 `%APPEND%`、无 `script-update-interval`、`requires_body` 标准属性、307 标准重定向）与 **Clash-Client 模块规范** 分别精修调优，共用无 `atob` 依赖的纯 JS 解码脚本：

| 插件名称 | 功能定位与双端精修亮点 | Loon 原生版 (`.lpx`) | Clash-Client 版 (`.plugin`) |
| :--- | :--- | :--- | :--- |
| **全能节点检测套件** | 三大长按深度检测（10 类客观拓扑 + 名称验伪 + RIPE BGP + 四源纯净度 + AI/流媒体解锁）+ 切网通知 + Web 面板 | [`.lpx` 链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-loon-node-info.lpx)<br>`loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-loon-node-info.lpx` | [`.plugin` 链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-clash-node-info.plugin) |
| **全局开屏与广告联盟拦截** | 拦截穿山甲、优量汇、百青藤、快手联盟、阿里妈妈及 Google/AppLovin/UnityAds 等开屏 SDK（免证书；Loon 版采用纯内联高频规则零 `RULE-SET` 报错） | [`loon-ad-guard.lpx`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/loon-ad-guard.lpx)<br>`loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/loon-ad-guard.lpx` | [`clash-ad-guard.plugin`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/clash-ad-guard.plugin) |
| **HTTPDNS 拦截与防绕过** | 拦截阿里/腾讯/百度/字节/B站/网易/美团/京东/知乎等私自走加密或裸 IP 双栈 HTTPDNS，防分流绕过与 DNS 泄露（免 MitM；Loon 版融合 `IP-CIDR6` 与裸 IP `URL-REGEX`） | [`kelee-httpdns-guard.lpx`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-httpdns-guard.lpx)<br>`loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-httpdns-guard.lpx` | [`kelee-httpdns-guard.plugin`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/kelee-httpdns-guard.plugin) |
| **外部链接直跳解锁** | 自动跳过微信、QQ、知乎、微博、CSDN、掘金、简书外链安全提示中转页，内置纯 JS Base64 / URL-safe Base64 解码器，302 秒达目标网页（需 MitM） | [`kelee-link-unlock.lpx`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-link-unlock.lpx)<br>`loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-link-unlock.lpx` | [`kelee-link-unlock.plugin`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/kelee-link-unlock.plugin) |
| **Google 防送中 & TF 解锁** | `google.cn` / `g.cn` / `maps.google.cn` 自动跳转国际版，并解除 TestFlight 安装测试版应用的 Apple ID 区域限制（需 MitM） | [`kelee-google-tf-unlock.lpx`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-google-tf-unlock.lpx)<br>`loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-google-tf-unlock.lpx` | [`kelee-google-tf-unlock.plugin`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/kelee-google-tf-unlock.plugin) |

---

## 🛠️ 五、工程构建与自动化测试

仓库提供零外部依赖的 Node.js 构建与双轨单元测试套件：

```bash
# 1. 从单一核心源码构建通用版与 Clash-Client 前后台隔离产物（加 --check 可校验产物一致性）
node scripts/build.js

# 2. 运行多客户端核心适配层、EDNS 解析与 10 类反欺诈链路拓扑单元测试
node tests/core-multi-client.test.js

# 3. 运行 Loon (.lpx) / Clash-Client (.plugin) 语法规范与纯 JSC 无 atob 沙箱测试
node tests/plugin-syntax.test.js
```

---

## 🙏 致谢与协议

- 感谢 [**@xream/scripts**](https://github.com/xream/scripts)、[**@luestr/ProxyResource (可莉)**](https://github.com/luestr/ProxyResource)、[**Loon**](https://nsloon.com)、[**ProjectClash/Clash-Client**](https://github.com/ProjectClash/Clash-Client)、[**MetaCubeX/mihomo**](https://github.com/MetaCubeX/mihomo) 与 [**Koolson/Qure**](https://github.com/Koolson/Qure)。
- 本仓库基于 [**GPL-3.0 License**](./LICENSE) 开源，仅供网络拓扑诊断与技术学习交流。
