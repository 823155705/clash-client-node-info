# Clash-Client 节点网络信息与纯净度查询模块

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)
[![Platform: iOS / macOS](https://img.shields.io/badge/Platform-iOS%20%7C%20macOS-111827.svg)](https://github.com/ProjectClash/Clash-Client)

基于 [**xream/scripts**](https://github.com/xream/scripts)（`net-lsp-x` / `ip-info` / `ip-score` / `ip-whois`）的设计理念，专为 [**ProjectClash/Clash-Client**](https://github.com/ProjectClash/Clash-Client)（iOS / macOS）双进程模块引擎深度重构的**节点落地信息、双 ISP 原生家宽属性与 IP 纯净度风控检测工具**。

---

## ✨ 一键导入地址

### 方式一：模块链接直接导入（推荐）

复制以下链接，打开 **Clash-Client** → 底部 **模块 (Modules)** → 点击右上角 **`+`**（或直接在输入框右侧点击粘贴按钮）添加：

```text
https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-clash-node-info.plugin
```

也可在手机浏览器或备忘录中使用 URL Scheme 唤起安装：

```text
clash://install-module?url=https%3A%2F%2Fraw.githubusercontent.com%2F823155705%2Fclash-client-node-info%2Fmain%2Fxream-clash-node-info.plugin
```

### 方式二：手动复制粘贴模块全文

若当前网络拉取模块文件不便，可直接打开仓库中的 [`xream-clash-node-info.plugin`](./xream-clash-node-info.plugin) 全选复制，在 **Clash-Client** → **模块** → **新建模块（手动输入）** 中粘贴保存。

---

## 🚀 核心特性与四大使用场景

一套模块同时提供 **4 种交互入口** 与 **1 项可选网络切换通知**：

### 1. 代理页长按任意节点 → 「节点信息查询」（快速全览）
在 **代理 (Proxies)** 页面长按任意代理节点，点击 **「节点信息查询」**：
- **节点协议与健康度**：原生读取 Mihomo 节点元数据（协议类型如 `VLESS` / `Hysteria2` / `Shadowsocks` / `Trojan`、UDP 转发支持状态、最近一次测速延迟 `ms`）。
- **本地直连入口对比**：展示当前国内直连 IP、归属省市与运营商（电信 / 联通 / 移动等）。
- **目标节点真实落地出口**：并发探测该节点的落地 **IPv4** 与 **IPv6** 支持情况、国家/地区旗帜、城市、时区、ASN 编号与所属 ISP / 机构。
- **双 ISP 原生属性与纯净度评估**：
  - 区分 **ASN 类型** 与 **运营商 (Company) 类型**，精准识别 **「双 ISP 原生家宽」**、**「单 ISP 住宅宽带」**、**「商业专线」** 与 **「IDC 机房托管 (Hosting)」**。
  - 对比 ASN 注册国与落地定位国，自动标注 **「原生归属 IP」** 或 **「广播 IP」**。
  - 接入 `ipapi.is` 欺诈滥用评分（`abuser_score`）及 6 项风险画像标签（`IDC机房` / `VPN特征` / `公开代理` / `历史滥用` / `Tor节点` / `爬虫标记`），并给出流媒体与 AI 服务（ChatGPT / Claude / TikTok）解锁友好度建议。

### 2. 代理页长按任意节点 → 「节点纯净度深度检测」（风控体检）
在基础查询之上额外执行深度交叉审计：
- **WHOIS 网段与注册局**：展示 CIDR 归属网段与 RIR（`APNIC` / `ARIN` / `RIPE` 等）。
- **多源黑名单扫描**：调用 `ip-score.com` 对数十个国际反垃圾/欺诈黑名单库进行逐一核验，并对比多库 GeoIP 定位一致性。

### 3. 模块详情页 → 「当前网络出口信息」实时面板
进入 **模块** → 点击本模块，顶部即展示 **「当前网络出口信息」** 卡片面板。点击卡片右上角刷新按钮，即可一键查看当前运行模式（规则分流 / 全局代理 / 全局直连）、直连入口与活跃代理落地摘要。

### 4. 浏览器可视化诊断门户（`http://net-lsp-x.com`）
开启模块页顶部的 **HTTPS 解密** 开关后，在 Safari 等浏览器访问：
- `http://net-lsp-x.com`：展示自适应 iOS 深色/浅色模式的响应式网络诊断网页卡片。
- `http://net-lsp-x.com/?node=节点名称`：在浏览器中直接指定任意节点名称进行定向探测。
- `http://net-lsp-x.com/?format=json`：输出完整结构化 JSON 数据，便于配合 iOS「快捷指令」自动化调用。

---

## 🛠️ 为什么需要专门针对 Clash-Client 重写适配？

原版 `xream/scripts` 面向 Surge / Loon / Stash 设计，直接在 `ProjectClash/Clash-Client` 中使用会遇到以下底层架构差异：

1. **解决「长按 A 节点却查出 B 节点 IP」的核心痛点**：
   - `Clash-Client` 采用主进程（App）与隧道扩展（PacketTunnel Extension）分离的双脚本运行时。长按节点触发的 `generic` 脚本运行在主进程 `ModuleAppScriptRunner` 中，其网络层出于架构边界设计忽略了 `$httpClient` 的 `{ node, policy }` 参数，导致普通脚本只能走当前系统隧道默认代理出口。
   - **本模块的双通道解决方案**：
     - **⚡ 优先通道（零切换 Tunnel 桥接，强烈推荐）**：通过 `[General] force-http-engine-hosts = net-lsp-x.com` 与 `[Host] net-lsp-x.com = 198.51.100.88`，只要开启「模块」页顶部的开关（点击生成证书即可，**甚至无需在 iOS 系统设置中安装或信任 CA 证书**），长按节点请求会通过纯 HTTP 唤醒 PacketTunnel 内的 `ModuleEngine`，在扩展进程内使用原生 `Clash-Outbound: <目标节点>` 直接从目标节点发包探测——**零策略切换、不中断后台连接、100% 测准所选节点**。
     - **🔄 自动回退通道（未开模块引擎时兜底）**：若用户未开启模块页顶部开关，脚本会自动利用 Loon 运行时的 `$config` 控制器接口快照当前运行模式与 `GLOBAL` 策略，毫秒级临时路由至目标节点完成探测，并在 `finally` 中严格原样恢复（内置异常中断自愈保护）。
2. **原生 UI 与语法零警告兼容**：
   - 采用 `Clash-Client` 原生支持的 SF Symbols 系统图标（`globe.asia.australia`、`shield.lefthalf.filled`）。
   - 弹窗排版严格匹配 `ClashScriptHTML` 富文本渲染引擎及深浅色对比度规范。
   - 模块解析实现 **0 忽略项（Zero Ignored Entries）**。

---

## ⚙️ 模块可配置参数说明

导入后可在 **模块 → 点进本模块 → 设置 (Settings)** 中随时通过原生开关调整：

| 参数项 | 默认值 | 说明 |
| :--- | :---: | :--- |
| **显示本地直连入口对比** | 开启 | 同时查询国内直连 IP、省市归属与运营商 |
| **查询 IP 纯净度与原生属性** | 开启 | 调用 `ipapi.is` 检测双 ISP 属性、滥用分与风险标签 |
| **检测节点 IPv6 出口支持** | 开启 | 探测目标节点是否具备可用 IPv6 出站能力 |
| **隐私保护（IP 部分打码）** | 关闭 | 开启后自动隐藏 IPv4/IPv6 中间段，方便安全截图分享 |
| **未开解密引擎时自动临时切换测速** | 开启 | 未开启模块页顶部开关时允许通过 `$config` 临时路由测速并自动还原 |
| **网络环境切换推送通知** | 关闭 | 开启后在 Wi-Fi / 蜂窝网络切换且出口变化时推送系统通知 |
| **接口超时时间（秒）** | `8` 秒 | 可选 `5` / `8` / `12` / `15` 秒，高延迟链路建议适当调大 |
| **ipapi.is API Key（可选）** | 留空 | 留空即可免费免 Key 使用；高频批量检测可填入免费申请的 Key |

---

## 💡 推荐使用贴士

- **开启零打扰直测模式**：建议前往 `Clash-Client` 的 **模块** 页面最上方，打开 **HTTPS 解密** 开关（提示需要证书时点击生成即可，如果仅使用本模块无需前往系统设置安装信任描述文件）。开启后长按任意节点底部会显示 `⚡ 零切换直测通道 (Tunnel Outbound)`。

---

## 🙏 致谢 (Acknowledgments)

本项目的诞生离不开以下优秀开源项目与公共基础设施的支持，特此致以诚挚感谢：

- [**@xream / scripts**](https://github.com/xream/scripts)（[@xream](https://github.com/xream) & `@Key`）：提供了极具创造力的 `net-lsp-x`、`ip-info`、`ip-score`、`ip-whois` 与 Sub-Store 节点检测脚本思路与风控评估模型，本项目核心功能均受其启发并在此基础上完成适配重写。
- [**ProjectClash / Clash-Client**](https://github.com/ProjectClash/Clash-Client)：打造了体验细腻、架构严谨的 Apple 平台原生客户端与模块脚本运行时。
- [**MetaCubeX / mihomo**](https://github.com/MetaCubeX/mihomo)：强大稳定的代理核心支持。
- [**Koolson / Qure**](https://github.com/Koolson/Qure)：精美的模块图标资源支持。
- **公共 IP 与风控数据服务商**：感谢 `ipapi.is`、`ip-api.com`、`ip.sb`、`ipwho.is`、`ip-score.com`、`ipinfo.io`、`ipip.net` 等提供的地理位置与网络安全查询接口。

---

## 📄 开源协议 (License)

本项目遵循上游 [`xream/scripts`](https://github.com/xream/scripts) 的开源协议，基于 [**GNU General Public License v3.0 (GPL-3.0)**](./LICENSE) 发布。
