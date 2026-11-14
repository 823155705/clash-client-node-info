# Clash-Client 全能节点检测与实用插件集

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)
[![Platform: iOS / macOS](https://img.shields.io/badge/Platform-iOS%20%7C%20macOS-111827.svg)](https://github.com/ProjectClash/Clash-Client)

深度融合 [**xream/scripts**](https://github.com/xream/scripts) 与 [**可莉插件仓库 (Kelee)**](https://github.com/luestr/ProxyResource)，专为 [**ProjectClash/Clash-Client**](https://github.com/ProjectClash/Clash-Client) 原生模块引擎定制重写（零忽略项、零污染策略切换）。

---

## 🚀 主模块：全能节点检测套件 (`v2.0.0`)

打开 **Clash-Client** → **模块** → 点击右上角 **`+`** 粘贴导入（或复制 [`xream-clash-node-info.plugin`](./xream-clash-node-info.plugin) 手动新建）：

```text
https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-clash-node-info.plugin
```

### 代理页长按任意节点 → 三大独立检测功能

| 菜单项 | 功能定位（互不重复、一屏展示） |
| :--- | :--- |
| 🌐 **节点链路与入口查询** | 秒查 `本地直连 ➔ 节点中转入口 ➔ 落地双栈 IPv4/v6 ➔ Cloudflare 边缘机房` 走向，并识别是否套用 **WARP / WARP+** |
| 🛡️ **节点纯净度深度检测** | 识别 **双 ISP 原生家宽 / 机房** 与 **原生 / 广播 IP**，融合 `ipapi.is` + `ProxyCheck` + `ip-score` **三源风控与 RBL 黑名单审计** |
| 🎬 **流媒体与 AI 解锁检测** | 并发实测 **ChatGPT (Web+iOS)**、**Claude**、**Gemini**、**Netflix**、**Disney+**、**YouTube Premium (防送中)**、**TikTok**、**动画疯** |

> **附带能力**：模块详情页内置 **「当前网络出口信息」** 面板；浏览器访问 `http://net-lsp-x.com` 可查看响应式诊断网页（支持 `?node=节点名` 与 `?format=json`）。

### 两项推荐配置（仅需一次）
1. **开启零切换秒测**：在 **模块** 页顶部打开 **「HTTPS 解密」**（点击生成证书即可，仅用本模块无需去系统设置信任证书），长按任意节点直接走底层 Tunnel 探测，无需临时切换全局策略。
2. **显示节点中转入口 IP**：前往 **设置 → 客户端设置 → 外部控制器** 选择 **「本机」**（重连一次 VPN 生效），复制页面上的 **密钥** 粘贴到本模块 **「设置 → 外部控制器密钥」** 即可。

---

## 🧩 精选移植插件（源自可莉插件仓库）

以下高频实用工具已针对 `Clash-Client` 语法与运行时完成零警告移植，可按需单独导入：

| 插件名称 | 功能简介 | 一键导入链接 |
| :--- | :--- | :--- |
| **HTTPDNS 拦截与防绕过** | 拦截微信/淘宝/B站/抖音/百度/网易等私自走 HTTPDNS，防分流失效与 DNS 泄露（免开解密） | [`kelee-httpdns-guard.plugin`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/kelee-httpdns-guard.plugin) |
| **外部链接直跳解锁** | 自动跳过微信、QQ、知乎、微博、CSDN、掘金、简书外链安全拦截中转页，302 秒达目标网页 | [`kelee-link-unlock.plugin`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/kelee-link-unlock.plugin) |
| **Google 防送中 & TF 解锁** | `google.cn` 自动跳转 `www.google.com`，并解除 TestFlight 安装测试版应用的区域限制 | [`kelee-region-redirect`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/kelee-google-tf-unlock.plugin) |

---

## 🙏 致谢与协议

- 感谢 [**@xream/scripts**](https://github.com/xream/scripts)、[**@luestr/ProxyResource (可莉)**](https://github.com/luestr/ProxyResource)、[**ProjectClash/Clash-Client**](https://github.com/ProjectClash/Clash-Client)、[**MetaCubeX/mihomo**](https://github.com/MetaCubeX/mihomo) 与 [**Koolson/Qure**](https://github.com/Koolson/Qure)。
- 本仓库基于 [**GPL-3.0 License**](./LICENSE) 开源，仅供网络诊断与技术学习交流。
