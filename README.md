# 节点检测工具与实用插件

适用于 **Loon** 与 **Clash-Client** 的节点信息检测工具及常用分流、去广告规则插件，支持查询节点入口与落地链路、IP 纯净度，以及流媒体和 AI 平台的解锁状态。

## 安装与使用

### Loon

要求 Loon `3.5.1 (983)` 及以上版本。

- **一键导入**：
  ```text
  loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-loon-node-info.lpx
  ```
- **订阅链接**：
  ```text
  https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-loon-node-info.lpx
  ```

导入后，在节点列表中**长按任意节点**即可选择对应检测项。脚本会直接读取节点配置并通过独立连接发起测试，无需开启外部控制器，也不会打断或切换当前正在使用的网络连接。

### Clash-Client

在「模块」页面点击右上角 `+` 导入以下链接：

```text
https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-clash-node-info.plugin
```

首次使用建议完成以下两项设置：

1. **开启 HTTPS 解密**：在「模块」页面顶部打开「HTTPS 解密」并生成证书（仅用于本地测试请求转发，无需在系统设置中安装信任证书）。若未开启，测试时会临时切换至目标节点并在结束后自动还原。
2. **填写外部控制器密钥**：前往「设置 -> 客户端设置 -> 外部控制器」选择「本机」，重连一次连接后，将页面显示的密钥填入本模块设置的「外部控制器密钥」中，用于读取节点中转入口地址。

> 其他支持通用脚本的客户端（如 Surge、Stash、Shadowrocket、Egern）可直接引用仓库根目录下的 [`xream-node-info.js`](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/xream-node-info.js)。

## 检测项说明

长按节点后包含三项检测菜单：

- **节点链路查询**：显示本地直连 IP（可关闭）、中转入口 IP 与所属运营商/ASN、落地出口 IP 与机构信息、RIPE BGP 上游线路概况，以及 IPv6 和 WARP 状态。链路类型仅根据实测的入口与落地 IP、ASN 及 DNS CNAME 记录判断（区分单跳直连、国内运营商中转、多线云入口中转、同云跨境中转、云全球加速等），不参考节点名称中的 `IEPL`、`IPLC` 等字样，避免将普通公网或云中转节点误标为物理专线。
- **节点纯净度检测**：查询落地 IP 的带宽属性（住宅宽带、商业宽带或机房托管）、原生/广播归属、综合风险评分及常见 RBL 黑名单命中情况。
- **流媒体与解锁检测**：测试当前节点对 ChatGPT、Claude、Gemini、Netflix、Disney+、YouTube Premium、TikTok 及巴哈姆特动画疯的访问与解锁地区。

此外，插件设置中可按需开启「网络切换通知」（仅在网络环境切换且出口发生变化时推送）；开启 `net-lsp-x.com` 的 MitM 后，也可在浏览器访问 `http://net-lsp-x.com` 查看网页版诊断结果。

## 其他实用插件

以下规则与脚本插件分别针对 Loon 与 Clash-Client 语法维护，按需单独导入即可（其中「外链直跳」与「Google 与 TestFlight 解锁」需为对应域名开启 MitM / HTTPS 解密并信任证书）：

| 插件名称 | 功能说明 | Loon (`.lpx`) | Clash-Client (`.plugin`) |
| :--- | :--- | :--- | :--- |
| 开屏与广告拦截 | 拦截常见国内 App 开屏广告与广告联盟域名 | [订阅链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/loon-ad-guard.lpx) · [一键导入](loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/loon-ad-guard.lpx) | [模块链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/clash-ad-guard.plugin) |
| HTTPDNS 拦截 | 拦截常见 App 的 HTTPDNS 请求，防止分流绕过与 DNS 泄露 | [订阅链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-httpdns-guard.lpx) · [一键导入](loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-httpdns-guard.lpx) | [模块链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/kelee-httpdns-guard.plugin) |
| 外链直跳 | 自动跳过微信、QQ、知乎、微博、CSDN、掘金、简书外链中转页 | [订阅链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-link-unlock.lpx) · [一键导入](loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-link-unlock.lpx) | [模块链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/kelee-link-unlock.plugin) |
| Google 与 TestFlight 解锁 | 将 `google.cn` 重定向至 `google.com`，并解除 TestFlight 区域限制 | [订阅链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-google-tf-unlock.lpx) · [一键导入](loon://import?plugin=https://raw.githubusercontent.com/823155705/clash-client-node-info/main/loon/plugins/kelee-google-tf-unlock.lpx) | [模块链接](https://raw.githubusercontent.com/823155705/clash-client-node-info/main/plugins/kelee-google-tf-unlock.plugin) |

## 本地开发与测试

```bash
node scripts/build.js
node tests/core-multi-client.test.js
node tests/plugin-syntax.test.js
```

## 致谢与开源协议

- 感谢 [xream/scripts](https://github.com/xream/scripts) 与 [luestr/ProxyResource](https://github.com/luestr/ProxyResource) 在节点信息查询及客户端分流规则方面提供的思路与参考，图标资源来自 [Koolson/Qure](https://github.com/Koolson/Qure)。
- 本项目遵循 [GPL-3.0 License](./LICENSE) 开源协议。
