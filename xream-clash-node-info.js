/**
 * xream Network & Node Info Suite — ProjectClash/Clash-Client 深度适配版
 *
 * 基于 https://github.com/xream/scripts (net-lsp-x / ip-info / ip-score / ip-whois / sub-store geo)
 * 专为 ProjectClash/Clash-Client (iOS / macOS) 双脚本运行时架构重写与增强：
 *
 * 1. 解决原版长按节点查错成「当前全局/规则代理节点」的核心问题：
 *    - 优先通道 (零打扰直连指定节点): 通过 http://net-lsp-x.com/__clash_node_check 唤醒
 *      PacketTunnel 内的 ModuleEngine，使用 { node, policy } (Clash-Outbound) 直接从目标节点发包，
 *      不切换任何策略组、不影响后台正在进行的连接，甚至无需信任 CA 证书（仅需开启模块页顶部开关）。
 *    - 自动回退通道 (未开启模块引擎时): 利用 Clash-Client Loon 运行时的 $config 接口 (clash.sock)，
 *      自动快照当前运行模式与 GLOBAL 选择，毫秒级临时路由测速并在 finally 中严格还原。
 * 2. 原生适配 Clash-Client 的 Mihomo nodeInfo 结构 (协议类型 type、UDP 支持、存活状态、最新延迟 ms)。
 * 3. 融合 xream 四大脚本能力：
 *    - 入口/国内直连 IP 与运营商定位对比
 *    - 目标节点落地 IPv4 / IPv6、国旗地理位置、ASN、ISP/Organization
 *    - 双维度原生属性判定 (ASN 类型 vs 运营商类型：双 ISP 原生家宽 / 单 ISP / 机房 Hosting / 商业宽带)
 *    - ipapi.is 欺诈滥用评分 (abuser_score) + 6 项风险标签 + WHOIS 网段 + ip-score 黑名单交叉核验
 * 4. 一套脚本同时驱动 5 种场景：
 *    - 代理页 -> 长按任意节点 -> 「节点信息查询」(快速全览)
 *    - 代理页 -> 长按任意节点 -> 「节点纯净度深度检测」(多源风控/原生属性/黑名单/流媒体&AI友好度)
 *    - 模块详情页 -> [Panel] 「当前网络出口信息」一键刷新面板
 *    - Safari 浏览器访问 http://net-lsp-x.com 响应式可视化网页卡片 (支持 ?node=节点名 & ?format=json)
 *    - 网络环境切换事件通知 (network-changed，可开关并自动防抖去重)
 */

(function () {
  'use strict';

  const BRIDGE_HOST = 'net-lsp-x.com';
  const BRIDGE_CHECK_PATH = '/__clash_node_check';
  const STATE_RESTORE_KEY = 'xream_clash_pending_restore_v1';
  const LAST_EVENT_KEY = 'xream_clash_last_net_event_v1';

  const COLORS = {
    primary: '#3b82f6',
    success: '#10b981',
    warning: '#f59e0b',
    danger: '#ef4444',
    purple: '#8b5cf6',
    muted: '#6b7280',
    cyan: '#06b6d4',
  };

  // ============================================================================
  // 1. 环境识别与参数解析
  // ============================================================================

  function parseArguments(raw) {
    const out = {};
    if (!raw) return out;
    if (typeof raw === 'object') {
      Object.keys(raw).forEach((k) => {
        out[k] = raw[k];
      });
      return out;
    }
    const text = String(raw).trim();
    if (!text) return out;
    if (text.startsWith('{') && text.endsWith('}')) {
      try {
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === 'object') return parsed;
      } catch (_) {}
    }
    text.split('&').forEach((pair) => {
      if (!pair) return;
      const idx = pair.indexOf('=');
      if (idx <= 0) return;
      const k = decodeURIComponent(pair.slice(0, idx).trim());
      let v = pair.slice(idx + 1).trim();
      try {
        v = decodeURIComponent(v);
      } catch (_) {}
      // 若占位符未被替换（如 "{IPAPI_KEY}"），视为空字符串
      if (/^\$?\{[^{}\s]+\}$/.test(v)) v = '';
      out[k] = v;
    });
    return out;
  }

  function toBool(val, defaultVal) {
    if (val === undefined || val === null || val === '') return defaultVal;
    if (typeof val === 'boolean') return val;
    const s = String(val).trim().toLowerCase();
    if (['1', 'true', 'yes', 'on', '开启', '是'].includes(s)) return true;
    if (['0', 'false', 'no', 'off', '关闭', '否'].includes(s)) return false;
    return defaultVal;
  }

  function toNum(val, defaultVal, minVal, maxVal) {
    const n = Number(val);
    if (!Number.isFinite(n)) return defaultVal;
    return Math.min(maxVal, Math.max(minVal, n));
  }

  function parseControllerPort(raw, defaultPort) {
    const s = String(raw || '').trim();
    if (!s) return defaultPort;
    const colonMatch = s.match(/:(\d{2,5})\/?$/);
    if (colonMatch) return toNum(colonMatch[1], defaultPort, 1, 65535);
    return toNum(s, defaultPort, 1, 65535);
  }

  function normalizeSecret(raw) {
    return String(raw || '')
      .trim()
      .replace(/^Bearer\s+/i, '')
      .trim();
  }

  const ARGS = parseArguments(typeof $argument !== 'undefined' ? $argument : '');
  const CFG = {
    mode: String(ARGS.MODE || 'basic').toLowerCase(),
    showDomestic: toBool(ARGS.SHOW_DOMESTIC, true),
    showEntrance: toBool(ARGS.SHOW_ENTRANCE, true),
    controllerPort: parseControllerPort(ARGS.CONTROLLER_PORT, 9090),
    controllerSecret: normalizeSecret(ARGS.CONTROLLER_SECRET),
    checkPurity: toBool(ARGS.CHECK_PURITY, true),
    checkIPv6: toBool(ARGS.CHECK_IPV6, true),
    maskIP: toBool(ARGS.MASK_IP, false),
    autoSwitchFallback: toBool(ARGS.AUTO_SWITCH_FALLBACK, true),
    notifyOnChange: toBool(ARGS.NOTIFY_ON_CHANGE, false),
    ipapiKey: String(ARGS.IPAPI_KEY || '').trim(),
    timeoutMs: Math.round(toNum(ARGS.TIMEOUT_SEC, 8, 3, 25) * 1000),
  };

  function log(msg) {
    try {
      console.log('[xream-clash] ' + msg);
    } catch (_) {}
  }

  // ============================================================================
  // 2. 存储与网络工具
  // ============================================================================

  function storeRead(key) {
    try {
      if (typeof $persistentStore !== 'undefined' && $persistentStore.read) {
        return $persistentStore.read(key);
      }
    } catch (_) {}
    return null;
  }

  function storeWrite(key, val) {
    try {
      if (typeof $persistentStore !== 'undefined' && $persistentStore.write) {
        return $persistentStore.write(String(val), key);
      }
    } catch (_) {}
    return false;
  }

  function notify(title, subtitle, body) {
    try {
      if (typeof $notification !== 'undefined' && $notification.post) {
        $notification.post(title || '', subtitle || '', body || '');
      }
    } catch (_) {}
  }

  function httpRequest(method, options, timeoutOverride) {
    const timeoutMs = timeoutOverride || CFG.timeoutMs;
    const reqOpts = typeof options === 'string' ? { url: options } : Object.assign({}, options);
    reqOpts.headers = Object.assign(
      {
        'User-Agent':
          'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
        Accept: 'application/json, text/plain, */*',
      },
      reqOpts.headers || {}
    );
    // Clash-Client (ModuleScriptGlobals.swift:374):
    // Loon 家族 ($loon 存在) 下 $httpClient.timeout 按毫秒解析 (value / 1000)，而 Surge/Stash 家族按秒解析
    const isLoonRuntime = typeof $loon !== 'undefined';
    reqOpts.timeout = isLoonRuntime
      ? Math.max(800, Math.round(timeoutMs))
      : Math.max(1, Math.ceil(timeoutMs / 1000));

    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(new Error('Timeout (' + timeoutMs + 'ms)'));
        }
      }, timeoutMs + 500);

      try {
        const fn =
          method === 'post'
            ? $httpClient.post.bind($httpClient)
            : $httpClient.get.bind($httpClient);
        fn(reqOpts, (err, resp, data) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (err) {
            reject(typeof err === 'string' ? new Error(err) : err);
            return;
          }
          const status = resp ? Number(resp.status || resp.statusCode || 0) : 0;
          resolve({ status, headers: (resp && resp.headers) || {}, body: data == null ? '' : String(data) });
        });
      } catch (e) {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(e);
        }
      }
    });
  }

  async function fetchJSON(options, timeoutMs, method) {
    const res = await httpRequest(method || 'get', options, timeoutMs);
    if (res.status < 200 || res.status >= 400) {
      throw new Error('HTTP ' + res.status);
    }
    const text = res.body.trim();
    if (!text) throw new Error('Empty body');
    return JSON.parse(text);
  }

  function buildOutboundOpts(url, targetNode, extraHeaders) {
    const opts = { url, headers: extraHeaders || {} };
    if (targetNode) {
      opts.node = targetNode;
      opts.policy = targetNode;
    }
    return opts;
  }

  // ============================================================================
  // 3. 格式化辅助函数 (国旗、脱敏、HTML 安全转义、ISP 简化)
  // ============================================================================

  function getFlagEmoji(countryCode) {
    if (!countryCode || typeof countryCode !== 'string') return '🌐';
    const cc = countryCode.trim().toUpperCase();
    if (cc === 'TW') return '🇹🇼';
    if (cc.length !== 2 || !/^[A-Z]{2}$/.test(cc)) return '🌐';
    const points = [cc.charCodeAt(0) + 127397, cc.charCodeAt(1) + 127397];
    return String.fromCodePoint(points[0], points[1]);
  }

  function maskIPString(ip, enabled) {
    if (!ip || !enabled) return ip || '-';
    const s = String(ip).trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      const p = s.split('.');
      return p[0] + '.' + p[1] + '.*.' + p[3];
    }
    if (s.includes(':')) {
      const p = s.split(':').filter(Boolean);
      if (p.length >= 3) return p[0] + ':' + p[1] + ':*:*:' + p[p.length - 1];
    }
    return s;
  }

  function esc(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function colorSpan(text, hex, bold) {
    const weight = bold ? '; font-weight:bold' : '';
    return '<span style="color:' + hex + weight + '">' + esc(text) + '</span>';
  }

  function maskDomainString(domain, enabled) {
    if (!domain || !enabled) return domain || '-';
    const parts = String(domain).trim().split('.');
    if (parts.length <= 1) return '***';
    return '***.***.' + parts[parts.length - 1];
  }

  function normalizeCNISP(raw) {
    const s = String(raw || '');
    if (/电信|telecom|chinanet|ctcc/i.test(s)) return '中国电信';
    if (/联通|unicom|cucc/i.test(s)) return '中国联通';
    if (/移动|mobile|cmcc|铁通/i.test(s)) return '中国移动';
    if (/广电|CBN|cable/i.test(s)) return '中国广电';
    if (/教育|cernet/i.test(s)) return '中国教育网';
    return s.trim();
  }

  function normalizeEntranceISP(rawISP, rawOrg, countryCode) {
    const combined = [rawISP, rawOrg].filter(Boolean).join(' ');
    if (/aliyun|alibaba|阿里云|万网/i.test(combined)) return '阿里云 BGP';
    if (/tencent|qcloud|腾讯云/i.test(combined)) return '腾讯云 BGP';
    if (/huawei|华为云/i.test(combined)) return '华为云 BGP';
    if (/ucloud|优刻得/i.test(combined)) return 'UCloud BGP';
    if (/volcengine|bytedance|火山引擎/i.test(combined)) return '火山引擎 BGP';
    if (/baidu|百度/i.test(combined)) return '百度智能云';
    if (/jdcloud|京东/i.test(combined)) return '京东云';
    if (String(countryCode || '').toUpperCase() === 'CN') {
      const cn = normalizeCNISP(combined);
      if (cn !== combined.trim()) return cn;
    }
    return String(rawISP || rawOrg || '').trim();
  }

  function deduplicateGeoParts(parts) {
    const seen = new Set();
    const out = [];
    for (const raw of parts) {
      const item = String(raw || '').trim();
      if (!item) continue;
      const key = item.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(item);
    }
    return out;
  }

  // ============================================================================
  // 4. 多源数据采集核心 (国内直连 / 落地 IPv4 & IPv6 / 纯净度与风控)
  // ============================================================================

  /**
   * 查询国内直连 IP 与归属地
   * 在模块 [Rule] 中已将以下域名指向 DIRECT，在 Tunnel 内也可显式指定 policy: 'DIRECT'
   */
  async function queryDomesticDirect(inTunnel) {
    const directPolicy = inTunnel ? 'DIRECT' : undefined;

    // 源 1: ipip.net (准确度最高，含省市运营商)
    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://myip.ipip.net/json', directPolicy),
        Math.min(CFG.timeoutMs, 4500)
      );
      if (j && j.data && j.data.ip) {
        const loc = Array.isArray(j.data.location) ? j.data.location : [];
        const geo = deduplicateGeoParts(loc.slice(0, 3)).join(' ');
        const isp = normalizeCNISP(loc[4] || loc[3] || '');
        return {
          ip: j.data.ip,
          countryCode: loc[0] === '中国' ? 'CN' : '',
          location: geo || '中国',
          isp: isp || '',
          source: 'ipip.net',
        };
      }
    } catch (_) {}

    // 源 2: 腾讯新闻 IP 接口
    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://r.inews.qq.com/api/ip2city', directPolicy),
        Math.min(CFG.timeoutMs, 4500)
      );
      if (j && j.ip) {
        const geo = deduplicateGeoParts([j.country, j.province, j.city, j.district]).join(' ');
        return {
          ip: j.ip,
          countryCode: j.country === '中国' ? 'CN' : '',
          location: geo || '',
          isp: normalizeCNISP(j.isp || ''),
          source: 'qq.com',
        };
      }
    } catch (_) {}

    // 源 3: 4.ipw.cn 纯 IP + $utils.geoip 兜底
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://4.ipw.cn', directPolicy),
        Math.min(CFG.timeoutMs, 4000)
      );
      const ip = res.body.trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
        let cc = 'CN';
        try {
          if (typeof $utils !== 'undefined' && $utils.geoip) {
            cc = $utils.geoip(ip) || 'CN';
          }
        } catch (_) {}
        return { ip, countryCode: cc, location: cc === 'CN' ? '中国' : cc, isp: '', source: 'ipw.cn' };
      }
    } catch (_) {}

    return null;
  }

  /**
   * 查询目标节点落地 IPv4 + 地理位置 + ASN + ISP (4 级高可用回退链)
   */
  async function queryLandingIPv4(targetNode) {
    // 源 1: ip-api.com (原生中文地名 + 完整 ASN/ISP/Org + Hosting/Proxy/Mobile 初筛)
    try {
      const j = await fetchJSON(
        buildOutboundOpts('http://ip-api.com/json/?fields=66842623&lang=zh-CN', targetNode),
        CFG.timeoutMs
      );
      if (j && j.status === 'success' && j.query) {
        let asn = '';
        let asnOrg = '';
        if (j.as) {
          const m = String(j.as).match(/^(AS\d+)\s*(.*)$/i);
          if (m) {
            asn = m[1].toUpperCase();
            asnOrg = m[2] || j.asname || '';
          } else {
            asnOrg = j.as;
          }
        }
        return {
          ip: j.query,
          country: j.country || '',
          countryCode: j.countryCode || '',
          region: j.regionName || '',
          city: j.city || '',
          timezone: j.timezone || '',
          isp: j.isp || '',
          org: j.org || asnOrg || '',
          asn: asn,
          mobile: Boolean(j.mobile),
          proxy: Boolean(j.proxy),
          hosting: Boolean(j.hosting),
          source: 'ip-api.com',
        };
      }
    } catch (e) {
      log('ip-api fallback: ' + (e.message || e));
    }

    // 源 2: ip.sb IPv4 GeoIP
    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://api-ipv4.ip.sb/geoip', targetNode),
        CFG.timeoutMs
      );
      if (j && j.ip) {
        return {
          ip: j.ip,
          country: j.country || '',
          countryCode: j.country_code || '',
          region: j.region || '',
          city: j.city || '',
          timezone: j.timezone || '',
          isp: j.isp || j.organization || '',
          org: j.organization || '',
          asn: j.asn ? 'AS' + j.asn : '',
          mobile: false,
          proxy: false,
          hosting: false,
          source: 'ip.sb',
        };
      }
    } catch (e) {
      log('ip.sb fallback: ' + (e.message || e));
    }

    // 源 3: ipwho.is (HTTPS + 中文支持)
    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://ipwho.is/?lang=zh-CN', targetNode),
        CFG.timeoutMs
      );
      if (j && j.success !== false && j.ip) {
        const conn = j.connection || {};
        return {
          ip: j.ip,
          country: j.country || '',
          countryCode: j.country_code || '',
          region: j.region || '',
          city: j.city || '',
          timezone: (j.timezone && j.timezone.id) || '',
          isp: conn.isp || conn.org || '',
          org: conn.org || '',
          asn: conn.asn ? 'AS' + conn.asn : '',
          mobile: false,
          proxy: Boolean(j.security && j.security.proxy),
          hosting: Boolean(j.security && j.security.hosting),
          source: 'ipwho.is',
        };
      }
    } catch (e) {
      log('ipwho.is fallback: ' + (e.message || e));
    }

    // 源 4: ipinfo.io 兜底
    const j = await fetchJSON(
      buildOutboundOpts('https://ipinfo.io/json', targetNode),
      CFG.timeoutMs
    );
    if (j && j.ip) {
      let asn = '';
      let org = j.org || '';
      const m = org.match(/^(AS\d+)\s*(.*)$/i);
      if (m) {
        asn = m[1].toUpperCase();
        org = m[2];
      }
      let cc = j.country || '';
      if (!cc && typeof $utils !== 'undefined' && $utils.geoip) {
        try {
          cc = $utils.geoip(j.ip) || '';
        } catch (_) {}
      }
      return {
        ip: j.ip,
        country: cc,
        countryCode: cc,
        region: j.region || '',
        city: j.city || '',
        timezone: j.timezone || '',
        isp: org,
        org: org,
        asn: asn,
        mobile: false,
        proxy: false,
        hosting: false,
        source: 'ipinfo.io',
      };
    }
    throw new Error('所有落地 IP 查询源均不可达，请检查该节点是否可用');
  }

  /**
   * 查询节点 IPv6 出口支持（快速超时，绝不拖慢主流程）
   */
  async function queryLandingIPv6(targetNode) {
    const v6Timeout = Math.min(CFG.timeoutMs, 3800);
    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://api-ipv6.ip.sb/geoip', targetNode),
        v6Timeout
      );
      if (j && j.ip && j.ip.includes(':')) {
        return {
          ip: j.ip,
          countryCode: j.country_code || '',
          asn: j.asn ? 'AS' + j.asn : '',
          isp: j.isp || j.organization || '',
        };
      }
    } catch (_) {}

    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://6.ipw.cn', targetNode),
        Math.min(v6Timeout, 2800)
      );
      const ip = res.body.trim();
      if (ip.includes(':')) {
        return { ip, countryCode: '', asn: '', isp: '' };
      }
    } catch (_) {}

    return null;
  }

  /**
   * 解析 ipapi.is 数据（融合 xream net-lsp-x 欺诈评分 + ip-whois 网段 + 双 ISP 原生属性判定）
   */
  function parseIPAPIIs(j) {
    if (!j || typeof j !== 'object' || j.error) return null;
    const asnObj = j.asn || {};
    const compObj = j.company || {};
    const locObj = j.location || {};

    const typeMap = {
      isp: '家庭宽带 (ISP)',
      hosting: '机房托管 (Hosting)',
      business: '商业宽带 (Business)',
      education: '教育科研 (Education)',
      government: '政府机构 (Gov)',
      banking: '金融专线 (Banking)',
      inactive: '未激活网段',
    };

    const asnTypeRaw = String(asnObj.type || '').toLowerCase();
    const compTypeRaw = String(compObj.type || '').toLowerCase();
    const asnTypeText = typeMap[asnTypeRaw] || (asnTypeRaw ? asnTypeRaw.toUpperCase() : '未知');
    const compTypeText = typeMap[compTypeRaw] || (compTypeRaw ? compTypeRaw.toUpperCase() : '未知');

    // 双维度原生/家宽分类（业界最看重的双 ISP 判定）
    let lineageLabel = '普通网络';
    let lineageLevel = 'info';
    if (asnTypeRaw === 'isp' && compTypeRaw === 'isp') {
      lineageLabel = '双 ISP 原生家宽';
      lineageLevel = 'excellent';
    } else if (asnTypeRaw === 'isp' || compTypeRaw === 'isp') {
      lineageLabel = '单 ISP 住宅/家宽';
      lineageLevel = 'good';
    } else if (asnTypeRaw === 'business' && compTypeRaw === 'business') {
      lineageLabel = '商业原生专线';
      lineageLevel = 'good';
    } else if (asnTypeRaw === 'hosting' || compTypeRaw === 'hosting' || j.is_datacenter) {
      lineageLabel = 'IDC 机房广播/托管';
      lineageLevel = 'warn';
    }

    // 解析 abuser_score: 例如 "0.0012 (Low)" 或 "0.045 (High)"
    function parseAbuserScore(raw) {
      if (!raw) return null;
      const s = String(raw).trim();
      const m = s.match(/^([0-9.]+)\s*\(([^)]+)\)/);
      const val = m ? parseFloat(m[1]) : NaN;
      const tag = m ? m[2].trim() : s;
      const pct = Number.isFinite(val) ? (val * 100).toFixed(2) + '%' : '';
      const levelMap = {
        'Very Low': { zh: '极低 (纯净)', level: 'excellent' },
        Low: { zh: '低风险 (良好)', level: 'good' },
        Elevated: { zh: '中等偏高', level: 'warn' },
        High: { zh: '高风险', level: 'danger' },
        'Very High': { zh: '极高风险 (脏IP)', level: 'danger' },
      };
      const mapped = levelMap[tag] || { zh: tag, level: 'info' };
      return {
        raw: s,
        ratio: Number.isFinite(val) ? val : null,
        percentText: pct,
        tagEn: tag,
        tagZh: mapped.zh,
        level: mapped.level,
      };
    }

    const compScore = parseAbuserScore(compObj.abuser_score);
    const asnScore = parseAbuserScore(asnObj.abuser_score);
    const primaryScore = compScore || asnScore;

    const flags = {
      datacenter: Boolean(j.is_datacenter),
      vpn: Boolean(j.is_vpn),
      proxy: Boolean(j.is_proxy),
      tor: Boolean(j.is_tor),
      abuser: Boolean(j.is_abuser),
      crawler: Boolean(j.is_crawler),
      mobile: Boolean(j.is_mobile),
      satellite: Boolean(j.is_satellite),
    };

    // 综合 0~100 风险分估算（越低越纯净）
    let riskIndex = 8;
    if (primaryScore && primaryScore.ratio !== null) {
      // ipapi.is ratio 通常在 0 ~ 0.1+ 之间
      riskIndex = Math.min(60, Math.round(primaryScore.ratio * 800));
    }
    if (flags.datacenter || asnTypeRaw === 'hosting' || compTypeRaw === 'hosting') riskIndex += 15;
    if (flags.vpn) riskIndex += 15;
    if (flags.proxy) riskIndex += 20;
    if (flags.abuser) riskIndex += 25;
    if (flags.tor) riskIndex += 35;
    if (flags.crawler) riskIndex += 10;
    if (asnTypeRaw === 'isp' && compTypeRaw === 'isp' && !flags.proxy && !flags.abuser && !flags.vpn) {
      riskIndex = Math.max(0, riskIndex - 6);
    }
    riskIndex = Math.max(0, Math.min(100, riskIndex));

    // 原生广播与归属国一致性检查 (ASN 注册国 vs IP 定位国)
    const asnCountry = String(asnObj.country || '').toUpperCase();
    const locCountry = String(locObj.country_code || '').toUpperCase();
    let broadcastText = '';
    if (asnCountry && locCountry) {
      broadcastText =
        asnCountry === locCountry
          ? '原生归属 (' + locCountry + ')'
          : '广播 IP (注册于 ' + asnCountry + ' → 落地 ' + locCountry + ')';
    }

    return {
      ip: j.ip || '',
      rir: j.rir || '',
      asn: asnObj.asn ? 'AS' + asnObj.asn : '',
      asnOrg: asnObj.org || '',
      asnRoute: asnObj.route || '',
      asnCountry,
      asnTypeRaw,
      asnTypeText,
      companyName: compObj.name || '',
      companyNetwork: compObj.network || '',
      companyTypeRaw: compTypeRaw,
      companyTypeText: compTypeText,
      lineageLabel,
      lineageLevel,
      broadcastText,
      isNativeGeo: Boolean(asnCountry && locCountry && asnCountry === locCountry),
      primaryScore,
      compScore,
      asnScore,
      flags,
      riskIndex,
      countryCode: locCountry,
      city: locObj.city || '',
      state: locObj.state || '',
    };
  }

  async function queryPurityIPAPI(ip, targetNode) {
    let url = 'https://api.ipapi.is/?q=' + encodeURIComponent(ip);
    if (CFG.ipapiKey) {
      url += '&key=' + encodeURIComponent(CFG.ipapiKey);
    }
    const j = await fetchJSON(buildOutboundOpts(url, targetNode), CFG.timeoutMs);
    return parseIPAPIIs(j);
  }

  /**
   * 深度模式下附加查询 ip-score.com 黑名单与多源 Geo 校验（源自 xream ip-score.js）
   */
  async function queryIPScoreExtra(targetNode) {
    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://ip-score.com/fulljson', targetNode, {
          'Content-Type': 'application/x-www-form-urlencoded',
          Origin: 'https://ip-score.com',
          Referer: 'https://ip-score.com/',
        }),
        Math.min(CFG.timeoutMs, 6500),
        'post'
      );
      if (!j || !j.ip) return null;
      const blObj = j.blacklist || {};
      const blKeys = Object.keys(blObj).filter((k) => k !== 'mx');
      let listedCount = 0;
      const listedNames = [];
      blKeys.forEach((k) => {
        const val = String(blObj[k] || '').toLowerCase();
        if (val && val !== 'false' && val !== 'clean' && val !== 'ok' && val !== 'none' && val !== '0') {
          listedCount++;
          listedNames.push(k);
        }
      });
      return {
        ip: j.ip,
        geo1: [j.geoip1 && j.geoip1.country, j.geoip1 && j.geoip1.city].filter(Boolean).join(' '),
        geo2: [j.geoip2 && j.geoip2.country, j.geoip2 && j.geoip2.city].filter(Boolean).join(' '),
        isp: (j.geoip1 && j.geoip1.isp) || (j.isp && j.isp.isp) || '',
        totalBlacklists: blKeys.length,
        listedCount,
        listedNames: listedNames.slice(0, 5),
      };
    } catch (_) {
      return null;
    }
  }

  /**
   * 执行目标节点的完整探测流程（可在 Tunnel 内指定 targetNode 执行，也可在 App 侧回退执行）
   */
  async function executeOutboundProbe(targetNode, deepMode, checkPurity, checkIPv6) {
    const startedAt = Date.now();
    const v4Promise = queryLandingIPv4(targetNode);
    const v6Promise = checkIPv6 ? queryLandingIPv6(targetNode) : Promise.resolve(null);
    const ipScorePromise = deepMode ? queryIPScoreExtra(targetNode) : Promise.resolve(null);

    const landing = await v4Promise;

    // 补充 Clash-Client 内置 GeoIP 库国家代码兜底
    if (!landing.countryCode && typeof $utils !== 'undefined' && $utils.geoip) {
      try {
        const geo = $utils.geoip(landing.ip);
        if (geo) landing.countryCode = geo;
      } catch (_) {}
    }

    let purity = null;
    if (checkPurity || deepMode) {
      try {
        purity = await queryPurityIPAPI(landing.ip, targetNode);
      } catch (e) {
        log('ipapi.is query failed: ' + (e.message || e));
      }
    }

    const [ipv6, ipScore] = await Promise.all([v6Promise, ipScorePromise]);

    return {
      ok: true,
      elapsedMs: Date.now() - startedAt,
      landing,
      ipv6,
      purity,
      ipScore,
    };
  }

  // ============================================================================
  // 5. Clash-Client 双通道节点路由引擎 (Bridge 优先 + $config 自动还原回退)
  // ============================================================================

  /**
   * 启动时自检：若上次因异常中断遗留了未还原的策略状态，立即自动恢复
   */
  function recoverDanglingPolicyIfAny() {
    if (typeof $config === 'undefined' || !$config.setRunningModel) return;
    const savedRaw = storeRead(STATE_RESTORE_KEY);
    if (!savedRaw) return;
    try {
      const saved = JSON.parse(savedRaw);
      if (saved && saved.ts && Date.now() - saved.ts < 120000) {
        if (typeof saved.runningModel === 'number') {
          $config.setRunningModel(saved.runningModel);
        }
        if (saved.globalProxy && $config.setSelectPolicy) {
          $config.setSelectPolicy('GLOBAL', saved.globalProxy);
        }
      }
    } catch (_) {}
    storeWrite(STATE_RESTORE_KEY, '');
  }

  /**
   * 尝试通过 http://net-lsp-x.com/__clash_node_check 调用 Tunnel Extension 桥接器
   */
  async function tryTunnelBridgeProbe(targetNode, deepMode) {
    const qs = [
      'node=' + encodeURIComponent(targetNode),
      'mode=' + encodeURIComponent(deepMode ? 'deep' : 'basic'),
      'purity=' + (CFG.checkPurity || deepMode ? '1' : '0'),
      'ipv6=' + (CFG.checkIPv6 ? '1' : '0'),
    ].join('&');
    const bridgeURL = 'http://' + BRIDGE_HOST + BRIDGE_CHECK_PATH + '?' + qs;
    const bridgeTimeout = Math.min(25000, CFG.timeoutMs * 2 + 4000);

    const res = await httpRequest(
      'get',
      {
        url: bridgeURL,
        headers: { 'X-Clash-Node-Bridge': '1', 'Cache-Control': 'no-cache' },
      },
      bridgeTimeout
    );

    if (res.status !== 200 || !res.body) {
      throw new Error('Bridge not intercepted (HTTP ' + res.status + ')');
    }
    const parsed = JSON.parse(res.body);
    if (!parsed || !parsed.fromClashTunnelBridge) {
      throw new Error('Not a valid bridge payload');
    }
    if (!parsed.ok) {
      throw new Error(parsed.error || '节点探测失败');
    }
    parsed.routeChannel = 'bridge';
    return parsed;
  }

  /**
   * 当未开启模块页顶部开关（HTTPS 解密 / 模块引擎）时，使用 Loon $config 接口回退
   */
  async function fallbackConfigSwitchProbe(targetNode, deepMode) {
    if (typeof $config === 'undefined' || typeof $config.getConfig !== 'function') {
      throw new Error('未检测到模块引擎，且当前格式不支持 $config 回退，请开启模块页顶部的 HTTPS 解密开关');
    }

    const rawCfg = $config.getConfig();
    const cfg = typeof rawCfg === 'string' ? JSON.parse(rawCfg) : rawCfg;
    if (!cfg || cfg.running_model === undefined) {
      throw new Error('Clash 未连接或控制器暂不可用');
    }

    const prevModel = Number(cfg.running_model); // 0: direct, 1: rule, 2: global
    const prevGlobal =
      ($config.getSelectedPolicy && $config.getSelectedPolicy('GLOBAL')) || cfg.global_proxy || '';

    const alreadyOnTarget = prevModel === 2 && prevGlobal === targetNode;
    if (!alreadyOnTarget && !CFG.autoSwitchFallback) {
      return {
        ok: false,
        needsEngineWarning: true,
        error:
          '当前未开启模块页顶部的「HTTPS 解密」引擎，且您在模块设置中关闭了「自动临时切换回退」。为避免把当前代理误判为所选节点，已停止本次查询。',
      };
    }

    let switched = false;
    try {
      if (!alreadyOnTarget) {
        storeWrite(
          STATE_RESTORE_KEY,
          JSON.stringify({ runningModel: prevModel, globalProxy: prevGlobal, ts: Date.now() })
        );
        const selOk = $config.setSelectPolicy('GLOBAL', targetNode);
        const modeOk = $config.setRunningModel(2);
        if (!selOk || !modeOk) {
          storeWrite(STATE_RESTORE_KEY, '');
          throw new Error('无法将 GLOBAL 临时路由至节点「' + targetNode + '」，建议开启模块页 HTTPS 解密开关实现零切换测速');
        }
        switched = true;
        // 留出极短缓冲确保系统网络栈切换至新全局出站
        await new Promise((r) => setTimeout(r, 80));
      }

      const data = await executeOutboundProbe(undefined, deepMode, CFG.checkPurity, CFG.checkIPv6);
      data.routeChannel = alreadyOnTarget ? 'active-global' : 'config-fallback';
      return data;
    } finally {
      if (switched) {
        try {
          $config.setRunningModel(prevModel);
          if (prevGlobal) {
            $config.setSelectPolicy('GLOBAL', prevGlobal);
          }
        } catch (_) {}
        storeWrite(STATE_RESTORE_KEY, '');
      }
    }
  }

  // ============================================================================
  // 5B. 节点中转入口捕获引擎 (配合「外部控制器 -> 本机」实时抓取 remoteDestination)
  // ============================================================================

  function isIPv4Literal(s) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s || '').trim());
  }

  function isIPv6Literal(s) {
    const v = String(s || '').trim();
    return v.includes(':') && /^[0-9a-fA-F:]+$/.test(v);
  }

  function isBogusEntranceIP(ip) {
    const s = String(ip || '').trim().toLowerCase();
    if (!s) return true;
    if (
      s === '0.0.0.0' ||
      s === '::' ||
      s === '::1' ||
      s.startsWith('127.') ||
      s.startsWith('198.18.') ||
      s.startsWith('198.19.') ||
      s === '198.51.100.88'
    ) {
      return true;
    }
    return false;
  }

  function isPrivateLANIP(ip) {
    const s = String(ip || '').trim().toLowerCase();
    if (!s) return false;
    if (s.startsWith('10.') || s.startsWith('192.168.')) return true;
    const m172 = s.match(/^172\.(\d{1,3})\./);
    if (m172 && Number(m172[1]) >= 16 && Number(m172[1]) <= 31) return true;
    const m100 = s.match(/^100\.(\d{1,3})\./);
    if (m100 && Number(m100[1]) >= 64 && Number(m100[1]) <= 127) return true;
    if (s.startsWith('fc') || s.startsWith('fd') || s.startsWith('fe80:')) return true;
    return false;
  }

  function parseHostPort(raw) {
    const s = String(raw || '').trim();
    if (!s) return null;
    let host = '';
    let port = '';

    if (s.startsWith('[')) {
      const closeIdx = s.indexOf(']');
      if (closeIdx > 1) {
        host = s.slice(1, closeIdx);
        const rest = s.slice(closeIdx + 1);
        if (rest.startsWith(':')) port = rest.slice(1);
      } else {
        host = s.replace(/^\[|\]$/g, '');
      }
    } else {
      const firstColon = s.indexOf(':');
      const lastColon = s.lastIndexOf(':');
      if (firstColon > 0 && firstColon === lastColon) {
        host = s.slice(0, firstColon);
        port = s.slice(firstColon + 1);
      } else {
        host = s;
      }
    }

    host = host.trim();
    port = port.trim();
    if (!host) return null;

    const v4 = isIPv4Literal(host);
    const v6 = !v4 && isIPv6Literal(host);
    if ((v4 || v6) && isBogusEntranceIP(host)) return null;
    if (!v4 && !v6 && host.toLowerCase() === BRIDGE_HOST) return null;

    return { host, port, isIPv4: v4, isIPv6: v6 };
  }

  function buildControllerHeaders() {
    const h = { Accept: 'application/json' };
    if (CFG.controllerSecret) {
      h.Authorization = 'Bearer ' + CFG.controllerSecret;
    }
    return h;
  }

  async function resolveDomainToIP(domain) {
    const d = String(domain || '').trim();
    if (!d) return '';

    // 通道 1: Clash-Client Loon 原生 $dns.query (直通 clash.sock 内核 DNS)
    if (typeof $dns !== 'undefined' && $dns && typeof $dns.query === 'function') {
      try {
        const ip = await new Promise((resolve) => {
          let done = false;
          const timer = setTimeout(() => {
            if (!done) {
              done = true;
              resolve('');
            }
          }, 2400);
          try {
            $dns.query({ domain: d, timeout: 2200 }, (err, data) => {
              if (done) return;
              done = true;
              clearTimeout(timer);
              if (err || !data || !Array.isArray(data.answers)) {
                resolve('');
                return;
              }
              for (const ans of data.answers) {
                const val = ans && ans.value ? String(ans.value).trim() : '';
                if ((isIPv4Literal(val) || isIPv6Literal(val)) && !isBogusEntranceIP(val)) {
                  resolve(val);
                  return;
                }
              }
              resolve('');
            });
          } catch (_) {
            if (!done) {
              done = true;
              clearTimeout(timer);
              resolve('');
            }
          }
        });
        if (ip) return ip;
      } catch (_) {}
    }

    // 通道 2: Mihomo 本机外部控制器 /dns/query
    try {
      const url =
        'http://127.0.0.1:' +
        CFG.controllerPort +
        '/dns/query?name=' +
        encodeURIComponent(d) +
        '&type=A';
      const j = await fetchJSON({ url, headers: buildControllerHeaders() }, 1800);
      if (j && Array.isArray(j.Answer)) {
        for (const ans of j.Answer) {
          const val = ans && ans.data ? String(ans.data).trim() : '';
          if ((isIPv4Literal(val) || isIPv6Literal(val)) && !isBogusEntranceIP(val)) {
            return val;
          }
        }
      }
    } catch (_) {}

    // 通道 3: 阿里公共 DoH JSON (纯 IP 直连免递归)
    try {
      const j = await fetchJSON(
        'https://223.5.5.5/resolve?name=' + encodeURIComponent(d) + '&type=1',
        2500
      );
      if (j && Array.isArray(j.Answer)) {
        for (const ans of j.Answer) {
          const val = ans && ans.data ? String(ans.data).trim() : '';
          if (isIPv4Literal(val) && !isBogusEntranceIP(val)) {
            return val;
          }
        }
      }
    } catch (_) {}

    return '';
  }

  /**
   * 显式按指定 IP 查询归属地与运营商（结果与当前请求走哪条出站无关）
   */
  async function queryIPGeoExplicit(ip) {
    const targetIP = String(ip || '').trim();
    if (!targetIP) return null;

    if (isPrivateLANIP(targetIP)) {
      return {
        ip: targetIP,
        country: '局域网 / 专网网关',
        countryCode: '',
        region: '',
        city: '',
        isp: '内网中转入口 (LAN / Tailscale / CGNAT)',
        ispDisplay: '局域网 / 内网网关',
        asn: '',
        isPrivate: true,
      };
    }

    // 源 1: ip-api.com 指定 IP 中文归属地
    try {
      const j = await fetchJSON(
        'http://ip-api.com/json/' + encodeURIComponent(targetIP) + '?fields=66842623&lang=zh-CN',
        4000
      );
      if (j && j.status === 'success') {
        let asn = '';
        let asnOrg = '';
        if (j.as) {
          const m = String(j.as).match(/^(AS\d+)\s*(.*)$/i);
          if (m) {
            asn = m[1].toUpperCase();
            asnOrg = m[2] || j.asname || '';
          }
        }
        const cc = j.countryCode || '';
        const rawISP = j.isp || '';
        const rawOrg = j.org || asnOrg || '';
        return {
          ip: targetIP,
          country: j.country || '',
          countryCode: cc,
          region: j.regionName || '',
          city: j.city || '',
          isp: rawISP,
          org: rawOrg,
          ispDisplay: normalizeEntranceISP(rawISP, rawOrg, cc),
          asn: asn,
          hosting: Boolean(j.hosting),
        };
      }
    } catch (_) {}

    // 源 2: ipwho.is 指定 IP 中文回退
    try {
      const j = await fetchJSON(
        'https://ipwho.is/' + encodeURIComponent(targetIP) + '?lang=zh-CN',
        4000
      );
      if (j && j.success !== false) {
        const conn = j.connection || {};
        const cc = j.country_code || '';
        const rawISP = conn.isp || '';
        const rawOrg = conn.org || '';
        return {
          ip: targetIP,
          country: j.country || '',
          countryCode: cc,
          region: j.region || '',
          city: j.city || '',
          isp: rawISP,
          org: rawOrg,
          ispDisplay: normalizeEntranceISP(rawISP, rawOrg, cc),
          asn: conn.asn ? 'AS' + conn.asn : '',
          hosting: Boolean(j.security && j.security.hosting),
        };
      }
    } catch (_) {}

    return null;
  }

  async function fetchControllerConnectionsSnapshot() {
    const url = 'http://127.0.0.1:' + CFG.controllerPort + '/connections';
    try {
      const res = await httpRequest('get', { url, headers: buildControllerHeaders() }, 1200);
      if (res.status === 401 || res.status === 403) {
        return { status: 'unauthorized', connections: [] };
      }
      if (res.status >= 200 && res.status < 300) {
        const j = JSON.parse(res.body.trim() || '{}');
        return {
          status: 'ok',
          connections: Array.isArray(j.connections) ? j.connections : [],
        };
      }
      return { status: 'unreachable', connections: [] };
    } catch (_) {
      return { status: 'unreachable', connections: [] };
    }
  }

  function findMatchingConnection(connections, nodeName) {
    if (!Array.isArray(connections) || connections.length === 0) return null;
    const probeHostRe = /(ip-api\.com|ip\.sb|ipwho\.is|ipinfo\.io|ipapi\.is|ip-score\.com|ipw\.cn)$/i;

    const sorted = connections.slice().sort((a, b) => {
      const ta = a && a.start ? Date.parse(a.start) || 0 : 0;
      const tb = b && b.start ? Date.parse(b.start) || 0 : 0;
      return tb - ta;
    });

    // 优先：精确匹配 chains 包含目标节点名或 specialProxy === nodeName
    if (nodeName) {
      for (const c of sorted) {
        if (!c || !c.metadata) continue;
        const parsed = parseHostPort(c.metadata.remoteDestination);
        if (!parsed) continue;
        const chains = Array.isArray(c.chains) ? c.chains : [];
        if (chains.includes(nodeName) || c.metadata.specialProxy === nodeName) {
          return { conn: c, parsed };
        }
      }
    }

    // 次选：匹配正在访问探测域名的代理活跃连接（适配模块详情 [Panel] 或策略组嵌套场景）
    for (const c of sorted) {
      if (!c || !c.metadata) continue;
      const host = String(c.metadata.host || '');
      if (!probeHostRe.test(host)) continue;
      const chains = Array.isArray(c.chains) ? c.chains : [];
      if (chains.length === 0 || chains[0] === 'DIRECT' || chains[0] === 'REJECT') continue;
      const parsed = parseHostPort(c.metadata.remoteDestination);
      if (!parsed) continue;
      return { conn: c, parsed };
    }

    return null;
  }

  /**
   * 在节点探测期间并发监听 Mihomo 本机外部控制器 /connections，零额外等待抓取节点真实入口 IP
   */
  async function runProbeWithEntranceCapture(nodeName, probeFn) {
    if (!CFG.showEntrance) {
      const probe = await probeFn();
      return { probe, entrance: null };
    }

    let probeFinished = false;
    let controllerStatus = 'unknown';
    let matchedRecord = null;
    let earlyDetailPromise = null;

    async function enrichMatch(match) {
      const { conn, parsed } = match;
      const chains = Array.isArray(conn.chains) ? conn.chains : [];
      const leafNode = chains.length > 0 ? String(chains[0] || '') : '';
      const entranceIP =
        parsed.isIPv4 || parsed.isIPv6 ? parsed.host : await resolveDomainToIP(parsed.host);
      const geo = entranceIP ? await queryIPGeoExplicit(entranceIP).catch(() => null) : null;
      return {
        status: 'ok',
        rawRemoteDst: String(conn.metadata.remoteDestination || ''),
        entranceHost: parsed.host,
        entrancePort: parsed.port,
        entranceIP: entranceIP || '',
        leafNode,
        chains,
        geo,
      };
    }

    async function trySnapshotOnce() {
      if (matchedRecord || controllerStatus === 'unreachable' || controllerStatus === 'unauthorized') {
        return;
      }
      const snap = await fetchControllerConnectionsSnapshot();
      controllerStatus = snap.status;
      if (snap.status !== 'ok') return;
      const found = findMatchingConnection(snap.connections, nodeName);
      if (found) {
        matchedRecord = found;
        earlyDetailPromise = enrichMatch(found);
      }
    }

    const watcherPromise = (async () => {
      await new Promise((r) => setTimeout(r, 180));
      if (probeFinished) return;
      await trySnapshotOnce();
      if (matchedRecord || probeFinished || controllerStatus !== 'ok') return;
      await new Promise((r) => setTimeout(r, 420));
      if (probeFinished) return;
      await trySnapshotOnce();
    })();

    let probe;
    try {
      probe = await probeFn();
    } finally {
      probeFinished = true;
    }

    await watcherPromise.catch(() => {});

    // 若探测快速返回时还未命中心跳采样，紧接一次即时快照（HTTPS Keep-Alive 连接此时仍在表中）
    if (!matchedRecord && (controllerStatus === 'unknown' || controllerStatus === 'ok')) {
      await trySnapshotOnce();
    }

    if (earlyDetailPromise) {
      const entrance = await earlyDetailPromise.catch(() => null);
      return { probe, entrance };
    }

    if (controllerStatus === 'unauthorized') {
      return { probe, entrance: { status: 'unauthorized' } };
    }
    if (controllerStatus === 'unreachable') {
      return { probe, entrance: { status: 'unreachable' } };
    }
    return { probe, entrance: { status: 'not_found' } };
  }

  // ============================================================================
  // 6. HTML 与面板渲染器（严格适配 ClashScriptHTML.swift 标签集与深浅色对比度）
  // ============================================================================

  function levelColor(level) {
    switch (level) {
      case 'excellent':
        return COLORS.success;
      case 'good':
        return COLORS.cyan;
      case 'warn':
        return COLORS.warning;
      case 'danger':
        return COLORS.danger;
      default:
        return COLORS.primary;
    }
  }

  function riskBadge(riskIndex) {
    if (riskIndex <= 15) return { label: '极度纯净 (' + riskIndex + '/100)', color: COLORS.success };
    if (riskIndex <= 35) return { label: '纯净良好 (' + riskIndex + '/100)', color: COLORS.cyan };
    if (riskIndex <= 60) return { label: '轻度风险 (' + riskIndex + '/100)', color: COLORS.warning };
    return { label: '高危预警 (' + riskIndex + '/100)', color: COLORS.danger };
  }

  function suitabilityHint(purity, landing) {
    if (!purity) return null;
    const f = purity.flags;
    if (purity.lineageLevel === 'excellent' && !f.proxy && !f.vpn && !f.abuser && purity.riskIndex <= 25) {
      return { text: '原生双 ISP 住宅 IP，极佳适配流媒体 / TikTok / ChatGPT / Claude', color: COLORS.success };
    }
    if ((purity.lineageLevel === 'good' || purity.isNativeGeo) && purity.riskIndex <= 40 && !f.abuser && !f.tor) {
      return { text: '信誉良好，适合日常 AI 服务（ChatGPT / Claude）及常规流媒体解锁', color: COLORS.cyan };
    }
    if (purity.riskIndex <= 65 && !f.tor) {
      return { text: '机房/共享特征明显，常规网页浏览顺畅，部分严格风控站点可能触发验证码', color: COLORS.warning };
    }
    return { text: '检测到较高滥用/代理标记，易触发 Cloudflare 验证或风控拦截', color: COLORS.danger };
  }

  /**
   * 渲染 Clash-Client 长按节点弹窗 HTML (ClashNodeScriptResultView -> ClashScriptHTML)
   */
  function renderNodeSheetHTML(params) {
    const { nodeName, nodeInfo, domestic, entrance, probe, deepMode } = params;
    const lines = [];

    // 1. 节点核心元数据区块 (Mihomo NodeRow 专属信息)
    lines.push('<b>▍节点状态</b>');
    lines.push('• <b>节点名称</b>：' + colorSpan(nodeName, COLORS.primary, true));
    if (entrance && entrance.leafNode && entrance.leafNode !== nodeName) {
      lines.push('• <b>实际节点</b>：' + colorSpan(entrance.leafNode, COLORS.cyan, true));
    }

    if (nodeInfo && typeof nodeInfo === 'object') {
      const metaParts = [];
      if (nodeInfo.type) metaParts.push(esc(nodeInfo.type));
      if (typeof nodeInfo.udp === 'boolean') {
        metaParts.push(
          nodeInfo.udp
            ? colorSpan('UDP ✓', COLORS.success, true)
            : colorSpan('UDP ✗', COLORS.muted, false)
        );
      }
      const hist = Array.isArray(nodeInfo.history) ? nodeInfo.history : [];
      const lastDelay = hist.length > 0 ? Number(hist[hist.length - 1].delay || 0) : 0;
      if (lastDelay > 0) {
        const dColor = lastDelay < 180 ? COLORS.success : lastDelay < 400 ? COLORS.warning : COLORS.danger;
        metaParts.push(colorSpan(lastDelay + ' ms', dColor, true));
      } else if (nodeInfo.alive === false) {
        metaParts.push(colorSpan('测速超时/离线', COLORS.danger, true));
      }
      if (metaParts.length > 0) {
        lines.push('• <b>协议特性</b>：' + metaParts.join('  |  '));
      }
    }

    // 2. 国内直连入口对比
    if (domestic && domestic.ip) {
      lines.push('');
      lines.push('<b>▍直连入口（本地网络）</b>');
      lines.push(
        '• <b>直连 IP</b>：<code>' + esc(maskIPString(domestic.ip, CFG.maskIP)) + '</code>'
      );
      const domGeo = [
        domestic.countryCode ? getFlagEmoji(domestic.countryCode) : '🇨🇳',
        domestic.location,
        domestic.isp,
      ]
        .filter(Boolean)
        .join(' ');
      if (domGeo) {
        lines.push('• <b>本地归属</b>：' + esc(domGeo));
      }
    }

    // 2B. 节点中转入口（配合「外部控制器 -> 本机」自动抓取）
    const landing = probe.landing;
    const purity = probe.purity;
    if (CFG.showEntrance && entrance) {
      if (entrance.status === 'ok' && (entrance.entranceIP || entrance.entranceHost)) {
        lines.push('');
        lines.push('<b>▍节点中转入口</b>');
        const entIP = entrance.entranceIP || '';
        const entHost = entrance.entranceHost || '';
        const isDomainHost = entHost && entHost !== entIP;
        const isDirectLine =
          Boolean(entIP) &&
          (entIP === landing.ip || Boolean(probe.ipv6 && probe.ipv6.ip && entIP === probe.ipv6.ip));

        if (entIP) {
          const portSuffix = !CFG.maskIP && entrance.entrancePort ? ':' + entrance.entrancePort : '';
          lines.push(
            '• <b>入口 IP</b>：<code>' +
              esc(maskIPString(entIP, CFG.maskIP) + portSuffix) +
              '</code>'
          );
        }
        if (isDomainHost) {
          const hostPortSuffix =
            !CFG.maskIP && !entIP && entrance.entrancePort ? ':' + entrance.entrancePort : '';
          lines.push(
            '• <b>入口域名</b>：<code>' +
              esc(maskDomainString(entHost, CFG.maskIP) + hostPortSuffix) +
              '</code>'
          );
        }

        lines.push(
          '• <b>链路类型</b>：' +
            (isDirectLine
              ? colorSpan('直连线路（入口即落地，未经过中转）', COLORS.cyan, true)
              : colorSpan('中转 / 专线加速（入口与落地分离）', COLORS.purple, true))
        );

        if (!isDirectLine && entrance.geo) {
          const eg = entrance.geo;
          const eFlag = eg.isPrivate
            ? '🏠'
            : getFlagEmoji(eg.countryCode || '');
          const eGeoText = deduplicateGeoParts([eg.country, eg.region, eg.city]).join(' ');
          if (eGeoText) {
            lines.push(
              '• <b>入口归属</b>：' +
                eFlag +
                ' ' +
                esc(eGeoText) +
                (eg.countryCode ? ' <code>[' + esc(eg.countryCode.toUpperCase()) + ']</code>' : '')
            );
          }
          const eISP = eg.ispDisplay || eg.isp || eg.org || '';
          if (eISP || eg.asn) {
            lines.push(
              '• <b>入口运营商</b>：' +
                (eg.asn ? '<code>' + esc(eg.asn) + '</code> ' : '') +
                esc(eISP || '未知')
            );
          }
        }
      } else if (entrance.status === 'unauthorized') {
        lines.push('');
        lines.push('<b>▍节点中转入口</b>');
        lines.push(
          '• <b>待填密钥</b>：' +
            colorSpan(
              '已检测到本机外部控制器，前往「设置 -> 客户端设置 -> 外部控制器」复制密钥并填入本模块「设置」即可显示中转入口',
              COLORS.warning,
              false
            )
        );
      } else if (entrance.status === 'unreachable') {
        lines.push('');
        lines.push('<b>▍节点中转入口</b>');
        lines.push(
          '• <b>开启方式</b>：<span style="color:' +
            COLORS.muted +
            '">前往「设置 -> 客户端设置 -> 外部控制器」选「本机」并把密钥填入模块设置，即可检测节点真实中转入口</span>'
        );
      }
    }

    // 3. 目标节点落地网络详情
    const flag = getFlagEmoji(landing.countryCode || (purity && purity.countryCode) || '');
    const geoText = deduplicateGeoParts([landing.country, landing.region, landing.city]).join(' ');

    lines.push('');
    lines.push('<b>▍节点落地出口</b>');
    lines.push(
      '• <b>落地 IPv4</b>：<code>' + esc(maskIPString(landing.ip, CFG.maskIP)) + '</code>'
    );
    if (probe.ipv6 && probe.ipv6.ip) {
      lines.push(
        '• <b>落地 IPv6</b>：<code>' + esc(maskIPString(probe.ipv6.ip, CFG.maskIP)) + '</code> ' +
          colorSpan('[支持 IPv6]', COLORS.success, true)
      );
    } else if (CFG.checkIPv6) {
      lines.push('• <b>落地 IPv6</b>：' + colorSpan('未启用 / 仅 IPv4', COLORS.muted, false));
    }

    lines.push(
      '• <b>落地位置</b>：' +
        flag +
        ' ' +
        esc(geoText || landing.countryCode || '未知') +
        (landing.countryCode ? ' <code>[' + esc(landing.countryCode.toUpperCase()) + ']</code>' : '')
    );

    const asnCode = (purity && purity.asn) || landing.asn || '';
    const ispName = landing.isp || (purity && purity.companyName) || landing.org || '未知';
    lines.push(
      '• <b>运营商/ASN</b>：' +
        (asnCode ? '<code>' + esc(asnCode) + '</code> ' : '') +
        esc(ispName)
    );
    if (landing.org && landing.org !== ispName) {
      lines.push('• <b>所属机构</b>：' + esc(landing.org));
    }
    if (landing.timezone) {
      lines.push('• <b>落地时区</b>：<code>' + esc(landing.timezone) + '</code>');
    }

    // 4. IP 纯净度、原生属性与风控评估
    if (purity) {
      lines.push('');
      lines.push('<b>▍IP 属性与纯净度评估</b>');
      lines.push(
        '• <b>线路属性</b>：' +
          colorSpan(purity.lineageLabel, levelColor(purity.lineageLevel), true)
      );
      lines.push(
        '• <b>双重类型</b>：ASN <code>' +
          esc(purity.asnTypeText) +
          '</code> ｜ 运营商 <code>' +
          esc(purity.companyTypeText) +
          '</code>'
      );
      if (purity.broadcastText) {
        lines.push(
          '• <b>广播归属</b>：' +
            colorSpan(
              purity.broadcastText,
              purity.isNativeGeo ? COLORS.success : COLORS.warning,
              purity.isNativeGeo
            )
        );
      }

      const rBadge = riskBadge(purity.riskIndex);
      lines.push('• <b>综合纯净度</b>：' + colorSpan(rBadge.label, rBadge.color, true));

      if (purity.primaryScore) {
        const sc = purity.primaryScore;
        const scoreDisp =
          sc.tagZh + (sc.percentText ? ' (' + sc.percentText + ')' : '');
        lines.push(
          '• <b>滥用评分</b>：' + colorSpan(scoreDisp, levelColor(sc.level), true)
        );
      }

      // 风险因子标签组
      const f = purity.flags;
      const hitTags = [];
      if (f.datacenter) hitTags.push(colorSpan('IDC机房', COLORS.warning, true));
      if (f.vpn) hitTags.push(colorSpan('VPN特征', COLORS.warning, true));
      if (f.proxy) hitTags.push(colorSpan('公开代理', COLORS.danger, true));
      if (f.abuser) hitTags.push(colorSpan('历史滥用', COLORS.danger, true));
      if (f.tor) hitTags.push(colorSpan('Tor节点', COLORS.danger, true));
      if (f.crawler) hitTags.push(colorSpan('爬虫标记', COLORS.warning, true));
      if (f.mobile) hitTags.push(colorSpan('蜂窝移动网', COLORS.success, true));

      lines.push(
        '• <b>风险画像</b>：' +
          (hitTags.length > 0
            ? hitTags.join(' · ')
            : colorSpan('无任何代理/VPN/滥用黑名单标记 ✓', COLORS.success, true))
      );

      if (deepMode) {
        if (purity.companyNetwork || purity.asnRoute) {
          lines.push(
            '• <b>WHOIS 网段</b>：<code>' +
              esc(purity.companyNetwork || purity.asnRoute) +
              '</code>' +
              (purity.rir ? ' (' + esc(purity.rir) + ')' : '')
          );
        }
        if (probe.ipScore) {
          const sc = probe.ipScore;
          const blClean = sc.listedCount === 0;
          const blText = blClean
            ? '0 / ' + sc.totalBlacklists + ' 命中（全部通过 ✓）'
            : sc.listedCount +
              ' / ' +
              sc.totalBlacklists +
              ' 命中 (' +
              sc.listedNames.join(', ') +
              ')';
          lines.push(
            '• <b>黑名单库</b>：' +
              colorSpan(blText, blClean ? COLORS.success : COLORS.danger, true)
          );
          if (sc.geo1 || sc.geo2) {
            lines.push(
              '• <b>多库定位</b>：GeoIP1 <code>' +
                esc(sc.geo1 || '-') +
                '</code> ｜ GeoIP2 <code>' +
                esc(sc.geo2 || '-') +
                '</code>'
            );
          }
        }
      }

      const hint = suitabilityHint(purity, landing);
      if (hint) {
        lines.push('• <b>场景建议</b>：' + colorSpan(hint.text, hint.color, false));
      }
    } else if (CFG.checkPurity || deepMode) {
      lines.push('');
      lines.push('<b>▍IP 属性与纯净度评估</b>');
      const fallbackType = landing.hosting
        ? colorSpan('IDC 机房 / Hosting', COLORS.warning, true)
        : landing.mobile
          ? colorSpan('移动蜂窝网络', COLORS.success, true)
          : colorSpan('常规 ISP / 未知类型', COLORS.primary, false);
      lines.push('• <b>基础识别</b>：' + fallbackType + '（纯净度风控接口响应超时，已展示基础数据）');
    }

    // 5. 底部通道状态说明
    lines.push('');
    const channelNote =
      probe.routeChannel === 'bridge'
        ? '⚡ 零切换直测通道 (Tunnel Outbound) · 耗时 ' + probe.elapsedMs + ' ms'
        : probe.routeChannel === 'active-global'
          ? '⚡ 当前全局节点直测 · 耗时 ' + probe.elapsedMs + ' ms'
          : '🔄 $config 策略临时回退直测（已原样还原）· 耗时 ' +
            probe.elapsedMs +
            ' ms（开启模块页 HTTPS 解密可享零切换）';
    lines.push('<span style="color:' + COLORS.muted + '">' + esc(channelNote) + '</span>');

    return lines.join('<br>');
  }

  // ============================================================================
  // 7. Safari 网页端 / JSON 接口处理 (http-request 拦截 net-lsp-x.com)
  // ============================================================================

  function parseQueryFromURL(rawURL) {
    const q = {};
    const idx = String(rawURL || '').indexOf('?');
    if (idx < 0) return q;
    const search = String(rawURL).slice(idx + 1).split('#')[0];
    search.split('&').forEach((kv) => {
      if (!kv) return;
      const eq = kv.indexOf('=');
      if (eq < 0) {
        q[decodeURIComponent(kv)] = '1';
      } else {
        try {
          q[decodeURIComponent(kv.slice(0, eq))] = decodeURIComponent(kv.slice(eq + 1));
        } catch (_) {
          q[kv.slice(0, eq)] = kv.slice(eq + 1);
        }
      }
    });
    return q;
  }

  function renderWebPortalHTML(domestic, probe, targetNode) {
    const landing = probe.landing;
    const purity = probe.purity;
    const flag = getFlagEmoji(landing.countryCode || '');
    const geo = deduplicateGeoParts([landing.country, landing.region, landing.city]).join(' ');
    const badge = purity ? riskBadge(purity.riskIndex) : null;
    const hint = purity ? suitabilityHint(purity, landing) : null;

    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>节点网络信息诊断 · Clash-Client</title>
<style>
  :root {
    --bg: #f4f6fb; --card: #ffffff; --text: #111827; --sub: #6b7280; --border: #e5e7eb; --accent: #3b82f6;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0b0f19; --card: #151b2b; --text: #f3f4f6; --sub: #9ca3af; --border: #263047; --accent: #60a5fa;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 20px 16px 40px; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", sans-serif;
    line-height: 1.55;
  }
  .wrap { max-width: 560px; margin: 0 auto; }
  .hero { margin-bottom: 16px; }
  .hero h1 { font-size: 20px; margin: 0 0 4px; display: flex; align-items: center; gap: 8px; }
  .hero p { margin: 0; font-size: 13px; color: var(--sub); }
  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: 16px;
    padding: 16px 18px; margin-bottom: 14px; box-shadow: 0 4px 18px rgba(0,0,0,0.04);
  }
  .card h2 {
    margin: 0 0 12px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--accent);
  }
  .row {
    display: flex; justify-content: space-between; align-items: baseline; gap: 12px;
    padding: 7px 0; border-bottom: 1px dashed var(--border); font-size: 14px;
  }
  .row:last-child { border-bottom: none; }
  .k { color: var(--sub); flex-shrink: 0; }
  .v { font-weight: 600; text-align: right; word-break: break-all; }
  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    background: rgba(59,130,246,0.1); padding: 2px 6px; border-radius: 6px; font-size: 13px;
  }
  .foot { text-align: center; font-size: 12px; color: var(--sub); margin-top: 16px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>🌐 网络与节点出口诊断</h1>
    <p>${esc(targetNode ? '指定探测节点：' + targetNode : '当前活跃代理出口实时检测')} · 耗时 ${probe.elapsedMs} ms</p>
  </div>
  ${
    domestic && domestic.ip
      ? `<div class="card">
    <h2>🇨🇳 本地直连入口</h2>
    <div class="row"><span class="k">直连 IP</span><span class="v"><code>${esc(maskIPString(domestic.ip, CFG.maskIP))}</code></span></div>
    <div class="row"><span class="k">归属与运营商</span><span class="v">${esc([domestic.location, domestic.isp].filter(Boolean).join(' '))}</span></div>
  </div>`
      : ''
  }
  <div class="card">
    <h2>${flag} 代理落地出口</h2>
    <div class="row"><span class="k">落地 IPv4</span><span class="v"><code>${esc(maskIPString(landing.ip, CFG.maskIP))}</code></span></div>
    <div class="row"><span class="k">落地 IPv6</span><span class="v">${probe.ipv6 && probe.ipv6.ip ? '<code>' + esc(maskIPString(probe.ipv6.ip, CFG.maskIP)) + '</code>' : '未启用 / 仅 IPv4'}</span></div>
    <div class="row"><span class="k">国家与城市</span><span class="v">${flag} ${esc(geo || landing.countryCode || '-')}</span></div>
    <div class="row"><span class="k">ASN / 运营商</span><span class="v">${esc([landing.asn, landing.isp || landing.org].filter(Boolean).join(' '))}</span></div>
    ${landing.timezone ? `<div class="row"><span class="k">时区</span><span class="v"><code>${esc(landing.timezone)}</code></span></div>` : ''}
  </div>
  ${
    purity
      ? `<div class="card">
    <h2>🛡️ IP 纯净度与原生属性</h2>
    <div class="row"><span class="k">线路属性</span><span class="v" style="color:${levelColor(purity.lineageLevel)}">${esc(purity.lineageLabel)}</span></div>
    <div class="row"><span class="k">ASN / 运营商类型</span><span class="v">${esc(purity.asnTypeText + ' / ' + purity.companyTypeText)}</span></div>
    ${purity.broadcastText ? `<div class="row"><span class="k">原生/广播判定</span><span class="v">${esc(purity.broadcastText)}</span></div>` : ''}
    ${badge ? `<div class="row"><span class="k">综合纯净度</span><span class="v" style="color:${badge.color}">${esc(badge.label)}</span></div>` : ''}
    ${purity.primaryScore ? `<div class="row"><span class="k">ipapi.is 滥用评分</span><span class="v">${esc(purity.primaryScore.raw)}</span></div>` : ''}
    ${hint ? `<div class="row"><span class="k">解锁评估</span><span class="v" style="color:${hint.color}">${esc(hint.text)}</span></div>` : ''}
  </div>`
      : ''
  }
  <div class="foot">xream/scripts Adapted for ProjectClash/Clash-Client · 可在 ?node=节点名 指定任意节点或 ?format=json 输出 JSON</div>
</div>
</body>
</html>`;
  }

  async function handleHTTPRequest() {
    const reqURL = ($request && $request.url) || '';
    const pathMatch = reqURL.match(/^https?:\/\/[^/?#]+([^?#]*)/i);
    const pathname = (pathMatch && pathMatch[1]) || '/';
    const query = parseQueryFromURL(reqURL);

    // A. App 长按节点桥接接口: /__clash_node_check
    if (pathname === BRIDGE_CHECK_PATH) {
      const targetNode = query.node || '';
      const deepMode = query.mode === 'deep';
      const checkPurity = query.purity !== '0';
      const checkIPv6 = query.ipv6 !== '0';

      try {
        const result = await executeOutboundProbe(
          targetNode || undefined,
          deepMode,
          checkPurity,
          checkIPv6
        );
        result.fromClashTunnelBridge = true;
        $done({
          response: {
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Cache-Control': 'no-store',
            },
            body: JSON.stringify(result),
          },
        });
      } catch (e) {
        $done({
          response: {
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Cache-Control': 'no-store',
            },
            body: JSON.stringify({
              ok: false,
              fromClashTunnelBridge: true,
              error: String((e && e.message) || e || 'Unknown error'),
            }),
          },
        });
      }
      return;
    }

    // B. 浏览器访问 http://net-lsp-x.com 网页或 ?format=json
    try {
      const targetNode = query.node || undefined;
      const deepMode = query.mode === 'deep';
      const [domestic, probe] = await Promise.all([
        CFG.showDomestic ? queryDomesticDirect(true) : Promise.resolve(null),
        executeOutboundProbe(targetNode, deepMode, CFG.checkPurity, CFG.checkIPv6),
      ]);

      if (query.format === 'json' || pathname === '/json' || pathname === '/api') {
        $done({
          response: {
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Access-Control-Allow-Origin': '*',
            },
            body: JSON.stringify({ ok: true, targetNode: targetNode || null, domestic, probe }, null, 2),
          },
        });
        return;
      }

      $done({
        response: {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
          body: renderWebPortalHTML(domestic, probe, targetNode),
        },
      });
    } catch (e) {
      $done({
        response: {
          status: 500,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          body: '网络诊断失败: ' + String((e && e.message) || e),
        },
      });
    }
  }

  // ============================================================================
  // 8. App 侧执行入口：长按节点弹窗 / 模块详情 [Panel] / 网络变化通知
  // ============================================================================

  async function handleNodeLongPress(nodeName, nodeInfo) {
    recoverDanglingPolicyIfAny();
    const deepMode = CFG.mode === 'deep';
    const sheetTitle = deepMode ? '节点纯净度深度检测' : '节点网络信息查询';

    // 先并发查国内直连（此时一定在用户原规则模式下，[Rule] DIRECT 生效）
    const domesticPromise = CFG.showDomestic
      ? queryDomesticDirect(false).catch(() => null)
      : Promise.resolve(null);

    let probe;
    let entrance = null;
    try {
      const res = await runProbeWithEntranceCapture(nodeName, () =>
        tryTunnelBridgeProbe(nodeName, deepMode)
      );
      probe = res.probe;
      entrance = res.entrance;
    } catch (bridgeErr) {
      log('Tunnel bridge unavailable (' + (bridgeErr.message || bridgeErr) + '), trying $config fallback...');
      // 等待直连查询完成后再切换 GLOBAL 模式，防止切换期间把国内直连查询带入全局代理
      const domesticBeforeSwitch = await domesticPromise;
      try {
        const res = await runProbeWithEntranceCapture(nodeName, () =>
          fallbackConfigSwitchProbe(nodeName, deepMode)
        );
        probe = res.probe;
        entrance = res.entrance;
      } catch (fallbackErr) {
        $done({
          title: sheetTitle,
          htmlMessage:
            '<b>▍节点查询失败</b><br>' +
            '• <b>目标节点</b>：' +
            colorSpan(nodeName, COLORS.primary, true) +
            '<br>• <b>原因说明</b>：' +
            colorSpan(String(fallbackErr.message || fallbackErr), COLORS.danger, false) +
            '<br><br><span style="color:' +
            COLORS.muted +
            '">💡 提示：建议在「模块」页面顶部开启「HTTPS 解密」开关（无需信任证书即可通过 HTTP 桥接实现零切换秒查任意节点）。</span>',
        });
        return;
      }

      if (probe && probe.needsEngineWarning) {
        $done({
          title: sheetTitle,
          htmlMessage:
            '<b>▍需要开启模块引擎或自动回退</b><br><br>' +
            colorSpan(probe.error, COLORS.warning, false) +
            '<br><br><b>可选解决方案（二选一）：</b><br>' +
            '1. <b>推荐</b>：前往「模块」页顶部开启 <b>HTTPS 解密</b>（走零打扰直测通道，无需切换全局策略）。<br>' +
            '2. 在本模块详情页「设置」中开启 <b>未开引擎时自动临时切换测速</b>。',
        });
        return;
      }

      const html = renderNodeSheetHTML({
        nodeName,
        nodeInfo,
        domestic: domesticBeforeSwitch,
        entrance,
        probe,
        deepMode,
      });
      $done({ title: sheetTitle, htmlMessage: html });
      return;
    }

    const domestic = await domesticPromise;
    const html = renderNodeSheetHTML({
      nodeName,
      nodeInfo,
      domestic,
      entrance,
      probe,
      deepMode,
    });
    $done({ title: sheetTitle, htmlMessage: html });
  }

  async function handleModulePanel() {
    recoverDanglingPolicyIfAny();
    try {
      let modeInfo = '';
      if (typeof $config !== 'undefined' && $config.getConfig) {
        try {
          const raw = $config.getConfig();
          const c = typeof raw === 'string' ? JSON.parse(raw) : raw;
          if (c) {
            const mName = { 0: '全局直连', 1: '规则分流', 2: '全局代理' }[c.running_model] || '连接中';
            const pol = c.running_model === 2 ? c.global_proxy : c.final;
            modeInfo = mName + (pol ? ' · 默认策略 ' + pol : '');
          }
        } catch (_) {}
      }

      const [domestic, probeWrap] = await Promise.all([
        CFG.showDomestic ? queryDomesticDirect(false).catch(() => null) : Promise.resolve(null),
        runProbeWithEntranceCapture('', () =>
          executeOutboundProbe(undefined, false, CFG.checkPurity, CFG.checkIPv6)
        ),
      ]);
      const probe = probeWrap.probe;
      const entrance = probeWrap.entrance;

      const lines = [];
      if (modeInfo) lines.push('运行模式：' + modeInfo);
      if (domestic && domestic.ip) {
        lines.push(
          '直连入口：' +
            maskIPString(domestic.ip, CFG.maskIP) +
            ' (' +
            [domestic.location, domestic.isp].filter(Boolean).join(' ') +
            ')'
        );
      }

      const l = probe.landing;
      if (entrance && entrance.status === 'ok' && entrance.entranceIP) {
        if (entrance.entranceIP === l.ip) {
          lines.push('中转入口：直连线路（入口即落地）');
        } else {
          const eg = entrance.geo;
          const eDesc = eg
            ? [
                deduplicateGeoParts([eg.country, eg.region, eg.city]).join(' '),
                eg.ispDisplay || eg.isp || eg.org,
              ]
                .filter(Boolean)
                .join(' ')
            : '';
          lines.push(
            '中转入口：' +
              maskIPString(entrance.entranceIP, CFG.maskIP) +
              (eDesc ? ' (' + eDesc + ')' : '')
          );
        }
      }
      const flag = getFlagEmoji(l.countryCode);
      const geo = deduplicateGeoParts([l.country, l.region, l.city]).join(' ');
      lines.push(
        '代理落地：' +
          maskIPString(l.ip, CFG.maskIP) +
          ' (' +
          flag +
          ' ' +
          (geo || l.countryCode || '-') +
          ')'
      );
      lines.push('运营商/ASN：' + [l.asn, l.isp || l.org].filter(Boolean).join(' '));

      if (probe.ipv6 && probe.ipv6.ip) {
        lines.push('IPv6 出口：' + maskIPString(probe.ipv6.ip, CFG.maskIP));
      }
      if (probe.purity) {
        const p = probe.purity;
        const badge = riskBadge(p.riskIndex);
        lines.push('纯净属性：' + p.lineageLabel + ' ｜ ' + badge.label);
      }

      const iconColor =
        probe.purity && probe.purity.riskIndex > 55
          ? '#EF4444'
          : probe.purity && probe.purity.riskIndex > 30
            ? '#F59E0B'
            : '#10B981';

      $done({
        title: '当前网络出口信息',
        content: lines.join('\n'),
        icon: 'globe.asia.australia',
        'icon-color': iconColor,
      });
    } catch (e) {
      $done({
        title: '当前网络出口信息',
        content: '查询失败：' + String((e && e.message) || e),
        icon: 'exclamationmark.triangle',
        'icon-color': '#EF4444',
      });
    }
  }

  async function handleNetworkChanged() {
    if (!CFG.notifyOnChange) {
      $done({});
      return;
    }
    try {
      const [domestic, landing] = await Promise.all([
        CFG.showDomestic ? queryDomesticDirect(false).catch(() => null) : Promise.resolve(null),
        queryLandingIPv4(undefined),
      ]);
      const fingerprint = [(domestic && domestic.ip) || '', landing.ip || '', landing.countryCode || ''].join('|');
      const prev = storeRead(LAST_EVENT_KEY);
      if (fingerprint && fingerprint !== prev) {
        storeWrite(LAST_EVENT_KEY, fingerprint);
        const flag = getFlagEmoji(landing.countryCode);
        const geo = deduplicateGeoParts([landing.country, landing.city]).join(' ');
        const sub = flag + ' 落地：' + maskIPString(landing.ip, CFG.maskIP) + ' (' + geo + ')';
        const body =
          (domestic && domestic.ip
            ? '🇨🇳 直连：' +
              maskIPString(domestic.ip, CFG.maskIP) +
              ' ' +
              [domestic.location, domestic.isp].filter(Boolean).join(' ') +
              '\n'
            : '') +
          '🏢 运营商：' +
          [landing.asn, landing.isp || landing.org].filter(Boolean).join(' ');
        notify('🌐 网络环境已切换', sub, body);
      }
    } catch (e) {
      log('network-changed check error: ' + (e.message || e));
    }
    $done({});
  }

  // ============================================================================
  // 9. 顶层分发路由
  // ============================================================================

  (async function main() {
    try {
      if (typeof $request !== 'undefined' && $request && $request.url) {
        await handleHTTPRequest();
        return;
      }

      const env = typeof $environment !== 'undefined' && $environment ? $environment : {};
      const params = env.params && typeof env.params === 'object' ? env.params : {};
      const nodeName = params.node ? String(params.node).trim() : '';

      if (nodeName) {
        await handleNodeLongPress(nodeName, params.nodeInfo || null);
        return;
      }

      if (CFG.mode === 'event') {
        await handleNetworkChanged();
        return;
      }

      await handleModulePanel();
    } catch (err) {
      log('Fatal script error: ' + ((err && err.stack) || err));
      $done({
        title: '节点信息查询异常',
        content: String((err && err.message) || err),
        htmlMessage: colorSpan('执行异常：' + String((err && err.message) || err), COLORS.danger, true),
      });
    }
  })();
})();
