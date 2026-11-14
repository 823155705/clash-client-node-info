/**
 * xream & Kelee Node Suite — ProjectClash/Clash-Client 全能节点检测套件 (v2.0.0)
 *
 * 深度融合：
 * 1. xream/scripts (ip-info / net-lsp-x / ip-whois / ip-score)
 * 2. 可莉插件仓库 (Node_detection_tool 流媒体&AI解锁 / WARP_Node_Query / NodeLinkCheck 代理链路)
 *
 * 专为 ProjectClash/Clash-Client (iOS / macOS) 三大独立长按菜单设计（零重叠、秒开排版）：
 * - 🌐 节点链路与入口查询 (MODE=info)  : 本地直连 ➔ 中转入口 ➔ 落地双栈 ➔ Cloudflare 边缘 POP & WARP 识别
 * - 🛡️ 节点纯净度深度检测 (MODE=purity): 双 ISP 原生家宽血统 + 广播/原生判定 + 三源风控/RBL 黑名单交叉审计
 * - 🎬 流媒体与 AI 解锁检测 (MODE=unlock): ChatGPT(Web+iOS) / Claude / Gemini / Netflix / YouTube / Disney+ / TikTok / 动画疯
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

  const CF_COLO_MAP = {
    HKG: '香港', TPE: '台北', KHH: '高雄', MFM: '澳门',
    NRT: '东京成田', HND: '东京羽田', KIX: '大阪', FUK: '福冈', OKA: '冲绳', NGO: '名古屋',
    ICN: '首尔', PUS: '釜山',
    SIN: '新加坡', KUL: '吉隆坡', BKK: '曼谷', SGN: '胡志明', HAN: '河内', MNL: '马尼拉', CGK: '雅加达', PNH: '金边',
    DEL: '新德里', BOM: '孟买', MAA: '金奈', DXB: '迪拜', DOH: '多哈', TLV: '特拉维夫', IST: '伊斯坦布尔',
    LAX: '洛杉矶', SJC: '圣何塞', SFO: '旧金山', SEA: '西雅图', PDX: '波特兰', SAN: '圣迭戈', PHX: '凤凰城',
    SLC: '盐湖城', DEN: '丹佛', DFW: '达拉斯', IAH: '休斯顿', ORD: '芝加哥', MSP: '明尼阿波利斯',
    IAD: '弗吉尼亚', EWR: '纽瓦克', JFK: '纽约', BOS: '波士顿', ATL: '亚特兰大', MIA: '迈阿密',
    YYZ: '多伦多', YVR: '温哥华', YUL: '蒙特利尔',
    LHR: '伦敦', MAN: '曼彻斯特', AMS: '阿姆斯特丹', FRA: '法兰克福', DUS: '杜塞尔多夫', MUC: '慕尼黑',
    CDG: '巴黎', MRS: '马赛', ZRH: '苏黎世', VIE: '维也纳', MXP: '米兰', FCO: '罗马', MAD: '马德里',
    WAW: '华沙', PRG: '布拉格', BUD: '布达佩斯', ARN: '斯德哥尔摩', HEL: '赫尔辛基', OSL: '奥斯陆', CPH: '哥本哈根',
    DME: '莫斯科', LED: '圣彼得堡',
    SYD: '悉尼', MEL: '墨尔本', BNE: '布里斯班', PER: '珀斯', AKL: '奥克兰',
    GRU: '圣保罗', EZE: '布宜诺斯艾利斯', SCL: '圣地亚哥', MEX: '墨西哥城', JNB: '约翰内斯堡',
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

  function normalizeMode(raw) {
    const m = String(raw || 'info').trim().toLowerCase();
    if (m === 'basic' || m === 'info') return 'info';
    if (m === 'deep' || m === 'purity') return 'purity';
    if (m === 'unlock' || m === 'media') return 'unlock';
    if (m === 'bridge' || m === 'event' || m === 'panel') return m;
    return 'info';
  }

  const ARGS = parseArguments(typeof $argument !== 'undefined' ? $argument : '');
  const CFG = {
    mode: normalizeMode(ARGS.MODE),
    showDomestic: toBool(ARGS.SHOW_DOMESTIC, true),
    showEntrance: toBool(ARGS.SHOW_ENTRANCE, true),
    controllerPort: parseControllerPort(ARGS.CONTROLLER_PORT, 9090),
    controllerSecret: normalizeSecret(ARGS.CONTROLLER_SECRET),
    checkIPv6: toBool(ARGS.CHECK_IPV6, true),
    maskIP: toBool(ARGS.MASK_IP, false),
    autoSwitchFallback: toBool(ARGS.AUTO_SWITCH_FALLBACK, true),
    notifyOnChange: toBool(ARGS.NOTIFY_ON_CHANGE, false),
    ipapiKey: String(ARGS.IPAPI_KEY || '').trim(),
    timeoutMs: Math.round(toNum(ARGS.TIMEOUT_SEC, 8, 3, 25) * 1000),
  };

  function log(msg) {
    try {
      console.log('[clash-suite] ' + msg);
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
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        Accept: 'application/json, text/html, text/plain, */*',
      },
      reqOpts.headers || {}
    );
    // Clash-Client Loon 运行时 ($loon 存在) 下 timeout 单位为毫秒，Surge/Stash 为秒
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
  // 3. 格式化辅助函数
  // ============================================================================

  function getFlagEmoji(countryCode) {
    if (!countryCode || typeof countryCode !== 'string') return '🌐';
    const cc = countryCode.trim().toUpperCase();
    if (cc === 'TW') return '🇹🇼';
    if (cc.length !== 2 || !/^[A-Z]{2}$/.test(cc)) return '🌐';
    return String.fromCodePoint(cc.charCodeAt(0) + 127397, cc.charCodeAt(1) + 127397);
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

  function maskDomainString(domain, enabled) {
    if (!domain || !enabled) return domain || '-';
    const parts = String(domain).trim().split('.');
    if (parts.length <= 1) return '***';
    return '***.***.' + parts[parts.length - 1];
  }

  function esc(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function colorSpan(text, hex, bold) {
    const weight = bold ? ';font-weight:bold' : '';
    return '<span style="color:' + hex + weight + '">' + esc(text) + '</span>';
  }

  function normalizeCNISP(raw) {
    const s = String(raw || '');
    if (/电信|telecom|chinanet|ctcc/i.test(s)) return '电信';
    if (/联通|unicom|cucc/i.test(s)) return '联通';
    if (/移动|mobile|cmcc|铁通/i.test(s)) return '移动';
    if (/广电|CBN|cable/i.test(s)) return '广电';
    if (/教育|cernet/i.test(s)) return '教育网';
    return s.trim();
  }

  function normalizeEntranceISP(rawISP, rawOrg, countryCode) {
    const combined = [rawISP, rawOrg].filter(Boolean).join(' ');
    if (/aliyun|alibaba|阿里云|万网/i.test(combined)) return '阿里云 BGP';
    if (/tencent|qcloud|腾讯云/i.test(combined)) return '腾讯云 BGP';
    if (/huawei|华为云/i.test(combined)) return '华为云 BGP';
    if (/ucloud|优刻得/i.test(combined)) return 'UCloud BGP';
    if (/volcengine|bytedance|火山引擎/i.test(combined)) return '火山引擎 BGP';
    if (/baidu|百度/i.test(combined)) return '百度云';
    if (/jdcloud|京东/i.test(combined)) return '京东云';
    if (String(countryCode || '').toUpperCase() === 'CN') {
      const cn = normalizeCNISP(combined);
      if (cn !== combined.trim()) return '中国' + cn;
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

  function scoreBar(cleanPercent) {
    const p = Math.max(0, Math.min(100, Math.round(cleanPercent)));
    const filled = Math.round(p / 10);
    return '▰'.repeat(filled) + '▱'.repeat(10 - filled);
  }

  // ============================================================================
  // 4. 基础链路与 Cloudflare WARP 探测 (MODE=info 核心)
  // ============================================================================

  async function queryDomesticDirect(inTunnel) {
    const directPolicy = inTunnel ? 'DIRECT' : undefined;

    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://myip.ipip.net/json', directPolicy),
        Math.min(CFG.timeoutMs, 4200)
      );
      if (j && j.data && j.data.ip) {
        const loc = Array.isArray(j.data.location) ? j.data.location : [];
        const geo = deduplicateGeoParts(loc.slice(1, 3)).join('');
        const isp = normalizeCNISP(loc[4] || loc[3] || '');
        return {
          ip: j.data.ip,
          countryCode: loc[0] === '中国' ? 'CN' : '',
          location: geo || loc[0] || '中国',
          isp: isp ? '中国' + isp.replace(/^中国/, '') : '',
          shortTag: (geo || '本地') + (isp || ''),
        };
      }
    } catch (_) {}

    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://r.inews.qq.com/api/ip2city', directPolicy),
        Math.min(CFG.timeoutMs, 4000)
      );
      if (j && j.ip) {
        const geo = deduplicateGeoParts([j.province, j.city]).join('');
        const isp = normalizeCNISP(j.isp || '');
        return {
          ip: j.ip,
          countryCode: j.country === '中国' ? 'CN' : '',
          location: geo || j.country || '中国',
          isp: isp ? '中国' + isp.replace(/^中国/, '') : '',
          shortTag: (geo || '本地') + (isp || ''),
        };
      }
    } catch (_) {}

    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://4.ipw.cn', directPolicy),
        Math.min(CFG.timeoutMs, 3500)
      );
      const ip = res.body.trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
        return { ip, countryCode: 'CN', location: '中国', isp: '', shortTag: '本地网络' };
      }
    } catch (_) {}

    return null;
  }

  async function queryLandingIPv4(targetNode) {
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
          asn,
          mobile: Boolean(j.mobile),
          proxy: Boolean(j.proxy),
          hosting: Boolean(j.hosting),
          source: 'ip-api.com',
        };
      }
    } catch (_) {}

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
    } catch (_) {}

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
    } catch (_) {}

    const j = await fetchJSON(buildOutboundOpts('https://ipinfo.io/json', targetNode), CFG.timeoutMs);
    if (j && j.ip) {
      let asn = '';
      let org = j.org || '';
      const m = org.match(/^(AS\d+)\s*(.*)$/i);
      if (m) {
        asn = m[1].toUpperCase();
        org = m[2];
      }
      const cc = j.country || '';
      return {
        ip: j.ip,
        country: cc,
        countryCode: cc,
        region: j.region || '',
        city: j.city || '',
        timezone: j.timezone || '',
        isp: org,
        org,
        asn,
        mobile: false,
        proxy: false,
        hosting: false,
        source: 'ipinfo.io',
      };
    }
    throw new Error('所有落地 IP 接口均无响应，请检查该节点是否连通');
  }

  async function queryLandingIPv6(targetNode) {
    const v6Timeout = Math.min(CFG.timeoutMs, 3400);
    try {
      const j = await fetchJSON(buildOutboundOpts('https://api-ipv6.ip.sb/geoip', targetNode), v6Timeout);
      if (j && j.ip && j.ip.includes(':')) {
        return { ip: j.ip, countryCode: j.country_code || '' };
      }
    } catch (_) {}
    try {
      const res = await httpRequest('get', buildOutboundOpts('https://6.ipw.cn', targetNode), 2500);
      const ip = res.body.trim();
      if (ip.includes(':')) return { ip, countryCode: '' };
    } catch (_) {}
    return null;
  }

  /**
   * 移植自可莉仓库「WARP节点查询」：探测 Cloudflare 边缘机房 POP 与 WARP 出站套壳状态
   */
  async function queryCloudflareTrace(targetNode) {
    const traceTimeout = Math.min(CFG.timeoutMs, 4200);
    const urls = ['https://www.cloudflare.com/cdn-cgi/trace', 'https://1.1.1.1/cdn-cgi/trace'];
    for (const u of urls) {
      try {
        const res = await httpRequest('get', buildOutboundOpts(u, targetNode), traceTimeout);
        if (res.status >= 200 && res.status < 400 && res.body.includes('colo=')) {
          const kv = {};
          res.body.split(/\r?\n/).forEach((line) => {
            const idx = line.indexOf('=');
            if (idx > 0) kv[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
          });
          const colo = (kv.colo || '').toUpperCase();
          const warp = (kv.warp || 'off').toLowerCase();
          return {
            colo,
            coloCity: CF_COLO_MAP[colo] || '',
            warp, // 'off' | 'on' | 'plus'
            http: kv.http || '',
            tls: kv.tls || '',
            loc: (kv.loc || '').toUpperCase(),
            ip: kv.ip || '',
          };
        }
      } catch (_) {}
    }
    return null;
  }

  // ============================================================================
  // 5. 多源 IP 纯净度与黑名单引擎 (MODE=purity 核心)
  // ============================================================================

  function parseAbuserScore(raw) {
    if (!raw) return null;
    const s = String(raw).trim();
    const numMatch = s.match(/([0-9]*\.?[0-9]+)/);
    const val = numMatch ? parseFloat(numMatch[1]) : NaN;
    const pct = Number.isFinite(val) ? (val * 100).toFixed(2) + '%' : '';
    if (/very\s*high/i.test(s) || val >= 0.05) return { raw: s, percentText: pct, tagZh: '极高危', level: 'danger' };
    if (/high/i.test(s) || val >= 0.02) return { raw: s, percentText: pct, tagZh: '偏高', level: 'danger' };
    if (/elevated/i.test(s) || val >= 0.008) return { raw: s, percentText: pct, tagZh: '中等偏高', level: 'warn' };
    if (/low/i.test(s) && !/very\s*low/i.test(s)) return { raw: s, percentText: pct, tagZh: '较低', level: 'good' };
    return { raw: s, percentText: pct, tagZh: '极低 (纯净)', level: 'excellent' };
  }

  function mapEntityTypeZh(typeStr) {
    const t = String(typeStr || '').toLowerCase();
    if (t === 'isp') return '家庭宽带(ISP)';
    if (t === 'hosting') return 'IDC机房(Hosting)';
    if (t === 'business') return '商业专线(Business)';
    if (t === 'education') return '教育科研(Edu)';
    if (t === 'government') return '政企机构(Gov)';
    if (t === 'banking') return '金融专线';
    return typeStr || '未知';
  }

  function parseIPAPIIs(j) {
    if (!j || typeof j !== 'object' || j.error) return null;
    const asnObj = j.asn || {};
    const compObj = j.company || {};
    const locObj = j.location || {};

    const asnType = String(asnObj.type || '').toLowerCase();
    const compType = String(compObj.type || '').toLowerCase();
    const isDatacenter = Boolean(j.is_datacenter);
    const isVPN = Boolean(j.is_vpn);
    const isProxy = Boolean(j.is_proxy);
    const isTor = Boolean(j.is_tor);
    const isAbuser = Boolean(j.is_abuser);
    const isCrawler = Boolean(j.is_crawler);
    const isMobile = Boolean(j.is_mobile);

    let lineageLabel = '普通网络';
    let lineageLevel = 'normal';
    if (asnType === 'isp' && compType === 'isp' && !isDatacenter) {
      lineageLabel = '✨ 双 ISP 原生家宽';
      lineageLevel = 'excellent';
    } else if ((asnType === 'isp' || compType === 'isp') && !isDatacenter) {
      lineageLabel = isMobile ? '📱 蜂窝移动原生网络' : '🏠 单 ISP 住宅/宽带';
      lineageLevel = 'good';
    } else if (asnType === 'hosting' || compType === 'hosting' || isDatacenter) {
      lineageLabel = '🖥️ IDC 机房托管';
      lineageLevel = 'warn';
    } else if (asnType === 'business' || compType === 'business') {
      lineageLabel = '🏢 商业企业专线';
      lineageLevel = 'good';
    } else if (asnType === 'education' || compType === 'education') {
      lineageLabel = '🎓 教育学术网络';
      lineageLevel = 'good';
    }

    const asnCountry = String(asnObj.country || '').toUpperCase();
    const locCountry = String(locObj.country_code || '').toUpperCase();
    let isNativeGeo = null;
    let broadcastText = '';
    if (asnCountry && locCountry) {
      isNativeGeo = asnCountry === locCountry;
      broadcastText = isNativeGeo
        ? '原生 IP (注册与落地均为 ' + locCountry + ')'
        : '广播 IP (注册于 ' + asnCountry + ' → 落地 ' + locCountry + ')';
    }

    const asnScore = parseAbuserScore(asnObj.abuser_score);
    const compScore = parseAbuserScore(compObj.abuser_score);
    const primaryScore = compScore || asnScore;

    let riskIndex = 0;
    if (isDatacenter || asnType === 'hosting' || compType === 'hosting') riskIndex += 20;
    if (isVPN) riskIndex += 20;
    if (isProxy) riskIndex += 25;
    if (isTor) riskIndex += 35;
    if (isAbuser) riskIndex += 30;
    if (isCrawler) riskIndex += 10;
    if (primaryScore) {
      if (primaryScore.level === 'danger') riskIndex += 30;
      else if (primaryScore.level === 'warn') riskIndex += 15;
      else if (primaryScore.level === 'good') riskIndex += 5;
    }
    riskIndex = Math.min(100, riskIndex);

    return {
      asn: asnObj.asn ? 'AS' + asnObj.asn : '',
      asnOrg: asnObj.org || '',
      asnTypeText: mapEntityTypeZh(asnType),
      asnRoute: asnObj.route || '',
      companyName: compObj.name || '',
      companyTypeText: mapEntityTypeZh(compType),
      companyNetwork: compObj.network || '',
      rir: j.rir || '',
      lineageLabel,
      lineageLevel,
      isNativeGeo,
      broadcastText,
      primaryScore,
      riskIndex,
      flags: {
        datacenter: isDatacenter,
        vpn: isVPN,
        proxy: isProxy,
        tor: isTor,
        abuser: isAbuser,
        crawler: isCrawler,
        mobile: isMobile,
      },
      countryCode: locCountry,
    };
  }

  async function queryPurityIPAPI(ip, targetNode) {
    let url = 'https://api.ipapi.is/?q=' + encodeURIComponent(ip);
    if (CFG.ipapiKey) url += '&key=' + encodeURIComponent(CFG.ipapiKey);
    try {
      const j = await fetchJSON(buildOutboundOpts(url, targetNode), CFG.timeoutMs);
      return parseIPAPIIs(j);
    } catch (e) {
      log('ipapi.is error: ' + (e.message || e));
      return null;
    }
  }

  /**
   * 第二独立风控源：proxycheck.io 免 Key 风险评分与连接属性交叉核验
   */
  async function queryProxyCheckIO(ip, targetNode) {
    const url = 'http://proxycheck.io/v2/' + encodeURIComponent(ip) + '?vpn=1&asn=1&risk=1';
    try {
      const j = await fetchJSON(buildOutboundOpts(url, targetNode), Math.min(CFG.timeoutMs, 5500));
      if (j && (j.status === 'ok' || j.status === 'warning') && j[ip]) {
        const rec = j[ip];
        const rawType = String(rec.type || '');
        const typeZhMap = {
          Residential: '住宅宽带',
          Wireless: '移动蜂窝',
          Business: '商业宽带',
          Hosting: 'IDC 机房',
          VPN: '商业 VPN',
          TOR: 'Tor 节点',
          Compromised: '被控肉鸡',
        };
        return {
          proxy: rec.proxy === 'yes',
          type: rawType,
          typeZh: typeZhMap[rawType] || rawType || '常规网络',
          risk: Number.isFinite(Number(rec.risk)) ? Number(rec.risk) : null,
          provider: rec.provider || '',
        };
      }
    } catch (e) {
      log('proxycheck.io error: ' + (e.message || e));
    }
    return null;
  }

  /**
   * 第三独立风控源：ip-score.com 40+ 国际反垃圾/欺诈黑名单库交叉扫描
   */
  async function queryIPScoreDeep(targetNode) {
    try {
      const res = await httpRequest(
        'post',
        Object.assign(buildOutboundOpts('https://ip-score.com/fulljson', targetNode), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Origin: 'https://ip-score.com',
            Referer: 'https://ip-score.com/',
          },
          body: '',
        }),
        Math.min(CFG.timeoutMs + 1500, 9500)
      );
      if (res.status >= 200 && res.status < 400 && res.body) {
        const j = JSON.parse(res.body);
        const bl = j.blacklist || {};
        const blKeys = Object.keys(bl);
        const hits = blKeys.filter((k) => /true|listed|yes|1/i.test(String(bl[k])));
        return {
          totalBlacklists: blKeys.length,
          listedCount: hits.length,
          listedNames: hits.slice(0, 5),
          geo1: j.geoip1 ? [j.geoip1.country, j.geoip1.city].filter(Boolean).join(' ') : '',
          geo2: j.geoip2 ? [j.geoip2.country, j.geoip2.city].filter(Boolean).join(' ') : '',
        };
      }
    } catch (e) {
      log('ip-score error: ' + (e.message || e));
    }
    return null;
  }

  // ============================================================================
  // 6. 流媒体与 AI 服务解锁探测引擎 (移植自可莉仓库 Node_detection_tool)
  // ============================================================================

  const OPENAI_BLOCKED = new Set(['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP', 'CU', 'SY', 'VE']);
  const CLAUDE_BLOCKED = new Set(['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP', 'CU', 'SY']);
  const GEMINI_BLOCKED = new Set(['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP', 'CU', 'SY']);
  const TIKTOK_BLOCKED = new Set(['CN', 'HK', 'IN', 'RU']);

  function parseTraceMap(body) {
    const kv = {};
    String(body || '')
      .split(/\r?\n/)
      .forEach((line) => {
        const idx = line.indexOf('=');
        if (idx > 0) kv[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      });
    return kv;
  }

  async function checkChatGPTUnlock(targetNode) {
    const t = Math.min(CFG.timeoutMs, 6000);
    const [traceRes, iosRes] = await Promise.all([
      httpRequest('get', buildOutboundOpts('https://chatgpt.com/cdn-cgi/trace', targetNode), t).catch(() => null),
      httpRequest(
        'get',
        buildOutboundOpts('https://ios.chat.openai.com/public-api/mobile/server_status/v1', targetNode),
        t
      ).catch(() => null),
    ]);

    const kv = traceRes && traceRes.body ? parseTraceMap(traceRes.body) : {};
    const loc = (kv.loc || '').toUpperCase();

    if (!traceRes && !iosRes) {
      return { name: 'ChatGPT', state: 'warn', text: '连接超时' };
    }
    if (loc && OPENAI_BLOCKED.has(loc)) {
      return { name: 'ChatGPT', state: 'no', text: '地区不支持 [' + loc + ']' };
    }

    const iosBody = (iosRes && iosRes.body) || '';
    const iosBlocked =
      !iosRes ||
      iosRes.status === 403 ||
      /unsupported_country|vpn|cf-error|attention required|disallowed_isp/i.test(iosBody);
    const regTag = loc ? ' [' + loc + ']' : '';

    if (!iosBlocked && iosRes.status >= 200 && iosRes.status < 400) {
      return { name: 'ChatGPT', state: 'yes', text: '完整解锁' + regTag + ' (Web + App)' };
    }
    if (loc) {
      return { name: 'ChatGPT', state: 'partial', text: '仅网页端可用' + regTag + ' (App受限)' };
    }
    return { name: 'ChatGPT', state: 'no', text: '访问受限 / 风控拦截' };
  }

  async function checkClaudeUnlock(targetNode) {
    const t = Math.min(CFG.timeoutMs, 6000);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://claude.ai/cdn-cgi/trace', targetNode),
        t
      );
      const kv = parseTraceMap(res.body);
      const loc = (kv.loc || '').toUpperCase();
      if (loc && CLAUDE_BLOCKED.has(loc)) {
        return { name: 'Claude', state: 'no', text: '地区不支持 [' + loc + ']' };
      }
      if (loc) {
        return { name: 'Claude', state: 'yes', text: '支持访问 [' + loc + ']' };
      }
    } catch (_) {}
    return { name: 'Claude', state: 'warn', text: '连接超时或受限' };
  }

  async function checkGeminiUnlock(targetNode, fallbackCC) {
    const t = Math.min(CFG.timeoutMs, 6500);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://gemini.google.com/app', targetNode, {
          'Accept-Language': 'en-US,en;q=0.9',
        }),
        t
      );
      const body = res.body || '';
      if (
        res.status === 451 ||
        res.status === 403 ||
        /isn't currently supported|not available in your country|faq#supported_countries/i.test(body)
      ) {
        return { name: 'Gemini', state: 'no', text: '当前地区不支持' + (fallbackCC ? ' [' + fallbackCC + ']' : '') };
      }
      if (fallbackCC && GEMINI_BLOCKED.has(fallbackCC.toUpperCase())) {
        return { name: 'Gemini', state: 'no', text: '地区受限 [' + fallbackCC.toUpperCase() + ']' };
      }
      if (res.status >= 200 && res.status < 400) {
        const ccMatch = body.match(/,"([A-Z]{2})","[a-z]{2}(?:-[A-Z]{2})?"/);
        const cc = (ccMatch && ccMatch[1]) || (fallbackCC || '').toUpperCase();
        if (cc && GEMINI_BLOCKED.has(cc)) {
          return { name: 'Gemini', state: 'no', text: '地区不支持 [' + cc + ']' };
        }
        return { name: 'Gemini', state: 'yes', text: '支持访问' + (cc ? ' [' + cc + ']' : '') };
      }
    } catch (_) {}
    return { name: 'Gemini', state: 'warn', text: '检测超时' };
  }

  function extractNetflixRegion(res) {
    const body = (res && res.body) || '';
    const hdrLoc =
      (res && res.headers && (res.headers.Location || res.headers.location || res.headers['x-originating-url'])) || '';
    const mUrl = (hdrLoc + ' ' + body.slice(0, 6000)).match(/netflix\.com\/([a-z]{2})(?:-[a-z]{2,})?\/title/i);
    if (mUrl) return mUrl[1].toUpperCase();
    const mJson = body.match(/"requestCountry"\s*:\s*\{\s*"id"\s*:\s*"([A-Z]{2})"/i);
    if (mJson) return mJson[1].toUpperCase();
    return 'US';
  }

  function isNetflixTitleAvailable(res) {
    if (!res) return false;
    if (res.status === 403 || res.status === 404 || res.status >= 500) return false;
    const b = res.body || '';
    if (/Not Available|NSES-404|page-lost|unblock|proxy/i.test(b.slice(0, 4000)) && b.length < 15000) {
      return false;
    }
    return res.status >= 200 && res.status < 400;
  }

  async function checkNetflixUnlock(targetNode) {
    const t = Math.min(CFG.timeoutMs, 6500);
    const [nonOrig, orig] = await Promise.all([
      httpRequest('get', buildOutboundOpts('https://www.netflix.com/title/81280792', targetNode), t).catch(() => null),
      httpRequest('get', buildOutboundOpts('https://www.netflix.com/title/80018499', targetNode), t).catch(() => null),
    ]);

    if (!nonOrig && !orig) {
      return { name: 'Netflix', state: 'warn', text: '连接超时' };
    }
    if (isNetflixTitleAvailable(nonOrig)) {
      const reg = extractNetflixRegion(nonOrig);
      return { name: 'Netflix', state: 'yes', text: '完整解锁 (含非自制剧) [' + reg + ']' };
    }
    if (isNetflixTitleAvailable(orig)) {
      const reg = extractNetflixRegion(orig);
      return { name: 'Netflix', state: 'partial', text: '仅解锁自制剧 (Originals) [' + reg + ']' };
    }
    return { name: 'Netflix', state: 'no', text: '未解锁 / 代理被拦截' };
  }

  async function checkYouTubePremiumUnlock(targetNode) {
    const t = Math.min(CFG.timeoutMs, 6000);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://www.youtube.com/premium', targetNode, {
          'Accept-Language': 'en-US,en;q=0.9',
        }),
        t
      );
      const b = res.body || '';
      if (/www\.google\.cn/i.test(b)) {
        return { name: 'YouTube', state: 'no', text: '送中警告 [CN] (无会员权益)' };
      }
      if (/Premium is not available in your country|在您所在的国家\/地区尚不可用/i.test(b)) {
        return { name: 'YouTube', state: 'partial', text: '网页可用 (当前地区未开会员)' };
      }
      const m = b.match(/"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"/) || b.match(/"countryCode"\s*:\s*"([A-Z]{2})"/);
      const cc = m ? m[1].toUpperCase() : '';
      if (cc === 'CN') {
        return { name: 'YouTube', state: 'no', text: '送中警告 [CN]' };
      }
      return { name: 'YouTube', state: 'yes', text: '支持 Premium' + (cc ? ' [' + cc + ']' : '') };
    } catch (_) {
      return { name: 'YouTube', state: 'warn', text: '连接超时' };
    }
  }

  async function checkDisneyPlusUnlock(targetNode, fallbackCC) {
    const t = Math.min(CFG.timeoutMs, 6000);
    const DISNEY_UNSUPPORTED = new Set(['CN', 'RU', 'BY', 'IR', 'KP', 'CU', 'SY', 'VN']);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://www.disneyplus.com/', targetNode, {
          'Accept-Language': 'en-US,en;q=0.9',
        }),
        t
      );
      const b = res.body || '';
      if (
        res.status === 403 ||
        res.status === 451 ||
        /Sorry, Disney\+ is not available|disneyplus\.com\/unavailable|not available in your region/i.test(b)
      ) {
        return { name: 'Disney+', state: 'no', text: '未解锁 / 地区不可用' };
      }
      const m = b.match(/content="https:\/\/www\.disneyplus\.com\/([a-z]{2}(?:-[a-z]{2})?)"/i);
      let cc = m ? m[1].split('-').pop().toUpperCase() : (fallbackCC || '').toUpperCase();
      if (cc && DISNEY_UNSUPPORTED.has(cc)) {
        return { name: 'Disney+', state: 'no', text: '地区未开通 [' + cc + ']' };
      }
      if (res.status >= 200 && res.status < 400) {
        return { name: 'Disney+', state: 'yes', text: '支持解锁' + (cc ? ' [' + cc + ']' : '') };
      }
    } catch (_) {}
    return { name: 'Disney+', state: 'warn', text: '检测超时' };
  }

  async function checkTikTokUnlock(targetNode, fallbackCC) {
    const t = Math.min(CFG.timeoutMs, 6000);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://www.tiktok.com/login', targetNode, {
          'Accept-Language': 'en-US,en;q=0.9',
        }),
        t
      );
      const b = res.body || '';
      if (res.status === 403 || /Access Denied|Please wait\.\.\./i.test(b.slice(0, 1500))) {
        return { name: 'TikTok', state: 'no', text: '节点 IP 被拦截 (403)' };
      }
      const m =
        b.match(/"region"\s*:\s*"([A-Z]{2})"/) ||
        b.match(/"\$region"\s*:\s*"([A-Z]{2})"/) ||
        b.match(/"countryCode"\s*:\s*"([A-Z]{2})"/);
      const cc = (m && m[1]) || (fallbackCC || '').toUpperCase();
      if (cc && TIKTOK_BLOCKED.has(cc)) {
        return { name: 'TikTok', state: 'no', text: '锁区不可用 [' + cc + ']' };
      }
      if (res.status >= 200 && res.status < 400) {
        return { name: 'TikTok', state: 'yes', text: '正常解锁' + (cc ? ' [' + cc + ']' : '') };
      }
    } catch (_) {}
    return { name: 'TikTok', state: 'warn', text: '连接超时' };
  }

  async function checkBahamutUnlock(targetNode) {
    const t = Math.min(CFG.timeoutMs, 5000);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=37783', targetNode),
        t
      );
      if (res.body && res.body.includes('animeSn')) {
        return { name: '动画疯', state: 'yes', text: '完整解锁 [TW/HK]' };
      }
      return { name: '动画疯', state: 'muted', text: '仅限台湾/港澳节点' };
    } catch (_) {
      return { name: '动画疯', state: 'muted', text: '仅限台湾/港澳节点' };
    }
  }

  // ============================================================================
  // 7. 按模式精准分流执行探测（彻底消除菜单重复与无效等待）
  // ============================================================================

  async function executeModeProbe(targetNode, mode) {
    const startedAt = Date.now();
    const runMode = normalizeMode(mode);

    // 模式 A: 节点链路与入口查询 (极速并发：落地 IPv4 + IPv6 + Cloudflare WARP & POP)
    if (runMode === 'info' || runMode === 'panel') {
      const [landing, ipv6, cfTrace] = await Promise.all([
        queryLandingIPv4(targetNode),
        CFG.checkIPv6 ? queryLandingIPv6(targetNode) : Promise.resolve(null),
        queryCloudflareTrace(targetNode),
      ]);
      return {
        ok: true,
        mode: runMode,
        elapsedMs: Date.now() - startedAt,
        landing,
        ipv6,
        cfTrace,
      };
    }

    // 模式 B: 节点纯净度深度检测 (三源交叉风控：ipapi.is + proxycheck.io + ip-score RBL)
    if (runMode === 'purity') {
      const landing = await queryLandingIPv4(targetNode);
      const [purity, proxyCheck, ipScore] = await Promise.all([
        queryPurityIPAPI(landing.ip, targetNode),
        queryProxyCheckIO(landing.ip, targetNode),
        queryIPScoreDeep(targetNode),
      ]);
      return {
        ok: true,
        mode: 'purity',
        elapsedMs: Date.now() - startedAt,
        landing,
        purity,
        proxyCheck,
        ipScore,
      };
    }

    // 模式 C: 流媒体与 AI 解锁检测 (8 大平台全并发实测)
    if (runMode === 'unlock') {
      const landingPromise = queryLandingIPv4(targetNode).catch(() => ({
        ip: '',
        country: '',
        countryCode: '',
      }));
      const landing = await landingPromise;
      const cc = landing.countryCode || '';
      const [chatgpt, claude, gemini, netflix, youtube, disney, tiktok, bahamut] = await Promise.all([
        checkChatGPTUnlock(targetNode),
        checkClaudeUnlock(targetNode),
        checkGeminiUnlock(targetNode, cc),
        checkNetflixUnlock(targetNode),
        checkYouTubePremiumUnlock(targetNode),
        checkDisneyPlusUnlock(targetNode, cc),
        checkTikTokUnlock(targetNode, cc),
        checkBahamutUnlock(targetNode),
      ]);
      return {
        ok: true,
        mode: 'unlock',
        elapsedMs: Date.now() - startedAt,
        landing,
        aiItems: [chatgpt, claude, gemini],
        mediaItems: [netflix, disney, youtube, tiktok, bahamut],
      };
    }

    throw new Error('Unknown probe mode: ' + runMode);
  }

  // ============================================================================
  // 8. 双通道指定节点桥接器 + 本机外部控制器中转入口抓取
  // ============================================================================

  function recoverDanglingPolicyIfAny() {
    if (typeof $config === 'undefined' || !$config.getConfig) return;
    const raw = storeRead(STATE_RESTORE_KEY);
    if (!raw) return;
    try {
      const saved = JSON.parse(raw);
      if (saved && typeof saved === 'object') {
        if (typeof saved.runningModel === 'number') $config.setRunningModel(saved.runningModel);
        if (saved.globalProxy) $config.setSelectPolicy('GLOBAL', saved.globalProxy);
      }
    } catch (_) {}
    storeWrite(STATE_RESTORE_KEY, '');
  }

  async function tryTunnelBridgeProbe(targetNode, mode) {
    const qs =
      'node=' + encodeURIComponent(targetNode) +
      '&mode=' + encodeURIComponent(mode) +
      '&ipv6=' + (CFG.checkIPv6 ? '1' : '0') +
      '&_t=' + Date.now();
    const bridgeURL = 'http://' + BRIDGE_HOST + BRIDGE_CHECK_PATH + '?' + qs;
    const timeoutBudget = mode === 'info' ? CFG.timeoutMs + 5000 : CFG.timeoutMs * 2 + 7000;
    const res = await httpRequest('get', bridgeURL, timeoutBudget);
    if (res.status !== 200 || !res.body) throw new Error('Bridge HTTP ' + res.status);
    const data = JSON.parse(res.body);
    if (!data || !data.fromClashTunnelBridge) throw new Error('Not intercepted by tunnel engine');
    if (!data.ok) throw new Error(data.error || '节点探测失败');
    data.routeChannel = 'bridge';
    return data;
  }

  async function fallbackConfigSwitchProbe(targetNode, mode) {
    if (typeof $config === 'undefined' || !$config.getConfig) {
      throw new Error('当前环境不支持 $config 控制器，请开启模块页顶部的 HTTPS 解密开关');
    }
    let cfg = {};
    try {
      const rawCfg = $config.getConfig();
      cfg = typeof rawCfg === 'string' ? JSON.parse(rawCfg) : rawCfg || {};
    } catch (_) {}

    const prevModel = Number(cfg.running_model);
    const prevGlobal =
      ($config.getSelectedPolicy && $config.getSelectedPolicy('GLOBAL')) || cfg.global_proxy || '';
    const alreadyOnTarget = prevModel === 2 && prevGlobal === targetNode;

    if (!alreadyOnTarget && !CFG.autoSwitchFallback) {
      return {
        ok: false,
        needsEngineWarning: true,
        error: '未开启模块页「HTTPS 解密」开关，且已关闭「自动临时切换测速」。',
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
          throw new Error('无法将 GLOBAL 临时切换至「' + targetNode + '」，建议开启模块页 HTTPS 解密开关');
        }
        switched = true;
        await new Promise((r) => setTimeout(r, 80));
      }

      const data = await executeModeProbe(undefined, mode);
      data.routeChannel = alreadyOnTarget ? 'active-global' : 'config-fallback';
      return data;
    } finally {
      if (switched) {
        try {
          $config.setRunningModel(prevModel);
          if (prevGlobal) $config.setSelectPolicy('GLOBAL', prevGlobal);
        } catch (_) {}
        storeWrite(STATE_RESTORE_KEY, '');
      }
    }
  }

  function isIPv4Literal(s) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s || '').trim());
  }

  function isIPv6Literal(s) {
    const v = String(s || '').trim();
    return v.includes(':') && /^[0-9a-fA-F:]+$/.test(v);
  }

  function isBogusEntranceIP(ip) {
    const s = String(ip || '').trim().toLowerCase();
    return (
      !s ||
      s === '0.0.0.0' ||
      s === '::' ||
      s === '::1' ||
      s.startsWith('127.') ||
      s.startsWith('198.18.') ||
      s.startsWith('198.19.') ||
      s === '198.51.100.88'
    );
  }

  function isPrivateLANIP(ip) {
    const s = String(ip || '').trim().toLowerCase();
    if (!s) return false;
    if (s.startsWith('10.') || s.startsWith('192.168.')) return true;
    const m172 = s.match(/^172\.(\d{1,3})\./);
    if (m172 && Number(m172[1]) >= 16 && Number(m172[1]) <= 31) return true;
    const m100 = s.match(/^100\.(\d{1,3})\./);
    if (m100 && Number(m100[1]) >= 64 && Number(m100[1]) <= 127) return true;
    return s.startsWith('fc') || s.startsWith('fd') || s.startsWith('fe80:');
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
    if (CFG.controllerSecret) h.Authorization = 'Bearer ' + CFG.controllerSecret;
    return h;
  }

  async function resolveDomainToIP(domain) {
    const d = String(domain || '').trim();
    if (!d) return '';

    if (typeof $dns !== 'undefined' && $dns && typeof $dns.query === 'function') {
      try {
        const ip = await new Promise((resolve) => {
          let done = false;
          const timer = setTimeout(() => {
            if (!done) {
              done = true;
              resolve('');
            }
          }, 2200);
          try {
            $dns.query({ domain: d, timeout: 2000 }, (err, data) => {
              if (done) return;
              done = true;
              clearTimeout(timer);
              if (!err && data && Array.isArray(data.answers)) {
                for (const ans of data.answers) {
                  const val = ans && ans.value ? String(ans.value).trim() : '';
                  if ((isIPv4Literal(val) || isIPv6Literal(val)) && !isBogusEntranceIP(val)) {
                    resolve(val);
                    return;
                  }
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

    try {
      const url =
        'http://127.0.0.1:' + CFG.controllerPort + '/dns/query?name=' + encodeURIComponent(d) + '&type=A';
      const j = await fetchJSON({ url, headers: buildControllerHeaders() }, 1600);
      if (j && Array.isArray(j.Answer)) {
        for (const ans of j.Answer) {
          const val = ans && ans.data ? String(ans.data).trim() : '';
          if ((isIPv4Literal(val) || isIPv6Literal(val)) && !isBogusEntranceIP(val)) return val;
        }
      }
    } catch (_) {}

    try {
      const j = await fetchJSON('https://223.5.5.5/resolve?name=' + encodeURIComponent(d) + '&type=1', 2200);
      if (j && Array.isArray(j.Answer)) {
        for (const ans of j.Answer) {
          const val = ans && ans.data ? String(ans.data).trim() : '';
          if (isIPv4Literal(val) && !isBogusEntranceIP(val)) return val;
        }
      }
    } catch (_) {}
    return '';
  }

  async function queryIPGeoExplicit(ip) {
    const targetIP = String(ip || '').trim();
    if (!targetIP) return null;
    if (isPrivateLANIP(targetIP)) {
      return {
        ip: targetIP,
        country: '内网网关',
        countryCode: '',
        region: '',
        city: '',
        ispDisplay: '局域网 / 组网入口',
        asn: '',
        isPrivate: true,
      };
    }

    try {
      const j = await fetchJSON(
        'http://ip-api.com/json/' + encodeURIComponent(targetIP) + '?fields=66842623&lang=zh-CN',
        3800
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
        return {
          ip: targetIP,
          country: j.country || '',
          countryCode: cc,
          region: j.regionName || '',
          city: j.city || '',
          isp: j.isp || '',
          org: j.org || asnOrg || '',
          ispDisplay: normalizeEntranceISP(j.isp || '', j.org || asnOrg || '', cc),
          asn,
        };
      }
    } catch (_) {}

    try {
      const j = await fetchJSON('https://ipwho.is/' + encodeURIComponent(targetIP) + '?lang=zh-CN', 3800);
      if (j && j.success !== false) {
        const conn = j.connection || {};
        const cc = j.country_code || '';
        return {
          ip: targetIP,
          country: j.country || '',
          countryCode: cc,
          region: j.region || '',
          city: j.city || '',
          isp: conn.isp || '',
          org: conn.org || '',
          ispDisplay: normalizeEntranceISP(conn.isp || '', conn.org || '', cc),
          asn: conn.asn ? 'AS' + conn.asn : '',
        };
      }
    } catch (_) {}
    return null;
  }

  async function fetchControllerConnectionsSnapshot() {
    const url = 'http://127.0.0.1:' + CFG.controllerPort + '/connections';
    try {
      const res = await httpRequest('get', { url, headers: buildControllerHeaders() }, 1200);
      if (res.status === 401 || res.status === 403) return { status: 'unauthorized', connections: [] };
      if (res.status >= 200 && res.status < 300) {
        const j = JSON.parse(res.body.trim() || '{}');
        return { status: 'ok', connections: Array.isArray(j.connections) ? j.connections : [] };
      }
      return { status: 'unreachable', connections: [] };
    } catch (_) {
      return { status: 'unreachable', connections: [] };
    }
  }

  function findMatchingConnection(connections, nodeName) {
    if (!Array.isArray(connections) || connections.length === 0) return null;
    const probeHostRe = /(ip-api\.com|ip\.sb|ipwho\.is|ipinfo\.io|cloudflare\.com|1\.1\.1\.1|ipw\.cn)$/i;
    const sorted = connections.slice().sort((a, b) => {
      const ta = a && a.start ? Date.parse(a.start) || 0 : 0;
      const tb = b && b.start ? Date.parse(b.start) || 0 : 0;
      return tb - ta;
    });

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

    for (const c of sorted) {
      if (!c || !c.metadata) continue;
      if (!probeHostRe.test(String(c.metadata.host || ''))) continue;
      const chains = Array.isArray(c.chains) ? c.chains : [];
      if (chains.length === 0 || chains[0] === 'DIRECT' || chains[0] === 'REJECT') continue;
      const parsed = parseHostPort(c.metadata.remoteDestination);
      if (!parsed) continue;
      return { conn: c, parsed };
    }
    return null;
  }

  async function runProbeWithEntranceCapture(nodeName, captureEnabled, probeFn) {
    if (!captureEnabled || !CFG.showEntrance) {
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
        entranceHost: parsed.host,
        entrancePort: parsed.port,
        entranceIP: entranceIP || '',
        leafNode,
        geo,
      };
    }

    async function trySnapshotOnce() {
      if (matchedRecord || controllerStatus === 'unreachable' || controllerStatus === 'unauthorized') return;
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
      await new Promise((r) => setTimeout(r, 160));
      if (probeFinished) return;
      await trySnapshotOnce();
      if (matchedRecord || probeFinished || controllerStatus !== 'ok') return;
      await new Promise((r) => setTimeout(r, 380));
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
    if (!matchedRecord && (controllerStatus === 'unknown' || controllerStatus === 'ok')) {
      await trySnapshotOnce();
    }

    if (earlyDetailPromise) {
      return { probe, entrance: await earlyDetailPromise.catch(() => null) };
    }
    if (controllerStatus === 'unauthorized') return { probe, entrance: { status: 'unauthorized' } };
    if (controllerStatus === 'unreachable') return { probe, entrance: { status: 'unreachable' } };
    return { probe, entrance: { status: 'not_found' } };
  }

  // ============================================================================
  // 9. 三大独立弹窗渲染器（紧凑一屏排版、高对比度、零冗余重复）
  // ============================================================================

  function levelColor(level) {
    if (level === 'excellent') return COLORS.success;
    if (level === 'good') return COLORS.cyan;
    if (level === 'warn') return COLORS.warning;
    if (level === 'danger') return COLORS.danger;
    return COLORS.primary;
  }

  function renderCompactHeader(nodeName, nodeInfo, leafNode) {
    const meta = [];
    if (nodeInfo && typeof nodeInfo === 'object') {
      if (nodeInfo.type) meta.push('<code>' + esc(String(nodeInfo.type).toUpperCase()) + '</code>');
      if (typeof nodeInfo.udp === 'boolean') {
        meta.push(nodeInfo.udp ? colorSpan('UDP ✓', COLORS.success, true) : colorSpan('UDP ✗', COLORS.muted, false));
      }
      const hist = Array.isArray(nodeInfo.history) ? nodeInfo.history : [];
      const delay = hist.length > 0 ? Number(hist[hist.length - 1].delay || 0) : 0;
      if (delay > 0) {
        const dc = delay < 160 ? COLORS.success : delay < 350 ? COLORS.warning : COLORS.danger;
        meta.push(colorSpan(delay + ' ms', dc, true));
      } else if (nodeInfo.alive === false) {
        meta.push(colorSpan('离线', COLORS.danger, true));
      }
    }
    const lines = [
      colorSpan('● ', COLORS.primary, true) +
        '<b>' + esc(nodeName) + '</b>' +
        (meta.length > 0 ? '  ' + meta.join(' · ') : ''),
    ];
    if (leafNode && leafNode !== nodeName) {
      lines.push('实际承载：' + colorSpan(leafNode, COLORS.cyan, true));
    }
    return lines;
  }

  function renderFooterNote(probe) {
    const ch =
      probe.routeChannel === 'bridge'
        ? '⚡ 零切换直测 · ' + probe.elapsedMs + ' ms'
        : probe.routeChannel === 'active-global'
          ? '⚡ 当前全局直测 · ' + probe.elapsedMs + ' ms'
          : '🔄 临时切换直测 (已还原) · ' + probe.elapsedMs + ' ms';
    return '<span style="color:' + COLORS.muted + '">' + esc(ch) + '</span>';
  }

  /**
   * 视图 1：🌐 节点链路与入口查询 (一屏展示完整拓扑 + 出入口 + Cloudflare WARP/POP)
   */
  function renderInfoSheetHTML({ nodeName, nodeInfo, domestic, entrance, probe }) {
    const l = probe.landing;
    const cf = probe.cfTrace;
    const flag = getFlagEmoji(l.countryCode);
    const lGeo = deduplicateGeoParts([l.country, l.region, l.city]).join(' ');
    const lines = renderCompactHeader(nodeName, nodeInfo, entrance && entrance.leafNode);

    // 1. 拓扑总览横幅
    const hops = [];
    if (domestic && domestic.ip) {
      hops.push('🇨🇳 ' + esc(domestic.shortTag || '本地'));
    }
    if (entrance && entrance.status === 'ok' && entrance.entranceIP) {
      const isDirect =
        entrance.entranceIP === l.ip ||
        Boolean(probe.ipv6 && probe.ipv6.ip && entrance.entranceIP === probe.ipv6.ip);
      if (isDirect) {
        hops.push(colorSpan('直连出境', COLORS.cyan, true));
      } else {
        const eg = entrance.geo;
        const eTag = eg
          ? (eg.isPrivate ? '🏠 内网' : getFlagEmoji(eg.countryCode) + ' ' + (eg.city || eg.region || eg.country || '中转').replace(/省|市|壮族自治区|维吾尔自治区|回族自治区/g, '')) +
            (eg.ispDisplay ? eg.ispDisplay.replace(/^中国/, '') : '')
          : '中转入口';
        hops.push(colorSpan(eTag, COLORS.purple, true));
      }
    }
    hops.push(flag + ' ' + esc(l.city || l.country || l.countryCode || '落地'));
    if (cf && cf.colo) {
      hops.push('☁️ ' + esc(cf.colo));
    }

    lines.push('');
    lines.push('<b>▸ 代理链路走向</b>');
    lines.push(hops.join(' ➔ '));

    // 2. 出入口明细
    lines.push('');
    lines.push('<b>▸ 入口与落地明细</b>');
    if (domestic && domestic.ip) {
      lines.push(
        '本地直连：<code>' +
          esc(maskIPString(domestic.ip, CFG.maskIP)) +
          '</code> · ' +
          esc([domestic.location, domestic.isp].filter(Boolean).join(' '))
      );
    }

    if (CFG.showEntrance && entrance) {
      if (entrance.status === 'ok' && (entrance.entranceIP || entrance.entranceHost)) {
        const entIP = entrance.entranceIP || '';
        const entHost = entrance.entranceHost || '';
        const isDirect =
          Boolean(entIP) &&
          (entIP === l.ip || Boolean(probe.ipv6 && probe.ipv6.ip && entIP === probe.ipv6.ip));
        const portStr = !CFG.maskIP && entrance.entrancePort ? ':' + entrance.entrancePort : '';
        if (isDirect) {
          lines.push(
            '中转入口：<code>' +
              esc(maskIPString(entIP, CFG.maskIP) + portStr) +
              '</code> ' +
              colorSpan('[直连无中转]', COLORS.cyan, true)
          );
        } else {
          const eg = entrance.geo;
          const eGeo = eg
            ? [
                eg.isPrivate ? '🏠' : getFlagEmoji(eg.countryCode),
                deduplicateGeoParts([eg.region || eg.country, eg.city]).join(''),
                eg.ispDisplay || eg.isp || eg.org,
              ]
                .filter(Boolean)
                .join(' ')
            : '';
          lines.push(
            '中转入口：<code>' +
              esc(maskIPString(entIP || entHost, CFG.maskIP) + portStr) +
              '</code>' +
              (eGeo ? ' · ' + esc(eGeo) : '')
          );
          if (entHost && entHost !== entIP) {
            lines.push('入口域名：<code>' + esc(maskDomainString(entHost, CFG.maskIP)) + '</code>');
          }
        }
      } else if (entrance.status === 'unauthorized') {
        lines.push('中转入口：' + colorSpan('待填密钥（模块设置中粘贴外部控制器密钥即可显示）', COLORS.warning, false));
      } else if (entrance.status === 'unreachable') {
        lines.push(
          '中转入口：<span style="color:' +
            COLORS.muted +
            '">未开启（设置→客户端设置→外部控制器→本机 填密钥可查）</span>'
        );
      }
    }

    lines.push(
      '落地 IPv4：<code>' +
        esc(maskIPString(l.ip, CFG.maskIP)) +
        '</code> · ' +
        flag +
        ' ' +
        esc(lGeo || l.countryCode || '-')
    );
    if (probe.ipv6 && probe.ipv6.ip) {
      lines.push(
        '落地 IPv6：<code>' +
          esc(maskIPString(probe.ipv6.ip, CFG.maskIP)) +
          '</code> ' +
          colorSpan('[双栈 ✓]', COLORS.success, true)
      );
    } else if (CFG.checkIPv6) {
      lines.push('落地 IPv6：<span style="color:' + COLORS.muted + '">未启用 (仅 IPv4)</span>');
    }

    lines.push(
      '运营商　：' +
        (l.asn ? '<code>' + esc(l.asn) + '</code> ' : '') +
        esc(l.isp || l.org || '未知')
    );
    if (l.timezone) {
      lines.push('落地时区：<code>' + esc(l.timezone) + '</code>');
    }

    // 3. Cloudflare WARP 与边缘节点 (可莉 WARP节点查询移植)
    if (cf) {
      lines.push('');
      lines.push('<b>▸ Cloudflare 边缘与 WARP</b>');
      const warpBadge =
        cf.warp === 'plus'
          ? colorSpan('WARP+ 启用 (Cloudflare 托管出站)', COLORS.purple, true)
          : cf.warp === 'on'
            ? colorSpan('WARP 普通版 (套用 CF 免费出口)', COLORS.warning, true)
            : colorSpan('未套用 WARP (节点原生直出)', COLORS.success, true);
      lines.push('WARP 状态：' + warpBadge);
      if (cf.colo) {
        const coloDesc = cf.coloCity ? cf.colo + ' · ' + cf.coloCity : cf.colo;
        const proto = [cf.http, cf.tls].filter(Boolean).join(' / ');
        lines.push(
          '边缘机房：<code>' + esc(coloDesc) + '</code>' + (proto ? ' (' + esc(proto) + ')' : '')
        );
      }
    }

    lines.push('');
    lines.push(renderFooterNote(probe));
    return lines.join('<br>');
  }

  /**
   * 视图 2：🛡️ 节点纯净度深度检测 (专注双 ISP 血统 + 三源欺诈风控 + RBL 黑名单审计)
   */
  function renderPuritySheetHTML({ nodeName, nodeInfo, probe }) {
    const l = probe.landing;
    const p = probe.purity;
    const pc = probe.proxyCheck;
    const sc = probe.ipScore;
    const flag = getFlagEmoji(l.countryCode || (p && p.countryCode));
    const lines = renderCompactHeader(nodeName, nodeInfo, '');

    lines.push(
      '检测目标：<code>' +
        esc(maskIPString(l.ip, CFG.maskIP)) +
        '</code> · ' +
        flag +
        ' ' +
        esc(deduplicateGeoParts([l.country, l.city]).join(' ')) +
        (l.asn ? ' <code>[' + esc(l.asn) + ']</code>' : '')
    );

    if (p) {
      // 综合风险加权 (结合 ipapi.is + proxycheck.io + ip-score RBL)
      let combinedRisk = p.riskIndex;
      if (pc && pc.risk !== null) {
        combinedRisk = Math.round(combinedRisk * 0.65 + pc.risk * 0.35);
      }
      if (sc && sc.listedCount > 0) {
        combinedRisk = Math.min(100, combinedRisk + sc.listedCount * 12);
      }
      const cleanScore = Math.max(0, 100 - combinedRisk);
      const rColor =
        combinedRisk <= 15
          ? COLORS.success
          : combinedRisk <= 35
            ? COLORS.cyan
            : combinedRisk <= 60
              ? COLORS.warning
              : COLORS.danger;
      const rLabel =
        combinedRisk <= 15
          ? '极度纯净'
          : combinedRisk <= 35
            ? '纯净良好'
            : combinedRisk <= 60
              ? '轻度风险'
              : '高危预警';

      lines.push('');
      lines.push('<b>▸ IP 血统与原生属性</b>');
      lines.push('线路血统：' + colorSpan(p.lineageLabel, levelColor(p.lineageLevel), true));
      lines.push(
        '双维类型：ASN <code>' +
          esc(p.asnTypeText) +
          '</code> ｜ 运营 <code>' +
          esc(p.companyTypeText) +
          '</code>'
      );
      if (p.broadcastText) {
        lines.push(
          '归属判定：' +
            colorSpan(p.broadcastText, p.isNativeGeo ? COLORS.success : COLORS.warning, p.isNativeGeo)
        );
      }
      if (p.companyNetwork || p.asnRoute) {
        lines.push(
          'WHOIS 段：<code>' +
            esc(p.companyNetwork || p.asnRoute) +
            '</code>' +
            (p.rir ? ' · <code>' + esc(p.rir) + '</code>' : '')
        );
      }

      lines.push('');
      lines.push('<b>▸ 三源风控与黑名单审计</b>');
      lines.push(
        '纯净指数：' +
          colorSpan(scoreBar(cleanScore) + ' ' + cleanScore + '分 · ' + rLabel, rColor, true)
      );
      if (p.primaryScore) {
        const s = p.primaryScore;
        lines.push(
          'ipapi 评分：' +
            colorSpan(s.tagZh + (s.percentText ? ' (滥用率 ' + s.percentText + ')' : ''), levelColor(s.level), true)
        );
      }
      if (pc) {
        const pcColor = pc.proxy ? COLORS.warning : COLORS.success;
        const pcText =
          pc.typeZh +
          (pc.risk !== null ? ' · 风险值 ' + pc.risk + '/100' : '') +
          (pc.proxy ? ' · 检出代理特征' : ' · 未检出公开代理');
        lines.push('ProxyCheck：' + colorSpan(pcText, pcColor, false));
      }
      if (sc) {
        const blOk = sc.listedCount === 0;
        const blTxt = blOk
          ? '0 / ' + sc.totalBlacklists + ' 库命中 (全部通过 ✓)'
          : sc.listedCount + ' / ' + sc.totalBlacklists + ' 命中 (' + sc.listedNames.join(', ') + ')';
        lines.push('RBL 黑名单：' + colorSpan(blTxt, blOk ? COLORS.success : COLORS.danger, true));
      }

      const f = p.flags;
      const tags = [];
      if (f.datacenter) tags.push(colorSpan('IDC机房', COLORS.warning, true));
      if (f.vpn) tags.push(colorSpan('VPN特征', COLORS.warning, true));
      if (f.proxy) tags.push(colorSpan('公开代理', COLORS.danger, true));
      if (f.abuser) tags.push(colorSpan('历史滥用', COLORS.danger, true));
      if (f.tor) tags.push(colorSpan('Tor出口', COLORS.danger, true));
      if (f.crawler) tags.push(colorSpan('爬虫标记', COLORS.warning, true));
      if (f.mobile) tags.push(colorSpan('移动蜂窝', COLORS.success, true));
      lines.push(
        '风险画像：' +
          (tags.length > 0 ? tags.join(' · ') : colorSpan('零风险标记 (极少弹验证码 ✓)', COLORS.success, true))
      );

      lines.push('');
      const verdict =
        combinedRisk <= 20 && p.lineageLevel === 'excellent'
          ? { t: '🌟 顶级原生家宽，强烈推荐用于主力 AI 账号与严苛风控业务', c: COLORS.success }
          : combinedRisk <= 40
            ? { t: '👍 信誉良好，Google 搜索免验证码，适合日常流媒体与 AI 使用', c: COLORS.cyan }
            : combinedRisk <= 65
              ? { t: '⚠️ 共享机房特征明显，高频请求偶发 Cloudflare / Google 验证', c: COLORS.warning }
              : { t: '🚨 欺诈/黑名单权重偏高，易触发风控封禁，仅建议普通浏览', c: COLORS.danger };
      lines.push(colorSpan(verdict.t, verdict.c, false));
    } else {
      lines.push('');
      lines.push('<b>▸ 风控核验结果</b>');
      if (pc) {
        lines.push(
          'ProxyCheck：' +
            colorSpan(
              pc.typeZh + (pc.risk !== null ? ' · 风险值 ' + pc.risk + '/100' : ''),
              pc.proxy ? COLORS.warning : COLORS.cyan,
              true
            )
        );
      } else {
        lines.push(colorSpan('风控数据库响应超时，请稍后重试或调大超时时间', COLORS.warning, false));
      }
    }

    lines.push('');
    lines.push(renderFooterNote(probe));
    return lines.join('<br>');
  }

  function formatUnlockRow(item) {
    const icon =
      item.state === 'yes'
        ? '✅'
        : item.state === 'partial'
          ? '⚠️'
          : item.state === 'no'
            ? '❌'
            : '➖';
    const col =
      item.state === 'yes'
        ? COLORS.success
        : item.state === 'partial'
          ? COLORS.warning
          : item.state === 'no'
            ? COLORS.danger
            : COLORS.muted;
    const padded = (item.name + '       ').slice(0, 8);
    return icon + ' <code>' + esc(padded) + '</code> ' + colorSpan(item.text, col, item.state === 'yes');
  }

  /**
   * 视图 3：🎬 流媒体与 AI 解锁检测 (移植自可莉 Node_detection_tool)
   */
  function renderUnlockSheetHTML({ nodeName, nodeInfo, probe }) {
    const l = probe.landing || {};
    const flag = getFlagEmoji(l.countryCode);
    const lines = renderCompactHeader(nodeName, nodeInfo, '');

    const allItems = [].concat(probe.aiItems || [], probe.mediaItems || []);
    const passCount = allItems.filter((x) => x.state === 'yes' || x.state === 'partial').length;

    if (l.ip) {
      lines.push(
        '落地出口：<code>' +
          esc(maskIPString(l.ip, CFG.maskIP)) +
          '</code> · ' +
          flag +
          ' ' +
          esc(l.country || l.countryCode || '') +
          ' · 解锁 <b>' +
          passCount +
          '/' +
          allItems.length +
          '</b>'
      );
    }

    lines.push('');
    lines.push('<b>▸ AI 大模型解锁</b>');
    (probe.aiItems || []).forEach((it) => lines.push(formatUnlockRow(it)));

    lines.push('');
    lines.push('<b>▸ 国际流媒体解锁</b>');
    (probe.mediaItems || []).forEach((it) => lines.push(formatUnlockRow(it)));

    lines.push('');
    lines.push(renderFooterNote(probe));
    return lines.join('<br>');
  }

  // ============================================================================
  // 10. Safari 浏览器网页卡片 / JSON 接口 (http://net-lsp-x.com)
  // ============================================================================

  function parseQueryFromURL(rawURL) {
    const q = {};
    const idx = String(rawURL || '').indexOf('?');
    if (idx < 0) return q;
    String(rawURL)
      .slice(idx + 1)
      .split('#')[0]
      .split('&')
      .forEach((kv) => {
        if (!kv) return;
        const eq = kv.indexOf('=');
        if (eq < 0) q[decodeURIComponent(kv)] = '1';
        else {
          try {
            q[decodeURIComponent(kv.slice(0, eq))] = decodeURIComponent(kv.slice(eq + 1));
          } catch (_) {
            q[kv.slice(0, eq)] = kv.slice(eq + 1);
          }
        }
      });
    return q;
  }

  function renderWebPortalHTML(domestic, infoProbe, purity, targetNode) {
    const l = infoProbe.landing;
    const cf = infoProbe.cfTrace;
    const flag = getFlagEmoji(l.countryCode || '');
    const geo = deduplicateGeoParts([l.country, l.region, l.city]).join(' ');
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>节点全能诊断 · Clash-Client</title>
<style>
  :root { --bg:#f4f6fb; --card:#fff; --text:#111827; --sub:#6b7280; --border:#e5e7eb; --accent:#3b82f6; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0b0f19; --card:#151b2b; --text:#f3f4f6; --sub:#9ca3af; --border:#263047; --accent:#60a5fa; }
  }
  * { box-sizing:border-box; }
  body { margin:0; padding:20px 16px 40px; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif; }
  .wrap { max-width:560px; margin:0 auto; }
  .hero { margin-bottom:16px; }
  .hero h1 { font-size:20px; margin:0 0 4px; }
  .hero p { margin:0; font-size:13px; color:var(--sub); }
  .card { background:var(--card); border:1px solid var(--border); border-radius:16px; padding:15px 18px; margin-bottom:12px; }
  .card h2 { margin:0 0 10px; font-size:13px; color:var(--accent); letter-spacing:0.04em; }
  .row { display:flex; justify-content:space-between; gap:12px; padding:6px 0; border-bottom:1px dashed var(--border); font-size:14px; }
  .row:last-child { border-bottom:none; }
  .k { color:var(--sub); flex-shrink:0; }
  .v { font-weight:600; text-align:right; word-break:break-all; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; background:rgba(59,130,246,0.1); padding:2px 6px; border-radius:6px; font-size:13px; }
  .foot { text-align:center; font-size:12px; color:var(--sub); margin-top:14px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>🌐 节点网络与纯净度诊断</h1>
    <p>${esc(targetNode ? '指定节点：' + targetNode : '当前活跃代理实时检测')} · ${infoProbe.elapsedMs} ms</p>
  </div>
  ${domestic && domestic.ip ? `<div class="card"><h2>🇨🇳 本地直连</h2>
    <div class="row"><span class="k">直连 IP</span><span class="v"><code>${esc(maskIPString(domestic.ip, CFG.maskIP))}</code></span></div>
    <div class="row"><span class="k">归属地</span><span class="v">${esc([domestic.location, domestic.isp].filter(Boolean).join(' '))}</span></div>
  </div>` : ''}
  <div class="card">
    <h2>${flag} 代理落地与边缘</h2>
    <div class="row"><span class="k">落地 IPv4</span><span class="v"><code>${esc(maskIPString(l.ip, CFG.maskIP))}</code></span></div>
    <div class="row"><span class="k">位置</span><span class="v">${flag} ${esc(geo || l.countryCode || '-')}</span></div>
    <div class="row"><span class="k">运营商</span><span class="v">${esc([l.asn, l.isp || l.org].filter(Boolean).join(' '))}</span></div>
    ${cf ? `<div class="row"><span class="k">CF 边缘 / WARP</span><span class="v"><code>${esc(cf.colo + (cf.coloCity ? '·' + cf.coloCity : ''))}</code> · WARP ${esc(cf.warp)}</span></div>` : ''}
  </div>
  ${purity ? `<div class="card"><h2>🛡️ 纯净度评估</h2>
    <div class="row"><span class="k">线路血统</span><span class="v">${esc(purity.lineageLabel)}</span></div>
    <div class="row"><span class="k">双维属性</span><span class="v">${esc(purity.asnTypeText + ' / ' + purity.companyTypeText)}</span></div>
    ${purity.broadcastText ? `<div class="row"><span class="k">归属判定</span><span class="v">${esc(purity.broadcastText)}</span></div>` : ''}
    <div class="row"><span class="k">纯净指数</span><span class="v">${Math.max(0, 100 - purity.riskIndex)} / 100</span></div>
  </div>` : ''}
  <div class="foot">支持 ?node=节点名 指定任意节点或 ?format=json 输出 JSON</div>
</div>
</body>
</html>`;
  }

  async function handleHTTPRequest() {
    const reqURL = ($request && $request.url) || '';
    const pathMatch = reqURL.match(/^https?:\/\/[^/?#]+([^?#]*)/i);
    const pathname = (pathMatch && pathMatch[1]) || '/';
    const query = parseQueryFromURL(reqURL);

    if (pathname === BRIDGE_CHECK_PATH) {
      const targetNode = query.node || '';
      const mode = normalizeMode(query.mode || 'info');
      try {
        const result = await executeModeProbe(targetNode || undefined, mode);
        result.fromClashTunnelBridge = true;
        $done({
          response: {
            status: 200,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
            body: JSON.stringify(result),
          },
        });
      } catch (e) {
        $done({
          response: {
            status: 200,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
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

    try {
      const targetNode = query.node || undefined;
      const [domestic, infoProbe] = await Promise.all([
        CFG.showDomestic ? queryDomesticDirect(true) : Promise.resolve(null),
        executeModeProbe(targetNode, 'info'),
      ]);
      const purity = await queryPurityIPAPI(infoProbe.landing.ip, targetNode);

      if (query.format === 'json' || pathname === '/json' || pathname === '/api') {
        $done({
          response: {
            status: 200,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' },
            body: JSON.stringify({ ok: true, targetNode: targetNode || null, domestic, probe: infoProbe, purity }, null, 2),
          },
        });
        return;
      }

      $done({
        response: {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
          body: renderWebPortalHTML(domestic, infoProbe, purity, targetNode),
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
  // 11. App 侧执行入口：长按三大菜单 / 模块面板 / 网络切换事件
  // ============================================================================

  async function handleNodeLongPress(nodeName, nodeInfo) {
    recoverDanglingPolicyIfAny();
    const mode = CFG.mode; // 'info' | 'purity' | 'unlock'
    const titleMap = {
      info: '节点链路与入口查询',
      purity: '节点纯净度深度检测',
      unlock: '流媒体与 AI 解锁检测',
    };
    const sheetTitle = titleMap[mode] || '节点网络信息查询';

    // 仅「链路与入口查询」才需要查国内直连与中转入口，其余两项零冗余提速！
    const needEntrance = mode === 'info';
    const domesticPromise =
      mode === 'info' && CFG.showDomestic
        ? queryDomesticDirect(false).catch(() => null)
        : Promise.resolve(null);

    let probe;
    let entrance = null;
    try {
      const res = await runProbeWithEntranceCapture(nodeName, needEntrance, () =>
        tryTunnelBridgeProbe(nodeName, mode)
      );
      probe = res.probe;
      entrance = res.entrance;
    } catch (bridgeErr) {
      log('Bridge unavailable (' + (bridgeErr.message || bridgeErr) + '), falling back to $config...');
      const domesticBeforeSwitch = await domesticPromise;
      try {
        const res = await runProbeWithEntranceCapture(nodeName, needEntrance, () =>
          fallbackConfigSwitchProbe(nodeName, mode)
        );
        probe = res.probe;
        entrance = res.entrance;
      } catch (fallbackErr) {
        $done({
          title: sheetTitle,
          htmlMessage:
            '<b>▍查询失败</b><br>' +
            '目标节点：' + colorSpan(nodeName, COLORS.primary, true) +
            '<br>原因说明：' + colorSpan(String(fallbackErr.message || fallbackErr), COLORS.danger, false) +
            '<br><br><span style="color:' + COLORS.muted + '">💡 建议开启「模块」页顶部的「HTTPS 解密」开关实现零切换直测。</span>',
        });
        return;
      }

      if (probe && probe.needsEngineWarning) {
        $done({
          title: sheetTitle,
          htmlMessage:
            colorSpan(probe.error, COLORS.warning, true) +
            '<br><br>1. 推荐：开启「模块」页顶部 <b>HTTPS 解密</b> 开关（零切换直测）。<br>2. 或在模块「设置」开启 <b>自动临时切换测速</b>。',
        });
        return;
      }

      const html = renderByMode(mode, { nodeName, nodeInfo, domestic: domesticBeforeSwitch, entrance, probe });
      $done({ title: sheetTitle, htmlMessage: html });
      return;
    }

    const domestic = await domesticPromise;
    const html = renderByMode(mode, { nodeName, nodeInfo, domestic, entrance, probe });
    $done({ title: sheetTitle, htmlMessage: html });
  }

  function renderByMode(mode, ctx) {
    if (mode === 'purity') return renderPuritySheetHTML(ctx);
    if (mode === 'unlock') return renderUnlockSheetHTML(ctx);
    return renderInfoSheetHTML(ctx);
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
            modeInfo = mName + (pol ? ' · ' + pol : '');
          }
        } catch (_) {}
      }

      const [domestic, probeWrap] = await Promise.all([
        CFG.showDomestic ? queryDomesticDirect(false).catch(() => null) : Promise.resolve(null),
        runProbeWithEntranceCapture('', true, () => executeModeProbe(undefined, 'panel')),
      ]);
      const probe = probeWrap.probe;
      const entrance = probeWrap.entrance;
      const l = probe.landing;
      const cf = probe.cfTrace;

      const lines = [];
      if (modeInfo) lines.push('模式：' + modeInfo);
      if (domestic && domestic.ip) {
        lines.push('直连：' + maskIPString(domestic.ip, CFG.maskIP) + ' (' + [domestic.location, domestic.isp].filter(Boolean).join(' ') + ')');
      }
      if (entrance && entrance.status === 'ok' && entrance.entranceIP && entrance.entranceIP !== l.ip) {
        const eg = entrance.geo;
        const eTxt = eg ? [eg.city || eg.region || eg.country, eg.ispDisplay || eg.isp].filter(Boolean).join(' ') : '';
        lines.push('入口：' + maskIPString(entrance.entranceIP, CFG.maskIP) + (eTxt ? ' (' + eTxt + ')' : ''));
      }
      const flag = getFlagEmoji(l.countryCode);
      const geo = deduplicateGeoParts([l.country, l.city]).join(' ');
      lines.push('落地：' + maskIPString(l.ip, CFG.maskIP) + ' (' + flag + ' ' + (geo || l.countryCode || '-') + ')');
      lines.push('网络：' + [l.asn, l.isp || l.org].filter(Boolean).join(' ') + (cf && cf.colo ? ' · CF-' + cf.colo : ''));

      $done({
        title: '当前网络出口信息',
        content: lines.join('\n'),
        icon: 'globe.asia.australia',
        'icon-color': '#10B981',
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
        notify(
          '🌐 网络出口已更新',
          flag + ' 落地：' + maskIPString(landing.ip, CFG.maskIP) + ' (' + geo + ')',
          (domestic && domestic.ip ? '🇨🇳 直连：' + maskIPString(domestic.ip, CFG.maskIP) + ' ' + (domestic.shortTag || '') + '\n' : '') +
            '🏢 ' + [landing.asn, landing.isp || landing.org].filter(Boolean).join(' ')
        );
      }
    } catch (_) {}
    $done({});
  }

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
      $done({
        title: '节点检测异常',
        content: String((err && err.message) || err),
        htmlMessage: colorSpan('执行异常：' + String((err && err.message) || err), COLORS.danger, true),
      });
    }
  })();
})();
