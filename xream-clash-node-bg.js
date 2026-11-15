/**
 * xream & Kelee Node Suite — ProjectClash/Clash-Client 全能节点检测套件 (v2.5.1 · BG-Tunnel-Event)
 *
 * 深度融合：
 * 1. xream/scripts (ip-info / net-lsp-x / ip-whois / ip-score)
 * 2. 可莉插件仓库 (Node_detection_tool 流媒体&AI解锁 / WARP_Node_Query / NodeLinkCheck 代理链路)
 *
 * 专为 ProjectClash/Clash-Client (iOS / macOS) 三大独立长按菜单设计（轻量化低并发架构、高信噪比排版、软熔断防隔离）：
 * - 🌐 节点链路与入口查询 (MODE=info)  : 本地直连 ➔ 中转入口(含ASN) ➔ 落地双栈 ➔ BGP上游骨干 ➔ CF边缘 & WARP
 * - 🛡️ 节点纯净度深度检测 (MODE=purity): 双 ISP 原生家宽血统 + 广播/原生判定 + BGP上游 + 三源风控/RBL审计
 * - 🎬 流媒体与 AI 解锁检测 (MODE=unlock): ChatGPT(Web+iOS) / Claude / Gemini / Netflix / YouTube / Disney+ / TikTok / 动画疯
 */

(function () {
  'use strict';

  const BRIDGE_HOST = 'net-lsp-x.com';
  const BRIDGE_CHECK_PATH = '/__clash_node_check';
  const STATE_RESTORE_KEY = 'xream_clash_pending_restore_v1';
  const LAST_EVENT_KEY = 'xream_clash_last_net_event_v1';
  const IP_CACHE_KEY = 'xream_clash_ip_cache_v1';
  const IP_CACHE_MAX = 16;
  const CACHE_TTL_BG_MS = 6 * 3600 * 1000; // 后台切网与面板复用缓存 6 小时
  const CACHE_TTL_FG_MS = 10 * 60 * 1000;  // 手动链路查询对静态 BGP/入口归属短缓存 10 分钟

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

  let _scriptSettled = false;
  let _softDeadlineTimer = null;

  function log(msg) {
    try {
      console.log('[clash-suite] ' + msg);
    } catch (_) {}
  }

  /**
   * 幂等安全结束器：确保全局只调用一次 $done，并在宿主看门狗到期前清理所有内部定时器，杜绝触发 SHA-256 隔离
   */
  function safeDone(payload) {
    if (_scriptSettled) return;
    _scriptSettled = true;
    if (_softDeadlineTimer) {
      clearTimeout(_softDeadlineTimer);
      _softDeadlineTimer = null;
    }
    try {
      $done(payload === undefined ? {} : payload);
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

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  /**
   * 并发限流执行器：将并发数严格控制在 iOS PacketTunnel (background_cap=10 / maximumPendingRequests=8) 红线内
   */
  async function runWithConcurrency(taskFns, limit) {
    const maxWorkers = Math.max(1, Math.min(limit || 3, taskFns.length));
    const results = new Array(taskFns.length);
    let nextIdx = 0;
    async function worker() {
      while (!_scriptSettled && nextIdx < taskFns.length) {
        const cur = nextIdx++;
        results[cur] = await taskFns[cur]();
      }
    }
    const workers = [];
    for (let i = 0; i < maxWorkers; i++) workers.push(worker());
    await Promise.all(workers);
    return results;
  }

  /**
   * 轻量级按 IP 维度的 LRU 元数据缓存（避免固定出口切网/刷面板时重复拉取 55KB BGP 表与风控接口）
   */
  function readIPCache(ip, field, maxAgeMs) {
    if (!ip || !field || !maxAgeMs || maxAgeMs <= 0) return null;
    try {
      const raw = storeRead(IP_CACHE_KEY);
      if (!raw) return null;
      const bag = JSON.parse(raw);
      const rec = bag && bag.entries && bag.entries[ip];
      if (!rec || !rec[field]) return null;
      const ts = Number((rec.tsMap && rec.tsMap[field]) || rec.ts || 0);
      if (Date.now() - ts > maxAgeMs) return null;
      return rec[field];
    } catch (_) {
      return null;
    }
  }

  function writeIPCache(ip, field, val) {
    if (!ip || !field || !val) return;
    try {
      const raw = storeRead(IP_CACHE_KEY);
      let bag = null;
      if (raw) {
        try {
          bag = JSON.parse(raw);
        } catch (_) {}
      }
      if (!bag || typeof bag !== 'object' || !bag.entries || typeof bag.entries !== 'object') {
        bag = { entries: {} };
      }
      const prev = bag.entries[ip] && typeof bag.entries[ip] === 'object' ? bag.entries[ip] : {};
      const now = Date.now();
      const tsMap = Object.assign({}, prev.tsMap || {}, { [field]: now });
      bag.entries[ip] = Object.assign({}, prev, { [field]: val, ts: now, tsMap });

      const keys = Object.keys(bag.entries);
      if (keys.length > IP_CACHE_MAX) {
        keys
          .sort((a, b) => Number(bag.entries[a].ts || 0) - Number(bag.entries[b].ts || 0))
          .slice(0, keys.length - IP_CACHE_MAX)
          .forEach((k) => {
            delete bag.entries[k];
          });
      }
      storeWrite(IP_CACHE_KEY, JSON.stringify(bag));
    } catch (_) {}
  }

  function httpRequest(method, options, timeoutOverride) {
    if (_scriptSettled) {
      return Promise.reject(new Error('Aborted after soft deadline'));
    }
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
          if (settled || _scriptSettled) {
            clearTimeout(timer);
            return;
          }
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
    if (/kingsoft|ksyun|金山云/i.test(combined)) return '金山云 BGP';
    if (/qingcloud|青云/i.test(combined)) return '青云 BGP';
    if (/ctyun|天翼云/i.test(combined)) return '天翼云 BGP';
    if (/ecloud|移动云/i.test(combined)) return '移动云 BGP';
    if (/cucloud|联通云/i.test(combined)) return '联通云 BGP';
    if (/baidu|百度/i.test(combined)) return '百度云 BGP';
    if (/jdcloud|京东/i.test(combined)) return '京东云 BGP';
    if (/cloudflare/i.test(combined)) return 'Cloudflare';
    if (/zenlayer/i.test(combined)) return 'Zenlayer 专网';
    if (/xtom/i.test(combined)) return 'xTom 专网';
    if (/misaka/i.test(combined)) return 'Misaka 专网';
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
    const v6Timeout = Math.min(CFG.timeoutMs, 3000);
    const t0 = Date.now();
    try {
      const j = await fetchJSON(buildOutboundOpts('https://api-ipv6.ip.sb/geoip', targetNode), v6Timeout);
      if (j && j.ip && j.ip.includes(':')) {
        return { ip: j.ip, countryCode: j.country_code || '' };
      }
    } catch (_) {
      // 若首个 IPv6 接口已耗尽超时窗口，说明节点无 IPv6 出站路由，直接跳过二次超时等待
      if (Date.now() - t0 >= v6Timeout - 200) return null;
    }
    try {
      const res = await httpRequest('get', buildOutboundOpts('https://6.ipw.cn', targetNode), 2200);
      const ip = res.body.trim();
      if (ip.includes(':')) return { ip, countryCode: '' };
    } catch (_) {}
    return null;
  }

  /**
   * 移植自可莉仓库「WARP节点查询」：探测 Cloudflare 边缘机房 POP 与 WARP 出站套壳状态
   */
  async function queryCloudflareTrace(targetNode) {
    const traceTimeout = Math.min(CFG.timeoutMs, 3800);
    const urls = ['https://www.cloudflare.com/cdn-cgi/trace', 'https://1.1.1.1/cdn-cgi/trace'];
    for (const u of urls) {
      const t0 = Date.now();
      try {
        const res = await httpRequest('get', buildOutboundOpts(u, targetNode), traceTimeout);
        if (res.status >= 200 && res.status < 400 && res.body.includes('colo=')) {
          const kv = parseTraceMap(res.body);
          const colo = (kv.colo || '').toUpperCase();
          const warp = (kv.warp || 'off').toLowerCase();
          return {
            colo,
            coloCity: CF_COLO_MAP[colo] || '',
            warp, // 'off' | 'on' | 'plus'
          };
        }
      } catch (_) {
        if (Date.now() - t0 >= traceTimeout - 200) break;
      }
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

  async function queryPurityIPAPI(ip, targetNode, timeoutOverride, cacheTTLMs) {
    if (!ip) return null;
    if (cacheTTLMs && cacheTTLMs > 0) {
      const cached = readIPCache(ip, 'purity', cacheTTLMs);
      if (cached) return cached;
    }
    let url = 'https://api.ipapi.is/?q=' + encodeURIComponent(ip);
    if (CFG.ipapiKey) url += '&key=' + encodeURIComponent(CFG.ipapiKey);
    try {
      const j = await fetchJSON(buildOutboundOpts(url, targetNode), timeoutOverride || CFG.timeoutMs);
      const parsed = parseIPAPIIs(j);
      if (parsed) writeIPCache(ip, 'purity', parsed);
      return parsed;
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
        };
      }
    } catch (e) {
      log('ip-score error: ' + (e.message || e));
    }
    return null;
  }

  // ============================================================================
  // 5B. BGP 宣告前缀与全球上游骨干网窥探引擎 (基于 RIPE NCC RIS 实时路由表)
  // ============================================================================

  const BGP_ASN_DB = {
    // 中国大陆精品优化与三大骨干网
    4809: { name: '电信 CN2', tier: 'cn-opt' },
    23764: { name: '电信 CTGNet', tier: 'cn-opt' },
    4134: { name: '电信 163', tier: 'cn-std' },
    4812: { name: '上海电信', tier: 'cn-std' },
    4847: { name: '北京电信', tier: 'cn-std' },
    9929: { name: '联通 9929', tier: 'cn-opt' },
    10099: { name: '联通 CUG', tier: 'cn-opt' },
    4837: { name: '联通 4837', tier: 'cn-std' },
    4808: { name: '北京联通', tier: 'cn-std' },
    58807: { name: '移动 CMIN2', tier: 'cn-opt' },
    58453: { name: '移动 CMI', tier: 'cn-opt' },
    9808: { name: '移动骨干', tier: 'cn-std' },
    56040: { name: '广东移动', tier: 'cn-std' },
    56046: { name: '江苏移动', tier: 'cn-std' },
    56048: { name: '北京移动', tier: 'cn-std' },
    4538: { name: '教育网 CERNET', tier: 'cn-std' },
    23910: { name: '教育网 CERNET2', tier: 'cn-opt' },
    7497: { name: '科技网 CSTNET', tier: 'cn-std' },

    // 国际顶级 Tier-1 骨干运营商
    3356: { name: 'Lumen (Level3)', tier: 'tier1' },
    1299: { name: 'Arelion (Telia)', tier: 'tier1' },
    2914: { name: 'NTT', tier: 'tier1' },
    174: { name: 'Cogent', tier: 'tier1' },
    3257: { name: 'GTT', tier: 'tier1' },
    6453: { name: 'Tata', tier: 'tier1' },
    3491: { name: 'PCCW 电讯盈科', tier: 'tier1' },
    6762: { name: 'Sparkle', tier: 'tier1' },
    6461: { name: 'Zayo', tier: 'tier1' },
    3320: { name: 'Deutsche Telekom', tier: 'tier1' },
    5511: { name: 'Orange', tier: 'tier1' },
    12956: { name: 'Telxius', tier: 'tier1' },
    701: { name: 'Verizon', tier: 'tier1' },
    7018: { name: 'AT&T', tier: 'tier1' },
    6830: { name: 'Liberty Global', tier: 'tier1' },

    // 亚太核心运营商与对华友好骨干
    17676: { name: '日本软银 SoftBank', tier: 'apac-opt' },
    4725: { name: '日本软银 ODN', tier: 'apac-opt' },
    2497: { name: '日本 IIJ', tier: 'apac-opt' },
    2516: { name: '日本 KDDI', tier: 'apac' },
    4713: { name: '日本 NTT OCN', tier: 'apac' },
    2527: { name: '日本 So-net', tier: 'apac' },
    7506: { name: '日本 GMO', tier: 'apac' },
    2500: { name: '日本 WIDE', tier: 'apac' },
    4760: { name: '香港 HKT', tier: 'apac' },
    9304: { name: '香港 HGC', tier: 'apac' },
    9269: { name: '香港 HKBN', tier: 'apac' },
    4515: { name: '香港 PCCW', tier: 'apac' },
    10118: { name: '香港 CMHK', tier: 'apac' },
    4609: { name: '澳门 CTM', tier: 'apac' },
    3462: { name: '中华电信 HiNet', tier: 'apac' },
    9924: { name: '台湾大哥大 TFN', tier: 'apac' },
    4780: { name: '台湾远传 Seednet', tier: 'apac' },
    4637: { name: 'Telstra 澳洲电讯', tier: 'apac' },
    7473: { name: 'Singtel 新电信', tier: 'apac' },
    4657: { name: 'StarHub 星和', tier: 'apac' },
    24482: { name: 'SG.GS 新加坡骨干', tier: 'apac' },
    18106: { name: 'ViewQwest', tier: 'apac' },
    4766: { name: '韩国 KT', tier: 'apac' },
    9318: { name: '韩国 SKB', tier: 'apac' },
    3786: { name: '韩国 LG DACOM', tier: 'apac' },

    // 知名互联网交换中心 (IXP)
    4635: { name: '香港 HKIX', tier: 'ixp' },
    4777: { name: '日本 JPIX', tier: 'ixp' },
    58952: { name: 'SGIX 新加坡交换', tier: 'ixp' },
    59105: { name: 'BBIX 亚太交换', tier: 'ixp' },
    24115: { name: 'Equinix IX', tier: 'ixp' },

    // 国际知名 Transit / 专线聚合 / 云厂商
    6939: { name: 'HE', tier: 'transit' },
    9002: { name: 'RETN', tier: 'transit' },
    137409: { name: 'GSL Networks', tier: 'transit' },
    33891: { name: 'Core-Backbone', tier: 'transit' },
    906: { name: 'DMIT', tier: 'agg' },
    54574: { name: 'DMIT 中国优化', tier: 'cn-opt' },
    21859: { name: 'Zenlayer', tier: 'agg' },
    3214: { name: 'xTom', tier: 'agg' },
    924: { name: 'xTom', tier: 'agg' },
    57695: { name: 'Misaka', tier: 'agg' },
    40065: { name: 'CeraNetworks', tier: 'agg' },
    136766: { name: 'Kirino', tier: 'agg' },
    141995: { name: 'Kirino', tier: 'agg' },
    13335: { name: 'Cloudflare', tier: 'cloud' },
    16509: { name: 'AWS', tier: 'cloud' },
    15169: { name: 'Google', tier: 'cloud' },
    8075: { name: 'Microsoft Azure', tier: 'cloud' },
    45102: { name: '阿里云国际', tier: 'cloud' },
    37963: { name: '阿里云', tier: 'cloud' },
    132203: { name: '腾讯云国际', tier: 'cloud' },
    45090: { name: '腾讯云', tier: 'cloud' },
    20473: { name: 'Vultr (Choopa)', tier: 'cloud' },
    60068: { name: 'CDN77 (DataCamp)', tier: 'cloud' },
    16276: { name: 'OVHcloud', tier: 'cloud' },
    24940: { name: 'Hetzner', tier: 'cloud' },
    14061: { name: 'DigitalOcean', tier: 'cloud' },
    63949: { name: 'Akamai (Linode)', tier: 'cloud' },
  };

  function lookupBGPASN(asnNum) {
    const n = Number(String(asnNum).replace(/^AS/i, ''));
    if (!Number.isFinite(n) || n <= 0) return { num: 0, asn: '', name: '', tier: 'other' };
    const rec = BGP_ASN_DB[n];
    return {
      num: n,
      asn: 'AS' + n,
      name: rec ? rec.name : '',
      tier: rec ? rec.tier : 'other',
    };
  }

  function parseBGPState(j) {
    const data = (j && j.data) || {};
    const routes = Array.isArray(data.bgp_state) ? data.bgp_state : [];
    if (routes.length === 0) return null;

    const prefix = String(data.resource || '');
    const originCounts = new Map();
    const hop1Counts = new Map();
    const hop2ByHop1 = new Map();
    const nearUpstreams = new Set();
    let totalMultiHop = 0;

    for (let i = 0; i < routes.length; i++) {
      const rawPath = routes[i] && Array.isArray(routes[i].path) ? routes[i].path : [];
      const path = [];
      for (let k = 0; k < rawPath.length; k++) {
        const v = rawPath[k];
        if (typeof v === 'number' && v > 0 && path[path.length - 1] !== v) {
          path.push(v);
        }
      }
      if (path.length === 0) continue;

      const origin = path[path.length - 1];
      originCounts.set(origin, (originCounts.get(origin) || 0) + 1);

      if (path.length >= 2) {
        totalMultiHop++;
        const h1 = path[path.length - 2];
        hop1Counts.set(h1, (hop1Counts.get(h1) || 0) + 1);
        nearUpstreams.add(h1);

        if (path.length >= 3) {
          const h2 = path[path.length - 3];
          if (!hop2ByHop1.has(h1)) hop2ByHop1.set(h1, new Map());
          const sub = hop2ByHop1.get(h1);
          sub.set(h2, (sub.get(h2) || 0) + 1);

          const h1Tier = lookupBGPASN(h1).tier;
          if (h1Tier === 'agg' || h1Tier === 'other' || h1Tier === 'cloud') {
            nearUpstreams.add(h2);
            if (path.length >= 4 && (lookupBGPASN(h2).tier === 'agg' || h2 === 54574)) {
              nearUpstreams.add(path[path.length - 4]);
            }
          }
        }
      }
    }

    const sortedOrigins = [...originCounts.entries()].sort((a, b) => b[1] - a[1]);
    const originNum = sortedOrigins.length > 0 ? sortedOrigins[0][0] : 0;
    const originInfo = lookupBGPASN(originNum);

    if (totalMultiHop === 0) {
      return {
        prefix,
        originASN: originInfo.asn,
        originName: originInfo.name,
        peerCount: routes.length,
        gradeLabel: '🌐 Anycast 自治直连路由',
        gradeShort: 'Anycast 自治直连',
        gradeLevel: 'good',
        aggregator: null,
        upstreams: [],
        shortNames: originInfo.name || originInfo.asn,
        cnOptNames: [],
      };
    }

    const hop1Sorted = [...hop1Counts.entries()].sort((a, b) => b[1] - a[1]);
    let effectiveSorted = hop1Sorted;
    let effectiveTotal = totalMultiHop;
    let aggregator = null;

    if (hop1Sorted.length > 0) {
      const [topAsn, topCnt] = hop1Sorted[0];
      const topMeta = lookupBGPASN(topAsn);
      const subMap = hop2ByHop1.get(topAsn);
      const isCarrierOrTier1 = ['tier1', 'cn-opt', 'cn-std', 'apac-opt'].includes(topMeta.tier);
      if (topCnt / totalMultiHop >= 0.82 && !isCarrierOrTier1 && subMap && subMap.size >= 2) {
        aggregator = { asn: topMeta.asn, name: topMeta.name };
        effectiveSorted = [...subMap.entries()].sort((a, b) => b[1] - a[1]);
        effectiveTotal = 0;
        for (const [, c] of effectiveSorted) effectiveTotal += c;
      }
    }

    const upstreams = effectiveSorted.slice(0, 5).map(([asnNum, cnt]) => {
      const meta = lookupBGPASN(asnNum);
      const pct = Math.max(1, Math.round((cnt / Math.max(1, effectiveTotal)) * 100));
      return {
        asn: meta.asn,
        name: meta.name,
        tier: meta.tier,
        pct,
        display: (meta.name ? meta.name + ' ' : '') + '[' + meta.asn + '] ' + pct + '%',
        short: meta.name || meta.asn,
      };
    });

    const cnOptNames = [];
    const apacOptNames = [];
    const cnStdNames = [];
    let tier1Count = 0;

    for (const asnNum of nearUpstreams) {
      const m = lookupBGPASN(asnNum);
      if (m.tier === 'cn-opt' && m.name && !cnOptNames.includes(m.name)) cnOptNames.push(m.name);
      else if (m.tier === 'apac-opt' && m.name && !apacOptNames.includes(m.name)) apacOptNames.push(m.name);
      else if (m.tier === 'cn-std' && m.name && !cnStdNames.includes(m.name)) cnStdNames.push(m.name);
    }
    for (const u of upstreams) {
      if (u.tier === 'tier1') tier1Count++;
    }

    let gradeLabel = '🌐 国际标准 BGP 路由';
    let gradeShort = '国际标准 BGP';
    let gradeLevel = 'normal';

    if (cnOptNames.length > 0) {
      gradeLabel = '🚀 中国大陆优化 BGP (' + cnOptNames.join(' / ') + ')';
      gradeShort = '中国优化 (' + cnOptNames.slice(0, 2).join('/') + ')';
      gradeLevel = 'excellent';
    } else if (apacOptNames.length > 0) {
      gradeLabel = '⚡ 亚太对华友好骨干 (' + apacOptNames.join(' / ') + ')';
      gradeShort = '亚太优化 (' + apacOptNames.slice(0, 2).join('/') + ')';
      gradeLevel = 'good';
    } else if (cnStdNames.length > 0) {
      gradeLabel = '🇨🇳 三网普通直连 BGP (' + cnStdNames.join(' / ') + ')';
      gradeShort = '三网直连 BGP';
      gradeLevel = 'good';
    } else if (tier1Count >= 2) {
      gradeLabel = '🌐 国际多线 Tier-1 BGP';
      gradeShort = '国际多线 Tier-1';
      gradeLevel = 'normal';
    } else if (tier1Count === 1) {
      gradeLabel = '🌐 国际单线 Tier-1 BGP';
      gradeShort = '国际 Tier-1';
      gradeLevel = 'normal';
    }

    const shortNames = upstreams
      .slice(0, 4)
      .map((u) => u.short)
      .join(' / ');

    return {
      prefix,
      originASN: originInfo.asn,
      originName: originInfo.name,
      peerCount: routes.length,
      gradeLabel,
      gradeShort,
      gradeLevel,
      aggregator,
      upstreams,
      shortNames,
      cnOptNames,
    };
  }

  async function queryBGPUpstreams(ip, targetNode, cacheTTLMs) {
    if (!ip || isPrivateLANIP(ip)) return null;
    if (cacheTTLMs && cacheTTLMs > 0) {
      const cached = readIPCache(ip, 'bgp', cacheTTLMs);
      if (cached) return cached;
    }
    const url = 'https://stat.ripe.net/data/bgp-state/data.json?resource=' + encodeURIComponent(ip);
    const bgpTimeout = Math.min(CFG.timeoutMs, 4200);
    try {
      const j = await fetchJSON(buildOutboundOpts(url, targetNode), bgpTimeout);
      const parsed = parseBGPState(j);
      if (parsed) writeIPCache(ip, 'bgp', parsed);
      return parsed;
    } catch (e) {
      log('bgp-state error: ' + (e.message || e));
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
    const t = Math.min(CFG.timeoutMs, 5500);
    // 先测非自制剧：若已完整解锁则直接返回，省去第 2 路大体积 HTML 下载；若连接彻底超时也不再二次卡死
    const nonOrig = await httpRequest(
      'get',
      buildOutboundOpts('https://www.netflix.com/title/81280792', targetNode),
      t
    ).catch(() => null);

    if (!nonOrig) {
      return { name: 'Netflix', state: 'warn', text: '连接超时' };
    }
    if (isNetflixTitleAvailable(nonOrig)) {
      const reg = extractNetflixRegion(nonOrig);
      return { name: 'Netflix', state: 'yes', text: '完整解锁 (含非自制剧) [' + reg + ']' };
    }

    const orig = await httpRequest(
      'get',
      buildOutboundOpts('https://www.netflix.com/title/80018499', targetNode),
      t
    ).catch(() => null);
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

    // 模式 A: 节点链路与入口查询 (受控并发 ≤3：落地 IPv4➔BGP上游 + IPv6 + Cloudflare WARP & POP)
    if (runMode === 'info' || runMode === 'panel') {
      const bgpTTL = runMode === 'panel' ? CACHE_TTL_BG_MS : CACHE_TTL_FG_MS;
      const landingWithBGP = queryLandingIPv4(targetNode).then(async (landing) => {
        const bgp = await queryBGPUpstreams(landing.ip, targetNode, bgpTTL).catch(() => null);
        return { landing, bgp };
      });
      const [lb, ipv6, cfTrace] = await Promise.all([
        landingWithBGP,
        runMode === 'info' && CFG.checkIPv6 ? queryLandingIPv6(targetNode) : Promise.resolve(null),
        queryCloudflareTrace(targetNode),
      ]);
      return {
        ok: true,
        mode: runMode,
        elapsedMs: Date.now() - startedAt,
        landing: lb.landing,
        bgp: lb.bgp,
        ipv6,
        cfTrace,
      };
    }

    // 模式 B: 节点纯净度深度检测 (手动触发一律实时现查风控库，受控 3 并发防双跳拥塞)
    if (runMode === 'purity') {
      const landing = await queryLandingIPv4(targetNode);
      const [purity, proxyCheck, ipScore, bgp] = await runWithConcurrency(
        [
          () => queryPurityIPAPI(landing.ip, targetNode, 0, 0),
          () => queryProxyCheckIO(landing.ip, targetNode),
          () => queryIPScoreDeep(targetNode),
          () => queryBGPUpstreams(landing.ip, targetNode, CACHE_TTL_FG_MS).catch(() => null),
        ],
        3
      );
      return {
        ok: true,
        mode: 'purity',
        elapsedMs: Date.now() - startedAt,
        landing,
        purity,
        proxyCheck,
        ipScore,
        bgp,
      };
    }

    // 模式 C: 流媒体与 AI 解锁检测 (3 路并发池：峰值 ≤4 请求，严守 iOS 8 请求上限与 10 槽位准入红线)
    if (runMode === 'unlock') {
      const landing = await queryLandingIPv4(targetNode).catch(() => ({
        ip: '',
        country: '',
        countryCode: '',
      }));
      const cc = landing.countryCode || '';
      const [chatgpt, claude, gemini, netflix, youtube, disney, tiktok, bahamut] =
        await runWithConcurrency(
          [
            () => checkChatGPTUnlock(targetNode),
            () => checkClaudeUnlock(targetNode),
            () => checkGeminiUnlock(targetNode, cc),
            () => checkNetflixUnlock(targetNode),
            () => checkYouTubePremiumUnlock(targetNode),
            () => checkDisneyPlusUnlock(targetNode, cc),
            () => checkTikTokUnlock(targetNode, cc),
            () => checkBahamutUnlock(targetNode),
          ],
          3
        );
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
    const timeoutBudget = mode === 'info' ? CFG.timeoutMs + 5000 : CFG.timeoutMs * 2 + 9500;
    const res = await httpRequest('get', bridgeURL, timeoutBudget);
    if (res.status !== 200 || !res.body) throw new Error('Bridge HTTP ' + res.status);
    const data = JSON.parse(res.body);
    if (!data || !data.fromClashTunnelBridge) throw new Error('Not intercepted by tunnel engine');
    if (!data.ok) throw new Error(data.error || '节点探测失败');
    if (data.landing && data.landing.ip) {
      if (data.bgp) writeIPCache(data.landing.ip, 'bgp', data.bgp);
      if (data.purity) writeIPCache(data.landing.ip, 'purity', data.purity);
    }
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
    const activeCtx = resolveActiveRoutingContext();
    const isActiveGlobal = prevModel === 2 && prevGlobal === targetNode;
    const isActiveRuleLeaf = prevModel === 1 && Boolean(targetNode) && activeCtx.leafNode === targetNode;
    const alreadyOnTarget = isActiveGlobal || isActiveRuleLeaf;

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
        await sleep(80);
      }

      const data = await executeModeProbe(undefined, mode);
      data.routeChannel = isActiveGlobal
        ? 'active-global'
        : isActiveRuleLeaf
          ? 'active-rule'
          : 'config-fallback';
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

  async function queryIPGeoExplicit(ip, cacheTTLMs) {
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

    const ttl = cacheTTLMs !== undefined ? cacheTTLMs : CACHE_TTL_FG_MS;
    if (ttl > 0) {
      const cached = readIPCache(targetIP, 'entGeo', ttl);
      if (cached) return cached;
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
        const res = {
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
        writeIPCache(targetIP, 'entGeo', res);
        return res;
      }
    } catch (_) {}

    try {
      const j = await fetchJSON('https://ipwho.is/' + encodeURIComponent(targetIP) + '?lang=zh-CN', 3800);
      if (j && j.success !== false) {
        const conn = j.connection || {};
        const cc = j.country_code || '';
        const res = {
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
        writeIPCache(targetIP, 'entGeo', res);
        return res;
      }
    } catch (_) {}

    try {
      const j = await fetchJSON('https://api.ip.sb/geoip/' + encodeURIComponent(targetIP), 3500);
      if (j && j.ip) {
        const cc = j.country_code || '';
        const res = {
          ip: targetIP,
          country: j.country || '',
          countryCode: cc,
          region: j.region || '',
          city: j.city || '',
          isp: j.isp || '',
          org: j.organization || '',
          ispDisplay: normalizeEntranceISP(j.isp || '', j.organization || '', cc),
          asn: j.asn ? 'AS' + j.asn : '',
        };
        writeIPCache(targetIP, 'entGeo', res);
        return res;
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

  async function fetchControllerProxyMeta(proxyName) {
    const name = String(proxyName || '').trim();
    if (!name) return null;
    const url =
      'http://127.0.0.1:' + CFG.controllerPort + '/proxies/' + encodeURIComponent(name);
    try {
      const j = await fetchJSON({ url, headers: buildControllerHeaders() }, 1000);
      if (j && typeof j === 'object') {
        return {
          name: String(j.name || name),
          type: String(j.type || ''),
          now: String(j.now || ''),
          dialerProxy: String(j['dialer-proxy'] || ''),
        };
      }
    } catch (_) {}
    return null;
  }

  async function resolveLeafProxyMeta(initialName) {
    let cur = String(initialName || '').trim();
    if (!cur) return null;
    const visited = new Set();
    let lastMeta = null;
    for (let i = 0; i < 6; i++) {
      if (!cur || visited.has(cur)) break;
      visited.add(cur);
      const meta = await fetchControllerProxyMeta(cur);
      if (!meta) break;
      lastMeta = meta;
      if (meta.now && meta.now !== cur) {
        cur = meta.now;
      } else {
        break;
      }
    }
    return lastMeta;
  }

  async function runProbeWithEntranceCapture(nodeName, captureEnabled, probeFn, opts) {
    if (!captureEnabled || !CFG.showEntrance) {
      const probe = await probeFn();
      return { probe, entrance: null };
    }

    const options = opts || {};
    const entCacheTTL = options.entCacheTTL !== undefined ? options.entCacheTTL : CACHE_TTL_FG_MS;
    let probeFinished = false;
    let controllerStatus = 'unknown';
    let matchedRecord = null;
    let earlyDetailPromise = null;

    async function enrichMatch(match) {
      const { conn, parsed } = match;
      const chains = Array.isArray(conn.chains) ? conn.chains : [];
      const leafNode = chains.length > 0 ? String(chains[0] || '') : '';
      const [entranceIP, proxyMeta] = await Promise.all([
        parsed.isIPv4 || parsed.isIPv6 ? Promise.resolve(parsed.host) : resolveDomainToIP(parsed.host),
        fetchControllerProxyMeta(leafNode || nodeName).catch(() => null),
      ]);
      const geo = entranceIP ? await queryIPGeoExplicit(entranceIP, entCacheTTL).catch(() => null) : null;
      return {
        status: 'ok',
        entranceHost: parsed.host,
        entrancePort: parsed.port,
        entranceIP: entranceIP || '',
        leafNode,
        chains,
        dialerProxy: (proxyMeta && proxyMeta.dialerProxy) || '',
        proxyType: (proxyMeta && proxyMeta.type) || '',
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
      const delays = options.lightPoll ? [220, 620] : [150, 320, 620, 1050];
      for (const waitMs of delays) {
        await sleep(waitMs);
        if (matchedRecord || probeFinished) return;
        await trySnapshotOnce();
        if (matchedRecord || probeFinished || controllerStatus !== 'ok') return;
      }
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

    // 即使连接在极短时间内已关闭，只要控制器在线也可补充读取节点链式拨号元数据
    const fallbackMeta =
      controllerStatus === 'ok' && nodeName ? await resolveLeafProxyMeta(nodeName).catch(() => null) : null;
    return {
      probe,
      entrance: {
        status: 'not_found',
        leafNode: (fallbackMeta && fallbackMeta.name) || '',
        dialerProxy: (fallbackMeta && fallbackMeta.dialerProxy) || '',
        proxyType: (fallbackMeta && fallbackMeta.type) || '',
      },
    };
  }

  // ============================================================================
  // 8B. 代理链路类型全场景分类器 & 拓扑构建器
  // ============================================================================

  function classifyLinkType({ nodeName, nodeInfo, entrance, probe }) {
    const l = (probe && probe.landing) || {};
    const cf = (probe && probe.cfTrace) || null;
    const warpMode =
      cf && (cf.warp === 'plus' || cf.warp === 'on') ? (cf.warp === 'plus' ? 'WARP+' : 'WARP') : '';
    const warpSuffix = warpMode ? ' + ' + warpMode : '';

    const landingCC = String(l.countryCode || '').toUpperCase();
    const landingASN = String(l.asn || '').toUpperCase();
    const isLandingCF =
      landingASN === 'AS13335' || /cloudflare/i.test(String(l.isp || '') + ' ' + String(l.org || ''));

    const rawNodeType = String(
      (nodeInfo && nodeInfo.type) || (entrance && entrance.proxyType) || ''
    ).toLowerCase();
    const isRelayGroup = rawNodeType === 'relay';
    const dialerProxy = String((entrance && entrance.dialerProxy) || '').trim();
    const chains = (entrance && Array.isArray(entrance.chains) && entrance.chains) || [];
    const hasNodeLibraryChain =
      dialerProxy.startsWith('__clash_chain_entry_') ||
      chains.some((c) => String(c || '').startsWith('__clash_chain_entry_'));

    // 1. 显式客户端链式代理（节点库链式代理 / dialer-proxy 前置转发 / Relay 多跳组）
    if (hasNodeLibraryChain) {
      return {
        code: 'chain-library',
        badge: '链式代理 · 双跳串联' + warpSuffix,
        detail: '客户端前置节点 ➔ 远端落地节点',
        color: COLORS.purple,
      };
    }
    if (dialerProxy && dialerProxy.toUpperCase() !== 'DIRECT') {
      return {
        code: 'chain-dialer',
        badge: '链式代理 · 前置拨号' + warpSuffix,
        detail: '经前置「' + dialerProxy + '」转发 ➔ 落地',
        color: COLORS.purple,
      };
    }
    if (isRelayGroup) {
      return {
        code: 'chain-relay',
        badge: '链式代理 · Relay 多跳' + warpSuffix,
        detail: '多节点顺序串联转发',
        color: COLORS.purple,
      };
    }

    // 2. 已捕获真实拨号入口 IP / 域名：精准判定直连、CDN、专线、BGP、跨国与同区链路
    if (entrance && entrance.status === 'ok' && (entrance.entranceIP || entrance.entranceHost)) {
      const entIP = entrance.entranceIP || '';
      const entHost = entrance.entranceHost || '';
      const eg = entrance.geo || null;
      const entCC = String((eg && eg.countryCode) || '').toUpperCase();
      const entASN = String((eg && eg.asn) || '').toUpperCase();
      const entISP = String((eg && (eg.ispDisplay || eg.isp || eg.org)) || '').trim();
      const isDirectIP =
        Boolean(entIP) &&
        (entIP === l.ip || Boolean(probe && probe.ipv6 && probe.ipv6.ip && entIP === probe.ipv6.ip));
      const isEntCF =
        entASN === 'AS13335' ||
        /cloudflare/i.test(entISP + ' ' + String((eg && eg.org) || '') + ' ' + entHost);

      // 2A. 局域网 / 旁路由 / Tailscale / ZeroTier 等组网内网网关入口
      if (eg && eg.isPrivate) {
        return {
          code: 'lan-gateway',
          badge: '内网 / 组网网关中转' + warpSuffix,
          detail: '局域网或组网网关入口 ➔ 远端落地',
          color: COLORS.purple,
        };
      }

      // 2B. 入口即落地（单跳直连无中转）
      if (isDirectIP) {
        if (warpMode) {
          return {
            code: 'direct-warp',
            badge: '直连线路 + ' + warpMode + ' 出站',
            detail: '入口即节点本身，出站经 CF 托管',
            color: COLORS.cyan,
          };
        }
        return {
          code: 'direct',
          badge: landingCC && landingCC !== 'CN' ? '直连出境线路' : '直连单跳线路',
          detail: '入口即落地，未经过中转服务器',
          color: COLORS.cyan,
        };
      }

      // 2C. 入口为 Cloudflare Anycast 节点（原生 WARP 隧道 vs CF CDN 优选回源）
      if (isEntCF) {
        if (warpMode || isLandingCF) {
          return {
            code: 'cf-warp-tunnel',
            badge: 'Cloudflare ' + (warpMode || 'WARP') + ' 隧道',
            detail: 'CF Anycast 边缘接入 ➔ 托管落地',
            color: COLORS.cyan,
          };
        }
        return {
          code: 'cf-cdn-origin',
          badge: 'Cloudflare CDN 优选线路',
          detail: 'CF Anycast 边缘接入 ➔ 源站落地',
          color: COLORS.primary,
        };
      }

      // 2D. 国内大陆入口（CN）中转出境：细分专线 IEPL/IPLC、云厂商多线 BGP、三大运营商公网中转
      if (entCC === 'CN' && landingCC !== 'CN') {
        const nameHint = String(nodeName || '') + ' ' + String(entrance.leafNode || '');
        const isDedicatedHint = /iepl|iplc|专线|内网专线|深港|沪日|沪美|广港|京德|京日|苏日/i.test(nameHint);
        const isCloudBGP =
          /BGP|阿里云|腾讯云|华为云|UCloud|火山引擎|金山云|青云|天翼云|移动云|联通云|百度云|京东云|Zenlayer|xTom|Misaka/i.test(
            entISP
          );

        if (isDedicatedHint) {
          return {
            code: 'cn-dedicated',
            badge: '跨境专线加速 (IEPL/IPLC)' + warpSuffix,
            detail: (entISP ? entISP + '入口' : '国内专线入口') + ' ➔ 跨境专线落地',
            color: COLORS.purple,
          };
        }
        if (isCloudBGP) {
          return {
            code: 'cn-bgp-transit',
            badge: '国内 BGP 专网中转' + warpSuffix,
            detail: entISP + '入口 ➔ 海外落地',
            color: COLORS.purple,
          };
        }
        return {
          code: 'cn-isp-transit',
          badge: '国内运营商中转加速' + warpSuffix,
          detail: (entISP ? entISP + '入口' : '国内公网入口') + ' ➔ 海外落地',
          color: COLORS.purple,
        };
      }

      // 2E. 境内同向中转（国内入口 ➔ 国内异地落地）
      if (entCC === 'CN' && landingCC === 'CN') {
        return {
          code: 'cn-internal-transit',
          badge: '境内内陆中转链路',
          detail: '国内前置入口 ➔ 国内异地落地',
          color: COLORS.purple,
        };
      }

      // 2F. 海外节点直连接入 + 落地侧套用 Cloudflare WARP 出站（避免误判为机场中转）
      if (entCC && entCC !== 'CN' && (warpMode || isLandingCF)) {
        return {
          code: 'overseas-direct-warp',
          badge: '直连入口 + ' + (warpMode || 'WARP') + ' 出站',
          detail: entCC + ' 节点直连 ➔ Cloudflare 托管落地',
          color: COLORS.cyan,
        };
      }

      // 2G. 海外跨国 / 跨地区跳板中转（如 HK/SG/JP 前置 ➔ US/TW/EU 落地）
      if (entCC && landingCC && entCC !== landingCC) {
        return {
          code: 'intl-transit',
          badge: '海外跨国跳板中转' + warpSuffix,
          detail: entCC + ' 前置入口 ➔ ' + landingCC + ' 远端落地',
          color: COLORS.purple,
        };
      }

      // 2H. 海外同国家/地区异 IP：区分「同 ASN 多 IP 直出」与「异运营商前置落地链（如 CMI ➔ HKT 家宽）」
      if (entCC && entCC === landingCC) {
        if (entASN && landingASN && entASN === landingASN) {
          return {
            code: 'same-asn-multi-ip',
            badge: '同网段多 IP 直出',
            detail: '出入口同属 ' + landingASN + ' (' + entCC + ')',
            color: COLORS.cyan,
          };
        }
        return {
          code: 'same-region-chain',
          badge: '同区异网中转 / 落地链',
          detail: entCC + ' 前置入口 ➔ 同区独立运营商落地',
          color: COLORS.purple,
        };
      }

      // 2I. 入口与落地分离（入口 Geo 超时兜底）
      return {
        code: 'separated-transit',
        badge: '中转 / 分离式链路' + warpSuffix,
        detail: '拨号入口与最终落地 IP 分离',
        color: COLORS.purple,
      };
    }

    // 3. 未捕获到拨号入口时的已知特征与引导兜底（确保任何状态下均显示「链路类型」）
    if (warpMode) {
      return {
        code: 'warp-outbound',
        badge: 'Cloudflare ' + warpMode + ' 托管出站',
        detail: !CFG.showEntrance ? '已关闭入口检测' : '配好外部控制器密钥可判别前端直连/中转',
        color: COLORS.purple,
      };
    }
    if (isLandingCF) {
      return {
        code: 'cf-outbound',
        badge: 'Cloudflare Anycast 出站',
        detail: !CFG.showEntrance ? '已关闭入口检测' : '配好外部控制器密钥可判别前端直连/中转',
        color: COLORS.cyan,
      };
    }
    if (!CFG.showEntrance) {
      return {
        code: 'outbound-only',
        badge: '常规代理出站',
        detail: '已在模块设置关闭中转入口检测',
        color: COLORS.primary,
      };
    }
    if (entrance && entrance.status === 'unauthorized') {
      return {
        code: 'pending-secret',
        badge: '待识别直连 / 中转',
        detail: '模块设置填入外部控制器密钥即可判别',
        color: COLORS.warning,
      };
    }
    if (entrance && entrance.status === 'unreachable') {
      return {
        code: 'pending-controller',
        badge: '待识别直连 / 中转',
        detail: '开启「外部控制器 → 本机」填密钥可判别',
        color: COLORS.muted,
      };
    }
    return {
      code: 'pending-sample',
      badge: '待识别直连 / 中转',
      detail: '本次连接采样过快结束，再测一次即可捕获入口',
      color: COLORS.muted,
    };
  }

  function buildTopologyHops({ domestic, entrance, probe }) {
    const l = (probe && probe.landing) || {};
    const cf = (probe && probe.cfTrace) || null;
    const flag = getFlagEmoji(l.countryCode);
    const htmlHops = [];
    const plainHops = [];

    if (domestic && domestic.ip) {
      const dLabel = '🇨🇳 ' + (domestic.shortTag || '本地');
      htmlHops.push(esc(dLabel));
      plainHops.push(dLabel);
    }

    if (entrance && entrance.status === 'ok' && (entrance.entranceIP || entrance.entranceHost)) {
      const entIP = entrance.entranceIP || '';
      const isDirect =
        Boolean(entIP) &&
        (entIP === l.ip || Boolean(probe && probe.ipv6 && probe.ipv6.ip && entIP === probe.ipv6.ip));
      if (isDirect) {
        const dTxt = String(l.countryCode || '').toUpperCase() === 'CN' ? '直连接入' : '直连出境';
        htmlHops.push(colorSpan(dTxt, COLORS.cyan, true));
        plainHops.push(dTxt);
      } else {
        const eg = entrance.geo;
        const entASN = String((eg && eg.asn) || '').toUpperCase();
        const isEntCF =
          entASN === 'AS13335' ||
          /cloudflare/i.test(String((eg && eg.ispDisplay) || '') + ' ' + String(entrance.entranceHost || ''));

        let eTag = '中转入口';
        let eColor = COLORS.purple;
        if (eg && eg.isPrivate) {
          eTag = '🏠 内网网关';
        } else if (isEntCF) {
          eTag = '☁️ CF 边缘入口';
          eColor = COLORS.primary;
        } else if (eg) {
          const place = (eg.city || eg.region || eg.country || '中转').replace(
            /省|市|壮族自治区|维吾尔自治区|回族自治区|特别行政区/g,
            ''
          );
          const shortISP = eg.ispDisplay ? eg.ispDisplay.replace(/^中国/, '').trim() : '';
          const sep =
            shortISP && (/[a-zA-Z]/.test(place) || /[a-zA-Z]/.test(shortISP) || shortISP.length > 2) ? ' ' : '';
          eTag = getFlagEmoji(eg.countryCode) + ' ' + place + (shortISP ? sep + shortISP : '');
        }
        htmlHops.push(colorSpan(eTag, eColor, true));
        plainHops.push(eTag);
      }
    } else if (entrance && entrance.dialerProxy && !entrance.dialerProxy.startsWith('__clash_chain_entry_')) {
      const dpTag = '🔗 ' + entrance.dialerProxy;
      htmlHops.push(colorSpan(dpTag, COLORS.purple, true));
      plainHops.push(dpTag);
    }

    const landTag = flag + ' ' + (l.city || l.country || l.countryCode || '落地');
    htmlHops.push(esc(landTag));
    plainHops.push(landTag);

    if (cf && cf.colo) {
      const cfTag = '☁️ ' + cf.colo;
      htmlHops.push(esc(cfTag));
      plainHops.push(cfTag);
    }

    return {
      html: htmlHops.join(' ➔ '),
      plain: plainHops.join(' ➔ '),
    };
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
        : probe.routeChannel === 'active-global' || probe.routeChannel === 'active-rule'
          ? '⚡ 当前节点直测 · ' + probe.elapsedMs + ' ms'
          : '🔄 临时切换直测 (已还原) · ' + probe.elapsedMs + ' ms';
    return '<span style="color:' + COLORS.muted + '">' + esc(ch) + '</span>';
  }

  /**
   * 视图 1：🌐 节点链路与入口查询 (一屏展示链路类型 + 拓扑走向 + 出入口 + Cloudflare WARP/POP)
   */
  function renderInfoSheetHTML({ nodeName, nodeInfo, domestic, entrance, probe }) {
    const l = probe.landing;
    const cf = probe.cfTrace;
    const flag = getFlagEmoji(l.countryCode);
    const lGeo = deduplicateGeoParts([l.country, l.region, l.city]).join(' ');
    const lines = renderCompactHeader(nodeName, nodeInfo, entrance && entrance.leafNode);

    // 1. 链路类型与拓扑走向总览
    const linkInfo = classifyLinkType({ nodeName, nodeInfo, entrance, probe });
    const topo = buildTopologyHops({ domestic, entrance, probe });

    lines.push('');
    lines.push('<b>▸ 代理链路与走向</b>');
    lines.push(
      '链路类型：' +
        colorSpan(linkInfo.badge, linkInfo.color, true) +
        (linkInfo.detail ? ' <span style="color:' + COLORS.muted + '">(' + esc(linkInfo.detail) + ')</span>' : '')
    );
    lines.push('链路走向：' + topo.html);

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
          if (entHost && entHost !== entIP) {
            lines.push('接入域名：<code>' + esc(maskDomainString(entHost, CFG.maskIP)) + '</code>');
          }
        } else {
          const eg = entrance.geo;
          const regCityParts = eg ? deduplicateGeoParts([eg.region || eg.country, eg.city]) : [];
          const regCitySep = regCityParts.some((p) => /[a-zA-Z]/.test(p)) ? ' ' : '';
          const eGeo = eg
            ? [
                eg.isPrivate ? '🏠' : getFlagEmoji(eg.countryCode),
                regCityParts.join(regCitySep),
                eg.ispDisplay || eg.isp || eg.org,
              ]
                .filter(Boolean)
                .join(' ')
            : '';
          const nonTransitCodes = new Set(['overseas-direct-warp', 'same-asn-multi-ip', 'cf-warp-tunnel']);
          const entLabel = nonTransitCodes.has(linkInfo.code) ? '拨号入口' : '中转入口';
          const entASNHtml = eg && eg.asn ? ' <code>[' + esc(eg.asn) + ']</code>' : '';
          lines.push(
            entLabel +
              '：<code>' +
              esc(maskIPString(entIP || entHost, CFG.maskIP) + portStr) +
              '</code>' +
              (eGeo ? ' · ' + esc(eGeo) : '') +
              entASNHtml
          );
          if (entHost && entHost !== entIP) {
            lines.push('入口域名：<code>' + esc(maskDomainString(entHost, CFG.maskIP)) + '</code>');
          }
        }
      } else if (entrance.status === 'unauthorized') {
        lines.push('中转入口：' + colorSpan('待填外部控制器密钥', COLORS.warning, false));
      } else if (entrance.status === 'unreachable') {
        lines.push(
          '中转入口：<span style="color:' +
            COLORS.muted +
            '">未开启（设置→客户端设置→外部控制器→本机）</span>'
        );
      } else if (entrance.status === 'not_found') {
        lines.push(
          '中转入口：<span style="color:' + COLORS.muted + '">连接已释放（重测即可捕获）</span>'
        );
      }
    }

    lines.push(
      '落地出口：<code>' +
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
    }

    lines.push(
      '运营商　：' +
        (l.asn ? '<code>' + esc(l.asn) + '</code> ' : '') +
        esc(l.isp || l.org || '未知')
    );

    if (cf) {
      const coloDesc = cf.colo ? (cf.coloCity ? cf.colo + ' · ' + cf.coloCity : cf.colo) : '';
      const warpTag =
        cf.warp === 'plus'
          ? colorSpan('[WARP+ 托管]', COLORS.purple, true)
          : cf.warp === 'on'
            ? colorSpan('[WARP 出站]', COLORS.warning, true)
            : colorSpan('[原生直出]', COLORS.success, false);
      lines.push(
        'CF 边缘 ：' + (coloDesc ? '<code>' + esc(coloDesc) + '</code> ' : '') + warpTag
      );
    }

    // 3. BGP 宣告前缀与全球上游骨干线路 (RIPE NCC RIS 实时路由表)
    const bgp = probe.bgp;
    if (bgp) {
      lines.push('');
      lines.push('<b>▸ BGP 路由与上游骨干</b>');
      const diffOrigin =
        bgp.originASN && l.asn && bgp.originASN.toUpperCase() !== String(l.asn).toUpperCase()
          ? ' · 宣告 <code>' + esc(bgp.originASN) + '</code>'
          : '';
      lines.push(
        'BGP 评级：' +
          colorSpan(bgp.gradeLabel, levelColor(bgp.gradeLevel), true) +
          (bgp.prefix ? ' · <code>' + esc(bgp.prefix) + '</code>' : '') +
          diffOrigin
      );
      if (bgp.aggregator && bgp.aggregator.asn) {
        lines.push(
          '聚合网关：' +
            (bgp.aggregator.name ? esc(bgp.aggregator.name) + ' ' : '') +
            '<code>[' +
            esc(bgp.aggregator.asn) +
            ']</code>'
        );
      }
      if (bgp.upstreams && bgp.upstreams.length > 0) {
        const upHtml = bgp.upstreams
          .slice(0, 4)
          .map((u) => {
            const namePart = u.name ? esc(u.name) + ' ' : '';
            return namePart + '<code>[' + esc(u.asn) + ']</code> ' + u.pct + '%';
          })
          .join(' · ');
        lines.push((bgp.aggregator ? '穿透上游：' : '直连上游：') + upHtml);
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
      if (probe.bgp) {
        lines.push(
          'BGP 评级：' +
            colorSpan(probe.bgp.gradeLabel, levelColor(probe.bgp.gradeLevel), true) +
            (probe.bgp.shortNames ? ' · <code>' + esc(probe.bgp.shortNames) + '</code>' : '')
        );
      }

      lines.push('');
      lines.push('<b>▸ 风控与黑名单审计</b>');
      lines.push(
        '纯净指数：' +
          colorSpan(scoreBar(cleanScore) + ' ' + cleanScore + '分 · ' + rLabel, rColor, true)
      );
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
      if (f.proxy || (pc && pc.proxy)) tags.push(colorSpan('公开代理', COLORS.danger, true));
      if (f.abuser) tags.push(colorSpan('历史滥用', COLORS.danger, true));
      if (f.tor) tags.push(colorSpan('Tor出口', COLORS.danger, true));
      if (f.crawler) tags.push(colorSpan('爬虫标记', COLORS.warning, true));
      if (f.mobile) tags.push(colorSpan('移动蜂窝', COLORS.success, true));
      lines.push(
        '风险画像：' +
          (tags.length > 0 ? tags.join(' · ') : colorSpan('零风险标记 ✓', COLORS.success, true))
      );
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

  function renderWebPortalHTML(domestic, entrance, infoProbe, purity, targetNode) {
    const l = infoProbe.landing;
    const cf = infoProbe.cfTrace;
    const flag = getFlagEmoji(l.countryCode || '');
    const geo = deduplicateGeoParts([l.country, l.region, l.city]).join(' ');
    const linkInfo = classifyLinkType({
      nodeName: targetNode || (entrance && entrance.leafNode) || '',
      nodeInfo: null,
      entrance,
      probe: infoProbe,
    });
    const topo = buildTopologyHops({ domestic, entrance, probe: infoProbe });
    const hasEnt =
      entrance && entrance.status === 'ok' && (entrance.entranceIP || entrance.entranceHost);
    const entGeoText =
      hasEnt && entrance.geo
        ? [
            entrance.geo.isPrivate ? '🏠' : getFlagEmoji(entrance.geo.countryCode),
            deduplicateGeoParts([entrance.geo.region || entrance.geo.country, entrance.geo.city]).join(''),
            entrance.geo.ispDisplay || entrance.geo.isp || entrance.geo.org,
            entrance.geo.asn ? '[' + entrance.geo.asn + ']' : '',
          ]
            .filter(Boolean)
            .join(' ')
        : '';
    const bgp = infoProbe.bgp;
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
  <div class="card">
    <h2>🔀 代理链路总览</h2>
    <div class="row"><span class="k">链路类型</span><span class="v" style="color:${linkInfo.color}">${esc(linkInfo.badge)}${linkInfo.detail ? ` <span style="font-weight:400;color:var(--sub)">(${esc(linkInfo.detail)})</span>` : ''}</span></div>
    <div class="row"><span class="k">链路走向</span><span class="v">${esc(topo.plain)}</span></div>
    ${hasEnt ? `<div class="row"><span class="k">拨号入口</span><span class="v"><code>${esc(maskIPString(entrance.entranceIP || entrance.entranceHost, CFG.maskIP))}</code>${entGeoText ? ' · ' + esc(entGeoText) : ''}</span></div>` : ''}
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
    ${bgp ? `<div class="row"><span class="k">BGP 评级</span><span class="v">${esc(bgp.gradeLabel)}</span></div>` : ''}
    ${bgp && bgp.upstreams && bgp.upstreams.length > 0 ? `<div class="row"><span class="k">${bgp.aggregator ? '穿透上游' : '直连上游'}</span><span class="v">${esc(bgp.upstreams.slice(0, 4).map((u) => u.display).join(' · '))}</span></div>` : ''}
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
        safeDone({
          response: {
            status: 200,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
            body: JSON.stringify(result),
          },
        });
      } catch (e) {
        safeDone({
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
      const [domestic, probeWrap] = await Promise.all([
        CFG.showDomestic ? queryDomesticDirect(true) : Promise.resolve(null),
        runProbeWithEntranceCapture(targetNode || '', true, () => executeModeProbe(targetNode, 'info')),
      ]);
      const infoProbe = probeWrap.probe;
      const entrance = probeWrap.entrance;
      const purity = await queryPurityIPAPI(infoProbe.landing.ip, targetNode);
      const linkType = classifyLinkType({
        nodeName: targetNode || (entrance && entrance.leafNode) || '',
        nodeInfo: null,
        entrance,
        probe: infoProbe,
      });
      const topology = buildTopologyHops({ domestic, entrance, probe: infoProbe }).plain;

      if (query.format === 'json' || pathname === '/json' || pathname === '/api') {
        safeDone({
          response: {
            status: 200,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' },
            body: JSON.stringify(
              { ok: true, targetNode: targetNode || null, linkType, topology, domestic, entrance, probe: infoProbe, purity },
              null,
              2
            ),
          },
        });
        return;
      }

      safeDone({
        response: {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
          body: renderWebPortalHTML(domestic, entrance, infoProbe, purity, targetNode),
        },
      });
    } catch (e) {
      safeDone({
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
        safeDone({
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
        safeDone({
          title: sheetTitle,
          htmlMessage:
            colorSpan(probe.error, COLORS.warning, true) +
            '<br><br>1. 推荐：开启「模块」页顶部 <b>HTTPS 解密</b> 开关（零切换直测）。<br>2. 或在模块「设置」开启 <b>自动临时切换测速</b>。',
        });
        return;
      }

      const html = renderByMode(mode, { nodeName, nodeInfo, domestic: domesticBeforeSwitch, entrance, probe });
      safeDone({ title: sheetTitle, htmlMessage: html });
      return;
    }

    const domestic = await domesticPromise;
    const html = renderByMode(mode, { nodeName, nodeInfo, domestic, entrance, probe });
    safeDone({ title: sheetTitle, htmlMessage: html });
  }

  function renderByMode(mode, ctx) {
    if (mode === 'purity') return renderPuritySheetHTML(ctx);
    if (mode === 'unlock') return renderUnlockSheetHTML(ctx);
    return renderInfoSheetHTML(ctx);
  }

  function resolveActiveRoutingContext() {
    const out = { modeName: '', rootGroup: '', leafNode: '' };
    if (typeof $config === 'undefined' || !$config.getConfig) return out;
    try {
      const raw = $config.getConfig();
      const c = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (!c || typeof c !== 'object') return out;
      out.modeName = { 0: '全局直连', 1: '规则分流', 2: '全局代理' }[c.running_model] || '';
      if (c.running_model === 0) {
        out.rootGroup = 'DIRECT';
        out.leafNode = 'DIRECT';
        return out;
      }
      const groups = new Set(Array.isArray(c.all_policy_groups) ? c.all_policy_groups : []);
      const startGroup =
        c.running_model === 2
          ? c.global_proxy || 'GLOBAL'
          : c.final || (Array.isArray(c.all_policy_groups) && c.all_policy_groups[0]) || '';
      out.rootGroup = String(startGroup || '').trim();
      if ($config.getSelectedPolicy && out.rootGroup) {
        let cur = out.rootGroup;
        const seen = new Set();
        for (let i = 0; i < 8; i++) {
          if (!cur || seen.has(cur)) break;
          seen.add(cur);
          if (groups.size > 0 && !groups.has(cur) && cur !== 'GLOBAL') break;
          const next = $config.getSelectedPolicy(cur);
          if (!next || typeof next !== 'string') break;
          cur = next.trim();
        }
        if (cur && cur !== 'GLOBAL') out.leafNode = cur;
      }
    } catch (_) {}
    return out;
  }

  function parsePrevEventState(raw) {
    if (!raw || typeof raw !== 'string') return null;
    const s = raw.trim();
    if (!s) return null;
    if (s[0] === '{') {
      try {
        const j = JSON.parse(s);
        if (j && typeof j === 'object') return j;
      } catch (_) {}
    }
    const parts = s.split('|');
    return {
      v: 1,
      domIP: parts[0] || '',
      landIP: parts[1] || '',
      cc: (parts[2] || '').toUpperCase(),
    };
  }

  async function handleModulePanel() {
    recoverDanglingPolicyIfAny();
    try {
      const routing = resolveActiveRoutingContext();
      const routeTarget =
        routing.rootGroup && routing.leafNode && routing.rootGroup !== routing.leafNode
          ? routing.rootGroup + ' ➔ ' + routing.leafNode
          : routing.leafNode || routing.rootGroup;
      const modeInfo = [routing.modeName, routeTarget].filter(Boolean).join(' · ');

      const [domestic, probeWrap] = await Promise.all([
        CFG.showDomestic ? queryDomesticDirect(false).catch(() => null) : Promise.resolve(null),
        runProbeWithEntranceCapture('', true, () => executeModeProbe(undefined, 'panel'), {
          lightPoll: true,
          entCacheTTL: CACHE_TTL_BG_MS,
        }),
      ]);
      const probe = probeWrap.probe;
      const entrance = probeWrap.entrance;
      const l = probe.landing;
      const cf = probe.cfTrace;
      const activeNode = (entrance && entrance.leafNode) || routing.leafNode || '';
      const linkInfo = classifyLinkType({
        nodeName: activeNode,
        nodeInfo: null,
        entrance,
        probe,
      });

      const lines = [];
      if (modeInfo) lines.push('模式：' + modeInfo);
      lines.push('链路：' + linkInfo.badge + (activeNode ? ' · ' + activeNode : ''));
      if (domestic && domestic.ip) {
        lines.push('直连：' + maskIPString(domestic.ip, CFG.maskIP) + ' (' + [domestic.location, domestic.isp].filter(Boolean).join(' ') + ')');
      }
      if (entrance && entrance.status === 'ok' && entrance.entranceIP && entrance.entranceIP !== l.ip) {
        const eg = entrance.geo;
        const eTxt = eg
          ? [eg.city || eg.region || eg.country, eg.ispDisplay || eg.isp, eg.asn]
              .filter(Boolean)
              .join(' ')
          : '';
        lines.push('入口：' + maskIPString(entrance.entranceIP, CFG.maskIP) + (eTxt ? ' (' + eTxt + ')' : ''));
      }
      const flag = getFlagEmoji(l.countryCode);
      const geo = deduplicateGeoParts([l.country, l.city]).join(' ');
      lines.push('落地：' + maskIPString(l.ip, CFG.maskIP) + ' (' + flag + ' ' + (geo || l.countryCode || '-') + ')');
      lines.push('网络：' + [l.asn, l.isp || l.org].filter(Boolean).join(' ') + (cf && cf.colo ? ' · CF-' + cf.colo : ''));
      if (probe.bgp) {
        lines.push(
          '上游：' + probe.bgp.gradeShort + (probe.bgp.shortNames ? ' · ' + probe.bgp.shortNames : '')
        );
      }

      safeDone({
        title: '当前网络出口信息',
        content: lines.join('\n'),
        icon: 'globe.asia.australia',
        'icon-color': '#10B981',
      });
    } catch (e) {
      safeDone({
        title: '当前网络出口信息',
        content: '查询失败：' + String((e && e.message) || e),
        icon: 'exclamationmark.triangle',
        'icon-color': '#EF4444',
      });
    }
  }

  async function handleNetworkChanged() {
    if (!CFG.notifyOnChange) {
      safeDone({});
      return;
    }
    try {
      // 轻度错峰退避 1.2s（配合客户端自身 2s 防抖），让内核节点握手、url-test 与前台请求优先通行
      await sleep(1200);

      const routing = resolveActiveRoutingContext();
      // 第一阶段：仅发 1 个约 250B 极简落地请求 + 本地直连对比，若出口与直连均未变化则立即静默退出
      const [domestic, landWrap] = await Promise.all([
        CFG.showDomestic ? queryDomesticDirect(false).catch(() => null) : Promise.resolve(null),
        runProbeWithEntranceCapture('', CFG.showEntrance, () => queryLandingIPv4(undefined), {
          lightPoll: true,
          entCacheTTL: CACHE_TTL_BG_MS,
        }),
      ]);
      const landing = landWrap.probe || {};
      const entrance = landWrap.entrance;

      const domIP = (domestic && domestic.ip) || '';
      const landIP = landing.ip || '';
      const cc = String(landing.countryCode || '').toUpperCase();
      const entIP = (entrance && entrance.status === 'ok' && entrance.entranceIP) || '';
      const activeNode = (entrance && entrance.leafNode) || routing.leafNode || '';

      const prev = parsePrevEventState(storeRead(LAST_EVENT_KEY));
      const hasChanged =
        Boolean(landIP) &&
        (!prev || prev.v !== 4 || prev.domIP !== domIP || prev.landIP !== landIP || prev.cc !== cc);

      if (hasChanged && !_scriptSettled) {
        storeWrite(
          LAST_EVENT_KEY,
          JSON.stringify({ v: 4, domIP, landIP, cc, entIP, node: activeNode })
        );

        // 第二阶段：仅当出口确实变化时才按需串行补齐详情，且优先复用 6 小时本地 IP 缓存（固定住宅 IP 0 下载）
        const isLandingCF =
          String(landing.asn || '').toUpperCase() === 'AS13335' ||
          /cloudflare/i.test(String(landing.isp || '') + ' ' + String(landing.org || ''));
        const cf = isLandingCF ? await queryCloudflareTrace(undefined).catch(() => null) : null;
        const bgp = await queryBGPUpstreams(landIP, undefined, CACHE_TTL_BG_MS).catch(() => null);
        const purity = await queryPurityIPAPI(
          landIP,
          undefined,
          Math.min(CFG.timeoutMs, 3800),
          CACHE_TTL_BG_MS
        );
        const probe = { landing, bgp, cfTrace: cf, ipv6: null };

        const linkInfo = classifyLinkType({
          nodeName: activeNode,
          nodeInfo: null,
          entrance,
          probe,
        });
        const topo = buildTopologyHops({ domestic, entrance, probe });

        const flag = getFlagEmoji(cc);
        const geo = deduplicateGeoParts([landing.country, landing.city]).join(' ') || cc || '未知地区';
        const regionLabel = landing.country || geo || cc;

        const domChanged = Boolean(prev && prev.domIP && domIP && prev.domIP !== domIP);
        const landChanged = Boolean(prev && prev.landIP && landIP && prev.landIP !== landIP);

        let titleText = '🌐 网络出口已更新 · ' + flag + ' ' + regionLabel;
        if (!prev || (!prev.domIP && !prev.landIP)) {
          titleText = '🌐 网络出口已就绪 · ' + flag + ' ' + regionLabel;
        } else if (domChanged && !landChanged) {
          titleText = '🌐 网络环境已切换 · ' + flag + ' ' + regionLabel;
        } else if (!domChanged && landChanged) {
          titleText = '🌐 代理出口已更新 · ' + flag + ' ' + regionLabel;
        }

        const showLinkBadge = linkInfo.code !== 'pending-controller';
        const subtitleText = showLinkBadge
          ? '🔀 ' + linkInfo.badge + (topo && topo.plain ? ' ｜ ' + topo.plain : '')
          : '🔀 ' + ((topo && topo.plain) || linkInfo.badge);

        const exitLines = [];
        exitLines.push(flag + ' 落地：' + maskIPString(landIP, CFG.maskIP) + ' (' + geo + ')');
        const asnText = [landing.asn, landing.isp || landing.org].filter(Boolean).join(' ');
        if (asnText) exitLines.push('🏢 归属：' + asnText);
        if (bgp) {
          exitLines.push(
            '🛣️ 上游：' +
              bgp.gradeShort +
              (bgp.shortNames ? ' · ' + bgp.shortNames : '')
          );
        }

        if (purity) {
          const cleanLineage = String(purity.lineageLabel || '')
            .replace(/^[^\w\u4e00-\u9fa5]+/, '')
            .trim();
          const nativeTag =
            purity.isNativeGeo === true ? '原生 IP' : purity.isNativeGeo === false ? '广播 IP' : '';
          const scoreTag = '纯净度 ' + Math.max(0, 100 - (purity.riskIndex || 0)) + '/100';
          const pText = [cleanLineage, nativeTag, scoreTag].filter(Boolean).join(' · ');
          if (pText) exitLines.push('🛡️ 属性：' + pText);
        }

        if (cf && (cf.warp === 'on' || cf.warp === 'plus')) {
          exitLines.push('⚡ 特性：WARP ' + (cf.warp === 'plus' ? 'Plus' : '开启'));
        }

        const routeLines = [];
        const routeTarget =
          routing.rootGroup && activeNode && routing.rootGroup !== activeNode
            ? routing.rootGroup + ' ➔ ' + activeNode
            : activeNode || routing.rootGroup;
        const strategyText = [routing.modeName, routeTarget].filter(Boolean).join(' · ');
        if (strategyText) routeLines.push('🧭 策略：' + strategyText);

        if (entIP && entIP !== landIP) {
          const eg = entrance.geo;
          const eCore = eg
            ? deduplicateGeoParts([eg.city || eg.region || eg.country, eg.ispDisplay || eg.isp]).join(' ')
            : '';
          const eTxt = [eCore, eg && eg.asn].filter(Boolean).join(' · ');
          routeLines.push('🚀 入口：' + maskIPString(entIP, CFG.maskIP) + (eTxt ? ' (' + eTxt + ')' : ''));
        }

        if (domIP && domIP !== landIP) {
          const domTag =
            (domestic && domestic.shortTag) ||
            [domestic && domestic.location, domestic && domestic.isp].filter(Boolean).join(' ');
          routeLines.push('🇨🇳 直连：' + maskIPString(domIP, CFG.maskIP) + (domTag ? ' (' + domTag + ')' : ''));
        }

        const bodyText =
          routeLines.length > 0 ? exitLines.join('\n') + '\n\n' + routeLines.join('\n') : exitLines.join('\n');
        if (!_scriptSettled) notify(titleText, subtitleText, bodyText);
      }
    } catch (e) {
      log('network-changed error: ' + ((e && e.message) || e));
    }
    safeDone({});
  }

  /**
   * 软超时提前熔断看门狗：远早于 .plugin 宿主 timeout 主动调用 $done 并还原挂起策略，
   * 确保宿主 ModuleScriptHost 永远不会进入超时看门狗并将脚本 SHA-256 写入 quarantine.json。
   */
  function armSoftDeadlineGuard(ctx) {
    let budgetMs = 36000;
    if (ctx.isHTTP) {
      budgetMs = Math.min(45000, Math.max(20000, CFG.timeoutMs * 3 + 10000));
    } else if (ctx.nodeName) {
      if (CFG.mode === 'unlock') {
        budgetMs = Math.min(56000, Math.max(28000, CFG.timeoutMs * 4 + 14000));
      } else if (CFG.mode === 'purity') {
        budgetMs = Math.min(48000, Math.max(24000, CFG.timeoutMs * 4 + 10000));
      } else {
        budgetMs = Math.min(38000, Math.max(20000, CFG.timeoutMs * 3 + 8000));
      }
    } else if (CFG.mode === 'event') {
      budgetMs = 22000;
    } else {
      budgetMs = 25000;
    }

    _softDeadlineTimer = setTimeout(() => {
      if (_scriptSettled) return;
      log('Soft deadline (' + budgetMs + 'ms) reached, settling early to prevent host quarantine');
      recoverDanglingPolicyIfAny();

      if (ctx.isHTTP) {
        const reqURL = ($request && $request.url) || '';
        const isBridge = reqURL.indexOf(BRIDGE_CHECK_PATH) !== -1;
        safeDone({
          response: {
            status: isBridge ? 200 : 504,
            headers: {
              'Content-Type': isBridge ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
              'Cache-Control': 'no-store',
            },
            body: isBridge
              ? JSON.stringify({
                  ok: false,
                  fromClashTunnelBridge: true,
                  error: '节点探测超时（目标节点可能不可用或握手过慢）',
                })
              : '节点探测响应超时，请检查节点连通性后重试',
          },
        });
        return;
      }

      if (ctx.nodeName) {
        const titleMap = {
          info: '节点链路与入口查询',
          purity: '节点纯净度深度检测',
          unlock: '流媒体与 AI 解锁检测',
        };
        const sheetTitle = titleMap[CFG.mode] || '节点网络信息查询';
        safeDone({
          title: sheetTitle,
          htmlMessage:
            '<b>▍查询超时已保护退出</b><br>' +
            '目标节点：' + colorSpan(ctx.nodeName, COLORS.primary, true) +
            '<br>原因说明：' + colorSpan('节点握手或远端接口响应超过安全时限，已自动中止探测', COLORS.warning, false) +
            '<br><br><span style="color:' + COLORS.muted + '">💡 请检查该节点是否能正常连通，或稍后重试。</span>',
        });
        return;
      }

      if (CFG.mode === 'event') {
        safeDone({});
        return;
      }

      safeDone({
        title: '当前网络出口信息',
        content: '查询超时，请检查当前网络或代理连通性后重试',
        icon: 'exclamationmark.triangle',
        'icon-color': '#F59E0B',
      });
    }, budgetMs);
  }

  (async function main() {
    const isHTTP = Boolean(typeof $request !== 'undefined' && $request && $request.url);
    const env = typeof $environment !== 'undefined' && $environment ? $environment : {};
    const params = env.params && typeof env.params === 'object' ? env.params : {};
    const nodeName = params.node ? String(params.node).trim() : '';

    armSoftDeadlineGuard({ isHTTP, nodeName });

    try {
      if (isHTTP) {
        await handleHTTPRequest();
        return;
      }
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
      recoverDanglingPolicyIfAny();
      safeDone({
        title: '节点检测异常',
        content: String((err && err.message) || err),
        htmlMessage: colorSpan('执行异常：' + String((err && err.message) || err), COLORS.danger, true),
      });
    }
  })();
})();
