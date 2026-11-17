/**
 * Node Detection Tool (v3.1.0 · Universal Multi-Client)
 *
 * 多客户端节点链路查询、IP 纯净度与流媒体解锁检测脚本
 * 适用环境：Loon / Clash-Client / Surge / Stash / Shadowrocket / Egern
 *
 * Repository: https://github.com/823155705/clash-client-node-info
 * License: GPL-3.0-or-later
 */

(function () {
  'use strict';

  const VERSION = '3.1.0';
  const BUILD_VARIANT = 'universal';
  const DEFAULT_HOST_HINT = 'auto';

  const BRIDGE_HOST = 'net-lsp-x.com';
  const BRIDGE_CHECK_PATH = '/__clash_node_check';
  const STATE_RESTORE_KEY = 'xream_clash_pending_restore_v1';
  const LAST_EVENT_KEY = 'xream_clash_last_net_event_v1';
  const IP_CACHE_KEY = 'xream_clash_ip_cache_v1';
  const IP_CACHE_MAX = 20;
  const CACHE_TTL_BG_MS = 6 * 3600 * 1000; // 后台切网与面板复用缓存 6 小时
  const CACHE_TTL_FG_MS = 10 * 60 * 1000;  // 前台链路查询对静态 BGP/入口归属短缓存 10 分钟

  // 深浅色模式双端高对比度语义调色盘（根容器不写死黑白文字色，自动继承 iOS/macOS 系统浅色/深色文本）
  const COLORS = {
    primary: '#3b82f6',
    success: '#10b981',
    warning: '#f59e0b',
    danger: '#ef4444',
    purple: '#8b5cf6',
    muted: '#8e8e93',
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

  // Cloudflare POP 三字码 -> ISO 国家/地区码映射（用于交叉验证海外入口直套 WARP vs 跨国跳板后再套 WARP）
  const CF_COLO_CC_MAP = {
    HKG: 'HK', TPE: 'TW', KHH: 'TW', MFM: 'MO',
    NRT: 'JP', HND: 'JP', KIX: 'JP', FUK: 'JP', OKA: 'JP', NGO: 'JP',
    ICN: 'KR', PUS: 'KR',
    SIN: 'SG', KUL: 'MY', BKK: 'TH', SGN: 'VN', HAN: 'VN', MNL: 'PH', CGK: 'ID', PNH: 'KH',
    DEL: 'IN', BOM: 'IN', MAA: 'IN', DXB: 'AE', DOH: 'QA', TLV: 'IL', IST: 'TR',
    LAX: 'US', SJC: 'US', SFO: 'US', SEA: 'US', PDX: 'US', SAN: 'US', PHX: 'US',
    SLC: 'US', DEN: 'US', DFW: 'US', IAH: 'US', ORD: 'US', MSP: 'US',
    IAD: 'US', EWR: 'US', JFK: 'US', BOS: 'US', ATL: 'US', MIA: 'US',
    YYZ: 'CA', YVR: 'CA', YUL: 'CA',
    LHR: 'GB', MAN: 'GB', AMS: 'NL', FRA: 'DE', DUS: 'DE', MUC: 'DE',
    CDG: 'FR', MRS: 'FR', ZRH: 'CH', VIE: 'AT', MXP: 'IT', FCO: 'IT', MAD: 'ES',
    WAW: 'PL', PRG: 'CZ', BUD: 'HU', ARN: 'SE', HEL: 'FI', OSL: 'NO', CPH: 'DK',
    DME: 'RU', LED: 'RU',
    SYD: 'AU', MEL: 'AU', BNE: 'AU', PER: 'AU', AKL: 'NZ',
    GRU: 'BR', EZE: 'AR', SCL: 'CL', MEX: 'MX', JNB: 'ZA',
  };

  // ============================================================================
  // 1. 多客户端宿主适配层 (HostAdapter) 与参数解析
  // ============================================================================

  function parseArguments(raw) {
    const out = {};
    if (raw === undefined || raw === null || raw === '') return out;
    if (typeof raw === 'object') {
      Object.keys(raw).forEach((k) => {
        const val = raw[k];
        if (typeof val === 'string' && /^\$?\{[^{}\s]+\}$/.test(val.trim())) {
          out[k] = '';
        } else {
          out[k] = val;
        }
      });
      return out;
    }
    const text = String(raw).trim();
    if (!text) return out;
    if (text.startsWith('{') && text.endsWith('}')) {
      try {
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return parseArguments(parsed);
        }
      } catch (_) {}
    }
    text.split('&').forEach((pair) => {
      if (!pair) return;
      const idx = pair.indexOf('=');
      if (idx <= 0) return;
      let k = pair.slice(0, idx).trim();
      let v = pair.slice(idx + 1).trim();
      try {
        k = decodeURIComponent(k);
      } catch (_) {}
      try {
        v = decodeURIComponent(v);
      } catch (_) {}
      if (/^\$?\{[^{}\s]+\}$/.test(v)) v = '';
      out[k] = v;
    });
    return out;
  }

  function toStr(val, defaultVal) {
    const fallback = defaultVal === undefined ? '' : defaultVal;
    if (val === undefined || val === null) return fallback;
    const s = String(val).trim();
    return s === '' ? fallback : s;
  }

  function toBool(val, defaultVal) {
    if (val === undefined || val === null || val === '') return defaultVal;
    if (typeof val === 'boolean') return val;
    if (typeof val === 'number') return val !== 0;
    const s = String(val).trim().toLowerCase();
    if (['1', 'true', 'yes', 'on', '开启', '是'].includes(s)) return true;
    if (['0', 'false', 'no', 'off', '关闭', '否'].includes(s)) return false;
    return defaultVal;
  }

  function toNum(val, defaultVal, minVal, maxVal) {
    if (val === undefined || val === null || val === '' || typeof val === 'boolean') return defaultVal;
    const n = Number(val);
    if (!Number.isFinite(n)) return defaultVal;
    return Math.min(maxVal, Math.max(minVal, n));
  }

  function parseControllerPort(raw, defaultPort) {
    const s = toStr(raw, '');
    if (!s) return defaultPort;
    const colonMatch = s.match(/:(\d{2,5})\/?$/);
    if (colonMatch) return toNum(colonMatch[1], defaultPort, 1, 65535);
    return toNum(s, defaultPort, 1, 65535);
  }

  function normalizeSecret(raw) {
    return toStr(raw, '')
      .replace(/^Bearer\s+/i, '')
      .trim();
  }

  function normalizeMode(raw) {
    const m = toStr(raw, 'info').toLowerCase();
    if (m === 'basic' || m === 'info') return 'info';
    if (m === 'deep' || m === 'purity') return 'purity';
    if (m === 'unlock' || m === 'media') return 'unlock';
    if (m === 'bridge' || m === 'event' || m === 'panel') return m;
    return 'info';
  }

  function normalizeClientHint(raw) {
    const c = toStr(raw, '').toLowerCase();
    if (!c || c === 'auto') return '';
    if (c === 'loon') return 'loon';
    if (c === 'clash' || c === 'clash-client' || c === 'projectclash' || c === 'mihomo') return 'clash';
    if (c === 'surge') return 'surge';
    if (c === 'stash') return 'stash';
    if (c === 'shadowrocket' || c === 'sr' || c === 'rocket') return 'shadowrocket';
    if (c === 'egern') return 'egern';
    return '';
  }

  /**
   * 运行模式解析优先级：
   * ① ARGS.MODE ➔ ② $request && $request.url ('bridge') ➔ ③ $script.name (按 Loon tag 匹配) ➔ ④ 'info'
   */
  function resolveRunMode(args, runtimeCtx) {
    const a = args && typeof args === 'object' ? args : {};
    const ctx = runtimeCtx || {};
    const explicitMode = toStr(a.MODE !== undefined ? a.MODE : a.mode, '');
    if (explicitMode) return normalizeMode(explicitMode);

    const req = ctx.request !== undefined ? ctx.request : typeof $request !== 'undefined' ? $request : null;
    if (req && req.url) return 'bridge';

    const sc = ctx.script !== undefined ? ctx.script : typeof $script !== 'undefined' ? $script : null;
    const scriptName = sc && sc.name ? String(sc.name).trim() : '';
    if (scriptName) {
      if (/纯净度|风险|风控|purity/i.test(scriptName)) return 'purity';
      if (/解锁|流媒体|unlock/i.test(scriptName)) return 'unlock';
      if (/切网|网络切换|切换通知|网络变化|event/i.test(scriptName)) return 'event';
      if (/网页诊断|诊断面板|portal/i.test(scriptName)) return 'info';
      return 'info';
    }

    return 'info';
  }

  /**
   * 精准宿主识别（彻底解决 Clash-Client 伪 $loon 注入陷阱）
   */
  function detectHostClient(args, runtimeCtx) {
    const a = args && typeof args === 'object' ? args : {};
    const ctx = runtimeCtx || {};

    // 1. 显式 CLIENT 参数最高优先级
    const explicit = normalizeClientHint(a.CLIENT !== undefined ? a.CLIENT : a.client);
    if (explicit) return explicit;

    const env =
      ctx.environment !== undefined
        ? ctx.environment
        : typeof $environment !== 'undefined' && $environment
          ? $environment
          : {};
    const rocketVal = ctx.rocket !== undefined ? ctx.rocket : typeof $rocket !== 'undefined' ? $rocket : undefined;
    const egernVal = ctx.egern !== undefined ? ctx.egern : typeof Egern !== 'undefined' ? Egern : undefined;
    const loonVal = ctx.loon !== undefined ? ctx.loon : typeof $loon !== 'undefined' ? $loon : undefined;
    const utilsVal = ctx.utils !== undefined ? ctx.utils : typeof $utils !== 'undefined' ? $utils : undefined;
    const scriptVal = ctx.script !== undefined ? ctx.script : typeof $script !== 'undefined' ? $script : undefined;
    const configVal = ctx.config !== undefined ? ctx.config : typeof $config !== 'undefined' ? $config : undefined;
    const hostHint = normalizeClientHint(ctx.hostHint !== undefined ? ctx.hostHint : DEFAULT_HOST_HINT);

    // 2. 独立特征宿主嗅探：Stash / Shadowrocket / Egern / Surge
    if (env && env['stash-version']) return 'stash';
    if (rocketVal !== undefined) return 'shadowrocket';
    if (egernVal !== undefined) return 'egern';
    if (env && env['surge-version']) return 'surge';

    // 3. 区分真 Loon 与 Clash-Client (ProjectClash)
    const params = env && env.params && typeof env.params === 'object' ? env.params : {};
    const nodeInfo = params.nodeInfo && typeof params.nodeInfo === 'object' ? params.nodeInfo : null;

    const hasMihomoNodeInfo =
      Boolean(nodeInfo) &&
      !nodeInfo.address &&
      (Array.isArray(nodeInfo.history) || 'alive' in nodeInfo || 'dialer-proxy' in nodeInfo);
    const loonStrMentionsClash = typeof loonVal === 'string' && /clash/i.test(loonVal);
    const variant = toStr(ctx.buildVariant !== undefined ? ctx.buildVariant : BUILD_VARIANT, '');
    const isClashArtifact = variant === 'clash-fg' || variant === 'clash-bg';
    const hasUtilsGeoIP = Boolean(utilsVal && typeof utilsVal.geoip === 'function');
    const hasLoonNodeAddress = Boolean(nodeInfo && typeof nodeInfo.address === 'string' && nodeInfo.address);

    if (hostHint === 'clash' || hasMihomoNodeInfo || loonStrMentionsClash) {
      return 'clash';
    }
    if (isClashArtifact && !hasUtilsGeoIP && !hasLoonNodeAddress) {
      return 'clash';
    }

    if (typeof loonVal === 'string') {
      const hasBuildNumber = /\(\d+\)\s*$/.test(loonVal);
      const hasScriptObj = Boolean(scriptVal && typeof scriptVal === 'object');
      const hasConfigAPI = Boolean(configVal && typeof configVal.getConfig === 'function');
      const isLoonWord = /\bloon\b/i.test(loonVal) && !hasConfigAPI;

      if (hasBuildNumber || hasUtilsGeoIP || hasLoonNodeAddress || hasScriptObj || isLoonWord) {
        return 'loon';
      }
    }

    if (hostHint) return hostHint;
    if (configVal && typeof configVal.getConfig === 'function') return 'clash';
    if (typeof loonVal === 'string') return 'loon';
    if (loonVal !== undefined) return 'clash';
    return 'clash';
  }

  const ARGS = parseArguments(typeof $argument !== 'undefined' ? $argument : '');
  const HOST_CLIENT = detectHostClient(ARGS);
  const CFG = {
    client: HOST_CLIENT,
    mode: resolveRunMode(ARGS),
    showDomestic: toBool(ARGS.SHOW_DOMESTIC, true),
    showEntrance: toBool(ARGS.SHOW_ENTRANCE, true),
    controllerPort: parseControllerPort(ARGS.CONTROLLER_PORT, 9090),
    controllerSecret: normalizeSecret(ARGS.CONTROLLER_SECRET),
    checkIPv6: toBool(ARGS.CHECK_IPV6, true),
    maskIP: toBool(ARGS.MASK_IP, false),
    autoSwitchFallback: toBool(ARGS.AUTO_SWITCH_FALLBACK, true),
    notifyOnChange: toBool(ARGS.NOTIFY_ON_CHANGE, false),
    ipapiKey: toStr(ARGS.IPAPI_KEY, ''),
    timeoutMs: Math.round(toNum(ARGS.TIMEOUT_SEC, 8, 3, 25) * 1000),
  };

  let _scriptSettled = false;
  let _softDeadlineTimer = null;

  function log(msg) {
    try {
      console.log('[xream-node:' + HOST_CLIENT + '] ' + msg);
    } catch (_) {}
  }

  /**
   * 幂等安全结束器：确保全局只调用一次 $done，并在宿主看门狗到期前清理内部定时器，杜绝触发 SHA-256 隔离
   */
  function safeDone(payload) {
    if (_scriptSettled) return;
    _scriptSettled = true;
    if (_softDeadlineTimer) {
      clearTimeout(_softDeadlineTimer);
      _softDeadlineTimer = null;
    }
    try {
      if (typeof $done === 'function') {
        $done(payload === undefined ? {} : payload);
      }
    } catch (_) {}
  }

  // ============================================================================
  // 2. 持久化存储、离线 MMDB 工具与多端网络请求适配
  // ============================================================================

  /**
   * 显式传入 key 读写 $persistentStore，确保 Loon 下不同 tag 的脚本共享同一缓存命名空间
   */
  function storeRead(key) {
    const k = toStr(key, '');
    if (!k) return null;
    try {
      if (typeof $persistentStore !== 'undefined' && $persistentStore && $persistentStore.read) {
        return $persistentStore.read(k);
      }
      if (typeof $prefs !== 'undefined' && $prefs && $prefs.valueForKey) {
        return $prefs.valueForKey(k);
      }
    } catch (_) {}
    return null;
  }

  function storeWrite(key, val) {
    const k = toStr(key, '');
    if (!k) return false;
    try {
      const strVal = val === undefined || val === null ? '' : String(val);
      if (typeof $persistentStore !== 'undefined' && $persistentStore && $persistentStore.write) {
        return $persistentStore.write(strVal, k);
      }
      if (typeof $prefs !== 'undefined' && $prefs && $prefs.setValueForKey) {
        return $prefs.setValueForKey(strVal, k);
      }
    } catch (_) {}
    return false;
  }

  function notify(title, subtitle, body) {
    try {
      if (typeof $notification !== 'undefined' && $notification && $notification.post) {
        $notification.post(title || '', subtitle || '', body || '');
      }
    } catch (_) {}
  }

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  /**
   * Loon / Surge 原生内置 MaxMind MMDB 0ms 离线查询兜底
   */
  function readNativeMMDB(ip, utilsOverride) {
    const out = { countryCode: '', asn: '', aso: '' };
    const target = toStr(ip, '');
    if (!target || isPrivateLANIP(target) || isBogusEntranceIP(target)) return out;
    const u = utilsOverride !== undefined ? utilsOverride : typeof $utils !== 'undefined' ? $utils : null;
    if (!u || typeof u !== 'object') return out;

    try {
      if (typeof u.geoip === 'function') {
        const rawCC = toStr(u.geoip(target), '').toUpperCase();
        if (/^[A-Z]{2}$/.test(rawCC) && rawCC !== 'XX' && rawCC !== 'ZZ') {
          out.countryCode = rawCC;
        }
      }
    } catch (_) {}

    try {
      if (typeof u.ipasn === 'function') {
        const rawASN = toStr(u.ipasn(target), '').replace(/^AS/i, '').trim();
        const n = Number(rawASN);
        if (Number.isFinite(n) && n > 0) {
          out.asn = 'AS' + n;
        }
      }
    } catch (_) {}

    try {
      if (typeof u.ipaso === 'function') {
        const rawASO = toStr(u.ipaso(target), '');
        if (rawASO && !/^(unknown|none|-)$/i.test(rawASO)) {
          out.aso = rawASO;
        }
      }
    } catch (_) {}

    return out;
  }

  /**
   * 并发限流执行器：将并发数严格控制在 iOS NetworkExtension 内存与连接红线内
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
   * 轻量级按 IP 维度的 LRU 元数据缓存
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

  /**
   * 按宿主计算 $httpClient timeout 参数单位：
   * - Loon / Clash-Client(含 $loon 运行时): 毫秒 (ms)
   * - Surge / Stash / Shadowrocket / Egern: 秒 (s) Math.ceil(timeoutMs / 1000)
   */
  function computeHttpClientTimeout(timeoutMs, hostClient) {
    const client = hostClient || HOST_CLIENT;
    if (client === 'surge' || client === 'stash' || client === 'shadowrocket' || client === 'egern') {
      return Math.max(1, Math.ceil(timeoutMs / 1000));
    }
    if (client === 'loon') {
      return Math.max(800, Math.round(timeoutMs));
    }
    const hasLoonCompat = typeof $loon !== 'undefined';
    return hasLoonCompat ? Math.max(800, Math.round(timeoutMs)) : Math.max(1, Math.ceil(timeoutMs / 1000));
  }

  /**
   * 多客户端出站节点/策略选择器：
   * - Loon: { node: targetNode, 'auto-redirect': false }
   * - Surge / Egern: { policy: targetNode, 'auto-redirect': false }
   * - Stash: { policy: targetNode, headers: { 'X-Stash-Selected-Proxy': encodeURIComponent(targetNode) }, 'auto-redirect': false }
   * - Shadowrocket: { headers: { 'X-Surge-Policy': targetNode }, 'auto-redirect': false }
   * - Clash-Client: { node: targetNode, policy: targetNode, 'auto-redirect': false }
   */
  function buildOutboundOpts(url, targetNode, extraHeaders, hostOverride) {
    const client = hostOverride || HOST_CLIENT;
    const headers = Object.assign({}, extraHeaders || {});
    const opts = {
      url,
      headers,
      'auto-redirect': false,
    };
    if (targetNode) {
      if (client === 'loon') {
        opts.node = targetNode;
      } else if (client === 'surge' || client === 'egern') {
        opts.policy = targetNode;
      } else if (client === 'stash') {
        opts.policy = targetNode;
        headers['X-Stash-Selected-Proxy'] = encodeURIComponent(targetNode);
      } else if (client === 'shadowrocket') {
        headers['X-Surge-Policy'] = targetNode;
      } else {
        opts.node = targetNode;
        opts.policy = targetNode;
      }
    }
    return opts;
  }

  function resolveDirectOutboundPolicy(inTunnel) {
    return inTunnel || HOST_CLIENT !== 'clash' ? 'DIRECT' : undefined;
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
    if (reqOpts['auto-redirect'] === undefined) {
      reqOpts['auto-redirect'] = false;
    }
    reqOpts.timeout = computeHttpClientTimeout(timeoutMs, HOST_CLIENT);

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
    let res = await httpRequest(method || 'get', options, timeoutMs);
    if (
      (res.status === 301 || res.status === 302 || res.status === 307 || res.status === 308) &&
      res.headers &&
      (res.headers.Location || res.headers.location)
    ) {
      const nextUrl = String(res.headers.Location || res.headers.location).trim();
      if (/^https?:\/\//i.test(nextUrl)) {
        const nextOpts =
          typeof options === 'string' ? { url: nextUrl } : Object.assign({}, options, { url: nextUrl });
        res = await httpRequest(method || 'get', nextOpts, timeoutMs);
      }
    }
    if (res.status < 200 || res.status >= 400) {
      throw new Error('HTTP ' + res.status);
    }
    const text = res.body.trim();
    if (!text) throw new Error('Empty body');
    return JSON.parse(text);
  }

  // ============================================================================
  // 3. 格式化辅助函数与客观 ISP 品牌规范化（严禁硬编码改写为 BGP / 专网）
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

  function esc(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function colorSpan(text, hex, bold) {
    const weight = bold ? ';font-weight:600' : '';
    return '<span style="color:' + hex + weight + '">' + esc(text) + '</span>';
  }

  const SHEET_HR =
    '<hr style="border:none;border-top:1px solid rgba(128,128,128,0.18);margin:8px 0">';
  const SHEET_SUB_HR =
    '<hr style="border:none;border-top:1px solid rgba(128,128,128,0.14);margin:6px 0">';

  function wrapSheetBodyHTML(innerHTML) {
    return (
      '<div style="font-family:-apple-system,BlinkMacSystemFont,\'PingFang SC\',sans-serif;font-size:13.5px;line-height:1.65">' +
      innerHTML +
      '</div>'
    );
  }

  function renderKVRow(label, valueHtml, minEm) {
    const w = minEm || '2.8em';
    return (
      '<span style="display:inline-block;min-width:' +
      w +
      ';color:' +
      COLORS.muted +
      '">' +
      esc(label) +
      '</span> ' +
      valueHtml
    );
  }

  // ISO 国家/地区码 -> 简明中文映射（消除英文源返回 Hong Kong / Singapore / United States 等中英混杂）
  const COUNTRY_CODE_ZH_MAP = {
    CN: '中国', HK: '香港', MO: '澳门', TW: '台湾', SG: '新加坡',
    JP: '日本', KR: '韩国', US: '美国', CA: '加拿大', MX: '墨西哥',
    GB: '英国', DE: '德国', FR: '法国', NL: '荷兰', CH: '瑞士',
    AT: '奥地利', BE: '比利时', IT: '意大利', ES: '西班牙', PT: '葡萄牙',
    SE: '瑞典', NO: '挪威', FI: '芬兰', DK: '丹麦', IE: '爱尔兰',
    PL: '波兰', CZ: '捷克', HU: '匈牙利', RO: '罗马尼亚', BG: '保加利亚',
    UA: '乌克兰', RU: '俄罗斯', TR: '土耳其', IL: '以色列', AE: '阿联酋',
    SA: '沙特', QA: '卡塔尔', IN: '印度', PK: '巴基斯坦', BD: '孟加拉',
    TH: '泰国', VN: '越南', MY: '马来西亚', PH: '菲律宾', ID: '印尼',
    KH: '柬埔寨', LA: '老挝', MM: '缅甸', NP: '尼泊尔', KZ: '哈萨克斯坦',
    AU: '澳大利亚', NZ: '新西兰', BR: '巴西', AR: '阿根廷', CL: '智利',
    CO: '哥伦比亚', PE: '秘鲁', ZA: '南非', EG: '埃及', NG: '尼日利亚',
    LU: '卢森堡', IS: '冰岛', GR: '希腊',
  };

  // 中国 34 省级行政区 + 重点口岸/省会及台湾主要城市英文/拼音 -> 中文归一表
  const CN_PLACE_ZH_MAP = {
    // 直辖市与港澳台
    beijing: '北京', peking: '北京',
    shanghai: '上海',
    tianjin: '天津',
    chongqing: '重庆',
    hongkong: '香港',
    macau: '澳门', macao: '澳门',
    taiwan: '台湾',
    // 23 省 + 5 自治区
    guangdong: '广东', canton: '广东',
    jiangsu: '江苏',
    zhejiang: '浙江',
    fujian: '福建',
    shandong: '山东',
    hubei: '湖北',
    hunan: '湖南',
    sichuan: '四川',
    henan: '河南',
    hebei: '河北',
    anhui: '安徽',
    jiangxi: '江西',
    liaoning: '辽宁',
    jilin: '吉林',
    heilongjiang: '黑龙江',
    shanxi: '山西',
    shaanxi: '陕西',
    yunnan: '云南',
    guizhou: '贵州',
    guangxi: '广西', guangxizhuangzu: '广西',
    hainan: '海南',
    gansu: '甘肃',
    qinghai: '青海',
    ningxia: '宁夏', ningxiahuizu: '宁夏',
    xinjiang: '新疆', xinjianguygur: '新疆', sinkiang: '新疆',
    tibet: '西藏', xizang: '西藏',
    innermongolia: '内蒙古', neimenggu: '内蒙古', neimongol: '内蒙古',
    // 华东/华南高频口岸与核心城市
    shenzhen: '深圳', guangzhou: '广州', dongguan: '东莞', foshan: '佛山',
    zhuhai: '珠海', zhongshan: '中山', huizhou: '惠州', jiangmen: '江门',
    shantou: '汕头', zhanjiang: '湛江', shaoguan: '韶关', qingyuan: '清远',
    jieyang: '揭阳', meizhou: '梅州', maoming: '茂名', zhaoqing: '肇庆',
    shanwei: '汕尾', yangjiang: '阳江', heyuan: '河源', chaozhou: '潮州', yunfu: '云浮',
    nanjing: '南京', suzhou: '苏州', wuxi: '无锡', changzhou: '常州',
    zhenjiang: '镇江', nantong: '南通', yangzhou: '扬州', xuzhou: '徐州',
    yancheng: '盐城', taizhou: '泰州', huaian: '淮安', lianyungang: '连云港',
    suqian: '宿迁', kunshan: '昆山',
    hangzhou: '杭州', ningbo: '宁波', wenzhou: '温州', jiaxing: '嘉兴',
    huzhou: '湖州', shaoxing: '绍兴', jinhua: '金华', yiwu: '义乌',
    quzhou: '衢州', zhoushan: '舟山', lishui: '丽水',
    xiamen: '厦门', fuzhou: '福州', quanzhou: '泉州', zhangzhou: '漳州',
    putian: '莆田', longyan: '龙岩', ningde: '宁德', sanming: '三明', nanping: '南平',
    qingdao: '青岛', jinan: '济南', yantai: '烟台', weifang: '潍坊',
    weihai: '威海', zibo: '淄博', linyi: '临沂', jining: '济宁', rizhao: '日照',
    // 华中/华北/西南/西北/东北主要省会与节点城市
    wuhan: '武汉', yichang: '宜昌', xiangyang: '襄阳',
    changsha: '长沙', zhuzhou: '株洲', hengyang: '衡阳',
    chengdu: '成都', mianyang: '绵阳', deyang: '德阳',
    xian: '西安', xianyang: '咸阳', baoding: '保定',
    zhengzhou: '郑州', luoyang: '洛阳',
    hefei: '合肥', wuhu: '芜湖', bangbu: '蚌埠',
    nanchang: '南昌', ganzhou: '赣州', jiujiang: '九江', shangrao: '上饶',
    shijiazhuang: '石家庄', tangshan: '唐山', langfang: '廊坊', zhangjiakou: '张家口', qinhuangdao: '秦皇岛',
    taiyuan: '太原', datong: '大同',
    shenyang: '沈阳', dalian: '大连', anshan: '鞍山',
    changchun: '长春', jilinshi: '吉林',
    harbin: '哈尔滨', daqing: '大庆',
    kunming: '昆明', dali: '大理',
    guiyang: '贵阳', zunyi: '遵义',
    nanning: '南宁', liuzhou: '柳州', guilin: '桂林', beihai: '北海',
    haikou: '海口', sanya: '三亚',
    lanzhou: '兰州', xining: '西宁', yinchuan: '银川',
    urumqi: '乌鲁木齐', wulumuqi: '乌鲁木齐',
    lhasa: '拉萨', lasa: '拉萨',
    hohhot: '呼和浩特', huhehaote: '呼和浩特', baotou: '包头',
    // 台湾主要城市
    taipei: '台北', newtaipei: '新北', xinbei: '新北', taoyuan: '桃园',
    taichung: '台中', tainan: '台南', kaohsiung: '高雄', hsinchu: '新竹',
    keelung: '基隆', changhua: '彰化',
  };

  function hasCJK(str) {
    return /[\u4e00-\u9fa5]/.test(String(str || ''));
  }

  function cleanCNPlaceName(str) {
    return String(str || '')
      .replace(/省|市|壮族自治区|维吾尔自治区|回族自治区|自治区|特别行政区|地区/g, '')
      .trim();
  }

  /**
   * 将大陆/港澳台省市名（含英文/拼音，如 "Shanghai", "Guangdong Province", "Xi'an"）归一为纯净中文简称
   */
  function normalizeCNPlace(raw) {
    const s = String(raw || '').trim();
    if (!s) return '';
    if (hasCJK(s)) return cleanCNPlaceName(s);
    const key = s
      .toLowerCase()
      .replace(/\b(autonomous\s+region|special\s+administrative\s+region|municipality|prefecture|province|prov|district|county|city|sar|zizhiqu|sheng|shi)\b/g, '')
      .replace(/[^a-z]/g, '');
    if (!key) return '';
    return CN_PLACE_ZH_MAP[key] || '';
  }

  function inferCountryCode(countryCode, countryName) {
    const cc = toStr(countryCode, '').toUpperCase();
    if (/^[A-Z]{2}$/.test(cc)) return cc;
    const c = toStr(countryName, '').toLowerCase();
    if (!c) return '';
    if (c === '中国' || c === 'china') return 'CN';
    if (c === '香港' || c === 'hong kong' || c === 'hongkong') return 'HK';
    if (c === '澳门' || c === 'macau' || c === 'macao') return 'MO';
    if (c === '台湾' || c === 'taiwan') return 'TW';
    if (c === '新加坡' || c === 'singapore') return 'SG';
    return '';
  }

  /**
   * 紧凑去重地理位置格式化：
   * - 港澳新等城市型地区直接输出「香港」「澳门」「新加坡」，彻底剔除 Kowloon / Hong Kong / Singapore 等重复或英文区名
   * - 中国大陆省市自动将英文/拼音映射为中文并去重（如 Shanghai -> 上海，Guangdong + Shenzhen -> 广东深圳；shortHop 模式下取城市简称「深圳」）
   * - 海外国家优先使用中文国名 + 紧凑城市名（无中文则保留如「美国 Los Angeles」，过滤冗余州省名与重复国名）
   */
  function formatCompactLocation(geoObj, opts) {
    if (!geoObj || typeof geoObj !== 'object') return '';
    if (geoObj.isPrivate) return '局域网';
    const shortHop = Boolean(opts && opts.shortHop);
    const cc = inferCountryCode(geoObj.countryCode, geoObj.country);

    if (cc === 'HK') return '香港';
    if (cc === 'MO') return '澳门';
    if (cc === 'SG') return '新加坡';

    if (cc === 'CN') {
      const regZh = normalizeCNPlace(geoObj.region);
      const cityZh = normalizeCNPlace(geoObj.city);
      if (shortHop) return cityZh || regZh || '中国';
      return deduplicateGeoParts([regZh, cityZh]).join('') || '中国';
    }

    if (cc === 'TW') {
      const cityZh = normalizeCNPlace(geoObj.city) || normalizeCNPlace(geoObj.region);
      if (shortHop || !cityZh || cityZh === '台湾') return '台湾';
      return '台湾' + cityZh;
    }

    const rawCountry = toStr(geoObj.country, '');
    const countryZh =
      COUNTRY_CODE_ZH_MAP[cc] || (hasCJK(rawCountry) ? rawCountry : '') || rawCountry || cc;
    if (shortHop) return countryZh || cc;

    let city = toStr(geoObj.city, '').replace(/\s+am\s+Main$/i, '').trim();
    if (!city && geoObj.region) {
      const reg = toStr(geoObj.region, '').trim();
      if (hasCJK(reg)) city = reg;
    }
    if (!city) return countryZh;

    const cityLower = city.toLowerCase();
    if (
      cityLower === countryZh.toLowerCase() ||
      cityLower === rawCountry.toLowerCase() ||
      cityLower === cc.toLowerCase()
    ) {
      return countryZh;
    }
    if (hasCJK(countryZh) && hasCJK(city)) {
      return countryZh.includes(city) ? countryZh : countryZh + city;
    }
    return [countryZh, city].filter(Boolean).join(' ');
  }

  function normalizeCNISP(raw) {
    const s = String(raw || '');
    if (/电信|telecom|chinanet|ctcc/i.test(s)) return '电信';
    if (/联通|unicom|cucc/i.test(s)) return '联通';
    if (/移动|mobile|cmcc|铁通/i.test(s)) return '移动';
    if (/广电|cbn|cable/i.test(s)) return '广电';
    if (/教育|cernet/i.test(s)) return '教育网';
    if (/科技网|cstnet/i.test(s)) return '科技网';
    return s.trim();
  }

  /**
   * 客观入口品牌名规范化：只还原真实云商/运营商名称，绝不把普通云厂商拔高为「XX云 BGP」或「XX 专网」
   */
  function normalizeEntranceISP(rawISP, rawOrg, countryCode) {
    const combined = [rawISP, rawOrg].filter(Boolean).join(' ');
    if (/aliyun|alibaba|alicloud|阿里云|万网/i.test(combined)) return '阿里云';
    if (/tencent|qcloud|腾讯云/i.test(combined)) return '腾讯云';
    if (/huawei|hwclouds|华为云/i.test(combined)) return '华为云';
    if (/ucloud|优刻得/i.test(combined)) return 'UCloud';
    if (/volcengine|bytedance|火山引擎|字节跳动/i.test(combined)) return '火山引擎';
    if (/kingsoft|ksyun|金山云/i.test(combined)) return '金山云';
    if (/qingcloud|青云/i.test(combined)) return '青云';
    if (/ctyun|天翼云/i.test(combined)) return '天翼云';
    if (/ecloud|移动云/i.test(combined)) return '移动云';
    if (/cucloud|联通云/i.test(combined)) return '联通云';
    if (/baidu|百度/i.test(combined)) return '百度智能云';
    if (/jdcloud|京东/i.test(combined)) return '京东云';
    if (/wangsu|chinanetcenter|网宿/i.test(combined)) return '网宿科技';
    if (/cloudflare/i.test(combined)) return 'Cloudflare';
    if (/zenlayer/i.test(combined)) return 'Zenlayer';
    if (/\bdmit\b/i.test(combined)) return 'DMIT';
    if (/xtom/i.test(combined)) return 'xTom';
    if (/misaka/i.test(combined)) return 'Misaka';
    if (/\baws\b|amazon/i.test(combined)) return 'AWS';
    if (/azure|microsoft/i.test(combined)) return 'Azure';
    if (/google\s*cloud|\bgcp\b/i.test(combined)) return 'Google Cloud';
    if (String(countryCode || '').toUpperCase() === 'CN') {
      const cn = normalizeCNISP(combined);
      if (cn && cn !== combined.trim()) return '中国' + cn.replace(/^中国/, '');
    }
    return String(rawISP || rawOrg || '').trim();
  }

  /**
   * 落地/通用 ISP 机构名精简裁剪：剥离冗余公司后缀 (LLC / Inc. / Ltd. / GmbH 等)，防止单行折行
   */
  function simplifyISPName(rawISP, rawOrg, countryCode) {
    const combined = [rawISP, rawOrg].filter(Boolean).join(' ').trim();
    if (!combined) return '';

    const cc = toStr(countryCode, '').toUpperCase();
    if (cc === 'CN') {
      const entBrand = normalizeEntranceISP(rawISP, rawOrg, 'CN');
      if (entBrand && entBrand !== combined) return entBrand.replace(/^中国/, '');
    }

    if (/cloudflare/i.test(combined)) return 'Cloudflare';
    if (/alibaba|aliyun|alicloud/i.test(combined)) return cc === 'CN' ? '阿里云' : '阿里云国际';
    if (/tencent|qcloud/i.test(combined)) return cc === 'CN' ? '腾讯云' : '腾讯云国际';
    if (/huawei/i.test(combined)) return '华为云';
    if (/\bucloud\b/i.test(combined)) return 'UCloud';
    if (/\bdmit\b/i.test(combined)) return 'DMIT';
    if (/\bxtom\b/i.test(combined)) return 'xTom';
    if (/\bmisaka\b/i.test(combined)) return 'Misaka';
    if (/\bkirino\b/i.test(combined)) return 'Kirino';
    if (/zenlayer/i.test(combined)) return 'Zenlayer';
    if (/\bamazon\b|\baws\b/i.test(combined)) return 'AWS';
    if (/google\s*(llc|cloud|inc)?$/i.test(combined)) return 'Google';
    if (/microsoft/i.test(combined)) return 'Microsoft';
    if (/oracle/i.test(combined)) return 'Oracle';
    if (/digitalocean/i.test(combined)) return 'DigitalOcean';
    if (/vultr|choopa/i.test(combined)) return 'Vultr';
    if (/linode|akamai/i.test(combined)) return 'Akamai';
    if (/hetzner/i.test(combined)) return 'Hetzner';
    if (/\bovh\b/i.test(combined)) return 'OVH';
    if (/datacamp|cdn77/i.test(combined)) return 'DataCamp';
    if (/comcast/i.test(combined)) return 'Comcast';
    if (/charter\s+communications/i.test(combined)) return 'Charter';
    if (/verizon/i.test(combined)) return 'Verizon';
    if (/\bat&t\b/i.test(combined)) return 'AT&T';
    if (/chunghwa\s*telecom|hinet/i.test(combined)) return 'HiNet';
    if (/hong\s*kong\s*telecommunications|\bhkt\b/i.test(combined)) return 'HKT';
    if (/\bpccw\b/i.test(combined)) return 'PCCW';
    if (/\bsingtel\b|singapore\s+telecommunications/i.test(combined)) return 'Singtel';
    if (/\bstarhub\b/i.test(combined)) return 'StarHub';
    if (/softbank/i.test(combined)) return 'SoftBank';
    if (/internet\s+initiative\s+japan|\biij\b/i.test(combined)) return 'IIJ';
    if (/\bkddi\b/i.test(combined)) return 'KDDI';
    if (/\bntt\b/i.test(combined)) return 'NTT';
    if (/china\s*telecom\s*global|\bctgnet\b/i.test(combined)) return 'CTGNet';
    if (/china\s*mobile\s*international|\bcmi\b/i.test(combined)) return 'CMI';
    if (/china\s*telecom|chinanet/i.test(combined)) return '中国电信';
    if (/china\s*unicom/i.test(combined)) return '中国联通';
    if (/china\s*mobile/i.test(combined)) return '中国移动';

    let base = toStr(rawISP || rawOrg, '');
    base = base.replace(/^AS\d+\s+/i, '');
    for (let i = 0; i < 3; i++) {
      const next = base
        .replace(
          /[\s,.]+(Private\s+Limited|Pte\.?\s*Ltd\.?|Pty\.?\s*Ltd\.?|Co\.?,?\s*Ltd\.?|Corp\.?|Corporation|Incorporated|Inc\.?|Limited|Ltd\.?|L\.?L\.?C\.?|LLP|GmbH\s*&\s*Co\.?\s*KG|GmbH|S\.?A\.?S\.?|S\.?A\.?|S\.?p\.?A\.?|B\.?V\.?|N\.?V\.?|PLC|AG|AB|Oy|S\.?R\.?L\.?|Communications|Telecommunications|Technologies|Technology|Holdings?|Services|Service|Networks?|Group)\.?$/i,
          ''
        )
        .trim();
      if (!next || next === base) break;
      base = next;
    }
    base = base.replace(/[,.\s]+$/, '').trim();
    if (base.length > 22) {
      const words = base.split(/\s+/);
      if (words.length > 2) base = words.slice(0, 2).join(' ');
    }
    return base || toStr(rawISP || rawOrg, '');
  }

  function formatProtocolName(rawType) {
    const t = toStr(rawType, '');
    if (!t) return '';
    const lower = t.toLowerCase();
    const map = {
      ss: 'Shadowsocks',
      shadowsocks: 'Shadowsocks',
      ssr: 'SSR',
      shadowsocksr: 'SSR',
      vmess: 'VMess',
      vless: 'VLESS',
      trojan: 'Trojan',
      hysteria2: 'Hysteria2',
      hy2: 'Hysteria2',
      hysteria: 'Hysteria',
      tuic: 'TUIC',
      wireguard: 'WireGuard',
      wg: 'WireGuard',
      snell: 'Snell',
      anytls: 'AnyTLS',
      http: 'HTTP',
      https: 'HTTPS',
      socks5: 'SOCKS5',
      socks: 'SOCKS5',
      relay: 'Relay',
    };
    return map[lower] || t;
  }

  function formatShortIPv6(ip, maskEnabled) {
    const s = toStr(ip, '');
    if (!s) return '';
    if (maskEnabled) return maskIPString(s, true);
    if (s.length <= 22) return s;
    const parts = s.split(':').filter(Boolean);
    if (parts.length >= 3) {
      return parts[0] + ':' + parts[1] + ':…:' + parts[parts.length - 1];
    }
    return s.slice(0, 20) + '…';
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
  // 4. 基础链路与 Cloudflare WARP 探测 (MODE=info 核心)
  // ============================================================================

  async function queryDomesticDirect(inTunnel) {
    const directPolicy = resolveDirectOutboundPolicy(inTunnel);

    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://myip.ipip.net/json', directPolicy),
        Math.min(CFG.timeoutMs, 4200)
      );
      if (j && j.data && j.data.ip) {
        const loc = Array.isArray(j.data.location) ? j.data.location : [];
        const prov = normalizeCNPlace(loc[1]);
        const city = normalizeCNPlace(loc[2]);
        const geo = deduplicateGeoParts([prov, city]).join('');
        const hopPlace = city || prov || '本地';
        const isp = normalizeCNISP(loc[4] || loc[3] || '');
        const shortISP = isp.replace(/^中国/, '');
        return {
          ip: j.data.ip,
          countryCode: loc[0] === '中国' || prov || city ? 'CN' : '',
          location: geo || normalizeCNPlace(loc[0]) || '中国',
          isp: shortISP ? '中国' + shortISP : '',
          fullTag: (geo || '中国') + shortISP,
          shortTag: hopPlace + shortISP,
        };
      }
    } catch (_) {}

    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://r.inews.qq.com/api/ip2city', directPolicy),
        Math.min(CFG.timeoutMs, 4000)
      );
      if (j && j.ip) {
        const prov = normalizeCNPlace(j.province);
        const city = normalizeCNPlace(j.city);
        const geo = deduplicateGeoParts([prov, city]).join('');
        const hopPlace = city || prov || '本地';
        const isp = normalizeCNISP(j.isp || '');
        const shortISP = isp.replace(/^中国/, '');
        return {
          ip: j.ip,
          countryCode: j.country === '中国' || prov || city ? 'CN' : '',
          location: geo || normalizeCNPlace(j.country) || '中国',
          isp: shortISP ? '中国' + shortISP : '',
          fullTag: (geo || '中国') + shortISP,
          shortTag: hopPlace + shortISP,
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
        return { ip, countryCode: 'CN', location: '中国', isp: '', fullTag: '本地网络', shortTag: '本地网络' };
      }
    } catch (_) {}

    return null;
  }

  function backfillLandingWithMMDB(record) {
    if (!record || !record.ip) return record;
    const mmdb = readNativeMMDB(record.ip);
    if (!record.countryCode && mmdb.countryCode) record.countryCode = mmdb.countryCode;
    if (!record.country && record.countryCode) record.country = record.countryCode;
    if (!record.asn && mmdb.asn) record.asn = mmdb.asn;
    if (!record.isp && mmdb.aso) record.isp = mmdb.aso;
    if (!record.org && mmdb.aso) record.org = mmdb.aso;
    return record;
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
        return backfillLandingWithMMDB({
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
        });
      }
    } catch (_) {}

    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://api-ipv4.ip.sb/geoip', targetNode),
        CFG.timeoutMs
      );
      if (j && j.ip) {
        return backfillLandingWithMMDB({
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
        });
      }
    } catch (_) {}

    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://ipwho.is/?lang=zh-CN', targetNode),
        CFG.timeoutMs
      );
      if (j && j.success !== false && j.ip) {
        const conn = j.connection || {};
        return backfillLandingWithMMDB({
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
        });
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
      return backfillLandingWithMMDB({
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
      });
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
   * 探测 Cloudflare 边缘机房 POP 与 WARP 出站套壳状态
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
            coloCountry: CF_COLO_CC_MAP[colo] || '',
            warp,
          };
        }
      } catch (_) {
        if (Date.now() - t0 >= traceTimeout - 200) break;
      }
    }
    return null;
  }

  // ============================================================================
  // 5. 多源 IP 纯净度与黑名单引擎 (MODE=purity: ipapi.is + ipinfo widget 免费双ISP补位 + IPPure + proxycheck + ip-score)
  // ============================================================================

  function parseAbuserScore(raw) {
    if (!raw) return null;
    const s = String(raw).trim();
    const numMatch = s.match(/([0-9]*\.?[0-9]+)/);
    const val = numMatch ? parseFloat(numMatch[1]) : NaN;
    const pct = Number.isFinite(val) ? (val * 100).toFixed(2) + '%' : '';
    if (/very\s*high/i.test(s) || val >= 0.05) return { raw: s, percentText: pct, tagZh: '极高', level: 'danger' };
    if (/high/i.test(s) || val >= 0.02) return { raw: s, percentText: pct, tagZh: '偏高', level: 'danger' };
    if (/elevated/i.test(s) || val >= 0.008) return { raw: s, percentText: pct, tagZh: '中等', level: 'warn' };
    if (/low/i.test(s) && !/very\s*low/i.test(s)) return { raw: s, percentText: pct, tagZh: '较低', level: 'good' };
    return { raw: s, percentText: pct, tagZh: '极低', level: 'excellent' };
  }

  function mapEntityTypeZh(typeStr) {
    const t = String(typeStr || '').trim().toLowerCase();
    if (t === 'isp') return '住宅 (ISP)';
    if (t === 'hosting') return '机房 (Hosting)';
    if (t === 'business') return '商业 (Business)';
    if (t === 'education') return '教育 (Edu)';
    if (t === 'government') return '政务 (Gov)';
    if (t === 'banking') return '金融 (Banking)';
    return '';
  }

  function deriveBandwidthNature(asnType, compType, isDatacenter, isMobile) {
    if (asnType === 'isp' && compType === 'isp' && !isDatacenter) {
      return { label: '双 ISP 原生家宽', level: 'excellent' };
    }
    if ((asnType === 'isp' || compType === 'isp') && !isDatacenter) {
      return { label: isMobile ? '移动蜂窝网络' : '单 ISP 住宅宽带', level: 'good' };
    }
    if (asnType === 'hosting' || compType === 'hosting' || isDatacenter) {
      return { label: '机房带宽', level: 'warn' };
    }
    if (asnType === 'business' || compType === 'business') {
      return { label: '商业宽带', level: 'good' };
    }
    if (asnType === 'education' || compType === 'education') {
      return { label: '教育科研网络', level: 'good' };
    }
    if (asnType === 'government' || compType === 'government') {
      return { label: '政务机构网络', level: 'good' };
    }
    if (asnType === 'banking' || compType === 'banking') {
      return { label: '金融机构网络', level: 'good' };
    }
    return { label: '', level: 'normal' };
  }

  function parseIPAPIIs(j) {
    if (!j || typeof j !== 'object' || j.error) return null;
    if (!j.ip && !j.asn && !j.company && !j.location) return null;
    const asnObj = j.asn && typeof j.asn === 'object' ? j.asn : {};
    const compObj = j.company && typeof j.company === 'object' ? j.company : {};
    const locObj = j.location && typeof j.location === 'object' ? j.location : {};

    const asnType = String(asnObj.type || '').toLowerCase();
    const compType = String(compObj.type || '').toLowerCase();
    const asnTypeText = mapEntityTypeZh(asnType);
    const companyTypeText = mapEntityTypeZh(compType);
    const hasDualTypes = Boolean(asnTypeText && companyTypeText);

    const isDatacenter = Boolean(j.is_datacenter);
    const isVPN = Boolean(j.is_vpn);
    const isProxy = Boolean(j.is_proxy);
    const isTor = Boolean(j.is_tor);
    const isAbuser = Boolean(j.is_abuser);
    const isCrawler = Boolean(j.is_crawler);
    const isMobile = Boolean(j.is_mobile);

    const nature = deriveBandwidthNature(asnType, compType, isDatacenter, isMobile);

    const asnCountry = String(asnObj.country || '').toUpperCase();
    const locCountry = String(locObj.country_code || '').toUpperCase();
    let isNativeGeo = null;
    let broadcastText = '';
    if (asnCountry && locCountry) {
      isNativeGeo = asnCountry === locCountry;
      broadcastText = isNativeGeo ? '原生 IP' : '广播 IP';
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

    const rawASN = toStr(asnObj.asn, '').replace(/^AS/i, '');
    return {
      asn: rawASN ? 'AS' + rawASN : '',
      asnOrg: asnObj.org || '',
      asnTypeText,
      asnRoute: asnObj.route || '',
      companyName: compObj.name || '',
      companyTypeText,
      companyNetwork: compObj.network || '',
      hasDualTypes,
      rir: j.rir || '',
      lineageLabel: nature.label,
      lineageLevel: nature.level,
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
      source: 'ipapi.is',
    };
  }

  /**
   * 免 Key 双维属性备用源解析器：https://ipinfo.io/widget/demo/{ip}
   * 解析 data.asn.type、data.company.type 与 data.privacy
   */
  function parseIPInfoWidget(j) {
    if (!j || typeof j !== 'object') return null;
    const d = j.data && typeof j.data === 'object' ? j.data : j;
    if (d.error || (!d.asn && !d.company && !d.privacy)) return null;

    const asnObj = d.asn && typeof d.asn === 'object' ? d.asn : {};
    const compObj = d.company && typeof d.company === 'object' ? d.company : {};
    const privObj = d.privacy && typeof d.privacy === 'object' ? d.privacy : {};
    const abuseObj = d.abuse && typeof d.abuse === 'object' ? d.abuse : {};

    const asnType = String(asnObj.type || '').toLowerCase();
    const compType = String(compObj.type || '').toLowerCase();
    const asnTypeText = mapEntityTypeZh(asnType);
    const companyTypeText = mapEntityTypeZh(compType);
    const hasDualTypes = Boolean(asnTypeText && companyTypeText);

    const isDatacenter = Boolean(privObj.hosting || d.is_hosting);
    const isVPN = Boolean(privObj.vpn);
    const isProxy = Boolean(privObj.proxy || privObj.relay);
    const isTor = Boolean(privObj.tor);
    const isMobile = Boolean(d.is_mobile);

    const nature = deriveBandwidthNature(asnType, compType, isDatacenter, isMobile);

    const locCountry = toStr(d.country, '').toUpperCase();
    const regCountry = toStr(abuseObj.country, '').toUpperCase();
    let isNativeGeo = null;
    let broadcastText = '';
    if (regCountry && locCountry) {
      isNativeGeo = regCountry === locCountry;
      broadcastText = isNativeGeo ? '原生 IP' : '广播 IP';
    }

    let riskIndex = 0;
    if (isDatacenter || asnType === 'hosting' || compType === 'hosting') riskIndex += 20;
    if (isVPN) riskIndex += 20;
    if (isProxy) riskIndex += 25;
    if (isTor) riskIndex += 35;
    riskIndex = Math.min(100, riskIndex);

    const rawASN = toStr(asnObj.asn, '').replace(/^AS/i, '');
    return {
      asn: rawASN ? 'AS' + rawASN : '',
      asnOrg: toStr(asnObj.name, ''),
      asnTypeText,
      asnRoute: toStr(asnObj.route, ''),
      companyName: toStr(compObj.name, ''),
      companyTypeText,
      companyNetwork: toStr(abuseObj.network, ''),
      hasDualTypes,
      rir: '',
      lineageLabel: nature.label,
      lineageLevel: nature.level,
      isNativeGeo,
      broadcastText,
      primaryScore: null,
      riskIndex,
      flags: {
        datacenter: isDatacenter,
        vpn: isVPN,
        proxy: isProxy,
        tor: isTor,
        abuser: false,
        crawler: false,
        mobile: isMobile,
      },
      countryCode: locCountry,
      source: 'ipinfo.io',
    };
  }

  function mergePurityRecords(primary, fallback) {
    if (!primary) return fallback || null;
    if (!fallback) return primary;
    const asnTypeText = primary.asnTypeText || fallback.asnTypeText;
    const companyTypeText = primary.companyTypeText || fallback.companyTypeText;
    const hasDualTypes = Boolean(asnTypeText && companyTypeText);
    const flags = {
      datacenter: Boolean(primary.flags.datacenter || fallback.flags.datacenter),
      vpn: Boolean(primary.flags.vpn || fallback.flags.vpn),
      proxy: Boolean(primary.flags.proxy || fallback.flags.proxy),
      tor: Boolean(primary.flags.tor || fallback.flags.tor),
      abuser: Boolean(primary.flags.abuser || fallback.flags.abuser),
      crawler: Boolean(primary.flags.crawler || fallback.flags.crawler),
      mobile: Boolean(primary.flags.mobile || fallback.flags.mobile),
    };
    const isNativeGeo = primary.isNativeGeo !== null ? primary.isNativeGeo : fallback.isNativeGeo;
    return Object.assign({}, fallback, primary, {
      asn: primary.asn || fallback.asn,
      asnOrg: primary.asnOrg || fallback.asnOrg,
      companyName: primary.companyName || fallback.companyName,
      asnTypeText,
      companyTypeText,
      hasDualTypes,
      lineageLabel: primary.lineageLabel || fallback.lineageLabel,
      lineageLevel: primary.lineageLabel ? primary.lineageLevel : fallback.lineageLevel,
      isNativeGeo,
      broadcastText: primary.broadcastText || fallback.broadcastText,
      riskIndex: Math.max(primary.riskIndex || 0, fallback.riskIndex || 0),
      flags,
    });
  }

  function parseIPPure(j) {
    if (!j || typeof j !== 'object' || (!j.ip && j.fraudScore === undefined)) return null;
    const rawScore = Number(j.fraudScore);
    const fraudScore = Number.isFinite(rawScore) ? Math.max(0, Math.min(100, Math.round(rawScore))) : null;
    const isResidential = typeof j.isResidential === 'boolean' ? j.isResidential : null;
    const isBroadcast = typeof j.isBroadcast === 'boolean' ? j.isBroadcast : null;
    const rawASN = toStr(j.asn, '').replace(/^AS/i, '');
    const asnNum = Number(rawASN);
    return {
      ip: toStr(j.ip, ''),
      asn: Number.isFinite(asnNum) && asnNum > 0 ? 'AS' + asnNum : '',
      asOrganization: toStr(j.asOrganization, ''),
      countryCode: toStr(j.countryCode, '').toUpperCase(),
      region: toStr(j.region, ''),
      city: toStr(j.city, ''),
      fraudScore,
      isResidential,
      isBroadcast,
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
    const reqTimeout = Math.min(timeoutOverride || CFG.timeoutMs, 5000);
    try {
      const j = await fetchJSON(buildOutboundOpts(url, targetNode), reqTimeout);
      const parsed = parseIPAPIIs(j);
      if (parsed && parsed.hasDualTypes) writeIPCache(ip, 'purity', parsed);
      return parsed;
    } catch (e) {
      log('ipapi.is error: ' + (e.message || e));
      return null;
    }
  }

  async function queryIPInfoWidget(ip, targetNode, timeoutOverride) {
    if (!ip) return null;
    const url = 'https://ipinfo.io/widget/demo/' + encodeURIComponent(ip);
    const reqTimeout = Math.min(timeoutOverride || CFG.timeoutMs, 5000);
    try {
      const j = await fetchJSON(
        buildOutboundOpts(url, targetNode, { Referer: 'https://ipinfo.io/' }),
        reqTimeout
      );
      return parseIPInfoWidget(j);
    } catch (e) {
      log('ipinfo widget error: ' + (e.message || e));
      return null;
    }
  }

  /**
   * 双 ISP 属性主备查询：优先 ipapi.is，当未配 Key 限流或缺失双维类型时自动由 ipinfo.io/widget/demo/{ip} 补位
   */
  async function queryPurityWithFallback(ip, targetNode, timeoutOverride, cacheTTLMs) {
    if (!ip) return null;
    if (cacheTTLMs && cacheTTLMs > 0) {
      const cached = readIPCache(ip, 'purity', cacheTTLMs);
      if (cached && cached.hasDualTypes) return cached;
    }
    const subTimeout = Math.min(timeoutOverride || CFG.timeoutMs, 5000);
    const primary = await queryPurityIPAPI(ip, targetNode, subTimeout, 0);
    if (primary && primary.hasDualTypes) {
      writeIPCache(ip, 'purity', primary);
      return primary;
    }
    const fallback = await queryIPInfoWidget(ip, targetNode, subTimeout);
    const merged = mergePurityRecords(primary, fallback);
    if (merged) writeIPCache(ip, 'purity', merged);
    return merged;
  }

  /**
   * 独立免鉴权纯净度与原生广播核验源：my.ippure.com/v1/info
   */
  async function queryIPPure(targetNode) {
    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://my.ippure.com/v1/info', targetNode),
        Math.min(CFG.timeoutMs, 5000)
      );
      return parseIPPure(j);
    } catch (e) {
      log('my.ippure.com error: ' + (e.message || e));
      return null;
    }
  }

  async function queryProxyCheckIO(ip, targetNode) {
    const url = 'http://proxycheck.io/v2/' + encodeURIComponent(ip) + '?vpn=1&asn=1&risk=1';
    try {
      const j = await fetchJSON(buildOutboundOpts(url, targetNode), Math.min(CFG.timeoutMs, 5000));
      if (j && (j.status === 'ok' || j.status === 'warning') && j[ip]) {
        const rec = j[ip];
        const rawType = String(rec.type || '');
        const typeZhMap = {
          Residential: '住宅宽带',
          Wireless: '移动蜂窝网络',
          Business: '商业宽带',
          Hosting: '机房带宽',
          VPN: '商业 VPN',
          TOR: 'Tor 节点',
          Compromised: '风险主机',
        };
        return {
          proxy: rec.proxy === 'yes',
          type: rawType,
          typeZh: typeZhMap[rawType] || '',
          risk: Number.isFinite(Number(rec.risk)) ? Number(rec.risk) : null,
          provider: rec.provider || '',
        };
      }
    } catch (e) {
      log('proxycheck.io error: ' + (e.message || e));
    }
    return null;
  }

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
        Math.min(CFG.timeoutMs, 5000)
      );
      if (res.status >= 200 && res.status < 400 && res.body) {
        const j = JSON.parse(res.body);
        const bl = j.blacklist || {};
        const blKeys = Object.keys(bl);
        const hits = blKeys.filter((k) => /true|listed|yes|1/i.test(String(bl[k])));
        return {
          totalBlacklists: blKeys.length,
          listedCount: hits.length,
          listedNames: hits.slice(0, 4),
        };
      }
    } catch (e) {
      log('ip-score error: ' + (e.message || e));
    }
    return null;
  }

  // ============================================================================
  // 5B. BGP 宣告前缀与全球上游骨干网窥探引擎 (RIPE NCC RIS 实时路由表)
  // ============================================================================

  const BGP_ASN_DB = {
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

    3356: { name: 'Lumen', tier: 'tier1' },
    1299: { name: 'Telia', tier: 'tier1' },
    2914: { name: 'NTT', tier: 'tier1' },
    174: { name: 'Cogent', tier: 'tier1' },
    3257: { name: 'GTT', tier: 'tier1' },
    6453: { name: 'Tata', tier: 'tier1' },
    3491: { name: 'PCCW', tier: 'tier1' },
    6762: { name: 'Sparkle', tier: 'tier1' },
    6461: { name: 'Zayo', tier: 'tier1' },
    3320: { name: 'DTAG', tier: 'tier1' },
    5511: { name: 'Orange', tier: 'tier1' },
    12956: { name: 'Telxius', tier: 'tier1' },
    701: { name: 'Verizon', tier: 'tier1' },
    7018: { name: 'AT&T', tier: 'tier1' },
    6830: { name: 'Liberty', tier: 'tier1' },

    17676: { name: 'SoftBank', tier: 'apac-opt' },
    4725: { name: 'SoftBank ODN', tier: 'apac-opt' },
    2497: { name: 'IIJ', tier: 'apac-opt' },
    2516: { name: 'KDDI', tier: 'apac' },
    4713: { name: 'NTT OCN', tier: 'apac' },
    2527: { name: 'So-net', tier: 'apac' },
    7506: { name: 'GMO', tier: 'apac' },
    2500: { name: 'WIDE', tier: 'apac' },
    4760: { name: '香港 HKT', tier: 'apac' },
    9304: { name: '香港 HGC', tier: 'apac' },
    9269: { name: '香港 HKBN', tier: 'apac' },
    4515: { name: '香港 PCCW', tier: 'apac' },
    10118: { name: '香港 CMHK', tier: 'apac' },
    4609: { name: '澳门 CTM', tier: 'apac' },
    3462: { name: 'HiNet', tier: 'apac' },
    9924: { name: 'TFN', tier: 'apac' },
    4780: { name: 'Seednet', tier: 'apac' },
    4637: { name: 'Telstra', tier: 'apac' },
    7473: { name: 'Singtel', tier: 'apac' },
    4657: { name: 'StarHub', tier: 'apac' },
    24482: { name: 'SG.GS', tier: 'apac' },
    18106: { name: 'ViewQwest', tier: 'apac' },
    4766: { name: '韩国 KT', tier: 'apac' },
    9318: { name: '韩国 SKB', tier: 'apac' },
    3786: { name: 'LG DACOM', tier: 'apac' },

    4635: { name: '香港 HKIX', tier: 'ixp' },
    4777: { name: '日本 JPIX', tier: 'ixp' },
    58952: { name: '新加坡 SGIX', tier: 'ixp' },
    59105: { name: '亚太 BBIX', tier: 'ixp' },
    24115: { name: 'Equinix IX', tier: 'ixp' },

    6939: { name: 'HE', tier: 'transit' },
    9002: { name: 'RETN', tier: 'transit' },
    137409: { name: 'GSL', tier: 'transit' },
    33891: { name: 'Core-Backbone', tier: 'transit' },
    906: { name: 'DMIT', tier: 'agg' },
    54574: { name: 'DMIT 优化', tier: 'cn-opt' },
    21859: { name: 'Zenlayer', tier: 'agg' },
    3214: { name: 'xTom', tier: 'agg' },
    924: { name: 'xTom', tier: 'agg' },
    57695: { name: 'Misaka', tier: 'agg' },
    40065: { name: 'CeraNetworks', tier: 'agg' },
    136766: { name: 'Kirino', tier: 'agg' },
    141995: { name: 'Kirino', tier: 'agg' },
    13335: { name: 'Cloudflare', tier: 'cloud' },
    16509: { name: 'AWS', tier: 'cloud' },
    14618: { name: 'AWS', tier: 'cloud' },
    15169: { name: 'Google', tier: 'cloud' },
    8075: { name: 'Azure', tier: 'cloud' },
    45102: { name: '阿里云国际', tier: 'cloud' },
    37963: { name: '阿里云', tier: 'cloud' },
    132203: { name: '腾讯云国际', tier: 'cloud' },
    45090: { name: '腾讯云', tier: 'cloud' },
    55990: { name: '华为云', tier: 'cloud' },
    136907: { name: '华为云国际', tier: 'cloud' },
    135377: { name: 'UCloud', tier: 'cloud' },
    138371: { name: '火山引擎', tier: 'cloud' },
    20473: { name: 'Vultr', tier: 'cloud' },
    60068: { name: 'DataCamp', tier: 'cloud' },
    16276: { name: 'OVH', tier: 'cloud' },
    24940: { name: 'Hetzner', tier: 'cloud' },
    14061: { name: 'DigitalOcean', tier: 'cloud' },
    63949: { name: 'Akamai', tier: 'cloud' },
  };

  function parseASNNum(asnRaw) {
    const n = Number(String(asnRaw || '').trim().replace(/^AS/i, ''));
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  function lookupBGPASN(asnNum) {
    const n = parseASNNum(asnNum);
    if (!n) return { num: 0, asn: '', name: '', tier: 'other' };
    const rec = BGP_ASN_DB[n];
    return {
      num: n,
      asn: 'AS' + n,
      name: rec ? rec.name : '',
      tier: rec ? rec.tier : 'other',
    };
  }

  /**
   * 将多行 BGP 路由数据浓缩为单行精炼描述（去除 /24 前缀、聚合网关独立行与百分比噪音）
   * 例如：「国际 Tier-1 多线 (Cogent / Zayo / GTT)」「中国优化 (电信 CN2 / 联通 9929)」「香港 HKIX / 香港 HKT」
   */
  function formatBGPCompactSummary(bgp) {
    if (!bgp || typeof bgp !== 'object') return '';
    const ups = Array.isArray(bgp.upstreams) ? bgp.upstreams : [];
    if (ups.length === 0) {
      if (bgp.originName) return 'Anycast 直连 (' + bgp.originName + ')';
      return bgp.gradeShort || 'Anycast 直连';
    }

    const namedPeers = [];
    for (const u of ups) {
      if (u && u.name && !namedPeers.includes(u.name)) namedPeers.push(u.name);
    }
    const corePeerText =
      namedPeers.length > 0
        ? namedPeers.slice(0, 3).join(' / ')
        : ups
            .slice(0, 2)
            .map((u) => u.short || u.asn)
            .filter(Boolean)
            .join(' / ');

    const cnOpts = Array.isArray(bgp.cnOptNames) ? bgp.cnOptNames : [];
    if (cnOpts.length > 0) {
      return '中国优化 (' + cnOpts.slice(0, 3).join(' / ') + ')';
    }
    const apacOpts = Array.isArray(bgp.apacOptNames) ? bgp.apacOptNames : [];
    if (apacOpts.length > 0) {
      const merged = deduplicateGeoParts(apacOpts.concat(namedPeers)).slice(0, 3).join(' / ');
      return '亚太优化' + (merged ? ' (' + merged + ')' : '');
    }
    const cnStds = Array.isArray(bgp.cnStdNames) ? bgp.cnStdNames : [];
    if (cnStds.length > 0) {
      return '三网直连 (' + cnStds.slice(0, 3).join(' / ') + ')';
    }

    let tier1Count = 0;
    for (const u of ups) {
      if (u && u.tier === 'tier1') tier1Count++;
    }
    if (tier1Count >= 2) {
      return '国际 Tier-1 多线' + (corePeerText ? ' (' + corePeerText + ')' : '');
    }
    if (tier1Count === 1) {
      return '国际 Tier-1' + (corePeerText ? ' (' + corePeerText + ')' : '');
    }
    return corePeerText || bgp.gradeShort || '国际 BGP';
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
      const singleObj = {
        prefix,
        originASN: originInfo.asn,
        originName: originInfo.name,
        peerCount: routes.length,
        gradeLabel: 'Anycast 直连',
        gradeShort: 'Anycast 直连',
        gradeLevel: 'good',
        aggregator: null,
        upstreams: [],
        shortNames: originInfo.name || originInfo.asn,
        cnOptNames: [],
        apacOptNames: [],
        cnStdNames: [],
      };
      singleObj.compactText = formatBGPCompactSummary(singleObj);
      return singleObj;
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

    let gradeLabel = '国际 BGP';
    let gradeShort = '国际 BGP';
    let gradeLevel = 'normal';

    if (cnOptNames.length > 0) {
      gradeLabel = '中国优化 (' + cnOptNames.join(' / ') + ')';
      gradeShort = '中国优化 (' + cnOptNames.slice(0, 2).join(' / ') + ')';
      gradeLevel = 'excellent';
    } else if (apacOptNames.length > 0) {
      gradeLabel = '亚太优化 (' + apacOptNames.join(' / ') + ')';
      gradeShort = '亚太优化 (' + apacOptNames.slice(0, 2).join(' / ') + ')';
      gradeLevel = 'good';
    } else if (cnStdNames.length > 0) {
      gradeLabel = '三网直连 (' + cnStdNames.join(' / ') + ')';
      gradeShort = '三网直连 BGP';
      gradeLevel = 'good';
    } else if (tier1Count >= 2) {
      gradeLabel = '国际 Tier-1 多线';
      gradeShort = '国际 Tier-1 多线';
      gradeLevel = 'normal';
    } else if (tier1Count === 1) {
      gradeLabel = '国际 Tier-1';
      gradeShort = '国际 Tier-1';
      gradeLevel = 'normal';
    }

    const shortNames = upstreams
      .slice(0, 3)
      .map((u) => u.short)
      .join(' / ');

    const resObj = {
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
      apacOptNames,
      cnStdNames,
    };
    resObj.compactText = formatBGPCompactSummary(resObj);
    return resObj;
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
  // 6. 流媒体与 AI 服务解锁探测引擎 (禁用自动重定向，精准识别 301/302/308 区域路由)
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
    const t = Math.min(CFG.timeoutMs, 5500);
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
      return { name: 'ChatGPT', state: 'no', text: '地区受限 [' + loc + ']' };
    }

    const iosBody = (iosRes && iosRes.body) || '';
    const iosBlocked =
      !iosRes ||
      iosRes.status === 403 ||
      /unsupported_country|vpn|cf-error|attention required|disallowed_isp/i.test(iosBody);
    const regTag = loc ? ' [' + loc + ']' : '';

    if (!iosBlocked && iosRes.status >= 200 && iosRes.status < 400) {
      return { name: 'ChatGPT', state: 'yes', text: '完整解锁' + regTag + ' (Web+App)' };
    }
    if (loc) {
      return { name: 'ChatGPT', state: 'partial', text: '仅网页可用' + regTag };
    }
    return { name: 'ChatGPT', state: 'no', text: '访问受限' };
  }

  async function checkClaudeUnlock(targetNode) {
    const t = Math.min(CFG.timeoutMs, 5500);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://claude.ai/cdn-cgi/trace', targetNode),
        t
      );
      const kv = parseTraceMap(res.body);
      const loc = (kv.loc || '').toUpperCase();
      if (loc && CLAUDE_BLOCKED.has(loc)) {
        return { name: 'Claude', state: 'no', text: '地区受限 [' + loc + ']' };
      }
      if (loc) {
        return { name: 'Claude', state: 'yes', text: '已解锁 [' + loc + ']' };
      }
    } catch (_) {}
    return { name: 'Claude', state: 'warn', text: '连接超时' };
  }

  async function checkGeminiUnlock(targetNode, fallbackCC) {
    const t = Math.min(CFG.timeoutMs, 5500);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://gemini.google.com/app', targetNode, {
          'Accept-Language': 'en-US,en;q=0.9',
        }),
        t
      );
      const body = res.body || '';
      const hdrLoc = String((res.headers && (res.headers.Location || res.headers.location)) || '');
      if (
        res.status === 451 ||
        res.status === 403 ||
        /isn't currently supported|not available in your country|faq#supported_countries/i.test(body + ' ' + hdrLoc)
      ) {
        return { name: 'Gemini', state: 'no', text: '地区受限' + (fallbackCC ? ' [' + fallbackCC + ']' : '') };
      }
      if (fallbackCC && GEMINI_BLOCKED.has(fallbackCC.toUpperCase())) {
        return { name: 'Gemini', state: 'no', text: '地区受限 [' + fallbackCC.toUpperCase() + ']' };
      }
      if (res.status >= 200 && res.status < 400) {
        const ccMatch = body.match(/,"([A-Z]{2})","[a-z]{2}(?:-[A-Z]{2})?"/);
        const cc = (ccMatch && ccMatch[1]) || (fallbackCC || '').toUpperCase();
        if (cc && GEMINI_BLOCKED.has(cc)) {
          return { name: 'Gemini', state: 'no', text: '地区受限 [' + cc + ']' };
        }
        return { name: 'Gemini', state: 'yes', text: '已解锁' + (cc ? ' [' + cc + ']' : '') };
      }
    } catch (_) {}
    return { name: 'Gemini', state: 'warn', text: '连接超时' };
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
    const hdrLoc = String((res.headers && (res.headers.Location || res.headers.location)) || '');
    if (/notavailable|page-lost|nses-404/i.test(hdrLoc)) return false;
    const b = res.body || '';
    if (/Not Available|NSES-404|page-lost|unblock|proxy/i.test(b.slice(0, 4000)) && b.length < 15000) {
      return false;
    }
    return res.status >= 200 && res.status < 400;
  }

  async function checkNetflixUnlock(targetNode) {
    const t = Math.min(CFG.timeoutMs, 5500);
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
      return { name: 'Netflix', state: 'yes', text: '完整解锁 [' + reg + ']' };
    }

    const orig = await httpRequest(
      'get',
      buildOutboundOpts('https://www.netflix.com/title/80018499', targetNode),
      t
    ).catch(() => null);
    if (isNetflixTitleAvailable(orig)) {
      const reg = extractNetflixRegion(orig);
      return { name: 'Netflix', state: 'partial', text: '仅自制剧 [' + reg + ']' };
    }
    return { name: 'Netflix', state: 'no', text: '未解锁' };
  }

  async function checkYouTubePremiumUnlock(targetNode) {
    const t = Math.min(CFG.timeoutMs, 5500);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://www.youtube.com/premium', targetNode, {
          'Accept-Language': 'en-US,en;q=0.9',
        }),
        t
      );
      const b = res.body || '';
      const hdrLoc = String((res.headers && (res.headers.Location || res.headers.location)) || '');
      if (/www\.google\.cn/i.test(b + ' ' + hdrLoc)) {
        return { name: 'YouTube', state: 'no', text: '送中 [CN]' };
      }
      if (/Premium is not available in your country|在您所在的国家\/地区尚不可用/i.test(b)) {
        return { name: 'YouTube', state: 'partial', text: '可用 (无会员区)' };
      }
      const m = b.match(/"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"/) || b.match(/"countryCode"\s*:\s*"([A-Z]{2})"/);
      const cc = m ? m[1].toUpperCase() : '';
      if (cc === 'CN') {
        return { name: 'YouTube', state: 'no', text: '送中 [CN]' };
      }
      return { name: 'YouTube', state: 'yes', text: '支持 Premium' + (cc ? ' [' + cc + ']' : '') };
    } catch (_) {
      return { name: 'YouTube', state: 'warn', text: '连接超时' };
    }
  }

  async function checkDisneyPlusUnlock(targetNode, fallbackCC) {
    const t = Math.min(CFG.timeoutMs, 5500);
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
      const hdrLoc = String((res.headers && (res.headers.Location || res.headers.location)) || '');
      if (
        res.status === 403 ||
        res.status === 451 ||
        /Sorry, Disney\+ is not available|disneyplus\.com\/.*unavailable|not available in your region/i.test(
          b + ' ' + hdrLoc
        )
      ) {
        return { name: 'Disney+', state: 'no', text: '未解锁' };
      }
      const mBody = b.match(/content="https:\/\/www\.disneyplus\.com\/([a-z]{2}(?:-[a-z]{2})?)"/i);
      const mHdr = hdrLoc.match(/disneyplus\.com\/(?:[a-z]{2}-)?([a-z]{2})(?:[/?#]|$)/i);
      const cc = mBody
        ? mBody[1].split('-').pop().toUpperCase()
        : mHdr
          ? mHdr[1].toUpperCase()
          : (fallbackCC || '').toUpperCase();
      if (cc && DISNEY_UNSUPPORTED.has(cc)) {
        return { name: 'Disney+', state: 'no', text: '地区未开通 [' + cc + ']' };
      }
      if (res.status >= 200 && res.status < 400) {
        return { name: 'Disney+', state: 'yes', text: '已解锁' + (cc ? ' [' + cc + ']' : '') };
      }
    } catch (_) {}
    return { name: 'Disney+', state: 'warn', text: '连接超时' };
  }

  async function checkTikTokUnlock(targetNode, fallbackCC) {
    const t = Math.min(CFG.timeoutMs, 5500);
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
        return { name: 'TikTok', state: 'no', text: 'IP 受限 (403)' };
      }
      const m =
        b.match(/"region"\s*:\s*"([A-Z]{2})"/) ||
        b.match(/"\$region"\s*:\s*"([A-Z]{2})"/) ||
        b.match(/"countryCode"\s*:\s*"([A-Z]{2})"/);
      const cc = (m && m[1]) || (fallbackCC || '').toUpperCase();
      if (cc && TIKTOK_BLOCKED.has(cc)) {
        return { name: 'TikTok', state: 'no', text: '锁区 [' + cc + ']' };
      }
      if (res.status >= 200 && res.status < 400) {
        return { name: 'TikTok', state: 'yes', text: '已解锁' + (cc ? ' [' + cc + ']' : '') };
      }
    } catch (_) {}
    return { name: 'TikTok', state: 'warn', text: '连接超时' };
  }

  async function checkBahamutUnlock(targetNode) {
    const t = Math.min(CFG.timeoutMs, 4500);
    try {
      const res = await httpRequest(
        'get',
        buildOutboundOpts('https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=37783', targetNode),
        t
      );
      if (res.body && res.body.includes('animeSn')) {
        return { name: '动画疯', state: 'yes', text: '已解锁 [TW]' };
      }
      return { name: '动画疯', state: 'muted', text: '未解锁' };
    } catch (_) {
      return { name: '动画疯', state: 'muted', text: '未解锁' };
    }
  }

  // ============================================================================
  // 7. 按模式精准分流执行探测
  // ============================================================================

  async function executeModeProbe(targetNode, mode) {
    const startedAt = Date.now();
    const runMode = normalizeMode(mode);

    // 模式 A: 节点链路查询
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

    // 模式 B: 节点纯净度检测（移除重复 BGP 查询，单接口超时收敛 <=5s，双ISP主备互补并发执行）
    if (runMode === 'purity') {
      const landing = await queryLandingIPv4(targetNode);
      const subTimeout = Math.min(CFG.timeoutMs, 5000);
      const [purity, ipPure, proxyCheck, ipScore] = await runWithConcurrency(
        [
          () => queryPurityWithFallback(landing.ip, targetNode, subTimeout, 0),
          () => queryIPPure(targetNode),
          () => queryProxyCheckIO(landing.ip, targetNode),
          () => queryIPScoreDeep(targetNode),
        ],
        4
      );
      return {
        ok: true,
        mode: 'purity',
        elapsedMs: Date.now() - startedAt,
        landing,
        purity,
        ipPure,
        proxyCheck,
        ipScore,
      };
    }

    // 模式 C: 流媒体与解锁检测
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
  // 8. 多端免控制器入口探测 + 智能 EDNS/CNAME 解析 + 国内/国际双源归属引擎
  // ============================================================================

  function recoverDanglingPolicyIfAny() {
    if (HOST_CLIENT !== 'clash') return;
    if (typeof $config === 'undefined' || !$config || !$config.getConfig) return;
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
    if (typeof $config === 'undefined' || !$config || !$config.getConfig) {
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
    const v = String(s || '').trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return false;
    return v.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
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

  function formatECSSubnet(ip) {
    const s = toStr(ip, '');
    if (!isIPv4Literal(s) || isPrivateLANIP(s) || isBogusEntranceIP(s)) return '';
    const p = s.split('.');
    return p[0] + '.' + p[1] + '.' + p[2] + '.0/24';
  }

  function parseHostPort(raw) {
    const s = String(raw || '')
      .replace(/\s*\([^)]*\)\s*$/, '')
      .trim();
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
    host = host.trim().replace(/\.$/, '');
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

  function extractDNSAnswerRecords(answers) {
    const cnameChain = [];
    let lastIP = '';
    if (!Array.isArray(answers)) return { ip: '', cnameChain };
    for (const ans of answers) {
      if (!ans) continue;
      if (typeof ans === 'string') {
        const clean = ans.trim().replace(/\.$/, '');
        if ((isIPv4Literal(clean) || isIPv6Literal(clean)) && !isBogusEntranceIP(clean)) {
          lastIP = clean;
        } else if (clean.includes('.') && !cnameChain.includes(clean)) {
          cnameChain.push(clean);
        }
        continue;
      }
      const rawType = ans.type;
      const typeUpper = String(rawType == null ? '' : rawType).toUpperCase();
      const val = String(ans.data != null ? ans.data : ans.value != null ? ans.value : '')
        .trim()
        .replace(/\.$/, '');
      if (!val) continue;
      if (Number(rawType) === 5 || typeUpper === 'CNAME') {
        if (!cnameChain.includes(val)) cnameChain.push(val);
      } else if (
        Number(rawType) === 1 ||
        Number(rawType) === 28 ||
        typeUpper === 'A' ||
        typeUpper === 'AAAA' ||
        isIPv4Literal(val) ||
        isIPv6Literal(val)
      ) {
        if ((isIPv4Literal(val) || isIPv6Literal(val)) && !isBogusEntranceIP(val)) {
          lastIP = val;
        }
      }
    }
    return { ip: lastIP, cnameChain };
  }

  async function queryAliDoHWithECS(domain, ecsSubnet, inTunnel) {
    const directPolicy = resolveDirectOutboundPolicy(inTunnel);
    const qs =
      'name=' +
      encodeURIComponent(domain) +
      '&type=1' +
      (ecsSubnet ? '&edns_client_subnet=' + encodeURIComponent(ecsSubnet) : '');
    const endpoints = ['https://223.5.5.5/resolve?' + qs, 'http://223.6.6.6/resolve?' + qs];

    for (const url of endpoints) {
      try {
        const j = await fetchJSON(buildOutboundOpts(url, directPolicy), 2500);
        if (Array.isArray(j)) {
          const parsedShort = extractDNSAnswerRecords(j);
          if (parsedShort.ip || parsedShort.cnameChain.length > 0) return parsedShort;
        } else if (j && Array.isArray(j.Answer)) {
          const parsed = extractDNSAnswerRecords(j.Answer);
          if (parsed.ip || parsed.cnameChain.length > 0) return parsed;
        }
      } catch (_) {}
    }
    return { ip: '', cnameChain: [] };
  }

  async function queryNativeHostDNS(domain) {
    if (typeof $dns === 'undefined' || !$dns || typeof $dns.query !== 'function') {
      return { ip: '', cnameChain: [] };
    }
    return new Promise((resolve) => {
      let done = false;
      const timer = setTimeout(() => {
        if (!done) {
          done = true;
          resolve({ ip: '', cnameChain: [] });
        }
      }, 3700);

      try {
        const queryOpts =
          HOST_CLIENT === 'loon'
            ? { domain, protocol: 'auto', timeout: 3500 }
            : { domain, timeout: 2200 };
        $dns.query(queryOpts, (err, data) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          if (!err && data && Array.isArray(data.answers)) {
            resolve(extractDNSAnswerRecords(data.answers));
            return;
          }
          resolve({ ip: '', cnameChain: [] });
        });
      } catch (_) {
        if (!done) {
          done = true;
          clearTimeout(timer);
          resolve({ ip: '', cnameChain: [] });
        }
      }
    });
  }

  /**
   * 智能 EDNS + CNAME 链入口域名解析：
   * 1. 并发执行阿里 DoH (带本地直连 IPv4 /24 EDNS 还原分省调度并提取完整 CNAME 链) + Loon 原生 $dns.query
   * 2. 回退链：(Clash 控制器 DNS) ➔ 腾讯 DNSPod HTTPDNS (119.28.28.28) ➔ Cloudflare DoH (1.0.0.1)
   */
  async function resolveEntranceDomain(domain, domesticIP, targetNode, inTunnel) {
    const d = toStr(domain, '').replace(/\.$/, '');
    if (!d) return { ip: '', cnameChain: [], source: 'empty' };
    if (isIPv4Literal(d) || isIPv6Literal(d)) {
      return { ip: isBogusEntranceIP(d) ? '' : d, cnameChain: [], source: 'literal' };
    }

    const ecsSubnet = formatECSSubnet(domesticIP);
    const cnameSet = new Set();
    const mergeCnames = (arr) => {
      if (Array.isArray(arr)) {
        arr.forEach((c) => {
          const clean = toStr(c, '').replace(/\.$/, '');
          if (clean) cnameSet.add(clean);
        });
      }
    };

    const [aliRes, nativeRes] = await Promise.all([
      queryAliDoHWithECS(d, ecsSubnet, inTunnel),
      queryNativeHostDNS(d),
    ]);
    mergeCnames(aliRes.cnameChain);
    mergeCnames(nativeRes.cnameChain);

    if (aliRes.ip || nativeRes.ip) {
      // 若带本地直连 ECS 命中阿里 DoH，优先取 ECS 精准省网 IP（若 Loon 本地栈已解析出同/有效 IP 亦互补保留完整 CNAME 链）
      const chosenIP = (ecsSubnet && aliRes.ip) || nativeRes.ip || aliRes.ip;
      const src =
        ecsSubnet && aliRes.ip
          ? 'ali-doh-ecs'
          : nativeRes.ip
            ? 'native-dns'
            : 'ali-doh';
      return { ip: chosenIP, cnameChain: [...cnameSet], source: src };
    }

    if (HOST_CLIENT === 'clash' || HOST_CLIENT === 'stash') {
      try {
        const url =
          'http://127.0.0.1:' + CFG.controllerPort + '/dns/query?name=' + encodeURIComponent(d) + '&type=A';
        const j = await fetchJSON({ url, headers: buildControllerHeaders() }, 1600);
        if (j && Array.isArray(j.Answer)) {
          const parsed = extractDNSAnswerRecords(j.Answer);
          mergeCnames(parsed.cnameChain);
          if (parsed.ip) return { ip: parsed.ip, cnameChain: [...cnameSet], source: 'controller-dns' };
        }
      } catch (_) {}
    }

    // 备选回退 1：腾讯 DNSPod HTTPDNS
    try {
      const directPolicy = resolveDirectOutboundPolicy(inTunnel);
      const clientIPParam =
        domesticIP && isIPv4Literal(domesticIP) && !isPrivateLANIP(domesticIP)
          ? '&ip=' + encodeURIComponent(domesticIP)
          : '';
      const res = await httpRequest(
        'get',
        buildOutboundOpts(
          'http://119.28.28.28/d?dn=' + encodeURIComponent(d) + '&ttl=1' + clientIPParam,
          directPolicy
        ),
        2200
      );
      if (res.status >= 200 && res.status < 400 && res.body) {
        const ipPart = res.body.trim().split(',')[0] || '';
        const candidates = ipPart.split(';').map((x) => x.trim());
        for (const cand of candidates) {
          if (isIPv4Literal(cand) && !isBogusEntranceIP(cand)) {
            return { ip: cand, cnameChain: [...cnameSet], source: 'dnspod-httpdns' };
          }
        }
      }
    } catch (_) {}

    // 备选回退 2：Cloudflare DoH 1.0.0.1
    try {
      const cfOutbound = HOST_CLIENT !== 'clash' ? targetNode : undefined;
      const j = await fetchJSON(
        buildOutboundOpts('https://1.0.0.1/dns-query?name=' + encodeURIComponent(d) + '&type=A', cfOutbound, {
          Accept: 'application/dns-json',
        }),
        2500
      );
      if (j && Array.isArray(j.Answer)) {
        const parsed = extractDNSAnswerRecords(j.Answer);
        mergeCnames(parsed.cnameChain);
        if (parsed.ip) return { ip: parsed.ip, cnameChain: [...cnameSet], source: 'cloudflare-doh' };
      }
    } catch (_) {}

    return { ip: '', cnameChain: [...cnameSet], source: 'failed' };
  }

  /**
   * 国内高精度 IP 归属补齐（严格遵循 xream 原则：仅对已判定为 CN 的入口 IP 调用！）
   * 顺序：ip.netart.cn ➔ api-v3.speedtest.cn ➔ rmb.pingan.com.cn
   */
  async function queryCNEntranceGeoPrecision(targetIP, inTunnel) {
    const directPolicy = resolveDirectOutboundPolicy(inTunnel);

    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://ip.netart.cn?ip=' + encodeURIComponent(targetIP), directPolicy),
        2600
      );
      const d = (j && j.data && typeof j.data === 'object' ? j.data : j) || {};
      const g = d.geo_cn || d.geo || d;
      const asObj = d.as || {};
      const region = cleanCNPlaceName(g.province || g.region || '');
      const city = cleanCNPlaceName(g.city || '');
      const ispRaw = toStr(g.isp || g.operator || '', '');
      const asnNum = parseASNNum(asObj.number || asObj.asn || '');
      if (region || city || ispRaw) {
        return {
          region,
          city,
          isp: ispRaw,
          org: toStr(asObj.name || asObj.info || '', ''),
          asn: asnNum ? 'AS' + asnNum : '',
          source: 'ip.netart.cn',
        };
      }
    } catch (_) {}

    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://api-v3.speedtest.cn/ip?ip=' + encodeURIComponent(targetIP), directPolicy),
        2600
      );
      const d = (j && j.data && typeof j.data === 'object' ? j.data : j) || {};
      const region = cleanCNPlaceName(d.province || d.region || '');
      const city = cleanCNPlaceName(d.city || '');
      const ispRaw = toStr(d.isp || d.operator || '', '');
      if (region || city || ispRaw) {
        return { region, city, isp: ispRaw, org: '', asn: '', source: 'speedtest.cn' };
      }
    } catch (_) {}

    try {
      const j = await fetchJSON(
        buildOutboundOpts(
          'https://rmb.pingan.com.cn/itam/mas/linden/ip/request?ip=' + encodeURIComponent(targetIP),
          directPolicy
        ),
        2600
      );
      const d = (j && j.data && typeof j.data === 'object' ? j.data : j) || {};
      const region = cleanCNPlaceName(d.province || d.region || '');
      const city = cleanCNPlaceName(d.city || '');
      const ispRaw = toStr(d.isp || d.operator || '', '');
      if (region || city || ispRaw) {
        return { region, city, isp: ispRaw, org: '', asn: '', source: 'pingan' };
      }
    } catch (_) {}

    return null;
  }

  /**
   * 国际入口归属查询（错开落地首选的 ip-api.com，优先走 ip.sb ➔ ipwho.is ➔ ip-api.com 防 429）
   */
  async function queryIntlEntranceGeo(targetIP, proxyOutbound) {
    const isV6 = isIPv6Literal(targetIP);
    const ipSbHost = isV6 ? 'https://api.ip.sb/geoip/' : 'https://api-ipv4.ip.sb/geoip/';

    try {
      const j = await fetchJSON(
        buildOutboundOpts(ipSbHost + encodeURIComponent(targetIP), proxyOutbound),
        3500
      );
      if (j && (j.ip || j.country_code || j.asn)) {
        const cc = toStr(j.country_code, '').toUpperCase();
        return {
          country: toStr(j.country, ''),
          countryCode: cc,
          region: toStr(j.region, ''),
          city: toStr(j.city, ''),
          isp: toStr(j.isp, ''),
          org: toStr(j.organization, ''),
          asn: j.asn ? 'AS' + String(j.asn).replace(/^AS/i, '') : '',
          source: 'ip.sb',
        };
      }
    } catch (_) {}

    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://ipwho.is/' + encodeURIComponent(targetIP) + '?lang=zh-CN', proxyOutbound),
        3600
      );
      if (j && j.success !== false && (j.ip || j.country_code)) {
        const conn = j.connection || {};
        const cc = toStr(j.country_code, '').toUpperCase();
        return {
          country: toStr(j.country, ''),
          countryCode: cc,
          region: toStr(j.region, ''),
          city: toStr(j.city, ''),
          isp: toStr(conn.isp, ''),
          org: toStr(conn.org, ''),
          asn: conn.asn ? 'AS' + String(conn.asn).replace(/^AS/i, '') : '',
          source: 'ipwho.is',
        };
      }
    } catch (_) {}

    try {
      const j = await fetchJSON(
        buildOutboundOpts(
          'http://ip-api.com/json/' + encodeURIComponent(targetIP) + '?fields=66842623&lang=zh-CN',
          proxyOutbound
        ),
        3600
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
        const cc = toStr(j.countryCode, '').toUpperCase();
        return {
          country: toStr(j.country, ''),
          countryCode: cc,
          region: toStr(j.regionName, ''),
          city: toStr(j.city, ''),
          isp: toStr(j.isp, ''),
          org: toStr(j.org || asnOrg, ''),
          asn,
          source: 'ip-api.com',
        };
      }
    } catch (_) {}

    return null;
  }

  /**
   * 入口 IP 双源融合归属引擎（xream 双源互补 + Loon/Surge $utils 0ms 兜底）
   */
  async function queryEntranceGeo(ip, opts) {
    const targetIP = toStr(ip, '');
    if (!targetIP) return null;
    if (isPrivateLANIP(targetIP)) {
      return {
        ip: targetIP,
        country: '内网网关',
        countryCode: '',
        region: '',
        city: '',
        isp: '',
        org: '',
        ispDisplay: '局域网 / 组网网关',
        asn: '',
        isPrivate: true,
      };
    }

    const options = opts || {};
    const ttl = options.cacheTTLMs !== undefined ? options.cacheTTLMs : CACHE_TTL_FG_MS;
    if (ttl > 0) {
      const cached = readIPCache(targetIP, 'entGeo', ttl);
      if (cached) return cached;
    }

    const proxyOutbound = HOST_CLIENT !== 'clash' ? options.targetNode : undefined;
    const inTunnel = Boolean(options.inTunnel);
    const mmdb = readNativeMMDB(targetIP);

    // 若 $utils.geoip 已在 0ms 离线确认入口为 CN，直接与国际源并发启动国内高精度源查询！
    let intlRes = null;
    let cnRes = null;
    if (mmdb.countryCode === 'CN') {
      [intlRes, cnRes] = await Promise.all([
        queryIntlEntranceGeo(targetIP, proxyOutbound),
        queryCNEntranceGeoPrecision(targetIP, inTunnel),
      ]);
    } else {
      intlRes = await queryIntlEntranceGeo(targetIP, proxyOutbound);
      const detectedCC = toStr((intlRes && intlRes.countryCode) || mmdb.countryCode, '').toUpperCase();
      if (detectedCC === 'CN') {
        cnRes = await queryCNEntranceGeoPrecision(targetIP, inTunnel);
      }
    }

    const finalCC = toStr((intlRes && intlRes.countryCode) || mmdb.countryCode, '').toUpperCase();
    if (!intlRes && !cnRes && !mmdb.countryCode && !mmdb.asn && !mmdb.aso) {
      return null;
    }

    const isCN = finalCC === 'CN';
    const country = isCN
      ? '中国'
      : toStr(COUNTRY_CODE_ZH_MAP[finalCC] || (intlRes && intlRes.country) || finalCC, '');
    const region = isCN
      ? toStr((cnRes && cnRes.region) || normalizeCNPlace(intlRes && intlRes.region), '')
      : toStr(intlRes && intlRes.region, '');
    const city = isCN
      ? toStr((cnRes && cnRes.city) || normalizeCNPlace(intlRes && intlRes.city), '')
      : toStr(intlRes && intlRes.city, '');
    const asn = toStr((intlRes && intlRes.asn) || (cnRes && cnRes.asn) || mmdb.asn, '').toUpperCase();
    const rawISP = isCN
      ? toStr((cnRes && cnRes.isp) || (intlRes && intlRes.isp), '')
      : toStr((intlRes && intlRes.isp) || mmdb.aso, '');
    const rawOrg = toStr((intlRes && intlRes.org) || (cnRes && cnRes.org) || mmdb.aso, '');
    const ispDisplay = normalizeEntranceISP(rawISP, rawOrg, finalCC);

    const merged = {
      ip: targetIP,
      country,
      countryCode: finalCC,
      region,
      city,
      isp: rawISP,
      org: rawOrg,
      ispDisplay,
      asn,
    };
    writeIPCache(targetIP, 'entGeo', merged);
    return merged;
  }

  /**
   * 解析 Loon $environment.params.proxyChainInfo 前置代理链元数据
   */
  function parseLoonProxyChain(rawChain, currentNodeName) {
    if (!rawChain) return { hasChain: false, chainDesc: '' };
    if (typeof rawChain === 'string') {
      const s = rawChain.trim();
      if (!s || s.toUpperCase() === 'DIRECT' || s === currentNodeName) {
        return { hasChain: false, chainDesc: '' };
      }
      return { hasChain: true, chainDesc: s };
    }
    if (Array.isArray(rawChain)) {
      const names = rawChain
        .map((item) => {
          if (typeof item === 'string') return item.trim();
          if (item && typeof item === 'object') return toStr(item.name || item.node || item.address, '');
          return '';
        })
        .filter((n) => n && n.toUpperCase() !== 'DIRECT');
      const filtered = currentNodeName ? names.filter((n) => n !== currentNodeName) : names;
      if (filtered.length > 0 || names.length >= 2) {
        return { hasChain: true, chainDesc: (filtered.length > 0 ? filtered : names).join(' ➔ ') };
      }
      return { hasChain: false, chainDesc: '' };
    }
    if (typeof rawChain === 'object') {
      const nodes = Array.isArray(rawChain.nodes || rawChain.chain || rawChain.proxies)
        ? rawChain.nodes || rawChain.chain || rawChain.proxies
        : null;
      if (nodes) return parseLoonProxyChain(nodes, currentNodeName);
      const single = toStr(rawChain.name || rawChain.proxy || rawChain.node || rawChain.address, '');
      if (single && single.toUpperCase() !== 'DIRECT' && single !== currentNodeName) {
        return { hasChain: true, chainDesc: single };
      }
    }
    return { hasChain: false, chainDesc: '' };
  }

  /**
   * Surge 内置 $httpAPI('/v1/requests/recent') 提取真实已拨号入口 IP（剥离 '(Proxy)'）
   */
  async function captureSurgeRecentEntrance() {
    if (typeof $httpAPI !== 'function') return null;
    const probeHostRe = /(ip-api\.com|ip\.sb|ipwho\.is|ipinfo\.io|cloudflare\.com|1\.1\.1\.1|ipw\.cn)/i;
    return new Promise((resolve) => {
      let done = false;
      const timer = setTimeout(() => {
        if (!done) {
          done = true;
          resolve(null);
        }
      }, 1200);

      try {
        $httpAPI('GET', '/v1/requests/recent', null, (res) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          const list = (res && Array.isArray(res.requests) && res.requests) || [];
          for (const req of list) {
            if (!req) continue;
            const u = String(req.URL || req.url || '');
            if (!probeHostRe.test(u)) continue;
            const remote = String(req.remoteAddress || '').trim();
            if (!remote || /\(Direct\)/i.test(remote)) continue;
            const parsed = parseHostPort(remote);
            if (parsed) {
              resolve({
                parsed,
                policyName: toStr(req.policyName, ''),
              });
              return;
            }
          }
          resolve(null);
        });
      } catch (_) {
        if (!done) {
          done = true;
          clearTimeout(timer);
          resolve(null);
        }
      }
    });
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
    const name = toStr(proxyName, '');
    if (!name) return null;
    const url =
      'http://127.0.0.1:' + CFG.controllerPort + '/proxies/' + encodeURIComponent(name);
    try {
      const j = await fetchJSON({ url, headers: buildControllerHeaders() }, 1000);
      if (j && typeof j === 'object') {
        return {
          name: toStr(j.name, name),
          type: toStr(j.type, ''),
          now: toStr(j.now, ''),
          dialerProxy: toStr(j['dialer-proxy'], ''),
          server: toStr(j.server || j.address, ''),
          port: toStr(j.port, ''),
        };
      }
    } catch (_) {}
    return null;
  }

  async function resolveLeafProxyMeta(initialName) {
    let cur = toStr(initialName, '');
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

  /**
   * 统一多客户端入口抓拍与归属丰富编排器
   */
  async function runProbeWithEntranceCapture(nodeName, captureEnabled, probeFn, opts) {
    if (!captureEnabled || !CFG.showEntrance) {
      const probe = await probeFn();
      return { probe, entrance: null };
    }

    const options = opts || {};
    const entCacheTTL = options.entCacheTTL !== undefined ? options.entCacheTTL : CACHE_TTL_FG_MS;
    const domesticPromise = options.domesticPromise || Promise.resolve(null);
    const inTunnel = Boolean(options.inTunnel);
    const envObj = typeof $environment !== 'undefined' && $environment ? $environment : {};
    const envParams = envObj.params && typeof envObj.params === 'object' ? envObj.params : {};
    const nodeInfo = options.nodeInfo || envParams.nodeInfo || null;
    const proxyChainRaw =
      options.proxyChainInfo !== undefined ? options.proxyChainInfo : envParams.proxyChainInfo;
    const loonChain = parseLoonProxyChain(proxyChainRaw, nodeName);

    // 路径 A：Loon（或具备原生 nodeInfo.address 的客户端）零外部控制器直取
    if (HOST_CLIENT === 'loon' || (nodeInfo && typeof nodeInfo.address === 'string' && nodeInfo.address)) {
      const rawAddr = nodeInfo && nodeInfo.address ? String(nodeInfo.address).trim() : '';
      const parsedAddr = rawAddr ? parseHostPort(rawAddr) : null;
      const explicitPort = nodeInfo && nodeInfo.port ? String(nodeInfo.port).trim() : '';

      if (!parsedAddr) {
        const probe = await probeFn();
        return {
          probe,
          entrance: loonChain.hasChain
            ? {
                status: 'chain_only',
                hasProxyChain: true,
                proxyChainDesc: loonChain.chainDesc,
                proxyType: toStr(nodeInfo && nodeInfo.type, ''),
              }
            : { status: 'no_node_context' },
        };
      }

      // 落地探测与入口 EDNS/CNAME 解析并行执行
      const dnsPromise = (async () => {
        if (parsedAddr.isIPv4 || parsedAddr.isIPv6) {
          return { ip: parsedAddr.host, cnameChain: [], source: 'literal' };
        }
        const dom = await domesticPromise.catch(() => null);
        return resolveEntranceDomain(parsedAddr.host, dom && dom.ip, nodeName || undefined, inTunnel);
      })();

      const [probe, dnsRes] = await Promise.all([probeFn(), dnsPromise]);
      const entranceIP = dnsRes.ip || '';
      const landingIP = (probe && probe.landing && probe.landing.ip) || '';
      const landingIPv6 = (probe && probe.ipv6 && probe.ipv6.ip) || '';
      const isSameAsLanding =
        Boolean(entranceIP) && (entranceIP === landingIP || (Boolean(landingIPv6) && entranceIP === landingIPv6));

      let geo = null;
      if (entranceIP) {
        if (isPrivateLANIP(entranceIP)) {
          geo = await queryEntranceGeo(entranceIP, { cacheTTLMs: entCacheTTL });
        } else if (!isSameAsLanding) {
          geo = await queryEntranceGeo(entranceIP, {
            cacheTTLMs: entCacheTTL,
            targetNode: nodeName || undefined,
            inTunnel,
          }).catch(() => null);
        }
      }

      return {
        probe,
        entrance: {
          status: 'ok',
          entranceHost: parsedAddr.host,
          entrancePort: explicitPort || parsedAddr.port || '',
          entranceIP,
          cnameChain: dnsRes.cnameChain || [],
          dnsSource: dnsRes.source || '',
          proxyType: toStr(nodeInfo && nodeInfo.type, ''),
          hasProxyChain: loonChain.hasChain,
          proxyChainDesc: loonChain.chainDesc,
          geo,
        },
      };
    }

    // 路径 B：Surge 通过内置 $httpAPI('/v1/requests/recent') 提取真实远端拨号地址
    if (HOST_CLIENT === 'surge') {
      const probe = await probeFn();
      const recent = await captureSurgeRecentEntrance();
      if (!recent || !recent.parsed) {
        return { probe, entrance: { status: 'not_found' } };
      }
      const dom = await domesticPromise.catch(() => null);
      const dnsRes =
        recent.parsed.isIPv4 || recent.parsed.isIPv6
          ? { ip: recent.parsed.host, cnameChain: [], source: 'literal' }
          : await resolveEntranceDomain(recent.parsed.host, dom && dom.ip, nodeName || undefined, inTunnel);
      const entranceIP = dnsRes.ip || '';
      const landingIP = (probe && probe.landing && probe.landing.ip) || '';
      const landingIPv6 = (probe && probe.ipv6 && probe.ipv6.ip) || '';
      const isSame =
        Boolean(entranceIP) && (entranceIP === landingIP || (Boolean(landingIPv6) && entranceIP === landingIPv6));
      const geo =
        entranceIP && !isSame
          ? await queryEntranceGeo(entranceIP, {
              cacheTTLMs: entCacheTTL,
              targetNode: nodeName || undefined,
              inTunnel,
            }).catch(() => null)
          : entranceIP && isPrivateLANIP(entranceIP)
            ? await queryEntranceGeo(entranceIP, { cacheTTLMs: entCacheTTL })
            : null;
      return {
        probe,
        entrance: {
          status: 'ok',
          entranceHost: recent.parsed.host,
          entrancePort: recent.parsed.port || '',
          entranceIP,
          cnameChain: dnsRes.cnameChain || [],
          leafNode: recent.policyName || '',
          geo,
        },
      };
    }

    // 路径 C：Shadowrocket / Egern 无外部控制器环境诚实返回
    if (HOST_CLIENT !== 'clash' && HOST_CLIENT !== 'stash') {
      const probe = await probeFn();
      return { probe, entrance: { status: 'unsupported_host' } };
    }

    // 路径 D：Clash-Client / Stash 并发轮询 :9090/connections 与 /proxies/{name}
    let probeFinished = false;
    let controllerStatus = 'unknown';
    let matchedRecord = null;
    let earlyDNSAndMetaPromise = null;

    async function startEarlyResolve(match) {
      const { conn, parsed } = match;
      const chains = Array.isArray(conn.chains) ? conn.chains : [];
      const leafNode = chains.length > 0 ? String(chains[0] || '') : '';
      const dom = await domesticPromise.catch(() => null);
      const [dnsRes, proxyMeta] = await Promise.all([
        parsed.isIPv4 || parsed.isIPv6
          ? Promise.resolve({ ip: parsed.host, cnameChain: [], source: 'literal' })
          : resolveEntranceDomain(parsed.host, dom && dom.ip, undefined, inTunnel),
        fetchControllerProxyMeta(leafNode || nodeName).catch(() => null),
      ]);
      return { parsed, chains, leafNode, dnsRes, proxyMeta };
    }

    async function trySnapshotOnce() {
      if (matchedRecord || controllerStatus === 'unreachable' || controllerStatus === 'unauthorized') return;
      const snap = await fetchControllerConnectionsSnapshot();
      controllerStatus = snap.status;
      if (snap.status !== 'ok') return;
      const found = findMatchingConnection(snap.connections, nodeName);
      if (found) {
        matchedRecord = found;
        earlyDNSAndMetaPromise = startEarlyResolve(found);
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

    if (earlyDNSAndMetaPromise) {
      const resolved = await earlyDNSAndMetaPromise.catch(() => null);
      if (resolved) {
        const entranceIP = (resolved.dnsRes && resolved.dnsRes.ip) || '';
        const landingIP = (probe && probe.landing && probe.landing.ip) || '';
        const landingIPv6 = (probe && probe.ipv6 && probe.ipv6.ip) || '';
        const isSame =
          Boolean(entranceIP) &&
          (entranceIP === landingIP || (Boolean(landingIPv6) && entranceIP === landingIPv6));
        const geo =
          entranceIP && (!isSame || isPrivateLANIP(entranceIP))
            ? await queryEntranceGeo(entranceIP, {
                cacheTTLMs: entCacheTTL,
                inTunnel,
              }).catch(() => null)
            : null;
        return {
          probe,
          entrance: {
            status: 'ok',
            entranceHost: resolved.parsed.host,
            entrancePort: resolved.parsed.port,
            entranceIP,
            cnameChain: (resolved.dnsRes && resolved.dnsRes.cnameChain) || [],
            dnsSource: (resolved.dnsRes && resolved.dnsRes.source) || '',
            leafNode: resolved.leafNode,
            chains: resolved.chains,
            dialerProxy: (resolved.proxyMeta && resolved.proxyMeta.dialerProxy) || '',
            proxyType: (resolved.proxyMeta && resolved.proxyMeta.type) || '',
            geo,
          },
        };
      }
    }

    if (controllerStatus === 'unauthorized') return { probe, entrance: { status: 'unauthorized' } };
    if (controllerStatus === 'unreachable') return { probe, entrance: { status: 'unreachable' } };

    const fallbackMeta =
      controllerStatus === 'ok' && nodeName ? await resolveLeafProxyMeta(nodeName).catch(() => null) : null;
    if (fallbackMeta && fallbackMeta.server) {
      const parsedServer = parseHostPort(fallbackMeta.server);
      if (parsedServer) {
        const dom = await domesticPromise.catch(() => null);
        const dnsRes =
          parsedServer.isIPv4 || parsedServer.isIPv6
            ? { ip: parsedServer.host, cnameChain: [], source: 'literal' }
            : await resolveEntranceDomain(parsedServer.host, dom && dom.ip, undefined, inTunnel);
        const entranceIP = dnsRes.ip || '';
        const landingIP = (probe && probe.landing && probe.landing.ip) || '';
        const isSame = Boolean(entranceIP) && entranceIP === landingIP;
        const geo =
          entranceIP && (!isSame || isPrivateLANIP(entranceIP))
            ? await queryEntranceGeo(entranceIP, { cacheTTLMs: entCacheTTL, inTunnel }).catch(() => null)
            : null;
        return {
          probe,
          entrance: {
            status: 'ok',
            entranceHost: parsedServer.host,
            entrancePort: fallbackMeta.port || parsedServer.port || '',
            entranceIP,
            cnameChain: dnsRes.cnameChain || [],
            leafNode: fallbackMeta.name || '',
            dialerProxy: fallbackMeta.dialerProxy || '',
            proxyType: fallbackMeta.type || '',
            geo,
          },
        };
      }
    }

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
  // 8B. 10 类 100% 客观证据驱动链路拓扑分类器 + 独立名称宣称验伪审计
  // ============================================================================

  // 官方云全球加速专网 CNAME / 接入域特征词典
  const GA_DEDICATED_DOMAIN_RE =
    /(?:^|\.)(?:ga\.aliyuncs\.com|aliyunga\d*\.com|aga\.tencenttd\.com|aga\.qcloud\.com|cdnhwc1\.com|globalaccelerator\.amazonaws\.com)$/i;

  // 跨国同云/同骨干集团自治系统词典 (用于识别 cn-same-cloud)
  const CLOUD_CORP_ASN_GROUPS = [
    { name: '阿里云', asns: new Set([37963, 45102, 24429, 134963]) },
    { name: '腾讯云', asns: new Set([45090, 132203, 132591]) },
    { name: '华为云', asns: new Set([55990, 136907]) },
    { name: 'UCloud', asns: new Set([135377, 59077]) },
    { name: '火山引擎', asns: new Set([138371, 396986, 139190]) },
    { name: 'AWS', asns: new Set([16509, 14618]) },
    { name: 'Azure', asns: new Set([8075]) },
    { name: 'Zenlayer', asns: new Set([21859]) },
  ];

  // 已验证的国内主流多线 BGP 云厂商 ASN 词典 (用于识别 cn-bgp-cloud)
  const CN_BGP_CLOUD_ASN_MAP = {
    37963: '阿里云',
    45102: '阿里云',
    24429: '阿里云',
    45090: '腾讯云',
    132203: '腾讯云',
    55990: '华为云',
    136907: '华为云',
    135377: 'UCloud',
    138371: '火山引擎',
    38365: '百度智能云',
    45062: '京东云',
    59019: '金山云',
    59078: '青云',
    48269: '网宿科技',
  };

  function findSameCloudCorp(entASNNum, landASNNum) {
    if (!entASNNum || !landASNNum) return null;
    for (const grp of CLOUD_CORP_ASN_GROUPS) {
      if (grp.asns.has(entASNNum) && grp.asns.has(landASNNum)) {
        return grp;
      }
    }
    return null;
  }

  function formatCNEntranceActor(eg, fallbackProvider) {
    const place = eg ? formatCompactLocation(eg) : '';
    const rawDisp = eg && (eg.ispDisplay || eg.isp || eg.org) ? String(eg.ispDisplay || eg.isp || eg.org) : '';
    const provider = (rawDisp ? rawDisp.replace(/^中国/, '').trim() : '') || fallbackProvider || '';
    if (place && provider && (!hasCJK(place) || !hasCJK(provider))) {
      return place + ' ' + provider;
    }
    return [place, provider].filter(Boolean).join('');
  }

  function formatEntranceSummary(eg) {
    if (!eg || typeof eg !== 'object') return '';
    if (eg.isPrivate) return '局域网网关';
    const cc = toStr(eg.countryCode, '').toUpperCase();
    const loc = formatCompactLocation(eg);
    const rawBrand = eg.ispDisplay
      ? eg.ispDisplay.replace(/^中国/, '').trim()
      : simplifyISPName(eg.isp, eg.org, cc);
    let geoIsp = loc;
    if (rawBrand) {
      if (!loc) geoIsp = rawBrand;
      else if (cc === 'CN' && hasCJK(loc) && hasCJK(rawBrand)) geoIsp = loc + rawBrand;
      else geoIsp = loc + ' ' + rawBrand;
    }
    return [geoIsp, eg.asn].filter(Boolean).join(' ');
  }

  /**
   * 100% 证据驱动链路分类器（物理斩断节点名关键词依赖：不读取 nodeName / leafNode 任何字符）
   */
  function classifyLinkType(ctx) {
    const input = ctx || {};
    const nodeInfo = input.nodeInfo || null;
    const entrance = input.entrance || null;
    const probe = input.probe || null;
    const hostClient = input.hostClient || HOST_CLIENT;

    const l = (probe && probe.landing) || {};
    const cf = (probe && probe.cfTrace) || null;
    const warpMode =
      cf && (cf.warp === 'plus' || cf.warp === 'on') ? (cf.warp === 'plus' ? 'WARP+' : 'WARP') : '';
    const warpSuffix = warpMode ? ' + ' + warpMode : '';

    const landingCC = toStr(l.countryCode, '').toUpperCase();
    const landingASN = toStr(l.asn, '').toUpperCase();
    const landingASNNum = parseASNNum(landingASN);
    const isLandingCF =
      landingASN === 'AS13335' || /cloudflare/i.test(toStr(l.isp, '') + ' ' + toStr(l.org, ''));

    const rawNodeType = toStr(
      (nodeInfo && nodeInfo.type) || (entrance && entrance.proxyType),
      ''
    ).toLowerCase();
    const isRelayGroup = rawNodeType === 'relay';
    const dialerProxy = toStr(entrance && entrance.dialerProxy, '');
    const chains = (entrance && Array.isArray(entrance.chains) && entrance.chains) || [];
    const hasNodeLibraryChain =
      dialerProxy.startsWith('__clash_chain_entry_') ||
      chains.some((c) => String(c || '').startsWith('__clash_chain_entry_'));
    const hasLoonChain = Boolean(entrance && entrance.hasProxyChain);

    // 第 1 类：客户端配置级链式代理（__clash_chain_entry_ / dialer-proxy / relay / Loon proxyChainInfo）
    if (hasNodeLibraryChain) {
      return {
        code: 'chain-library',
        badge: '链式代理' + warpSuffix,
        detail: '客户端节点库双跳串联',
        color: COLORS.purple,
      };
    }
    if (dialerProxy && dialerProxy.toUpperCase() !== 'DIRECT') {
      return {
        code: 'chain-dialer',
        badge: '链式代理' + warpSuffix,
        detail: '经前置「' + dialerProxy + '」串联',
        color: COLORS.purple,
      };
    }
    if (hasLoonChain) {
      const chainDesc = toStr(entrance && entrance.proxyChainDesc, '');
      return {
        code: 'chain-loon',
        badge: '链式代理' + warpSuffix,
        detail: chainDesc ? '经前置「' + chainDesc + '」串联' : '客户端前置代理链串联',
        color: COLORS.purple,
      };
    }
    if (isRelayGroup) {
      return {
        code: 'chain-relay',
        badge: '链式代理' + warpSuffix,
        detail: '客户端 Relay 多跳串联',
        color: COLORS.purple,
      };
    }

    // 已捕获真实拨号入口 IP / 域名
    if (entrance && entrance.status === 'ok' && (entrance.entranceIP || entrance.entranceHost)) {
      const entIP = toStr(entrance.entranceIP, '');
      const entHost = toStr(entrance.entranceHost, '').replace(/\.$/, '');
      const cnameChain = Array.isArray(entrance.cnameChain) ? entrance.cnameChain : [];
      const eg = entrance.geo || null;
      const entCC = toStr(eg && eg.countryCode, '').toUpperCase();
      const entASN = toStr(eg && eg.asn, '').toUpperCase();
      const entASNNum = parseASNNum(entASN);
      const entISP = toStr(eg && (eg.ispDisplay || eg.isp || eg.org), '');

      const isPrivateEnt = Boolean((eg && eg.isPrivate) || (entIP && isPrivateLANIP(entIP)));
      const isDirectIP =
        Boolean(entIP) &&
        (entIP === l.ip || Boolean(probe && probe.ipv6 && probe.ipv6.ip && entIP === probe.ipv6.ip));
      const isEntCF =
        entASN === 'AS13335' ||
        /cloudflare/i.test(entISP + ' ' + toStr(eg && eg.org, '') + ' ' + entHost);

      // 第 2 类：RFC1918 私网 / 100.64.0.0/10 异地组网 / IPv6 ULA 局域网网关
      if (isPrivateEnt) {
        return {
          code: 'lan-gateway',
          badge: '局域网网关中转' + warpSuffix,
          detail: '内网或组网网关接入',
          color: COLORS.purple,
        };
      }

      // 第 3 类：出入口同 IP 单跳直连（含单跳直连 + WARP 出站）
      if (isDirectIP) {
        if (warpMode) {
          return {
            code: 'direct-warp',
            badge: '单跳直连 + ' + warpMode,
            detail: '入口即落地服务器',
            color: COLORS.cyan,
          };
        }
        return {
          code: 'direct',
          badge: '单跳直连',
          detail: '入口即落地服务器',
          color: COLORS.cyan,
        };
      }

      // 第 4 类：入口为 AS13335 Cloudflare Anycast 边缘节点
      if (isEntCF) {
        if (warpMode || isLandingCF) {
          return {
            code: 'cf-warp-tunnel',
            badge: 'Cloudflare ' + (warpMode || 'WARP') + ' 隧道',
            detail: 'CF 边缘接入',
            color: COLORS.cyan,
          };
        }
        return {
          code: 'cf-cdn-origin',
          badge: 'Cloudflare CDN 反代',
          detail: 'CF 边缘反代回源',
          color: COLORS.primary,
        };
      }

      // 第 5 类：国内入口跨境出境四级客观细分（绝不凭名字或臆测输出不可见的二层 IEPL/IPLC）
      if (entCC === 'CN' && landingCC && landingCC !== 'CN') {
        const domainCandidates = [entHost].concat(cnameChain).filter(Boolean);
        const hitsGlobalAccelerator = domainCandidates.some((d) =>
          GA_DEDICATED_DOMAIN_RE.test(String(d).replace(/\.$/, ''))
        );
        if (hitsGlobalAccelerator) {
          const actor = formatCNEntranceActor(eg, '');
          return {
            code: 'cn-cloud-ga',
            badge: '云全球加速中转' + warpSuffix,
            detail: (actor || '云全球加速') + '入口',
            color: COLORS.purple,
          };
        }

        const sameCloud = findSameCloudCorp(entASNNum, landingASNNum);
        if (sameCloud) {
          const actor = formatCNEntranceActor(eg, sameCloud.name);
          return {
            code: 'cn-same-cloud',
            badge: '同云跨境中转' + warpSuffix,
            detail: (actor || sameCloud.name) + '入口',
            color: COLORS.purple,
          };
        }

        const bgpCloudName = CN_BGP_CLOUD_ASN_MAP[entASNNum] || '';
        if (bgpCloudName) {
          const actor = formatCNEntranceActor(eg, bgpCloudName);
          return {
            code: 'cn-bgp-cloud',
            badge: '国内 BGP 云中转' + warpSuffix,
            detail: (actor || bgpCloudName) + '入口',
            color: COLORS.purple,
          };
        }

        const ispActor = formatCNEntranceActor(eg, '');
        return {
          code: 'cn-isp-transit',
          badge: '国内运营商中转' + warpSuffix,
          detail: (ispActor || '国内运营商') + '入口',
          color: COLORS.purple,
        };
      }

      // 第 6 类：境内内陆中转链路（国内入口 ➔ 国内异地出口）
      if (entCC === 'CN' && landingCC === 'CN') {
        return {
          code: 'cn-internal-transit',
          badge: '境内内陆中转',
          detail: '国内入口至国内异地出口',
          color: COLORS.purple,
        };
      }

      // 第 7 类：海外入口分离拓扑（交叉校验 cfTrace.colo 所在国区分跨国跳板套 WARP）
      if (entCC && entCC !== 'CN') {
        if (warpMode || isLandingCF) {
          const coloUpper = toStr(cf && cf.colo, '').toUpperCase();
          const coloCC = toStr((cf && cf.coloCountry) || CF_COLO_CC_MAP[coloUpper], '').toUpperCase();
          const isCrossCountryBeforeWarp =
            Boolean(landingCC) && entCC !== landingCC && (!coloCC || coloCC !== entCC);

          if (isCrossCountryBeforeWarp) {
            return {
              code: 'intl-transit-warp',
              badge: '海外跳板 + ' + (warpMode || 'WARP'),
              detail: entCC + ' 跳板至 ' + landingCC,
              color: COLORS.purple,
            };
          }
          return {
            code: 'overseas-direct-warp',
            badge: '海外入口 + ' + (warpMode || 'WARP'),
            detail: entCC + ' 入口经 WARP 出站',
            color: COLORS.cyan,
          };
        }

        if (landingCC && entCC !== landingCC) {
          return {
            code: 'intl-transit',
            badge: '海外跨国中转',
            detail: entCC + ' 跳板至 ' + landingCC,
            color: COLORS.purple,
          };
        }

        if (entASN && landingASN && entASN === landingASN) {
          return {
            code: 'same-asn-multi-ip',
            badge: '同网段多 IP 出站',
            detail: '出入口同属 ' + landingASN,
            color: COLORS.cyan,
          };
        }

        return {
          code: 'same-region-chain',
          badge: '海外同区中转',
          detail: entCC + ' 同区独立网络落地',
          color: COLORS.purple,
        };
      }

      // 第 8 类：入口与落地不同 IP 但入口 Geo 超时兜底
      return {
        code: 'separated-transit',
        badge: '分离式中转' + warpSuffix,
        detail: '入口与落地 IP 分离',
        color: COLORS.purple,
      };
    }

    // 第 9 类：未捕获入口诚实兜底（严格区分宿主：仅在 Clash-Client/Stash 提示控制器）
    if (!CFG.showEntrance) {
      return {
        code: 'outbound-only',
        badge: '仅测得落地',
        detail: '已关闭入口检测',
        color: COLORS.primary,
      };
    }

    if (hostClient === 'clash' || hostClient === 'stash') {
      if (warpMode) {
        return {
          code: 'warp-outbound',
          badge: warpMode + ' 托管出站',
          detail: '开启外部控制器可识别前端入口',
          color: COLORS.purple,
        };
      }
      if (isLandingCF) {
        return {
          code: 'cf-outbound',
          badge: 'Cloudflare 出站',
          detail: '开启外部控制器可识别前端入口',
          color: COLORS.cyan,
        };
      }
      if (entrance && entrance.status === 'unauthorized') {
        return {
          code: 'pending-secret',
          badge: '仅测得落地 (待填密钥)',
          detail: '填入外部控制器密钥即可识别入口',
          color: COLORS.warning,
        };
      }
      if (entrance && entrance.status === 'unreachable') {
        return {
          code: 'pending-controller',
          badge: '仅测得落地 (未开控制器)',
          detail: '开启外部控制器可识别入口',
          color: COLORS.muted,
        };
      }
      return {
        code: 'pending-sample',
        badge: '仅测得落地',
        detail: '重测可捕获入口',
        color: COLORS.muted,
      };
    }

    return {
      code: warpMode ? 'warp-outbound' : isLandingCF ? 'cf-outbound' : 'outbound-only',
      badge: warpMode ? '仅测得落地 (' + warpMode + ')' : '仅测得落地',
      detail: '长按具体节点运行可解析入口',
      color: warpMode ? COLORS.purple : COLORS.primary,
    };
  }

  /**
   * 独立「名称宣称验伪提示」审计器 —— 只验伪、绝不正向加分！
   * 仅当客观探测铁证 100% 证伪节点名宣称时返回一句自然客观提示，否则返回 null。
   */
  function detectNameClaimMismatch(nodeName, facts) {
    const name = toStr(nodeName, '');
    if (!name || !facts || typeof facts !== 'object') return null;

    const entrance = facts.entrance || null;
    const probe = facts.probe || null;
    const linkInfo = facts.linkInfo || null;
    const landingObj = facts.landing || (probe && probe.landing) || {};
    const eg = (entrance && entrance.geo) || facts.entranceGeo || null;

    const hasClientChain = Boolean(
      facts.hasClientChain ||
        (linkInfo && /^chain-/.test(String(linkInfo.code || ''))) ||
        (entrance &&
          (entrance.hasProxyChain ||
            (entrance.dialerProxy && String(entrance.dialerProxy).toUpperCase() !== 'DIRECT')))
    );

    const entIP = toStr(facts.entIP !== undefined ? facts.entIP : entrance && entrance.entranceIP, '');
    const entHost = toStr(
      facts.entHost !== undefined ? facts.entHost : entrance && entrance.entranceHost,
      ''
    );
    const landIP = toStr(facts.landingIP !== undefined ? facts.landingIP : landingObj.ip, '');
    const landIPv6 = toStr(
      facts.landingIPv6 !== undefined ? facts.landingIPv6 : probe && probe.ipv6 && probe.ipv6.ip,
      ''
    );
    const entASN = toStr(facts.entASN !== undefined ? facts.entASN : eg && eg.asn, '').toUpperCase();
    const entCC = toStr(facts.entCC !== undefined ? facts.entCC : eg && eg.countryCode, '').toUpperCase();
    const isPrivate = Boolean(
      facts.isPrivate || (eg && eg.isPrivate) || (entIP && isPrivateLANIP(entIP))
    );
    if (isPrivate) return null;

    const isSameIP =
      Boolean(entIP) && (entIP === landIP || (Boolean(landIPv6) && entIP === landIPv6));
    const isEntCF = Boolean(
      facts.isEntCF ||
        entASN === 'AS13335' ||
        (linkInfo && (linkInfo.code === 'cf-warp-tunnel' || linkInfo.code === 'cf-cdn-origin')) ||
        /cloudflare/i.test(toStr(eg && (eg.ispDisplay || eg.org), '') + ' ' + entHost)
    );

    // 规则 1：节点名含专线/中转，实测出入口为同一 IP
    if (!hasClientChain && /iepl|iplc|专线|内网专线|中转/i.test(name) && isSameIP) {
      return '节点名含专线/中转，实测出入口为同一 IP';
    }

    // 规则 2：节点名含专线/跨境口岸，实测入口为 Cloudflare 公共边缘
    if (/iepl|iplc|专线|内网专线|深港|广港|沪日|沪美|京德|京日|苏日/i.test(name) && isEntCF) {
      return '节点名含专线，实测入口为 Cloudflare 公共边缘';
    }

    // 规则 3：节点名含境内跨境专线，实测首跳直连境外（无境内入口）
    if (
      !hasClientChain &&
      /iepl|iplc|内网专线|深港|广港|沪日|沪美|京德|京日|苏日/i.test(name) &&
      Boolean(entCC) &&
      entCC !== 'CN'
    ) {
      const ccZh = COUNTRY_CODE_ZH_MAP[entCC] || entCC;
      return '节点名含境内专线，实测首跳直连境外 (' + ccZh + ')';
    }

    return null;
  }

  function resolveBGPRoleLabel(linkCode) {
    return linkCode === 'direct' || linkCode === 'direct-warp' ? '跨境骨干' : '落地互联';
  }

  /**
   * 单行简洁路径条：仅包含真实网络跳点，去除末尾多余的 ☁️ POP 代码，仅当开启 WARP 时在末尾追加 WARP
   */
  function buildTopologyHops({ domestic, entrance, probe }) {
    const l = (probe && probe.landing) || {};
    const cf = (probe && probe.cfTrace) || null;
    const flag = getFlagEmoji(l.countryCode);
    const htmlHops = [];
    const plainHops = [];

    if (domestic && domestic.ip) {
      const dLabel = '🇨🇳 ' + (domestic.shortTag || domestic.location || '本地');
      htmlHops.push(esc(dLabel));
      plainHops.push(dLabel);
    }

    if (entrance && entrance.hasProxyChain && entrance.proxyChainDesc) {
      const lcTag = entrance.proxyChainDesc;
      htmlHops.push(colorSpan(lcTag, COLORS.purple, true));
      plainHops.push(lcTag);
    }

    if (entrance && entrance.status === 'ok' && (entrance.entranceIP || entrance.entranceHost)) {
      const entIP = entrance.entranceIP || '';
      const isDirect =
        Boolean(entIP) &&
        (entIP === l.ip || Boolean(probe && probe.ipv6 && probe.ipv6.ip && entIP === probe.ipv6.ip));
      if (!isDirect) {
        const eg = entrance.geo;
        const entASN = String((eg && eg.asn) || '').toUpperCase();
        const isEntCF =
          entASN === 'AS13335' ||
          /cloudflare/i.test(String((eg && eg.ispDisplay) || '') + ' ' + String(entrance.entranceHost || ''));

        let eTag = '中转入口';
        let eColor = COLORS.purple;
        if ((eg && eg.isPrivate) || (entIP && isPrivateLANIP(entIP))) {
          eTag = '局域网网关';
        } else if (isEntCF) {
          eTag = '☁️ CF 边缘';
          eColor = COLORS.primary;
        } else if (eg) {
          const hopPlace = formatCompactLocation(eg, { shortHop: true }) || '入口';
          const shortISP = eg.ispDisplay
            ? eg.ispDisplay.replace(/^中国/, '').trim()
            : simplifyISPName(eg.isp, eg.org, eg.countryCode);
          const sep = shortISP && (!hasCJK(hopPlace) || !hasCJK(shortISP)) ? ' ' : '';
          eTag = getFlagEmoji(eg.countryCode) + ' ' + hopPlace + (shortISP ? sep + shortISP : '');
        }
        htmlHops.push(colorSpan(eTag, eColor, true));
        plainHops.push(eTag);
      }
    } else if (entrance && entrance.dialerProxy && !entrance.dialerProxy.startsWith('__clash_chain_entry_')) {
      const dpTag = entrance.dialerProxy;
      htmlHops.push(colorSpan(dpTag, COLORS.purple, true));
      plainHops.push(dpTag);
    }

    if (l.ip || l.countryCode || l.country) {
      const landPlace = formatCompactLocation(l, { shortHop: true }) || l.countryCode || '落地';
      const landTag = flag + ' ' + landPlace;
      htmlHops.push(esc(landTag));
      plainHops.push(landTag);
    }

    if (cf && (cf.warp === 'on' || cf.warp === 'plus')) {
      const wTag = cf.warp === 'plus' ? 'WARP+' : 'WARP';
      htmlHops.push(colorSpan(wTag, COLORS.purple, true));
      plainHops.push(wTag);
    }

    return {
      html: htmlHops.join(' ➔ '),
      plain: plainHops.join(' ➔ '),
      hopCount: plainHops.length,
    };
  }

  // ============================================================================
  // 9. 极简一屏弹窗渲染器（Apple 原生信息面板风格、深浅色自适应、零重复、零底部废话）
  // ============================================================================

  function levelColor(level) {
    if (level === 'excellent') return COLORS.success;
    if (level === 'good') return COLORS.cyan;
    if (level === 'warn') return COLORS.warning;
    if (level === 'danger') return COLORS.danger;
    return COLORS.primary;
  }

  /**
   * 视图 1：节点链路查询 (MODE=info) —— 严格控制在 7~9 行内，iPhone 一屏完整呈现
   */
  function renderInfoSheetHTML({ nodeName, nodeInfo, domestic, entrance, probe, hostClient }) {
    const activeHost = hostClient || HOST_CLIENT;
    const l = probe.landing || {};
    const cf = probe.cfTrace || null;
    const displayTitle = nodeName || '当前出口';
    const leafNode = entrance && entrance.leafNode ? String(entrance.leafNode).trim() : '';

    const linkInfo = classifyLinkType({ nodeInfo, entrance, probe, hostClient: activeHost });
    const claimWarning = detectNameClaimMismatch(nodeName, { entrance, probe, linkInfo });
    const topo = buildTopologyHops({ domestic, entrance, probe });

    const proto = formatProtocolName((nodeInfo && nodeInfo.type) || (entrance && entrance.proxyType));
    const subParts = [];
    if (leafNode && leafNode !== displayTitle) subParts.push(esc(leafNode));
    if (proto) subParts.push(esc(proto));
    subParts.push(colorSpan(linkInfo.badge, linkInfo.color, true));

    const topLines = [
      '<b>' + esc(displayTitle) + '</b>',
      '<span style="font-size:12.5px;color:' + COLORS.muted + '">' + subParts.join(' · ') + '</span>',
    ];
    if (topo.hopCount >= 2) {
      topLines.push('<span style="font-size:12.5px">' + topo.html + '</span>');
    }

    const detailRows = [];

    if (domestic && domestic.ip) {
      const domDesc =
        domestic.fullTag ||
        [domestic.location, (domestic.isp || '').replace(/^中国/, '')].filter(Boolean).join('');
      detailRows.push(
        renderKVRow(
          '直连',
          esc(maskIPString(domestic.ip, CFG.maskIP)) + (domDesc ? ' · ' + esc(domDesc) : '')
        )
      );
    }

    if (CFG.showEntrance && entrance) {
      if (entrance.status === 'ok' && (entrance.entranceIP || entrance.entranceHost)) {
        const entIP = entrance.entranceIP || '';
        const entHost = entrance.entranceHost || '';
        const isDirect =
          Boolean(entIP) &&
          (entIP === l.ip || Boolean(probe.ipv6 && probe.ipv6.ip && entIP === probe.ipv6.ip));
        if (!isDirect) {
          const entSummary = formatEntranceSummary(entrance.geo);
          const gaSuffix =
            linkInfo.code === 'cn-cloud-ga' ? ' ' + colorSpan('[GA加速]', COLORS.purple, true) : '';
          detailRows.push(
            renderKVRow(
              '入口',
              esc(maskIPString(entIP || entHost, CFG.maskIP)) +
                (entSummary ? ' · ' + esc(entSummary) : '') +
                gaSuffix
            )
          );
        }
      } else if (activeHost === 'clash' || activeHost === 'stash') {
        if (entrance.status === 'unauthorized') {
          detailRows.push(renderKVRow('入口', colorSpan('待填外部控制器密钥', COLORS.warning, false)));
        } else if (entrance.status === 'unreachable') {
          detailRows.push(
            renderKVRow('入口', '<span style="color:' + COLORS.muted + '">未开启外部控制器</span>')
          );
        }
      }
    }

    const landLoc = formatCompactLocation(l) || l.countryCode || '-';
    const landISP = simplifyISPName(l.isp, l.org, l.countryCode);
    const landProvider = [landISP, l.asn].filter(Boolean).join(' ');
    const landSegs = [esc(maskIPString(l.ip, CFG.maskIP)), esc(landLoc)];
    if (landProvider) landSegs.push(esc(landProvider));
    detailRows.push(renderKVRow('落地', landSegs.join(' · ')));

    const bgp = probe.bgp;
    if (bgp) {
      const bgpText = bgp.compactText || formatBGPCompactSummary(bgp);
      if (bgpText) {
        detailRows.push(
          renderKVRow(
            '线路',
            colorSpan(bgpText, levelColor(bgp.gradeLevel), bgp.gradeLevel === 'excellent')
          )
        );
      }
    }

    if (CFG.checkIPv6 && probe.ipv6 && probe.ipv6.ip) {
      detailRows.push(
        renderKVRow(
          '双栈',
          colorSpan('支持 IPv6', COLORS.success, false) +
            ' <span style="color:' +
            COLORS.muted +
            '">(' +
            esc(formatShortIPv6(probe.ipv6.ip, CFG.maskIP)) +
            ')</span>'
        )
      );
    }

    if (cf && (cf.warp === 'on' || cf.warp === 'plus')) {
      const warpLabel = (cf.warp === 'plus' ? 'WARP+ 已启用' : '已启用') + (cf.colo ? ' (' + cf.colo + ')' : '');
      detailRows.push(renderKVRow('WARP', colorSpan(warpLabel, COLORS.purple, false)));
    }

    if (claimWarning) {
      detailRows.push(renderKVRow('提示', colorSpan(claimWarning, COLORS.warning, false)));
    }

    return wrapSheetBodyHTML(topLines.join('<br>') + SHEET_HR + detailRows.join('<br>'));
  }

  /**
   * 视图 2：节点纯净度检测 (MODE=purity) —— 严格控制在 6~7 行内，零重复、零「未知」
   */
  function renderPuritySheetHTML({ nodeName, probe }) {
    const l = probe.landing || {};
    const p = probe.purity || null;
    const ipp = probe.ipPure || null;
    const pc = probe.proxyCheck || null;
    const sc = probe.ipScore || null;
    const displayTitle = nodeName || '当前出口';

    const effCC = toStr(
      l.countryCode || (p && p.countryCode) || (ipp && ipp.countryCode),
      ''
    ).toUpperCase();
    const locStr =
      formatCompactLocation(l) || COUNTRY_CODE_ZH_MAP[effCC] || effCC || '-';
    const rawISP =
      l.isp || l.org || (p && (p.companyName || p.asnOrg)) || (ipp && ipp.asOrganization) || '';
    const cleanISP = simplifyISPName(rawISP, '', effCC);
    const asnStr = l.asn || (p && p.asn) || (ipp && ipp.asn) || '';
    const providerStr = [cleanISP, asnStr].filter(Boolean).join(' ');
    const subSegs = [esc(maskIPString(l.ip, CFG.maskIP)), esc(locStr)];
    if (providerStr) subSegs.push(esc(providerStr));

    const topLines = [
      '<b>' + esc(displayTitle) + '</b>',
      '<span style="font-size:12.5px;color:' + COLORS.muted + '">' + subSegs.join(' · ') + '</span>',
    ];

    const detailRows = [];
    const COL_W = '3.6em';

    if (p || ipp || pc || sc) {
      // 1. 属性（合并带宽性质 + 原生/广播结论，绝不重复展示）
      let natureLabel = '';
      let natureLevel = 'normal';
      if (p && p.lineageLabel) {
        natureLabel = p.lineageLabel;
        natureLevel = p.lineageLevel;
      } else if (ipp && ipp.isResidential === true) {
        natureLabel = '住宅宽带';
        natureLevel = 'good';
      } else if (pc && pc.typeZh && (pc.type === 'Residential' || pc.type === 'Wireless' || pc.type === 'Business')) {
        natureLabel = pc.typeZh;
        natureLevel = 'good';
      } else if (l.hosting || (pc && pc.type === 'Hosting')) {
        natureLabel = '机房带宽';
        natureLevel = 'warn';
      } else if (ipp && ipp.isResidential === false) {
        natureLabel = '机房/商业网络';
        natureLevel = 'warn';
      } else if (l.mobile) {
        natureLabel = '移动蜂窝网络';
        natureLevel = 'good';
      } else {
        natureLabel = '常规网络';
        natureLevel = 'normal';
      }

      const isNative =
        p && typeof p.isNativeGeo === 'boolean'
          ? p.isNativeGeo
          : ipp && typeof ipp.isBroadcast === 'boolean'
            ? !ipp.isBroadcast
            : null;
      const nativeHtml =
        isNative === true
          ? ' · ' + colorSpan('原生 IP', COLORS.success, true)
          : isNative === false
            ? ' · ' + colorSpan('广播 IP', COLORS.warning, true)
            : '';
      detailRows.push(
        renderKVRow('属性', colorSpan(natureLabel, levelColor(natureLevel), true) + nativeHtml, COL_W)
      );

      // 2. 类型（仅当 ipapi.is 或 ipinfo 拿到真实双维类型时展示，未拿到直接省略，严禁显示「未知」）
      if (p && p.hasDualTypes && p.asnTypeText && p.companyTypeText) {
        detailRows.push(
          renderKVRow(
            '类型',
            'ASN ' + esc(p.asnTypeText) + ' · 运营 ' + esc(p.companyTypeText),
            COL_W
          )
        );
      }

      // 3. 评分（合并综合评分与 IPPure 欺诈值，去除方块条与冗余词藻）
      const hasRichPurity = Boolean(
        p && (p.hasDualTypes || p.lineageLabel || p.primaryScore || p.riskIndex > 0)
      );
      let combinedRisk = hasRichPurity
        ? p.riskIndex
        : ipp && ipp.fraudScore !== null
          ? ipp.fraudScore
          : pc && pc.risk !== null
            ? pc.risk
            : 15;
      if (hasRichPurity && ipp && ipp.fraudScore !== null && pc && pc.risk !== null) {
        combinedRisk = Math.round(p.riskIndex * 0.5 + ipp.fraudScore * 0.25 + pc.risk * 0.25);
      } else if (hasRichPurity && ipp && ipp.fraudScore !== null) {
        combinedRisk = Math.round(p.riskIndex * 0.65 + ipp.fraudScore * 0.35);
      } else if (hasRichPurity && pc && pc.risk !== null) {
        combinedRisk = Math.round(p.riskIndex * 0.65 + pc.risk * 0.35);
      } else if (!hasRichPurity && ipp && ipp.fraudScore !== null && pc && pc.risk !== null) {
        combinedRisk = Math.round(ipp.fraudScore * 0.6 + pc.risk * 0.4);
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
          ? '纯净'
          : combinedRisk <= 35
            ? '良好'
            : combinedRisk <= 60
              ? '一般'
              : '高风险';
      const fraudSuffix =
        ipp && ipp.fraudScore !== null
          ? ' <span style="color:' + COLORS.muted + '">· 欺诈值 ' + ipp.fraudScore + '</span>'
          : '';
      detailRows.push(
        renderKVRow(
          '评分',
          colorSpan(cleanScore + ' / 100 · ' + rLabel, rColor, true) + fraudSuffix,
          COL_W
        )
      );

      // 4. 风险
      const f = (p && p.flags) || {};
      const riskTags = [];
      if (f.datacenter || (pc && pc.type === 'Hosting') || l.hosting) {
        riskTags.push(colorSpan('机房托管', COLORS.warning, false));
      }
      if (f.vpn || f.proxy || (pc && (pc.proxy || pc.type === 'VPN')) || l.proxy) {
        riskTags.push(colorSpan('代理/VPN', COLORS.danger, true));
      }
      if (f.tor || (pc && pc.type === 'TOR')) {
        riskTags.push(colorSpan('Tor 节点', COLORS.danger, true));
      }
      if (f.abuser || (pc && pc.type === 'Compromised')) {
        riskTags.push(colorSpan('滥用记录', COLORS.danger, true));
      }
      if (f.crawler) {
        riskTags.push(colorSpan('爬虫标记', COLORS.warning, false));
      }
      detailRows.push(
        renderKVRow(
          '风险',
          riskTags.length > 0 ? riskTags.join(' · ') : colorSpan('无代理 / VPN / 滥用标记', COLORS.success, false),
          COL_W
        )
      );

      // 5. 黑名单
      if (sc) {
        const blHtml =
          sc.listedCount === 0
            ? colorSpan('未命中', COLORS.success, false) +
              ' <span style="color:' +
              COLORS.muted +
              '">(0 / ' +
              sc.totalBlacklists +
              ')</span>'
            : colorSpan('命中 ' + sc.listedCount + ' 项: ' + sc.listedNames.join(', '), COLORS.danger, true);
        detailRows.push(renderKVRow('黑名单', blHtml, COL_W));
      }
    } else {
      detailRows.push(colorSpan('风控接口响应超时，请稍后重试', COLORS.warning, false));
    }

    return wrapSheetBodyHTML(topLines.join('<br>') + SHEET_HR + detailRows.join('<br>'));
  }

  function formatUnlockRow(item) {
    const col =
      item.state === 'yes'
        ? COLORS.success
        : item.state === 'partial'
          ? COLORS.warning
          : item.state === 'no'
            ? COLORS.danger
            : COLORS.muted;
    return renderKVRow(item.name, colorSpan(item.text, col, item.state === 'yes'), '5.2em');
  }

  /**
   * 视图 3：流媒体与解锁检测 (MODE=unlock) —— 分组简明一屏展示，无底部小字
   */
  function renderUnlockSheetHTML({ nodeName, probe }) {
    const l = probe.landing || {};
    const displayTitle = nodeName || '当前出口';
    const aiRows = (probe.aiItems || []).map(formatUnlockRow);
    const mediaRows = (probe.mediaItems || []).map(formatUnlockRow);
    const allItems = [].concat(probe.aiItems || [], probe.mediaItems || []);
    const passCount = allItems.filter((x) => x.state === 'yes' || x.state === 'partial').length;

    const subSegs = [];
    if (l.ip) subSegs.push(esc(maskIPString(l.ip, CFG.maskIP)));
    const loc = formatCompactLocation(l) || l.countryCode || '';
    if (loc) subSegs.push(esc(loc));
    subSegs.push('解锁 ' + passCount + ' / ' + allItems.length);

    const topLines = [
      '<b>' + esc(displayTitle) + '</b>',
      '<span style="font-size:12.5px;color:' + COLORS.muted + '">' + subSegs.join(' · ') + '</span>',
    ];

    const bodySections = [];
    if (aiRows.length > 0) bodySections.push(aiRows.join('<br>'));
    if (mediaRows.length > 0) bodySections.push(mediaRows.join('<br>'));

    return wrapSheetBodyHTML(topLines.join('<br>') + SHEET_HR + bodySections.join(SHEET_SUB_HR));
  }

  // ============================================================================
  // 10. 网页诊断面板 / JSON 接口 (http://net-lsp-x.com)
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
    const l = infoProbe.landing || {};
    const cf = infoProbe.cfTrace || null;
    const flag = getFlagEmoji(l.countryCode || '');
    const geo = formatCompactLocation(l) || l.countryCode || '-';
    const landISP = simplifyISPName(l.isp, l.org, l.countryCode);
    const effectiveName = targetNode || (entrance && entrance.leafNode) || '';
    const linkInfo = classifyLinkType({
      nodeInfo: null,
      entrance,
      probe: infoProbe,
    });
    const claimWarning = detectNameClaimMismatch(effectiveName, {
      entrance,
      probe: infoProbe,
      linkInfo,
    });
    const topo = buildTopologyHops({ domestic, entrance, probe: infoProbe });
    const hasEnt =
      entrance &&
      entrance.status === 'ok' &&
      (entrance.entranceIP || entrance.entranceHost) &&
      entrance.entranceIP !== l.ip;
    const entSummary = hasEnt ? formatEntranceSummary(entrance.geo) : '';
    const bgp = infoProbe.bgp;
    const bgpText = bgp ? bgp.compactText || formatBGPCompactSummary(bgp) : '';
    const warpActive = cf && (cf.warp === 'on' || cf.warp === 'plus');
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>节点诊断面板 · v${VERSION}</title>
<style>
  :root { --bg:#f5f5f7; --card:#fff; --text:#1d1d1f; --sub:#6e6e73; --border:#e5e5ea; --accent:#007aff; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#000; --card:#1c1c1e; --text:#f5f5f7; --sub:#8e8e93; --border:#2c2c2e; --accent:#0a84ff; }
  }
  * { box-sizing:border-box; }
  body { margin:0; padding:20px 16px 36px; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif; }
  .wrap { max-width:520px; margin:0 auto; }
  .hero { margin-bottom:14px; }
  .hero h1 { font-size:19px; margin:0 0 4px; }
  .hero p { margin:0; font-size:13px; color:var(--sub); }
  .card { background:var(--card); border:1px solid var(--border); border-radius:14px; padding:14px 16px; margin-bottom:12px; }
  .row { display:flex; justify-content:space-between; gap:12px; padding:6px 0; border-bottom:1px solid var(--border); font-size:14px; }
  .row:last-child { border-bottom:none; }
  .k { color:var(--sub); flex-shrink:0; }
  .v { font-weight:500; text-align:right; word-break:break-all; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; }
  .foot { text-align:center; font-size:12px; color:var(--sub); margin-top:12px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>节点诊断面板</h1>
    <p>${esc(targetNode ? '节点：' + targetNode : '当前活跃连接')}</p>
  </div>
  <div class="card">
    <div class="row"><span class="k">链路</span><span class="v" style="color:${linkInfo.color}">${esc(linkInfo.badge)}</span></div>
    ${topo.hopCount >= 2 ? `<div class="row"><span class="k">路径</span><span class="v">${esc(topo.plain)}</span></div>` : ''}
    ${domestic && domestic.ip ? `<div class="row"><span class="k">直连</span><span class="v"><code>${esc(maskIPString(domestic.ip, CFG.maskIP))}</code>${domestic.fullTag ? ' · ' + esc(domestic.fullTag) : ''}</span></div>` : ''}
    ${hasEnt ? `<div class="row"><span class="k">入口</span><span class="v"><code>${esc(maskIPString(entrance.entranceIP || entrance.entranceHost, CFG.maskIP))}</code>${entSummary ? ' · ' + esc(entSummary) : ''}</span></div>` : ''}
    <div class="row"><span class="k">落地</span><span class="v"><code>${esc(maskIPString(l.ip, CFG.maskIP))}</code> · ${flag} ${esc(geo)}${landISP || l.asn ? ' · ' + esc([landISP, l.asn].filter(Boolean).join(' ')) : ''}</span></div>
    ${bgpText ? `<div class="row"><span class="k">线路</span><span class="v">${esc(bgpText)}</span></div>` : ''}
    ${warpActive ? `<div class="row"><span class="k">WARP</span><span class="v">已启用${cf.colo ? ' (' + esc(cf.colo) + ')' : ''}</span></div>` : ''}
    ${claimWarning ? `<div class="row"><span class="k">提示</span><span class="v" style="color:${COLORS.warning}">${esc(claimWarning)}</span></div>` : ''}
  </div>
  ${purity ? `<div class="card">
    ${purity.lineageLabel || purity.broadcastText ? `<div class="row"><span class="k">属性</span><span class="v">${esc([purity.lineageLabel, purity.broadcastText].filter(Boolean).join(' · '))}</span></div>` : ''}
    ${purity.hasDualTypes ? `<div class="row"><span class="k">类型</span><span class="v">${esc('ASN ' + purity.asnTypeText + ' · 运营 ' + purity.companyTypeText)}</span></div>` : ''}
    <div class="row"><span class="k">评分</span><span class="v">${Math.max(0, 100 - purity.riskIndex)} / 100</span></div>
  </div>` : ''}
  <div class="foot">支持 ?node=节点名 指定节点或 ?format=json 输出 JSON</div>
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
      const domesticPromise = CFG.showDomestic
        ? queryDomesticDirect(true).catch(() => null)
        : Promise.resolve(null);
      const probeWrap = await runProbeWithEntranceCapture(
        targetNode || '',
        true,
        () => executeModeProbe(targetNode, 'info'),
        { domesticPromise, inTunnel: true }
      );
      const domestic = await domesticPromise;
      const infoProbe = probeWrap.probe;
      const entrance = probeWrap.entrance;
      const purity = await queryPurityWithFallback(infoProbe.landing.ip, targetNode);
      const effectiveName = targetNode || (entrance && entrance.leafNode) || '';
      const linkType = classifyLinkType({
        nodeInfo: null,
        entrance,
        probe: infoProbe,
      });
      const claimWarning = detectNameClaimMismatch(effectiveName, {
        entrance,
        probe: infoProbe,
        linkInfo: linkType,
      });
      const topology = buildTopologyHops({ domestic, entrance, probe: infoProbe }).plain;

      if (query.format === 'json' || pathname === '/json' || pathname === '/api') {
        safeDone({
          response: {
            status: 200,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' },
            body: JSON.stringify(
              {
                ok: true,
                version: VERSION,
                hostClient: HOST_CLIENT,
                targetNode: targetNode || null,
                linkType,
                claimWarning,
                topology,
                domestic,
                entrance,
                probe: infoProbe,
                purity,
              },
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
          body: '诊断请求失败: ' + String((e && e.message) || e),
        },
      });
    }
  }

  // ============================================================================
  // 11. 多客户端交互入口：节点长按 / Loon 仪表盘直测 / 模块面板 / 网络切换通知
  // ============================================================================

  function getSheetTitleByMode(mode) {
    const titleMap = {
      info: '节点链路查询',
      purity: '节点纯净度检测',
      unlock: '流媒体与解锁检测',
    };
    return titleMap[mode] || '节点信息查询';
  }

  function renderByMode(mode, ctx) {
    if (mode === 'purity') return renderPuritySheetHTML(ctx);
    if (mode === 'unlock') return renderUnlockSheetHTML(ctx);
    return renderInfoSheetHTML(ctx);
  }

  async function handleNodeLongPress(nodeName, nodeInfo) {
    const mode = CFG.mode; // 'info' | 'purity' | 'unlock'
    const sheetTitle = getSheetTitleByMode(mode);
    const needEntrance = mode === 'info';
    const domesticPromise =
      mode === 'info' && CFG.showDomestic
        ? queryDomesticDirect(HOST_CLIENT !== 'clash').catch(() => null)
        : Promise.resolve(null);

    // 非 Clash-Client 宿主（Loon / Surge / Stash / Shadowrocket / Egern）：
    // 原生直走节点/策略隧道，绝不调 net-lsp-x.com Bridge，绝不改 $config 全局策略！
    if (HOST_CLIENT !== 'clash') {
      try {
        const res = await runProbeWithEntranceCapture(
          nodeName,
          needEntrance,
          async () => {
            const p = await executeModeProbe(nodeName || undefined, mode);
            p.routeChannel = nodeName ? 'direct-node' : 'active-default';
            return p;
          },
          { nodeInfo, domesticPromise }
        );
        const domestic = await domesticPromise;
        const displayNode =
          nodeName ||
          (res.entrance && res.entrance.leafNode) ||
          resolveActiveRoutingContext().leafNode ||
          '当前出口';
        const html = renderByMode(mode, {
          nodeName: displayNode,
          nodeInfo,
          domestic,
          entrance: res.entrance,
          probe: res.probe,
        });
        safeDone({ title: sheetTitle, htmlMessage: html });
      } catch (err) {
        safeDone({
          title: sheetTitle,
          htmlMessage: wrapSheetBodyHTML(
            '<b>' +
              esc(nodeName || '当前出口') +
              '</b>' +
              SHEET_HR +
              colorSpan('查询失败：' + String((err && err.message) || err), COLORS.danger, false)
          ),
        });
      }
      return;
    }

    // Clash-Client 宿主：完整保留零切换 Bridge ➔ 降级 $config 临时切换与自动还原机制
    recoverDanglingPolicyIfAny();
    let probe;
    let entrance = null;
    try {
      const res = await runProbeWithEntranceCapture(
        nodeName,
        needEntrance,
        () => tryTunnelBridgeProbe(nodeName, mode),
        { nodeInfo, domesticPromise }
      );
      probe = res.probe;
      entrance = res.entrance;
    } catch (bridgeErr) {
      log('Bridge unavailable (' + (bridgeErr.message || bridgeErr) + '), falling back to $config...');
      const domesticBeforeSwitch = await domesticPromise;
      try {
        const res = await runProbeWithEntranceCapture(
          nodeName,
          needEntrance,
          () => fallbackConfigSwitchProbe(nodeName, mode),
          { nodeInfo, domesticPromise: Promise.resolve(domesticBeforeSwitch) }
        );
        probe = res.probe;
        entrance = res.entrance;
      } catch (fallbackErr) {
        safeDone({
          title: sheetTitle,
          htmlMessage: wrapSheetBodyHTML(
            '<b>' +
              esc(nodeName) +
              '</b>' +
              SHEET_HR +
              colorSpan('查询失败：' + String(fallbackErr.message || fallbackErr), COLORS.danger, false) +
              '<br><span style="color:' +
              COLORS.muted +
              ';font-size:12.5px">请开启模块页顶部的「HTTPS 解密」开关后重试。</span>'
          ),
        });
        return;
      }

      if (probe && probe.needsEngineWarning) {
        safeDone({
          title: sheetTitle,
          htmlMessage: wrapSheetBodyHTML(
            colorSpan(probe.error, COLORS.warning, true) +
              SHEET_HR +
              '请开启模块页顶部 <b>HTTPS 解密</b> 开关，或在设置中开启 <b>自动临时切换测速</b>。'
          ),
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

  function resolveActiveRoutingContext() {
    const out = { modeName: '', rootGroup: '', leafNode: '' };
    if (typeof $config === 'undefined' || !$config || !$config.getConfig) return out;
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

      const domesticPromise = CFG.showDomestic
        ? queryDomesticDirect(HOST_CLIENT !== 'clash').catch(() => null)
        : Promise.resolve(null);
      const probeWrap = await runProbeWithEntranceCapture(
        '',
        true,
        () => executeModeProbe(undefined, 'panel'),
        {
          lightPoll: true,
          entCacheTTL: CACHE_TTL_BG_MS,
          domesticPromise,
        }
      );
      const domestic = await domesticPromise;
      const probe = probeWrap.probe;
      const entrance = probeWrap.entrance;
      const l = probe.landing;
      const activeNode = (entrance && entrance.leafNode) || routing.leafNode || '';
      const linkInfo = classifyLinkType({
        nodeInfo: null,
        entrance,
        probe,
      });

      const lines = [];
      if (modeInfo) lines.push('模式：' + modeInfo);
      lines.push('链路：' + linkInfo.badge + (activeNode ? ' · ' + activeNode : ''));
      if (domestic && domestic.ip) {
        const domDesc = domestic.fullTag || [domestic.location, domestic.isp].filter(Boolean).join(' ');
        lines.push('直连：' + maskIPString(domestic.ip, CFG.maskIP) + (domDesc ? ' · ' + domDesc : ''));
      }
      if (entrance && entrance.status === 'ok' && entrance.entranceIP && entrance.entranceIP !== l.ip) {
        const eTxt = formatEntranceSummary(entrance.geo);
        lines.push('入口：' + maskIPString(entrance.entranceIP, CFG.maskIP) + (eTxt ? ' · ' + eTxt : ''));
      }
      const geo = formatCompactLocation(l) || l.countryCode || '-';
      const isp = simplifyISPName(l.isp, l.org, l.countryCode);
      const landProvider = [isp, l.asn].filter(Boolean).join(' ');
      lines.push(
        '落地：' +
          maskIPString(l.ip, CFG.maskIP) +
          ' · ' +
          geo +
          (landProvider ? ' · ' + landProvider : '')
      );
      if (probe.bgp) {
        const bgpText = probe.bgp.compactText || formatBGPCompactSummary(probe.bgp);
        if (bgpText) lines.push('线路：' + bgpText);
      }

      safeDone({
        title: '网络出口信息',
        content: lines.join('\n'),
        icon: 'globe.asia.australia',
        'icon-color': '#10B981',
      });
    } catch (e) {
      safeDone({
        title: '网络出口信息',
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
      await sleep(1200);

      const routing = resolveActiveRoutingContext();
      const domesticPromise = CFG.showDomestic
        ? queryDomesticDirect(HOST_CLIENT !== 'clash').catch(() => null)
        : Promise.resolve(null);
      const landWrap = await runProbeWithEntranceCapture(
        '',
        CFG.showEntrance,
        () => queryLandingIPv4(undefined),
        {
          lightPoll: true,
          entCacheTTL: CACHE_TTL_BG_MS,
          domesticPromise,
        }
      );
      const domestic = await domesticPromise;
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

        const isLandingCF =
          String(landing.asn || '').toUpperCase() === 'AS13335' ||
          /cloudflare/i.test(String(landing.isp || '') + ' ' + String(landing.org || ''));
        const cf = isLandingCF ? await queryCloudflareTrace(undefined).catch(() => null) : null;
        const bgp = await queryBGPUpstreams(landIP, undefined, CACHE_TTL_BG_MS).catch(() => null);
        const purity = await queryPurityWithFallback(
          landIP,
          undefined,
          Math.min(CFG.timeoutMs, 3800),
          CACHE_TTL_BG_MS
        );
        const probe = { landing, bgp, cfTrace: cf, ipv6: null };

        const linkInfo = classifyLinkType({
          nodeInfo: null,
          entrance,
          probe,
        });
        const topo = buildTopologyHops({ domestic, entrance, probe });

        const flag = getFlagEmoji(cc);
        const geo = formatCompactLocation(landing) || cc || '未知地区';
        const regionLabel = COUNTRY_CODE_ZH_MAP[cc] || landing.country || geo;

        const domChanged = Boolean(prev && prev.domIP && domIP && prev.domIP !== domIP);
        const landChanged = Boolean(prev && prev.landIP && landIP && prev.landIP !== landIP);

        let titleText = '网络出口已更新 · ' + flag + ' ' + regionLabel;
        if (!prev || (!prev.domIP && !prev.landIP)) {
          titleText = '网络出口已就绪 · ' + flag + ' ' + regionLabel;
        } else if (domChanged && !landChanged) {
          titleText = '网络环境已切换 · ' + flag + ' ' + regionLabel;
        } else if (!domChanged && landChanged) {
          titleText = '代理出口已更新 · ' + flag + ' ' + regionLabel;
        }

        const uncapturedCodes = new Set([
          'pending-controller',
          'pending-secret',
          'pending-sample',
          'outbound-only',
        ]);
        const showLinkBadge = !uncapturedCodes.has(linkInfo.code);
        const subtitleText = showLinkBadge
          ? linkInfo.badge + (topo.hopCount >= 2 ? ' · ' + topo.plain : '')
          : (topo.hopCount >= 2 ? topo.plain : linkInfo.badge);

        const bodyLines = [];
        const cleanISP = simplifyISPName(landing.isp, landing.org, cc);
        const landProv = [cleanISP, landing.asn].filter(Boolean).join(' ');
        bodyLines.push('落地：' + maskIPString(landIP, CFG.maskIP) + ' · ' + geo + (landProv ? ' · ' + landProv : ''));

        if (entIP && entIP !== landIP) {
          const eTxt = formatEntranceSummary(entrance.geo);
          bodyLines.push('入口：' + maskIPString(entIP, CFG.maskIP) + (eTxt ? ' · ' + eTxt : ''));
        }
        if (bgp) {
          const bgpText = bgp.compactText || formatBGPCompactSummary(bgp);
          if (bgpText) bodyLines.push('线路：' + bgpText);
        }
        if (purity && (purity.lineageLabel || purity.isNativeGeo !== null)) {
          const nativeTag =
            purity.isNativeGeo === true ? '原生 IP' : purity.isNativeGeo === false ? '广播 IP' : '';
          const scoreTag = Math.max(0, 100 - (purity.riskIndex || 0)) + ' / 100';
          const pText = [purity.lineageLabel, nativeTag, scoreTag].filter(Boolean).join(' · ');
          if (pText) bodyLines.push('纯净：' + pText);
        }
        if (domIP && domIP !== landIP) {
          const domTag = domestic && (domestic.fullTag || domestic.shortTag || domestic.location);
          bodyLines.push('直连：' + maskIPString(domIP, CFG.maskIP) + (domTag ? ' · ' + domTag : ''));
        }

        if (!_scriptSettled) notify(titleText, subtitleText, bodyLines.join('\n'));
      }
    } catch (e) {
      log('network-changed error: ' + ((e && e.message) || e));
    }
    safeDone({});
  }

  /**
   * 软超时提前熔断看门狗：远早于宿主硬看门狗主动调用 $done，避免触发隔离机制
   */
  function armSoftDeadlineGuard(ctx) {
    let budgetMs = 36000;
    if (ctx.isHTTP) {
      budgetMs = Math.min(45000, Math.max(20000, CFG.timeoutMs * 3 + 10000));
    } else if (ctx.nodeName || HOST_CLIENT === 'loon') {
      if (CFG.mode === 'unlock') {
        budgetMs = Math.min(56000, Math.max(28000, CFG.timeoutMs * 4 + 14000));
      } else if (CFG.mode === 'purity') {
        budgetMs = Math.min(36000, Math.max(18000, CFG.timeoutMs * 3 + 8000));
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
      log('Soft deadline (' + budgetMs + 'ms) reached, settling early');
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
                  error: '节点探测超时',
                })
              : '节点探测响应超时，请检查节点连通性后重试',
          },
        });
        return;
      }

      if (ctx.nodeName || (HOST_CLIENT === 'loon' && CFG.mode !== 'event')) {
        const sheetTitle = getSheetTitleByMode(CFG.mode);
        safeDone({
          title: sheetTitle,
          htmlMessage: wrapSheetBodyHTML(
            '<b>' +
              esc(ctx.nodeName || '当前出口') +
              '</b>' +
              SHEET_HR +
              colorSpan('节点握手或远端接口超时，请检查节点连通性后重试。', COLORS.warning, false)
          ),
        });
        return;
      }

      if (CFG.mode === 'event') {
        safeDone({});
        return;
      }

      safeDone({
        title: '网络出口信息',
        content: '查询超时，请检查当前网络或代理连通性后重试',
        icon: 'exclamationmark.triangle',
        'icon-color': '#F59E0B',
      });
    }, budgetMs);
  }

  async function main() {
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
      // Loon 无 [Panel] 段：用户在仪表盘手动点运行 generic 脚本时，直接实测当前默认活跃出口并弹出富文本卡片！
      if (HOST_CLIENT === 'loon') {
        await handleNodeLongPress('', params.nodeInfo || null);
        return;
      }
      await handleModulePanel();
    } catch (err) {
      recoverDanglingPolicyIfAny();
      safeDone({
        title: '节点检测异常',
        content: String((err && err.message) || err),
        htmlMessage: wrapSheetBodyHTML(
          colorSpan('执行异常：' + String((err && err.message) || err), COLORS.danger, true)
        ),
      });
    }
  }

  // CommonJS 测试导出钩子（仅在无宿主 $done 的 Node.js 单元测试加载时跳过自动执行并导出核心纯函数）
  const isNodeTestImport =
    typeof module !== 'undefined' &&
    module &&
    typeof module.exports === 'object' &&
    typeof $done === 'undefined';

  if (isNodeTestImport) {
    module.exports = {
      VERSION,
      BUILD_VARIANT,
      DEFAULT_HOST_HINT,
      COLORS,
      CF_COLO_MAP,
      CF_COLO_CC_MAP,
      COUNTRY_CODE_ZH_MAP,
      CN_PLACE_ZH_MAP,
      CN_BGP_CLOUD_ASN_MAP,
      CLOUD_CORP_ASN_GROUPS,
      GA_DEDICATED_DOMAIN_RE,
      parseArguments,
      toBool,
      toNum,
      resolveRunMode,
      detectHostClient,
      computeHttpClientTimeout,
      buildOutboundOpts,
      normalizeCNPlace,
      formatCompactLocation,
      normalizeCNISP,
      normalizeEntranceISP,
      simplifyISPName,
      formatProtocolName,
      formatShortIPv6,
      parseIPAPIIs,
      parseIPInfoWidget,
      parseIPPure,
      parseBGPState,
      formatBGPCompactSummary,
      isIPv4Literal,
      isIPv6Literal,
      isPrivateLANIP,
      isBogusEntranceIP,
      formatECSSubnet,
      parseHostPort,
      extractDNSAnswerRecords,
      parseLoonProxyChain,
      readNativeMMDB,
      resolveEntranceDomain,
      queryEntranceGeo,
      classifyLinkType,
      detectNameClaimMismatch,
      resolveBGPRoleLabel,
      buildTopologyHops,
      renderInfoSheetHTML,
      renderPuritySheetHTML,
      renderUnlockSheetHTML,
      renderWebPortalHTML,
      main,
    };
  } else {
    main();
  }
})();
