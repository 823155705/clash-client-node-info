/**
 * xream & Kelee Node Suite — 多客户端全能节点检测引擎 (v3.0.0 · Core Source)
 *
 * 深度融合：
 * 1. xream/scripts (net-lsp-x / ip-info / ip-score / Sub-Store HostAdapter & 双源互补归属)
 * 2. 可莉插件生态 (Node_detection_tool 流媒体&AI解锁 / WARP_Node_Query / Loon 原生无控制器入口直取)
 * 3. 10 类 100% 客观证据驱动链路拓扑分类器 + 独立名称宣称验伪审计 + 双轴 BGP 评级解耦
 *
 * 原生支持宿主：Loon (一等公民) · Clash-Client (ProjectClash) · Surge · Stash · Shadowrocket · Egern
 * - 🌐 节点链路与入口查询 (MODE=info)  : 本地直连 ➔ 智能EDNS/CNAME入口(含ASN) ➔ 落地双栈 ➔ 双轴BGP骨干 ➔ CF边缘 & WARP
 * - 🛡️ 节点纯净度深度检测 (MODE=purity): 双 ISP 原生家宽血统 + 广播/原生判定 + BGP上游 + 四源风控/RBL交叉审计
 * - 🎬 流媒体与 AI 解锁检测 (MODE=unlock): ChatGPT(Web+iOS) / Claude / Gemini / Netflix / YouTube / Disney+ / TikTok / 动画疯
 */

(function () {
  'use strict';

  const VERSION = '3.0.0';
  const BUILD_VARIANT = 'core-source';
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

  function wrapSheetBodyHTML(innerHTML) {
    return (
      '<div style="font-family:-apple-system,BlinkMacSystemFont,\'PingFang SC\',sans-serif;font-size:13.5px;line-height:1.55">' +
      innerHTML +
      '</div>'
    );
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

  function cleanCNPlaceName(str) {
    return String(str || '')
      .replace(/省|市|壮族自治区|维吾尔自治区|回族自治区|自治区|特别行政区/g, '')
      .trim();
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
    const directPolicy = resolveDirectOutboundPolicy(inTunnel);

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
  // 5. 四源 IP 纯净度与黑名单引擎 (MODE=purity: ipapi.is + my.ippure.com + proxycheck + ip-score)
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
    if (t === 'business') return '商业/政企宽带';
    if (t === 'education') return '教育科研(Edu)';
    if (t === 'government') return '政务机构(Gov)';
    if (t === 'banking') return '金融机构网络';
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
      lineageLabel = '🏢 商业/政企宽带';
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
   * 独立免鉴权纯净度交叉核验与降级兜底源：my.ippure.com/v1/info
   */
  async function queryIPPure(targetNode) {
    try {
      const j = await fetchJSON(
        buildOutboundOpts('https://my.ippure.com/v1/info', targetNode),
        Math.min(CFG.timeoutMs, 5500)
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
      const j = await fetchJSON(buildOutboundOpts(url, targetNode), Math.min(CFG.timeoutMs, 5500));
      if (j && (j.status === 'ok' || j.status === 'warning') && j[ip]) {
        const rec = j[ip];
        const rawType = String(rec.type || '');
        const typeZhMap = {
          Residential: '住宅宽带',
          Wireless: '移动蜂窝',
          Business: '商业/政企宽带',
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

    4635: { name: '香港 HKIX', tier: 'ixp' },
    4777: { name: '日本 JPIX', tier: 'ixp' },
    58952: { name: 'SGIX 新加坡交换', tier: 'ixp' },
    59105: { name: 'BBIX 亚太交换', tier: 'ixp' },
    24115: { name: 'Equinix IX', tier: 'ixp' },

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
    14618: { name: 'AWS', tier: 'cloud' },
    15169: { name: 'Google', tier: 'cloud' },
    8075: { name: 'Microsoft Azure', tier: 'cloud' },
    45102: { name: '阿里云国际', tier: 'cloud' },
    37963: { name: '阿里云', tier: 'cloud' },
    132203: { name: '腾讯云国际', tier: 'cloud' },
    45090: { name: '腾讯云', tier: 'cloud' },
    55990: { name: '华为云', tier: 'cloud' },
    136907: { name: '华为云国际', tier: 'cloud' },
    135377: { name: 'UCloud', tier: 'cloud' },
    138371: { name: '火山引擎', tier: 'cloud' },
    20473: { name: 'Vultr (Choopa)', tier: 'cloud' },
    60068: { name: 'CDN77 (DataCamp)', tier: 'cloud' },
    16276: { name: 'OVHcloud', tier: 'cloud' },
    24940: { name: 'Hetzner', tier: 'cloud' },
    14061: { name: 'DigitalOcean', tier: 'cloud' },
    63949: { name: 'Akamai (Linode)', tier: 'cloud' },
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
      const hdrLoc = String((res.headers && (res.headers.Location || res.headers.location)) || '');
      if (
        res.status === 451 ||
        res.status === 403 ||
        /isn't currently supported|not available in your country|faq#supported_countries/i.test(body + ' ' + hdrLoc)
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
      const hdrLoc = String((res.headers && (res.headers.Location || res.headers.location)) || '');
      if (/www\.google\.cn/i.test(b + ' ' + hdrLoc)) {
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
      const hdrLoc = String((res.headers && (res.headers.Location || res.headers.location)) || '');
      if (
        res.status === 403 ||
        res.status === 451 ||
        /Sorry, Disney\+ is not available|disneyplus\.com\/.*unavailable|not available in your region/i.test(
          b + ' ' + hdrLoc
        )
      ) {
        return { name: 'Disney+', state: 'no', text: '未解锁 / 地区不可用' };
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
  // 7. 按模式精准分流执行探测
  // ============================================================================

  async function executeModeProbe(targetNode, mode) {
    const startedAt = Date.now();
    const runMode = normalizeMode(mode);

    // 模式 A: 节点链路与入口查询
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

    // 模式 B: 节点纯净度深度检测（四源交叉核验：ipapi.is + my.ippure.com + proxycheck.io + ip-score RBL + RIPE BGP）
    if (runMode === 'purity') {
      const landing = await queryLandingIPv4(targetNode);
      const [purity, ipPure, proxyCheck, ipScore, bgp] = await runWithConcurrency(
        [
          () => queryPurityIPAPI(landing.ip, targetNode, 0, 0),
          () => queryIPPure(targetNode),
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
        ipPure,
        proxyCheck,
        ipScore,
        bgp,
      };
    }

    // 模式 C: 流媒体与 AI 解锁检测
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
    const country = isCN ? '中国' : toStr((intlRes && intlRes.country) || finalCC, '');
    const region = isCN
      ? toStr((cnRes && cnRes.region) || cleanCNPlaceName(intlRes && intlRes.region), '')
      : toStr(intlRes && intlRes.region, '');
    const city = isCN
      ? toStr((cnRes && cnRes.city) || cleanCNPlaceName(intlRes && intlRes.city), '')
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
    const place = eg
      ? deduplicateGeoParts([cleanCNPlaceName(eg.region), cleanCNPlaceName(eg.city)]).join('')
      : '';
    const rawDisp = eg && (eg.ispDisplay || eg.isp || eg.org) ? String(eg.ispDisplay || eg.isp || eg.org) : '';
    const provider = (rawDisp ? rawDisp.replace(/^中国/, '').trim() : '') || fallbackProvider || '';
    return [place, provider].filter(Boolean).join('');
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
        badge: '客户端链式代理' + warpSuffix,
        detail: '客户端节点库双跳串联 ➔ 远端落地',
        color: COLORS.purple,
      };
    }
    if (dialerProxy && dialerProxy.toUpperCase() !== 'DIRECT') {
      return {
        code: 'chain-dialer',
        badge: '客户端链式代理' + warpSuffix,
        detail: '经客户端前置「' + dialerProxy + '」串联 ➔ 远端落地',
        color: COLORS.purple,
      };
    }
    if (hasLoonChain) {
      const chainDesc = toStr(entrance && entrance.proxyChainDesc, '');
      return {
        code: 'chain-loon',
        badge: '客户端链式代理' + warpSuffix,
        detail: (chainDesc ? '经前置代理链「' + chainDesc + '」串联' : '客户端前置代理链串联') + ' ➔ 远端落地',
        color: COLORS.purple,
      };
    }
    if (isRelayGroup) {
      return {
        code: 'chain-relay',
        badge: '客户端链式代理' + warpSuffix,
        detail: '客户端 Relay 多跳串联 ➔ 远端落地',
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
          badge: '局域网 / 组网网关中转' + warpSuffix,
          detail: '内网或异地组网网关接入 ➔ 远端落地',
          color: COLORS.purple,
        };
      }

      // 第 3 类：出入口同 IP 单跳直连（含单跳直连 + WARP 出站）
      if (isDirectIP) {
        if (warpMode) {
          return {
            code: 'direct-warp',
            badge: '单跳直连 + ' + warpMode + ' 出站',
            detail: '入口即落地服务器，未经过任何中转节点（出站经 CF 托管）',
            color: COLORS.cyan,
          };
        }
        return {
          code: 'direct',
          badge: landingCC && landingCC !== 'CN' ? '单跳直连出境' : '单跳直连线路',
          detail: '入口即落地服务器，未经过任何中转节点',
          color: COLORS.cyan,
        };
      }

      // 第 4 类：入口为 AS13335 Cloudflare Anycast 边缘节点
      if (isEntCF) {
        if (warpMode || isLandingCF) {
          return {
            code: 'cf-warp-tunnel',
            badge: 'Cloudflare ' + (warpMode || 'WARP') + ' 隧道',
            detail: 'CF Anycast 边缘接入 ➔ 托管出站',
            color: COLORS.cyan,
          };
        }
        return {
          code: 'cf-cdn-origin',
          badge: 'Cloudflare CDN 边缘反代',
          detail: 'CF Anycast 边缘接入 ➔ 源站落地',
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
            badge: '云全球加速专网中转 (GA/AGA)' + warpSuffix,
            detail: (actor ? actor + '全球加速入口' : '云厂商全球加速入口') + ' ➔ 专网跨境落地',
            color: COLORS.purple,
          };
        }

        const sameCloud = findSameCloudCorp(entASNNum, landingASNNum);
        if (sameCloud) {
          const actor = formatCNEntranceActor(eg, sameCloud.name);
          return {
            code: 'cn-same-cloud',
            badge: '同云架构跨境中转' + warpSuffix,
            detail: (actor ? actor + '入口' : sameCloud.name + '境内入口') + ' ➔ 同集团海外落地',
            color: COLORS.purple,
          };
        }

        const bgpCloudName = CN_BGP_CLOUD_ASN_MAP[entASNNum] || '';
        if (bgpCloudName) {
          const actor = formatCNEntranceActor(eg, bgpCloudName);
          return {
            code: 'cn-bgp-cloud',
            badge: '国内多线 BGP 云入口中转' + warpSuffix,
            detail: (actor ? actor + '多线入口' : bgpCloudName + '多线入口') + ' ➔ 海外落地',
            color: COLORS.purple,
          };
        }

        const ispActor = formatCNEntranceActor(eg, '');
        return {
          code: 'cn-isp-transit',
          badge: '国内运营商入口中转' + warpSuffix,
          detail: (ispActor ? ispActor + '入口' : '国内运营商入口') + ' ➔ 海外落地',
          color: COLORS.purple,
        };
      }

      // 第 6 类：境内内陆中转链路（国内入口 ➔ 国内异地出口）
      if (entCC === 'CN' && landingCC === 'CN') {
        return {
          code: 'cn-internal-transit',
          badge: '境内内陆中转链路',
          detail: '国内前置入口 ➔ 国内异地出口',
          color: COLORS.purple,
        };
      }

      // 第 7 类：海外入口分离拓扑（修复原分支顺序 Bug：交叉校验 cfTrace.colo 所在国区分跨国跳板套 WARP）
      if (entCC && entCC !== 'CN') {
        if (warpMode || isLandingCF) {
          const coloUpper = toStr(cf && cf.colo, '').toUpperCase();
          const coloCC = toStr((cf && cf.coloCountry) || CF_COLO_CC_MAP[coloUpper], '').toUpperCase();
          const isCrossCountryBeforeWarp =
            Boolean(landingCC) && entCC !== landingCC && (!coloCC || coloCC !== entCC);

          if (isCrossCountryBeforeWarp) {
            return {
              code: 'intl-transit-warp',
              badge: '海外跨国跳板 + ' + (warpMode || 'WARP') + ' 出站',
              detail: entCC + ' 前置跳板 ➔ ' + landingCC + ' 托管出站',
              color: COLORS.purple,
            };
          }
          return {
            code: 'overseas-direct-warp',
            badge: '海外入口 + ' + (warpMode || 'WARP') + ' 出站',
            detail: entCC + ' 入口接入 ➔ Cloudflare 托管出站',
            color: COLORS.cyan,
          };
        }

        if (landingCC && entCC !== landingCC) {
          return {
            code: 'intl-transit',
            badge: '海外跨国跳板中转',
            detail: entCC + ' 前置跳板 ➔ ' + landingCC + ' 远端落地',
            color: COLORS.purple,
          };
        }

        if (entASN && landingASN && entASN === landingASN) {
          return {
            code: 'same-asn-multi-ip',
            badge: '海外同网段多 IP 出站',
            detail: '出入口同属 ' + landingASN + ' (' + entCC + ')',
            color: COLORS.cyan,
          };
        }

        return {
          code: 'same-region-chain',
          badge: '海外同区异网落地链',
          detail: entCC + ' 前置入口 ➔ 同区独立网络落地',
          color: COLORS.purple,
        };
      }

      // 第 8 类：入口与落地不同 IP 但入口 Geo 超时兜底
      return {
        code: 'separated-transit',
        badge: '分离式中转链路' + warpSuffix,
        detail: '拨号入口与最终落地 IP 分离',
        color: COLORS.purple,
      };
    }

    // 第 9 类：未捕获入口诚实兜底（严格区分宿主：仅在 Clash-Client/Stash 提示控制器，Loon/其他端诚实显示仅测得落地出站）
    if (!CFG.showEntrance) {
      return {
        code: 'outbound-only',
        badge: '仅测得落地出站',
        detail: '已在设置中关闭入口检测',
        color: COLORS.primary,
      };
    }

    if (hostClient === 'clash' || hostClient === 'stash') {
      if (warpMode) {
        return {
          code: 'warp-outbound',
          badge: 'Cloudflare ' + warpMode + ' 托管出站',
          detail: '开启外部控制器并填密钥可判别前端入口',
          color: COLORS.purple,
        };
      }
      if (isLandingCF) {
        return {
          code: 'cf-outbound',
          badge: 'Cloudflare Anycast 出站',
          detail: '开启外部控制器并填密钥可判别前端入口',
          color: COLORS.cyan,
        };
      }
      if (entrance && entrance.status === 'unauthorized') {
        return {
          code: 'pending-secret',
          badge: '仅测得落地出站 (待填密钥)',
          detail: '填入外部控制器密钥即可捕获入口',
          color: COLORS.warning,
        };
      }
      if (entrance && entrance.status === 'unreachable') {
        return {
          code: 'pending-controller',
          badge: '仅测得落地出站 (未开控制器)',
          detail: '开启「外部控制器 → 本机」填密钥可判别入口',
          color: COLORS.muted,
        };
      }
      return {
        code: 'pending-sample',
        badge: '仅测得落地出站',
        detail: '本次连接采样过快结束，重测即可捕获入口',
        color: COLORS.muted,
      };
    }

    return {
      code: warpMode ? 'warp-outbound' : isLandingCF ? 'cf-outbound' : 'outbound-only',
      badge: warpMode ? '仅测得落地出站 (' + warpMode + ')' : '仅测得落地出站',
      detail: '长按具体节点运行可自动解析入口链路',
      color: warpMode ? COLORS.purple : COLORS.primary,
    };
  }

  /**
   * 独立「名称宣称验伪提示」审计器 —— 只验伪、绝不正向加分！
   * 仅当客观探测铁证 100% 证伪节点名宣称时返回一行警示文案，否则返回 null。
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

    // 规则 1：名称标称中转/专线，实测出入口同 IP（纯单跳直连）
    if (!hasClientChain && /iepl|iplc|专线|内网专线|中转/i.test(name) && isSameIP) {
      return '名称标称中转/专线，实测出入口同 IP（纯单跳直连）';
    }

    // 规则 2：名称标称专线/跨境口岸，实测入口为 AS13335 Cloudflare 公共 Anycast
    if (/iepl|iplc|专线|内网专线|深港|广港|沪日|沪美|京德|京日|苏日/i.test(name) && isEntCF) {
      return '名称标称专线，实测为 Cloudflare Anycast 公共边缘接入';
    }

    // 规则 3：名称标称境内跨境专线，实测首跳直连境外（无境内入口）
    if (
      !hasClientChain &&
      /iepl|iplc|内网专线|深港|广港|沪日|沪美|京德|京日|苏日/i.test(name) &&
      Boolean(entCC) &&
      entCC !== 'CN'
    ) {
      return '名称标称境内跨境专线，实测首跳直连境外 (' + entCC + ')，无境内入口';
    }

    return null;
  }

  /**
   * 双轴 BGP 标签解耦：
   * - 单跳直连出境 -> 「跨境骨干」（公网 BGP 直接决定跨境去回程质量）
   * - 国内中转 / 海外跳板 / 分离链路 -> 「落地互联」（明确代表落地机国际/回程互联，而非中转去程物理介质）
   */
  function resolveBGPRoleLabel(linkCode) {
    return linkCode === 'direct' || linkCode === 'direct-warp' ? '跨境骨干' : '落地互联';
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

    if (entrance && entrance.hasProxyChain && entrance.proxyChainDesc) {
      const lcTag = '🔗 ' + entrance.proxyChainDesc;
      htmlHops.push(colorSpan(lcTag, COLORS.purple, true));
      plainHops.push(lcTag);
    }

    if (entrance && entrance.status === 'ok' && (entrance.entranceIP || entrance.entranceHost)) {
      const entIP = entrance.entranceIP || '';
      const isDirect =
        Boolean(entIP) &&
        (entIP === l.ip || Boolean(probe && probe.ipv6 && probe.ipv6.ip && entIP === probe.ipv6.ip));
      if (isDirect) {
        const dTxt = String(l.countryCode || '').toUpperCase() === 'CN' ? '单跳直连' : '直连出境';
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
        if ((eg && eg.isPrivate) || (entIP && isPrivateLANIP(entIP))) {
          eTag = '🏠 组网网关';
        } else if (isEntCF) {
          eTag = '☁️ CF 边缘入口';
          eColor = COLORS.primary;
        } else if (eg) {
          const place = cleanCNPlaceName(eg.city || eg.region || eg.country || '入口');
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
  // 9. 三大独立弹窗渲染器（深浅色模式自适应排版、零硬编码底色/主文字色）
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
      if (nodeInfo.tls === 1 || nodeInfo.tls === true) {
        meta.push(colorSpan('TLS ✓', COLORS.success, true));
      }
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
    const displayTitle = nodeName || '当前默认出口';
    const lines = [
      colorSpan('● ', COLORS.primary, true) +
        '<b>' +
        esc(displayTitle) +
        '</b>' +
        (meta.length > 0 ? '  ' + meta.join(' · ') : ''),
    ];
    if (leafNode && leafNode !== displayTitle) {
      lines.push('实际承载：' + colorSpan(leafNode, COLORS.cyan, true));
    }
    return lines;
  }

  function renderFooterNote(probe) {
    let ch = '⚡ 原生直走隧道 · ' + probe.elapsedMs + ' ms';
    if (probe.routeChannel === 'bridge') {
      ch = '⚡ 零切换直测 · ' + probe.elapsedMs + ' ms';
    } else if (probe.routeChannel === 'active-default') {
      ch = '⚡ 当前默认出口直测 · ' + probe.elapsedMs + ' ms';
    } else if (probe.routeChannel === 'active-global' || probe.routeChannel === 'active-rule') {
      ch = '⚡ 当前节点直测 · ' + probe.elapsedMs + ' ms';
    } else if (probe.routeChannel === 'config-fallback') {
      ch = '🔄 临时切换直测 (已还原) · ' + probe.elapsedMs + ' ms';
    }
    return '<span style="color:' + COLORS.muted + '">' + esc(ch) + '</span>';
  }

  /**
   * 视图 1：🌐 节点链路与入口查询
   */
  function renderInfoSheetHTML({ nodeName, nodeInfo, domestic, entrance, probe, hostClient }) {
    const activeHost = hostClient || HOST_CLIENT;
    const l = probe.landing;
    const cf = probe.cfTrace;
    const flag = getFlagEmoji(l.countryCode);
    const lGeo = deduplicateGeoParts([l.country, l.region, l.city]).join(' ');
    const lines = renderCompactHeader(nodeName, nodeInfo, entrance && entrance.leafNode);

    const linkInfo = classifyLinkType({ nodeInfo, entrance, probe, hostClient: activeHost });
    const claimWarning = detectNameClaimMismatch(nodeName, { entrance, probe, linkInfo });
    const topo = buildTopologyHops({ domestic, entrance, probe });

    lines.push('');
    lines.push('<b>▸ 代理链路与走向</b>');
    lines.push(
      '链路类型：' +
        colorSpan(linkInfo.badge, linkInfo.color, true) +
        (linkInfo.detail ? ' <span style="color:' + COLORS.muted + '">(' + esc(linkInfo.detail) + ')</span>' : '')
    );
    if (claimWarning) {
      lines.push('名称核验：' + colorSpan('⚠️ ' + claimWarning, COLORS.warning, true));
    }
    lines.push('链路走向：' + topo.html);

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
          if (
            linkInfo.code === 'cn-cloud-ga' &&
            Array.isArray(entrance.cnameChain) &&
            entrance.cnameChain.length > 0
          ) {
            const gaCname = entrance.cnameChain[entrance.cnameChain.length - 1];
            lines.push('专网调度：<code>' + esc(maskDomainString(gaCname, CFG.maskIP)) + '</code>');
          }
        }
      } else if (activeHost === 'clash' || activeHost === 'stash') {
        if (entrance.status === 'unauthorized') {
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

    // 双轴 BGP 评级解耦：单跳直连显示「跨境骨干」，中转/跳板显示「落地互联」
    const bgp = probe.bgp;
    if (bgp) {
      const bgpRole = resolveBGPRoleLabel(linkInfo.code);
      lines.push('');
      lines.push('<b>▸ BGP 路由与上游骨干</b>');
      const diffOrigin =
        bgp.originASN && l.asn && bgp.originASN.toUpperCase() !== String(l.asn).toUpperCase()
          ? ' · 宣告 <code>' + esc(bgp.originASN) + '</code>'
          : '';
      lines.push(
        bgpRole +
          '：' +
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
    return wrapSheetBodyHTML(lines.join('<br>'));
  }

  /**
   * 视图 2：🛡️ 节点纯净度深度检测（融合 ipapi.is + my.ippure.com + proxycheck.io + ip-score RBL）
   */
  function renderPuritySheetHTML({ nodeName, nodeInfo, probe }) {
    const l = probe.landing;
    const p = probe.purity;
    const ipp = probe.ipPure;
    const pc = probe.proxyCheck;
    const sc = probe.ipScore;
    const flag = getFlagEmoji(l.countryCode || (p && p.countryCode) || (ipp && ipp.countryCode));
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

    if (p || ipp) {
      let combinedRisk = p ? p.riskIndex : ipp && ipp.fraudScore !== null ? ipp.fraudScore : 25;
      if (p && ipp && ipp.fraudScore !== null && pc && pc.risk !== null) {
        combinedRisk = Math.round(p.riskIndex * 0.5 + ipp.fraudScore * 0.25 + pc.risk * 0.25);
      } else if (p && ipp && ipp.fraudScore !== null) {
        combinedRisk = Math.round(p.riskIndex * 0.65 + ipp.fraudScore * 0.35);
      } else if (p && pc && pc.risk !== null) {
        combinedRisk = Math.round(p.riskIndex * 0.65 + pc.risk * 0.35);
      } else if (!p && ipp && ipp.fraudScore !== null && pc && pc.risk !== null) {
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
          ? '极度纯净'
          : combinedRisk <= 35
            ? '纯净良好'
            : combinedRisk <= 60
              ? '轻度风险'
              : '高危预警';

      lines.push('');
      lines.push('<b>▸ IP 血统与原生属性</b>');
      if (p) {
        lines.push('线路血统：' + colorSpan(p.lineageLabel, levelColor(p.lineageLevel), true));
        lines.push(
          '双维类型：ASN <code>' +
            esc(p.asnTypeText) +
            '</code> ｜ 运营 <code>' +
            esc(p.companyTypeText) +
            '</code>'
        );
      } else if (ipp) {
        const ippLineage =
          ipp.isResidential === true ? '🏠 住宅宽带网络 (IPPure)' : '🖥️ 机房/商业网络 (IPPure)';
        lines.push(
          '线路血统：' + colorSpan(ippLineage, ipp.isResidential ? COLORS.success : COLORS.warning, true)
        );
      }

      const broadcastText =
        (p && p.broadcastText) ||
        (ipp && ipp.isBroadcast !== null
          ? ipp.isBroadcast
            ? '广播 IP (IPPure 核验)'
            : '原生 IP (IPPure 核验)'
          : '');
      const isNativeGeo =
        p && p.isNativeGeo !== null
          ? p.isNativeGeo
          : ipp && ipp.isBroadcast !== null
            ? !ipp.isBroadcast
            : null;
      if (broadcastText) {
        lines.push(
          '归属判定：' +
            colorSpan(broadcastText, isNativeGeo ? COLORS.success : COLORS.warning, Boolean(isNativeGeo))
        );
      }

      if (p && (p.companyNetwork || p.asnRoute)) {
        lines.push(
          'WHOIS 段：<code>' +
            esc(p.companyNetwork || p.asnRoute) +
            '</code>' +
            (p.rir ? ' · <code>' + esc(p.rir) + '</code>' : '')
        );
      }
      if (probe.bgp) {
        lines.push(
          '出口 BGP：' +
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
      if (ipp && ipp.fraudScore !== null) {
        const ippTags = ['欺诈值 ' + ipp.fraudScore + '/100'];
        if (ipp.isResidential !== null) ippTags.push(ipp.isResidential ? '住宅属性' : '非住宅');
        if (ipp.isBroadcast !== null) ippTags.push(ipp.isBroadcast ? '广播宣告' : '原生宣告');
        lines.push('交叉核验：<code>IPPure</code> ' + esc(ippTags.join(' · ')));
      }
      if (sc) {
        const blOk = sc.listedCount === 0;
        const blTxt = blOk
          ? '0 / ' + sc.totalBlacklists + ' 库命中 (全部通过 ✓)'
          : sc.listedCount + ' / ' + sc.totalBlacklists + ' 命中 (' + sc.listedNames.join(', ') + ')';
        lines.push('RBL 黑名单：' + colorSpan(blTxt, blOk ? COLORS.success : COLORS.danger, true));
      }

      if (p) {
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
      }
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
    return wrapSheetBodyHTML(lines.join('<br>'));
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
   * 视图 3：🎬 流媒体与 AI 解锁检测
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
    return wrapSheetBodyHTML(lines.join('<br>'));
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
    const bgpRole = resolveBGPRoleLabel(linkInfo.code);
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>节点全能诊断 · v${VERSION}</title>
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
    ${claimWarning ? `<div class="row"><span class="k">名称核验</span><span class="v" style="color:${COLORS.warning}">⚠️ ${esc(claimWarning)}</span></div>` : ''}
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
    ${bgp ? `<div class="row"><span class="k">${esc(bgpRole)}</span><span class="v">${esc(bgp.gradeLabel)}</span></div>` : ''}
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
      const purity = await queryPurityIPAPI(infoProbe.landing.ip, targetNode);
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
          body: '网络诊断失败: ' + String((e && e.message) || e),
        },
      });
    }
  }

  // ============================================================================
  // 11. 多客户端交互入口：节点长按 / Loon 仪表盘直测 / 模块面板 / 网络切换事件
  // ============================================================================

  function getSheetTitleByMode(mode) {
    const titleMap = {
      info: '节点链路与入口查询',
      purity: '节点纯净度深度检测',
      unlock: '流媒体与 AI 解锁检测',
    };
    return titleMap[mode] || '节点网络信息查询';
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
          '当前活跃出口';
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
            '<b>▍查询失败</b><br>' +
              '目标节点：' +
              colorSpan(nodeName || '当前活跃出口', COLORS.primary, true) +
              '<br>原因说明：' +
              colorSpan(String((err && err.message) || err), COLORS.danger, false) +
              '<br><br><span style="color:' +
              COLORS.muted +
              '">💡 请检查该节点是否有效连通，或在插件参数中适当调大超时时间。</span>'
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
            '<b>▍查询失败</b><br>' +
              '目标节点：' +
              colorSpan(nodeName, COLORS.primary, true) +
              '<br>原因说明：' +
              colorSpan(String(fallbackErr.message || fallbackErr), COLORS.danger, false) +
              '<br><br><span style="color:' +
              COLORS.muted +
              '">💡 建议开启「模块」页顶部的「HTTPS 解密」开关实现零切换直测。</span>'
          ),
        });
        return;
      }

      if (probe && probe.needsEngineWarning) {
        safeDone({
          title: sheetTitle,
          htmlMessage: wrapSheetBodyHTML(
            colorSpan(probe.error, COLORS.warning, true) +
              '<br><br>1. 推荐：开启「模块」页顶部 <b>HTTPS 解密</b> 开关（零切换直测）。<br>2. 或在模块「设置」开启 <b>自动临时切换测速</b>。'
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
      const cf = probe.cfTrace;
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
        lines.push(
          '直连：' +
            maskIPString(domestic.ip, CFG.maskIP) +
            ' (' +
            [domestic.location, domestic.isp].filter(Boolean).join(' ') +
            ')'
        );
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
          resolveBGPRoleLabel(linkInfo.code) +
            '：' +
            probe.bgp.gradeShort +
            (probe.bgp.shortNames ? ' · ' + probe.bgp.shortNames : '')
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
        const purity = await queryPurityIPAPI(
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

        const uncapturedCodes = new Set([
          'pending-controller',
          'pending-secret',
          'pending-sample',
          'outbound-only',
        ]);
        const showLinkBadge = !uncapturedCodes.has(linkInfo.code);
        const subtitleText = showLinkBadge
          ? '🔀 ' + linkInfo.badge + (topo && topo.plain ? ' ｜ ' + topo.plain : '')
          : '🔀 ' + ((topo && topo.plain) || linkInfo.badge);

        const exitLines = [];
        exitLines.push(flag + ' 落地：' + maskIPString(landIP, CFG.maskIP) + ' (' + geo + ')');
        const asnText = [landing.asn, landing.isp || landing.org].filter(Boolean).join(' ');
        if (asnText) exitLines.push('🏢 归属：' + asnText);
        if (bgp) {
          exitLines.push(
            '🛣️ ' +
              resolveBGPRoleLabel(linkInfo.code) +
              '：' +
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
                  error: '节点探测超时（目标节点可能不可用或握手过慢）',
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
            '<b>▍查询超时已保护退出</b><br>' +
              '目标节点：' +
              colorSpan(ctx.nodeName || '当前活跃出口', COLORS.primary, true) +
              '<br>原因说明：' +
              colorSpan('节点握手或远端接口响应超过安全时限，已自动中止探测', COLORS.warning, false) +
              '<br><br><span style="color:' +
              COLORS.muted +
              '">💡 请检查该节点是否能正常连通，或稍后重试。</span>'
          ),
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
      normalizeCNISP,
      normalizeEntranceISP,
      parseIPAPIIs,
      parseIPPure,
      parseBGPState,
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
