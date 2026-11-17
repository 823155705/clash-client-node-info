#!/usr/bin/env node
/**
 * Zero-dependency White-Box + Black-Box (vm Sandbox) Automated Unit Test Suite
 * for xream & Kelee Multi-Client Node Engine v3.0.0
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const vm = require('vm');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const CORE_FILE = path.join(ROOT, 'src', 'xream-node-core.js');
const UNIVERSAL_FILE = path.join(ROOT, 'xream-node-info.js');
const CLASH_FG_FILE = path.join(ROOT, 'xream-clash-node-info.js');
const CLASH_BG_FILE = path.join(ROOT, 'xream-clash-node-bg.js');
const BUILD_SCRIPT = path.join(ROOT, 'scripts', 'build.js');

const core = require(CORE_FILE);

let passed = 0;
let failed = 0;

async function runTest(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (err) {
    failed++;
    console.error(`  ❌ ${name}`);
    console.error('     ' + (err && err.stack ? err.stack.split('\n').slice(0, 4).join('\n     ') : err));
  }
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath, 'utf8'), 'utf8').digest('hex');
}

/**
 * Helper to execute any built artifact in an isolated VM sandbox simulating Loon / Clash / Surge / Stash
 */
function runScriptInSandbox(scriptPath, opts) {
  const code = fs.readFileSync(scriptPath, 'utf8');
  const store = Object.assign({}, opts.initialStore || {});
  const storeCalls = [];
  const httpCalls = [];
  const notifications = [];
  const configCalls = [];
  const dnsCalls = [];

  return new Promise((resolve, reject) => {
    let settled = false;
    const hardGuard = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(new Error('VM sandbox timed out waiting for $done'));
      }
    }, 8000);

    const sandbox = {
      console: { log: () => {}, warn: () => {}, error: () => {} },
      setTimeout: (fn, ms) => setTimeout(fn, Number(ms) > 1400 ? Number(ms) : 5),
      clearTimeout,
      Date,
      Math,
      JSON,
      Object,
      Array,
      String,
      Number,
      Boolean,
      RegExp,
      Set,
      Map,
      Promise,
      Error,
      TypeError,
      encodeURIComponent,
      decodeURIComponent,
      parseFloat,
      parseInt,
      isNaN,
      isFinite,
      $done: (payload) => {
        if (settled) return;
        settled = true;
        clearTimeout(hardGuard);
        resolve({
          donePayload: payload,
          store,
          storeCalls,
          httpCalls,
          notifications,
          configCalls,
          dnsCalls,
        });
      },
      $persistentStore: {
        read: (key) => {
          storeCalls.push({ op: 'read', key });
          return key ? (store[key] !== undefined ? store[key] : null) : null;
        },
        write: (val, key) => {
          storeCalls.push({ op: 'write', key, val });
          if (key) store[key] = String(val);
          return Boolean(key);
        },
      },
      $notification: {
        post: (title, subtitle, body) => {
          notifications.push({ title, subtitle, body });
        },
      },
      $httpClient: {
        get: (reqOpts, cb) => {
          const normalized = typeof reqOpts === 'string' ? { url: reqOpts } : reqOpts;
          httpCalls.push(Object.assign({ method: 'GET' }, normalized));
          Promise.resolve()
            .then(() => opts.onHttp('GET', normalized))
            .then((res) => {
              if (!res) {
                cb(new Error('Unmocked URL: ' + normalized.url));
                return;
              }
              if (res.error) {
                cb(res.error);
                return;
              }
              cb(
                null,
                { status: res.status || 200, headers: res.headers || {} },
                typeof res.body === 'object' ? JSON.stringify(res.body) : String(res.body == null ? '' : res.body)
              );
            })
            .catch((e) => cb(e));
        },
        post: (reqOpts, cb) => {
          const normalized = typeof reqOpts === 'string' ? { url: reqOpts } : reqOpts;
          httpCalls.push(Object.assign({ method: 'POST' }, normalized));
          Promise.resolve()
            .then(() => opts.onHttp('POST', normalized))
            .then((res) => {
              if (!res) {
                cb(new Error('Unmocked POST URL: ' + normalized.url));
                return;
              }
              if (res.error) {
                cb(res.error);
                return;
              }
              cb(
                null,
                { status: res.status || 200, headers: res.headers || {} },
                typeof res.body === 'object' ? JSON.stringify(res.body) : String(res.body == null ? '' : res.body)
              );
            })
            .catch((e) => cb(e));
        },
      },
    };

    if (opts.argument !== undefined) sandbox.$argument = opts.argument;
    if (opts.environment !== undefined) sandbox.$environment = opts.environment;
    if (opts.loon !== undefined) sandbox.$loon = opts.loon;
    if (opts.script !== undefined) sandbox.$script = opts.script;
    if (opts.request !== undefined) sandbox.$request = opts.request;
    if (opts.rocket !== undefined) sandbox.$rocket = opts.rocket;
    if (opts.Egern !== undefined) sandbox.Egern = opts.Egern;
    if (opts.utils !== undefined) sandbox.$utils = opts.utils;
    if (opts.httpAPI !== undefined) sandbox.$httpAPI = opts.httpAPI;
    if (opts.dnsHandler) {
      sandbox.$dns = {
        query: (qOpts, cb) => {
          dnsCalls.push(qOpts);
          Promise.resolve()
            .then(() => opts.dnsHandler(qOpts))
            .then((ans) => cb(null, ans))
            .catch((e) => cb(e));
        },
      };
    }
    if (opts.configState) {
      const st = Object.assign({ running_model: 1, global_proxy: 'Auto', final: 'Proxy' }, opts.configState);
      sandbox.$config = {
        getConfig: () => JSON.stringify(st),
        getSelectedPolicy: (g) => (g === 'GLOBAL' ? st.global_proxy : st.selected || 'AutoNode'),
        setSelectPolicy: (g, p) => {
          configCalls.push({ op: 'setSelectPolicy', group: g, policy: p });
          if (g === 'GLOBAL') st.global_proxy = p;
          return true;
        },
        setRunningModel: (m) => {
          configCalls.push({ op: 'setRunningModel', model: m });
          st.running_model = m;
          return true;
        },
      };
    }

    vm.runInNewContext(code, sandbox, { filename: path.basename(scriptPath) });
  });
}

(async function runAll() {
  console.log('\n=== [1] Build System & SHA-256 Anti-Quarantine Audit ===');

  await runTest('build.js --check passes and all 3 generated artifacts have distinct headers & SHA-256', () => {
    const out = execFileSync(process.execPath, [BUILD_SCRIPT, '--check'], { encoding: 'utf8' });
    assert.ok(out.includes('All 3 artifacts are up-to-date'));

    const uHead = fs.readFileSync(UNIVERSAL_FILE, 'utf8').slice(0, 260);
    const fgHead = fs.readFileSync(CLASH_FG_FILE, 'utf8').slice(0, 260);
    const bgHead = fs.readFileSync(CLASH_BG_FILE, 'utf8').slice(0, 260);

    assert.ok(uHead.includes('v3.0.0 · Universal Multi-Client'));
    assert.ok(fgHead.includes('v3.0.0 · Clash-Client FG-Interactive'));
    assert.ok(bgHead.includes('v3.0.0 · Clash-Client BG-Tunnel-Event'));

    const hU = sha256(UNIVERSAL_FILE);
    const hFG = sha256(CLASH_FG_FILE);
    const hBG = sha256(CLASH_BG_FILE);
    assert.notStrictEqual(hFG, hBG, 'FG and BG SHA-256 must differ');
    assert.notStrictEqual(hU, hFG, 'Universal and FG SHA-256 must differ');
    assert.notStrictEqual(hU, hBG, 'Universal and BG SHA-256 must differ');
  });

  await runTest('Static source audit: classifyLinkType has ZERO name-keyword regexes and normalizeEntranceISP has ZERO hardcoded BGP/专网', () => {
    const fnSrc = core.classifyLinkType.toString();
    assert.ok(!/nodeName|leafNode/i.test(fnSrc), 'classifyLinkType must not reference nodeName or leafNode');
    assert.ok(!/深港|广港|沪日|沪美|京德|京日|苏日/i.test(fnSrc), 'classifyLinkType must not match city-pair keywords');

    assert.strictEqual(core.normalizeEntranceISP('Alibaba Cloud LLC', '', 'CN'), '阿里云');
    assert.strictEqual(core.normalizeEntranceISP('Tencent Cloud Computing', '', 'CN'), '腾讯云');
    assert.strictEqual(core.normalizeEntranceISP('Huawei Cloud Service', '', 'CN'), '华为云');
    assert.strictEqual(core.normalizeEntranceISP('UCloud Information Technology', '', 'CN'), 'UCloud');
    assert.strictEqual(core.normalizeEntranceISP('', 'Zenlayer Inc', 'HK'), 'Zenlayer');
    assert.strictEqual(core.normalizeEntranceISP('', 'DMIT Cloud Services', 'HK'), 'DMIT');
    assert.strictEqual(core.normalizeEntranceISP('China Mobile Jiangsu', '', 'CN'), '中国移动');
    assert.ok(!core.normalizeEntranceISP('Alibaba Cloud', '', 'CN').includes('BGP'));
    assert.ok(!core.normalizeEntranceISP('Zenlayer', '', 'HK').includes('专网'));
  });

  console.log('\n=== [2] HostAdapter: Multi-Client Detection, $argument & Timeout/Outbound ===');

  await runTest('parseArguments handles Loon native Object (boolean/number/string/null), QueryString & JSON', () => {
    const loonArg = core.parseArguments({
      SHOW_DOMESTIC: false,
      MASK_IP: true,
      TIMEOUT_SEC: 12,
      CONTROLLER_SECRET: null,
      IPAPI_KEY: null,
    });
    assert.strictEqual(core.toBool(loonArg.SHOW_DOMESTIC, true), false);
    assert.strictEqual(core.toBool(loonArg.MASK_IP, false), true);
    assert.strictEqual(core.toNum(loonArg.TIMEOUT_SEC, 8, 3, 25), 12);
    // Crucial regression guard: null / empty input must fallback to defaultVal (8), NOT clamp Number(null)=0 to minVal (3)
    assert.strictEqual(core.toNum(loonArg.CONTROLLER_SECRET, 8, 3, 25), 8);
    assert.strictEqual(core.toNum('', 8, 3, 25), 8);

    const qsArg = core.parseArguments('CLIENT=clash&MODE=purity&MASK_IP=1&IPAPI_KEY={IPAPI_KEY}');
    assert.strictEqual(qsArg.CLIENT, 'clash');
    assert.strictEqual(qsArg.MODE, 'purity');
    assert.strictEqual(core.toBool(qsArg.MASK_IP, false), true);
    assert.strictEqual(qsArg.IPAPI_KEY, '');

    const jsonArg = core.parseArguments('{"CLIENT":"surge","MODE":"unlock","TIMEOUT_SEC":15}');
    assert.strictEqual(jsonArg.CLIENT, 'surge');
    assert.strictEqual(jsonArg.MODE, 'unlock');
    assert.strictEqual(core.toNum(jsonArg.TIMEOUT_SEC, 8, 3, 25), 15);
  });

  await runTest('resolveRunMode follows exact priority: ARGS.MODE -> $request.url -> $script.name -> default info', () => {
    assert.strictEqual(
      core.resolveRunMode({ MODE: 'unlock' }, { script: { name: '节点纯净度深度检测' } }),
      'unlock'
    );
    assert.strictEqual(
      core.resolveRunMode({}, { request: { url: 'http://net-lsp-x.com/' }, script: { name: 'Web诊断面板' } }),
      'bridge'
    );
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '节点纯净度深度检测' } }), 'purity');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '流媒体与 AI 解锁检测' } }), 'unlock');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '网络切换出口通知' } }), 'event');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '节点链路与入口查询' } }), 'info');
    assert.strictEqual(core.resolveRunMode({}, {}), 'info');
  });

  await runTest('detectHostClient accurately distinguishes True Loon, Clash-Client (fake $loon), Surge, Stash, SR & Egern', () => {
    // Explicit CLIENT wins
    assert.strictEqual(core.detectHostClient({ CLIENT: 'loon' }, { config: { getConfig: () => '{}' } }), 'loon');
    assert.strictEqual(core.detectHostClient({ CLIENT: 'clash' }, { loon: 'iPhone 18.0 3.5.1(998)' }), 'clash');

    // Stash / Shadowrocket / Egern / Surge
    assert.strictEqual(core.detectHostClient({}, { environment: { 'stash-version': '2.6.4' } }), 'stash');
    assert.strictEqual(core.detectHostClient({}, { rocket: {} }), 'shadowrocket');
    assert.strictEqual(core.detectHostClient({}, { egern: {} }), 'egern');
    assert.strictEqual(core.detectHostClient({}, { environment: { 'surge-version': '5.8.0' } }), 'surge');

    // Clash-Client fake $loon traps
    assert.strictEqual(
      core.detectHostClient({}, {
        loon: 'iPhone 18.0 3.2.0(1000)',
        environment: { params: { node: 'HK 01', nodeInfo: { type: 'ss', alive: true, history: [{ delay: 45 }] } } },
        config: { getConfig: () => '{}' },
      }),
      'clash'
    );
    assert.strictEqual(
      core.detectHostClient({}, { loon: true, config: { getConfig: () => '{}' } }),
      'clash'
    );
    assert.strictEqual(
      core.detectHostClient({}, { loon: 'ProjectClash 1.2', config: { getConfig: () => '{}' } }),
      'clash'
    );

    // True Loon variants
    assert.strictEqual(
      core.detectHostClient({}, { loon: 'iPhone16,2 18.1 3.5.1(998)', config: { getConfig: () => '{}' } }),
      'loon'
    );
    assert.strictEqual(
      core.detectHostClient({}, {
        loon: 'Mac 3.5.1',
        utils: { geoip: () => 'HK' },
        config: { getConfig: () => '{}' },
      }),
      'loon'
    );
    assert.strictEqual(
      core.detectHostClient({}, {
        loon: 'iPhone',
        environment: { params: { node: 'HK', nodeInfo: { address: 'hk.entry.com', port: 443, type: 'Trojan' } } },
      }),
      'loon'
    );
    assert.strictEqual(
      core.detectHostClient({}, {
        loon: 'Loon',
        script: { name: '网络切换出口通知' },
        config: { getConfig: () => '{}' },
      }),
      'loon'
    );
  });

  await runTest('Outbound options & timeout units adapt cleanly per client (Loon ms vs Surge/Stash/SR/Egern s)', () => {
    assert.strictEqual(core.computeHttpClientTimeout(8000, 'loon'), 8000);
    assert.strictEqual(core.computeHttpClientTimeout(8000, 'surge'), 8);
    assert.strictEqual(core.computeHttpClientTimeout(8500, 'stash'), 9);
    assert.strictEqual(core.computeHttpClientTimeout(8000, 'shadowrocket'), 8);
    assert.strictEqual(core.computeHttpClientTimeout(8000, 'egern'), 8);

    const loonOpts = core.buildOutboundOpts('https://example.com', 'HK-Node', {}, 'loon');
    assert.strictEqual(loonOpts.node, 'HK-Node');
    assert.strictEqual(loonOpts.policy, undefined);
    assert.strictEqual(loonOpts['auto-redirect'], false);

    const surgeOpts = core.buildOutboundOpts('https://example.com', 'HK-Node', {}, 'surge');
    assert.strictEqual(surgeOpts.policy, 'HK-Node');
    assert.strictEqual(surgeOpts.node, undefined);

    const stashOpts = core.buildOutboundOpts('https://example.com', '🇭🇰 香港 01', {}, 'stash');
    assert.strictEqual(stashOpts.policy, '🇭🇰 香港 01');
    assert.strictEqual(stashOpts.headers['X-Stash-Selected-Proxy'], encodeURIComponent('🇭🇰 香港 01'));

    const srOpts = core.buildOutboundOpts('https://example.com', 'JP-Node', {}, 'shadowrocket');
    assert.strictEqual(srOpts.headers['X-Surge-Policy'], 'JP-Node');
  });

  console.log('\n=== [3] 10-Category Objective Link Classifier & Anti-Fraud Name Audit ===');

  await runTest('Covers all 10 objective link categories accurately including overseas WARP branch-order fix', () => {
    // 1. Client chain (Clash dialer-proxy & Loon proxyChainInfo & Relay)
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '1.1.1.2', dialerProxy: '前置香港' },
        probe: { landing: { ip: '8.8.4.4', countryCode: 'US', asn: 'AS15169' } },
      }).code,
      'chain-dialer'
    );
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '1.1.1.2', hasProxyChain: true, proxyChainDesc: 'HK-Entry' },
        probe: { landing: { ip: '8.8.4.4', countryCode: 'US', asn: 'AS15169' } },
      }).code,
      'chain-loon'
    );
    assert.strictEqual(
      core.classifyLinkType({
        nodeInfo: { type: 'relay' },
        probe: { landing: { ip: '8.8.4.4', countryCode: 'US' } },
      }).code,
      'chain-relay'
    );

    // 2. LAN / Mesh Gateway (RFC1918 & Tailscale 100.64.0.0/10)
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '100.88.1.5', geo: { isPrivate: true } },
        probe: { landing: { ip: '203.0.113.9', countryCode: 'JP', asn: 'AS2497' } },
      }).code,
      'lan-gateway'
    );

    // 3. Direct & Direct + WARP
    const directRes = core.classifyLinkType({
      entrance: { status: 'ok', entranceIP: '203.0.113.10', geo: { countryCode: 'JP', asn: 'AS2497' } },
      probe: { landing: { ip: '203.0.113.10', countryCode: 'JP', asn: 'AS2497' } },
    });
    assert.strictEqual(directRes.code, 'direct');
    assert.strictEqual(directRes.badge, '单跳直连出境');
    assert.ok(directRes.detail.includes('入口即落地服务器，未经过任何中转节点'));

    const directWarpRes = core.classifyLinkType({
      entrance: { status: 'ok', entranceIP: '203.0.113.10' },
      probe: {
        landing: { ip: '203.0.113.10', countryCode: 'JP', asn: 'AS13335' },
        cfTrace: { colo: 'NRT', warp: 'plus' },
      },
    });
    assert.strictEqual(directWarpRes.code, 'direct-warp');

    // 4. Cloudflare Entrance (WARP tunnel vs CDN origin)
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '162.159.192.1', geo: { countryCode: 'US', asn: 'AS13335' } },
        probe: { landing: { ip: '104.28.1.5', countryCode: 'HK', asn: 'AS13335' }, cfTrace: { colo: 'HKG', warp: 'on' } },
      }).code,
      'cf-warp-tunnel'
    );
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '104.16.10.1', geo: { countryCode: 'US', asn: 'AS13335' } },
        probe: { landing: { ip: '45.76.100.20', countryCode: 'JP', asn: 'AS20473' }, cfTrace: { colo: 'NRT', warp: 'off' } },
      }).code,
      'cf-cdn-origin'
    );

    // 5a. CN Cloud Global Accelerator (GA/AGA)
    const gaRes = core.classifyLinkType({
      entrance: {
        status: 'ok',
        entranceHost: 'entry.airport.io',
        entranceIP: '47.115.20.30',
        cnameChain: ['ga-bp1abc.ga.aliyuncs.com'],
        geo: { countryCode: 'CN', region: '广东', city: '深圳', ispDisplay: '阿里云', asn: 'AS37963' },
      },
      probe: { landing: { ip: '103.10.20.30', countryCode: 'HK', asn: 'AS4760' } },
    });
    assert.strictEqual(gaRes.code, 'cn-cloud-ga');
    assert.ok(gaRes.badge.includes('云全球加速专网中转 (GA/AGA)'));

    // 5b. CN Same-Cloud Cross-Border (Alibaba CN AS37963 -> Alibaba Intl AS45102)
    const sameCloudRes = core.classifyLinkType({
      entrance: {
        status: 'ok',
        entranceIP: '120.76.10.20',
        geo: { countryCode: 'CN', region: '广东', city: '深圳', ispDisplay: '阿里云', asn: 'AS37963' },
      },
      probe: { landing: { ip: '47.242.10.20', countryCode: 'HK', asn: 'AS45102' } },
    });
    assert.strictEqual(sameCloudRes.code, 'cn-same-cloud');
    assert.strictEqual(sameCloudRes.badge, '同云架构跨境中转');

    // 5c. CN Multi-Line BGP Cloud Entrance (UCloud AS135377 -> HKT AS4760)
    const bgpCloudRes = core.classifyLinkType({
      entrance: {
        status: 'ok',
        entranceIP: '106.75.10.20',
        geo: { countryCode: 'CN', region: '上海', city: '上海', ispDisplay: 'UCloud', asn: 'AS135377' },
      },
      probe: { landing: { ip: '218.102.10.20', countryCode: 'HK', asn: 'AS4760' } },
    });
    assert.strictEqual(bgpCloudRes.code, 'cn-bgp-cloud');
    assert.strictEqual(bgpCloudRes.badge, '国内多线 BGP 云入口中转');

    // 5d. CN ISP Transit (Zhenjiang Mobile AS56046 -> Japan IIJ AS2497)
    const ispRes = core.classifyLinkType({
      entrance: {
        status: 'ok',
        entranceIP: '221.178.10.20',
        geo: { countryCode: 'CN', region: '江苏', city: '镇江', ispDisplay: '中国移动', asn: 'AS56046' },
      },
      probe: { landing: { ip: '210.130.10.20', countryCode: 'JP', asn: 'AS2497' } },
    });
    assert.strictEqual(ispRes.code, 'cn-isp-transit');
    assert.strictEqual(ispRes.badge, '国内运营商入口中转');
    assert.ok(ispRes.detail.includes('江苏镇江移动入口'));

    // 6. CN Internal Transit
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '180.101.1.2', geo: { countryCode: 'CN', asn: 'AS4134' } },
        probe: { landing: { ip: '123.125.1.2', countryCode: 'CN', asn: 'AS4808' } },
      }).code,
      'cn-internal-transit'
    );

    // 7a. Overseas Cross-Country Jump + WARP (HK entry -> US VPS -> WARP LAX) — Bug Fix!
    const intlWarpRes = core.classifyLinkType({
      entrance: { status: 'ok', entranceIP: '45.207.1.2', geo: { countryCode: 'HK', asn: 'AS58453' } },
      probe: {
        landing: { ip: '104.28.200.10', countryCode: 'US', asn: 'AS13335' },
        cfTrace: { colo: 'LAX', warp: 'on' },
      },
    });
    assert.strictEqual(intlWarpRes.code, 'intl-transit-warp');
    assert.strictEqual(intlWarpRes.badge, '海外跨国跳板 + WARP 出站');

    // 7b. Overseas Local Entry + WARP (HK entry -> local WARP HKG, even if landing IP geo says US!)
    const localWarpRes = core.classifyLinkType({
      entrance: { status: 'ok', entranceIP: '45.207.1.2', geo: { countryCode: 'HK', asn: 'AS58453' } },
      probe: {
        landing: { ip: '104.28.200.11', countryCode: 'US', asn: 'AS13335' },
        cfTrace: { colo: 'HKG', warp: 'on' },
      },
    });
    assert.strictEqual(localWarpRes.code, 'overseas-direct-warp');
    assert.strictEqual(localWarpRes.badge, '海外入口 + WARP 出站');

    // 7c / 7d / 7e: intl-transit, same-asn-multi-ip, same-region-chain
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '45.207.1.2', geo: { countryCode: 'HK', asn: 'AS58453' } },
        probe: { landing: { ip: '198.51.100.20', countryCode: 'US', asn: 'AS20473' } },
      }).code,
      'intl-transit'
    );
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '218.102.1.1', geo: { countryCode: 'HK', asn: 'AS4760' } },
        probe: { landing: { ip: '218.102.9.9', countryCode: 'HK', asn: 'AS4760' } },
      }).code,
      'same-asn-multi-ip'
    );
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '45.207.1.2', geo: { countryCode: 'HK', asn: 'AS58453' } },
        probe: { landing: { ip: '218.102.9.9', countryCode: 'HK', asn: 'AS4760' } },
      }).code,
      'same-region-chain'
    );

    // 8. Separated transit (Geo timeout)
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '198.51.100.5', geo: null },
        probe: { landing: { ip: '203.0.113.5', countryCode: 'SG', asn: 'AS7473' } },
      }).code,
      'separated-transit'
    );

    // 9. Host-aware uncaptured fallback
    const loonFallback = core.classifyLinkType({
      entrance: { status: 'no_node_context' },
      probe: { landing: { ip: '203.0.113.5', countryCode: 'SG' } },
      hostClient: 'loon',
    });
    assert.strictEqual(loonFallback.code, 'outbound-only');
    assert.strictEqual(loonFallback.badge, '仅测得落地出站');
    assert.ok(!loonFallback.detail.includes('外部控制器'));

    const clashFallback = core.classifyLinkType({
      entrance: { status: 'unreachable' },
      probe: { landing: { ip: '203.0.113.5', countryCode: 'SG' } },
      hostClient: 'clash',
    });
    assert.strictEqual(clashFallback.code, 'pending-controller');
    assert.ok(clashFallback.detail.includes('外部控制器'));
  });

  await runTest('Anti-fraud test: Nodes named IEPL/IPLC/深港/沪日 NEVER get IEPL badge, and falsified claims trigger warnings', () => {
    // Fake IEPL name on ordinary Alibaba Cloud CN -> HK HKT
    const aliCtx = {
      nodeName: '🇭🇰 旗舰深港 IEPL 专线 01 [×1.0]',
      entrance: {
        status: 'ok',
        entranceIP: '120.76.22.33',
        geo: { countryCode: 'CN', region: '广东', city: '深圳', ispDisplay: '阿里云', asn: 'AS37963' },
      },
      probe: {
        landing: { ip: '218.102.33.44', country: '香港', countryCode: 'HK', asn: 'AS4760', isp: 'HKT' },
        bgp: { gradeLabel: '🌐 国际多线 Tier-1 BGP', gradeLevel: 'normal', prefix: '218.102.32.0/20', upstreams: [] },
        elapsedMs: 380,
      },
      hostClient: 'loon',
    };
    const aliLink = core.classifyLinkType(aliCtx);
    assert.strictEqual(aliLink.code, 'cn-bgp-cloud');
    assert.ok(!/IEPL|IPLC|跨境专线/i.test(aliLink.badge));
    // Cannot falsify L2 medium when entrance is genuinely in CN, so mismatch warning is null (honest neutrality)
    assert.strictEqual(core.detectNameClaimMismatch(aliCtx.nodeName, aliCtx), null);

    // Fake 沪日 IPLC name on Zhenjiang Mobile broadband NAT
    const zjCtx = {
      nodeName: '🇯🇵 沪日 IPLC 内网专线 VIP',
      entrance: {
        status: 'ok',
        entranceIP: '221.178.55.66',
        geo: { countryCode: 'CN', region: '江苏', city: '镇江', ispDisplay: '中国移动', asn: 'AS56046' },
      },
      probe: { landing: { ip: '210.130.1.8', countryCode: 'JP', asn: 'AS2497' }, elapsedMs: 410 },
    };
    const zjLink = core.classifyLinkType(zjCtx);
    assert.strictEqual(zjLink.code, 'cn-isp-transit');
    assert.ok(!/IEPL|IPLC|专线/i.test(zjLink.badge));

    // Falsification 1: Named 深港 IEPL / 中转, but entIP === landing.ip (pure single-hop direct)
    const fakeDirectWarn = core.detectNameClaimMismatch('🇭🇰 深港 IEPL 专线 01', {
      entIP: '203.0.113.88',
      landingIP: '203.0.113.88',
      entCC: 'HK',
      entASN: 'AS4760',
    });
    assert.strictEqual(fakeDirectWarn, '名称标称中转/专线，实测出入口同 IP（纯单跳直连）');

    // Falsification 2: Named 广港专线, but entrance is AS13335 Cloudflare
    const fakeCFWarn = core.detectNameClaimMismatch('🇭🇰 广港 IEPL 专线', {
      entIP: '104.16.88.1',
      landingIP: '45.76.10.20',
      entCC: 'US',
      entASN: 'AS13335',
    });
    assert.strictEqual(fakeCFWarn, '名称标称专线，实测为 Cloudflare Anycast 公共边缘接入');

    // Falsification 3: Named 沪日 IPLC, but first hop goes directly to HK (no CN entrance)
    const fakeCrossWarn = core.detectNameClaimMismatch('🇯🇵 沪日 IPLC 02', {
      entIP: '45.207.10.2',
      landingIP: '210.130.10.9',
      entCC: 'HK',
      entASN: 'AS58453',
    });
    assert.strictEqual(fakeCrossWarn, '名称标称境内跨境专线，实测首跳直连境外 (HK)，无境内入口');
  });

  await runTest('Dual-axis BGP decoupling (跨境骨干 vs 落地互联) & Light/Dark adaptive HTML styling', () => {
    const baseBGP = {
      gradeLabel: '🚀 中国大陆优化 BGP (电信 CN2)',
      gradeShort: '中国优化 (电信 CN2)',
      gradeLevel: 'excellent',
      prefix: '59.43.0.0/16',
      upstreams: [{ asn: 'AS4809', name: '电信 CN2', pct: 100, display: '电信 CN2 [AS4809] 100%' }],
    };

    const directHTML = core.renderInfoSheetHTML({
      nodeName: '🇭🇰 香港 CN2 直连',
      nodeInfo: { type: 'Trojan', tls: 1 },
      domestic: { ip: '113.108.1.2', location: '广东深圳', isp: '中国电信', shortTag: '广东深圳电信' },
      entrance: { status: 'ok', entranceIP: '203.0.113.66', geo: { countryCode: 'HK', asn: 'AS4809' } },
      probe: {
        landing: { ip: '203.0.113.66', country: '香港', countryCode: 'HK', asn: 'AS4809', isp: 'China Telecom' },
        bgp: baseBGP,
        elapsedMs: 210,
        routeChannel: 'direct-node',
      },
      hostClient: 'loon',
    });
    assert.ok(directHTML.includes('跨境骨干：'), 'Direct node must label BGP as 跨境骨干');
    assert.ok(!directHTML.includes('落地互联：'));
    assert.ok(!/color\s*:\s*(#000|#fff|black|white)/i.test(directHTML), 'Root HTML must not hardcode black/white text');

    const transitHTML = core.renderInfoSheetHTML({
      nodeName: '🇭🇰 深港 IEPL 虚标直连测试',
      nodeInfo: { type: 'Shadowsocks' },
      domestic: { ip: '113.108.1.2', location: '广东深圳', isp: '中国电信', shortTag: '广东深圳电信' },
      entrance: {
        status: 'ok',
        entranceIP: '120.76.10.1',
        geo: { countryCode: 'CN', region: '广东', city: '深圳', ispDisplay: '阿里云', asn: 'AS37963' },
      },
      probe: {
        landing: { ip: '203.0.113.66', country: '香港', countryCode: 'HK', asn: 'AS4760', isp: 'HKT' },
        bgp: baseBGP,
        elapsedMs: 250,
        routeChannel: 'direct-node',
      },
      hostClient: 'loon',
    });
    assert.ok(transitHTML.includes('落地互联：'), 'Transited node must label BGP as 落地互联');
    assert.ok(!transitHTML.includes('跨境骨干：'));

    // Purity business translation check
    const parsedBiz = core.parseIPAPIIs({
      asn: { asn: 4760, org: 'HKT Business', type: 'business', country: 'HK' },
      company: { name: 'HKT Enterprise', type: 'business' },
      location: { country_code: 'HK' },
    });
    assert.strictEqual(parsedBiz.lineageLabel, '🏢 商业/政企宽带');
    assert.strictEqual(parsedBiz.asnTypeText, '商业/政企宽带');
    assert.ok(!parsedBiz.lineageLabel.includes('专线'));
  });

  console.log('\n=== [4] End-to-End Black-Box VM Simulations Across Clients ===');

  await runTest('Loon E2E (MODE=info via $script.name + Object $argument + nodeInfo.address + EDNS GA CNAME + $dns.query + $utils + ms timeout)', async () => {
    const res = await runScriptInSandbox(UNIVERSAL_FILE, {
      loon: 'iPhone16,2 18.2 3.5.1(998)',
      script: { name: '节点链路与入口查询' },
      argument: {
        SHOW_DOMESTIC: true,
        SHOW_ENTRANCE: true,
        CHECK_IPV6: false,
        MASK_IP: false,
        TIMEOUT_SEC: 9,
        IPAPI_KEY: null,
      },
      environment: {
        params: {
          node: '🇭🇰 阿里全球加速节点',
          nodeInfo: {
            address: 'hk-ga.example.net',
            port: 14433,
            tls: 1,
            type: 'Vless',
          },
        },
      },
      utils: {
        geoip: (ip) => (ip.startsWith('47.115.') ? 'CN' : 'HK'),
        ipasn: (ip) => (ip.startsWith('47.115.') ? 37963 : 4760),
        ipaso: (ip) => (ip.startsWith('47.115.') ? 'Alibaba Cloud' : 'HKT'),
      },
      dnsHandler: (qOpts) => {
        return {
          domain: qOpts.domain,
          answers: [{ name: qOpts.domain, type: 'A', value: '47.115.88.99', ttl: 60 }],
        };
      },
      onHttp: (method, req) => {
        const u = req.url;
        if (u.includes('net-lsp-x.com') || u.includes('127.0.0.1:9090')) {
          throw new Error('Loon must NEVER call Clash bridge or 9090 controller: ' + u);
        }
        if (u.includes('myip.ipip.net')) {
          return { body: { ret: 'ok', data: { ip: '221.226.18.99', location: ['中国', '江苏', '南京', '', '电信'] } } };
        }
        if (u.includes('223.5.5.5/resolve')) {
          assert.ok(
            u.includes('edns_client_subnet=221.226.18.0%2F24') || u.includes('edns_client_subnet=221.226.18.0/24'),
            'Ali DoH must carry /24 EDNS subnet from domestic IP'
          );
          return {
            body: {
              Status: 0,
              Answer: [
                { name: 'hk-ga.example.net.', type: 5, data: 'ga-bp1xyz.ga.aliyuncs.com.' },
                { name: 'ga-bp1xyz.ga.aliyuncs.com.', type: 1, data: '47.115.88.99' },
              ],
            },
          };
        }
        if (u.includes('api-ipv4.ip.sb/geoip/47.115.88.99')) {
          return { body: { ip: '47.115.88.99', country_code: 'CN', country: 'China', asn: 37963, organization: 'Alibaba' } };
        }
        if (u.includes('ip.netart.cn?ip=47.115.88.99')) {
          return {
            body: {
              code: 200,
              data: {
                ip: '47.115.88.99',
                geo_cn: { country: '中国', province: '江苏省', city: '南京市', isp: '阿里云' },
                as: { number: 37963, name: 'CNNIC-ALIBABA-CN' },
              },
            },
          };
        }
        if (u.includes('ip-api.com/json/?fields=')) {
          return {
            body: {
              status: 'success',
              query: '218.102.50.60',
              country: '香港',
              countryCode: 'HK',
              regionName: '香港',
              city: 'Hong Kong',
              isp: 'PCCW Limited',
              org: 'HKT',
              as: 'AS4760 HKT Limited',
            },
          };
        }
        if (u.includes('stat.ripe.net')) {
          return {
            body: {
              data: {
                resource: '218.102.48.0/20',
                bgp_state: [
                  { path: [3356, 3491, 4760] },
                  { path: [2914, 4635, 4760] },
                ],
              },
            },
          };
        }
        if (u.includes('cdn-cgi/trace')) {
          return { body: 'colo=HKG\nwarp=off\n' };
        }
        return { status: 404, body: '' };
      },
    });

    assert.strictEqual(res.donePayload.title, '节点链路与入口查询');
    assert.ok(res.donePayload.htmlMessage.includes('云全球加速专网中转 (GA/AGA)'));
    assert.ok(res.donePayload.htmlMessage.includes('江苏南京'));
    assert.ok(res.donePayload.htmlMessage.includes('落地互联：'));
    assert.ok(res.donePayload.htmlMessage.includes('TLS ✓'));

    // Verify Loon timeout is in milliseconds (9s -> 9000ms) and node option is set with auto-redirect: false
    const landingCall = res.httpCalls.find((c) => c.url.includes('ip-api.com/json/?fields='));
    assert.strictEqual(landingCall.node, '🇭🇰 阿里全球加速节点');
    assert.strictEqual(landingCall.timeout, 9000);
    assert.strictEqual(landingCall['auto-redirect'], false);

    // Verify Loon native $dns.query received protocol: 'auto' and ms timeout
    assert.strictEqual(res.dnsCalls.length, 1);
    assert.strictEqual(res.dnsCalls[0].protocol, 'auto');
    assert.strictEqual(res.dnsCalls[0].timeout, 3500);

    // Verify every $persistentStore read/write passed explicit key
    assert.ok(res.storeCalls.length > 0);
    assert.ok(res.storeCalls.every((c) => typeof c.key === 'string' && c.key.length > 0));
  });

  await runTest('Loon E2E: Purity mode ($script.name routing + my.ippure.com fallback) & Dashboard manual run', async () => {
    const res = await runScriptInSandbox(UNIVERSAL_FILE, {
      loon: 'iPhone16,2 18.2 3.5.1(998)',
      script: { name: '节点纯净度深度检测' },
      argument: { MASK_IP: false, TIMEOUT_SEC: 7 },
      // Simulate manual click in Loon Dashboard: no params.node!
      environment: { params: {} },
      configState: { running_model: 1, final: 'Proxy', selected: '🇺🇸 美国原生家宽' },
      onHttp: (method, req) => {
        const u = req.url;
        if (u.includes('ip-api.com/json/?fields=')) {
          return {
            body: {
              status: 'success',
              query: '73.15.20.25',
              country: '美国',
              countryCode: 'US',
              city: 'Los Angeles',
              isp: 'Comcast Cable',
              as: 'AS7922 Comcast Cable Communications',
            },
          };
        }
        // Simulate ipapi.is timeout/429 to verify my.ippure.com fallback!
        if (u.includes('api.ipapi.is')) {
          return { status: 429, body: '{"error":"rate limited"}' };
        }
        if (u.includes('my.ippure.com/v1/info')) {
          return {
            body: {
              ip: '73.15.20.25',
              asn: 7922,
              asOrganization: 'Comcast Cable',
              countryCode: 'US',
              fraudScore: 8,
              isResidential: true,
              isBroadcast: false,
            },
          };
        }
        if (u.includes('proxycheck.io')) {
          return { body: { status: 'ok', '73.15.20.25': { proxy: 'no', type: 'Residential', risk: 5 } } };
        }
        if (u.includes('ip-score.com/fulljson')) {
          return { body: { blacklist: { spamhaus: false, barracuda: false, sorbs: false } } };
        }
        if (u.includes('stat.ripe.net')) {
          return { body: { data: { resource: '73.0.0.0/8', bgp_state: [{ path: [3356, 7922] }] } } };
        }
        return { status: 404, body: '' };
      },
    });

    // Must return rich popup { title, htmlMessage }, NOT Surge [Panel] plain text
    assert.strictEqual(res.donePayload.title, '节点纯净度深度检测');
    assert.ok(typeof res.donePayload.htmlMessage === 'string' && res.donePayload.htmlMessage.length > 50);
    assert.ok(res.donePayload.htmlMessage.includes('住宅宽带网络 (IPPure)'));
    assert.ok(res.donePayload.htmlMessage.includes('原生 IP (IPPure 核验)'));
    assert.ok(res.donePayload.htmlMessage.includes('IPPure'));
  });

  await runTest('Clash-Client E2E: Fake $loon trap defeated + Bridge fallback to $config switch & policy restoration', async () => {
    const res = await runScriptInSandbox(CLASH_FG_FILE, {
      // Inject fake $loon mimicking Loon build string + Mihomo nodeInfo!
      loon: 'iPhone 18.0 3.2.0(1000)',
      argument: 'MODE=info&SHOW_DOMESTIC=true&SHOW_ENTRANCE=true&AUTO_SWITCH_FALLBACK=true&TIMEOUT_SEC=6',
      environment: {
        params: {
          node: '🇭🇰 深港 IEPL 假标直连',
          nodeInfo: { type: 'ss', udp: true, alive: true, history: [{ delay: 38 }] },
        },
      },
      configState: { running_model: 1, global_proxy: 'DIRECT', final: 'Proxy', selected: 'OldNode' },
      onHttp: (method, req) => {
        const u = req.url;
        if (u.includes('net-lsp-x.com/__clash_node_check')) {
          // Simulate MITM disabled so Bridge fails and triggers $config fallback!
          return { status: 502, body: '' };
        }
        if (u.includes('127.0.0.1:9090/connections')) {
          return {
            body: {
              connections: [
                {
                  start: new Date().toISOString(),
                  chains: ['🇭🇰 深港 IEPL 假标直连', 'GLOBAL'],
                  metadata: { host: 'ip-api.com', remoteDestination: '203.0.113.77:8388' },
                },
              ],
            },
          };
        }
        if (u.includes('127.0.0.1:9090/proxies/')) {
          return { body: { name: '🇭🇰 深港 IEPL 假标直连', type: 'Shadowsocks' } };
        }
        if (u.includes('myip.ipip.net')) {
          return { body: { data: { ip: '113.100.1.2', location: ['中国', '广东', '深圳', '', '电信'] } } };
        }
        if (u.includes('ip-api.com/json/?fields=')) {
          return {
            body: {
              status: 'success',
              query: '203.0.113.77',
              country: '香港',
              countryCode: 'HK',
              city: 'Hong Kong',
              isp: 'HKT',
              as: 'AS4760 HKT',
            },
          };
        }
        if (u.includes('cdn-cgi/trace')) {
          return { body: 'colo=HKG\nwarp=off\n' };
        }
        if (u.includes('stat.ripe.net')) {
          return { body: { data: { resource: '203.0.113.0/24', bgp_state: [{ path: [4809, 4760] }] } } };
        }
        return { status: 404, body: '' };
      },
    });

    assert.ok(res.httpCalls.some((c) => c.url.includes('net-lsp-x.com/__clash_node_check')), 'Must attempt Bridge first');
    assert.strictEqual(res.configCalls.length, 4, 'Must switch GLOBAL + model=2 and restore both in finally');
    assert.deepStrictEqual(res.configCalls[0], { op: 'setSelectPolicy', group: 'GLOBAL', policy: '🇭🇰 深港 IEPL 假标直连' });
    assert.deepStrictEqual(res.configCalls[1], { op: 'setRunningModel', model: 2 });
    assert.deepStrictEqual(res.configCalls[2], { op: 'setRunningModel', model: 1 });
    assert.deepStrictEqual(res.configCalls[3], { op: 'setSelectPolicy', group: 'GLOBAL', policy: 'DIRECT' });

    assert.ok(res.donePayload.htmlMessage.includes('单跳直连出境'));
    assert.ok(res.donePayload.htmlMessage.includes('名称标称中转/专线，实测出入口同 IP（纯单跳直连）'));
    assert.ok(res.donePayload.htmlMessage.includes('跨境骨干：'));
  });

  await runTest('Surge & Stash E2E: Second-unit timeouts, Surge $httpAPI (Proxy) stripping & Stash header injection', async () => {
    // Surge simulation
    const surgeRes = await runScriptInSandbox(UNIVERSAL_FILE, {
      environment: {
        'surge-version': '5.9.0',
        params: { node: 'SG-Surge-Policy' },
      },
      argument: 'MODE=info&CHECK_IPV6=0&TIMEOUT_SEC=8',
      httpAPI: (method, apiPath, body, cb) => {
        assert.strictEqual(apiPath, '/v1/requests/recent');
        cb({
          requests: [
            {
              URL: 'http://ip-api.com/json/?fields=66842623&lang=zh-CN',
              policyName: 'SG-Surge-Policy',
              remoteAddress: '120.76.99.88:443 (Proxy)',
            },
          ],
        });
      },
      onHttp: (method, req) => {
        const u = req.url;
        if (u.includes('myip.ipip.net')) {
          return { body: { data: { ip: '113.100.1.2', location: ['中国', '广东', '广州', '', '移动'] } } };
        }
        if (u.includes('ip-api.com/json/?fields=')) {
          return {
            body: {
              status: 'success',
              query: '103.20.30.40',
              country: '新加坡',
              countryCode: 'SG',
              city: 'Singapore',
              isp: 'Singtel',
              as: 'AS7473 Singtel',
            },
          };
        }
        if (u.includes('api-ipv4.ip.sb/geoip/120.76.99.88')) {
          return { body: { ip: '120.76.99.88', country_code: 'CN', asn: 37963, organization: 'Alibaba Cloud' } };
        }
        if (u.includes('ip.netart.cn?ip=120.76.99.88')) {
          return { body: { data: { geo_cn: { province: '广东省', city: '深圳市', isp: '阿里云' }, as: { number: 37963 } } } };
        }
        if (u.includes('cdn-cgi/trace')) return { body: 'colo=SIN\nwarp=off\n' };
        return { status: 404, body: '' };
      },
    });

    const surgeLandingReq = surgeRes.httpCalls.find((c) => c.url.includes('ip-api.com/json/?fields='));
    assert.strictEqual(surgeLandingReq.policy, 'SG-Surge-Policy');
    assert.strictEqual(surgeLandingReq.timeout, 8, 'Surge timeout MUST be in seconds (8), not ms');
    assert.ok(surgeRes.donePayload.htmlMessage.includes('国内多线 BGP 云入口中转'));
    assert.ok(surgeRes.donePayload.htmlMessage.includes('120.76.99.88'));

    // Stash simulation
    const stashRes = await runScriptInSandbox(UNIVERSAL_FILE, {
      environment: {
        'stash-version': '2.7.0',
        params: { node: '🇯🇵 东京节点' },
      },
      argument: 'MODE=info&SHOW_DOMESTIC=0&SHOW_ENTRANCE=0&CHECK_IPV6=0&TIMEOUT_SEC=10',
      onHttp: (method, req) => {
        if (req.url.includes('ip-api.com/json/?fields=')) {
          return {
            body: { status: 'success', query: '210.130.5.6', country: '日本', countryCode: 'JP', as: 'AS2497 IIJ' },
          };
        }
        if (req.url.includes('cdn-cgi/trace')) return { body: 'colo=NRT\nwarp=off\n' };
        return { status: 404, body: '' };
      },
    });

    const stashLandingReq = stashRes.httpCalls.find((c) => c.url.includes('ip-api.com/json/?fields='));
    assert.strictEqual(stashLandingReq.policy, '🇯🇵 东京节点');
    assert.strictEqual(stashLandingReq.headers['X-Stash-Selected-Proxy'], encodeURIComponent('🇯🇵 东京节点'));
    assert.strictEqual(stashLandingReq.timeout, 10, 'Stash timeout MUST be in seconds (10)');
  });

  await runTest('Loon E2E: Streaming Unlock (302 Location redirect parsing with auto-redirect: false) & Network-Changed Event & Web Portal JSON', async () => {
    // 1. Streaming Unlock on Loon
    const unlockRes = await runScriptInSandbox(UNIVERSAL_FILE, {
      loon: 'iPhone16,2 18.2 3.5.1(998)',
      script: { name: '流媒体与 AI 解锁检测' },
      argument: { MASK_IP: false, TIMEOUT_SEC: 8 },
      environment: { params: { node: '🇸🇬 新加坡解锁节点', nodeInfo: { address: '103.20.30.40', port: 443, type: 'Hysteria2' } } },
      onHttp: (method, req) => {
        const u = req.url;
        if (u.includes('ip-api.com')) return { body: { status: 'success', query: '103.20.30.40', country: '新加坡', countryCode: 'SG' } };
        if (u.includes('chatgpt.com/cdn-cgi/trace')) return { body: 'loc=SG\ncolo=SIN\n' };
        if (u.includes('ios.chat.openai.com')) return { status: 200, body: '{"status":"normal"}' };
        if (u.includes('claude.ai/cdn-cgi/trace')) return { body: 'loc=SG\n' };
        if (u.includes('gemini.google.com/app')) return { status: 200, body: ',"SG","en-US"' };
        if (u.includes('netflix.com/title/81280792')) {
          return { status: 302, headers: { Location: 'https://www.netflix.com/sg/title/81280792' }, body: '' };
        }
        if (u.includes('youtube.com/premium')) return { status: 200, body: '"INNERTUBE_CONTEXT_GL":"SG"' };
        if (u.includes('disneyplus.com')) {
          return { status: 302, headers: { Location: 'https://www.disneyplus.com/en-sg' }, body: '' };
        }
        if (u.includes('tiktok.com/login')) return { status: 200, body: '{"region":"SG"}' };
        if (u.includes('ani.gamer.com.tw')) return { status: 200, body: '{"error":"bad region"}' };
        return { status: 404, body: '' };
      },
    });
    assert.strictEqual(unlockRes.donePayload.title, '流媒体与 AI 解锁检测');
    assert.ok(unlockRes.donePayload.htmlMessage.includes('完整解锁 [SG] (Web + App)'));
    assert.ok(unlockRes.donePayload.htmlMessage.includes('完整解锁 (含非自制剧) [SG]'));
    assert.ok(unlockRes.donePayload.htmlMessage.includes('支持解锁 [SG]'));

    // 2. Network-changed Event on Loon
    const eventRes = await runScriptInSandbox(UNIVERSAL_FILE, {
      loon: 'iPhone16,2 18.2 3.5.1(998)',
      script: { name: '网络切换出口通知' },
      argument: { SHOW_DOMESTIC: true, SHOW_ENTRANCE: true, NOTIFY_ON_CHANGE: true, MASK_IP: true, TIMEOUT_SEC: 6 },
      configState: { running_model: 1, final: 'Proxy', selected: '🇯🇵 日本主力' },
      onHttp: (method, req) => {
        const u = req.url;
        if (u.includes('myip.ipip.net')) return { body: { data: { ip: '221.226.1.2', location: ['中国', '江苏', '苏州', '', '电信'] } } };
        if (u.includes('ip-api.com')) {
          return { body: { status: 'success', query: '210.130.9.8', country: '日本', countryCode: 'JP', city: 'Tokyo', as: 'AS2497 IIJ' } };
        }
        if (u.includes('stat.ripe.net')) return { body: { data: { resource: '210.130.0.0/16', bgp_state: [{ path: [2914, 2497] }] } } };
        if (u.includes('api.ipapi.is')) {
          return { body: { asn: { asn: 2497, type: 'isp', country: 'JP' }, company: { type: 'isp' }, location: { country_code: 'JP' } } };
        }
        return { status: 404, body: '' };
      },
    });
    assert.strictEqual(eventRes.notifications.length, 1);
    assert.ok(eventRes.notifications[0].title.includes('日本'));
    assert.ok(eventRes.notifications[0].body.includes('210.130.*.8'), 'MASK_IP should mask notification IP');

    // 3. Web Portal JSON endpoint with claimWarning
    const webRes = await runScriptInSandbox(CLASH_BG_FILE, {
      loon: true,
      argument: 'CLIENT=clash&MODE=bridge&SHOW_DOMESTIC=0&CHECK_IPV6=0',
      request: { url: 'http://net-lsp-x.com/json?node=%F0%9F%87%AD%F0%9F%87%B0%20%E6%B7%B1%E6%B8%AF%20IEPL' },
      configState: { running_model: 1 },
      onHttp: (method, req) => {
        const u = req.url;
        if (u.includes('127.0.0.1:9090/connections')) {
          return {
            body: {
              connections: [
                {
                  start: new Date().toISOString(),
                  chains: ['🇭🇰 深港 IEPL', 'Proxy'],
                  metadata: { host: 'ip-api.com', remoteDestination: '104.16.10.20:443' },
                },
              ],
            },
          };
        }
        if (u.includes('127.0.0.1:9090/proxies/')) return { body: { name: '🇭🇰 深港 IEPL', type: 'Trojan' } };
        if (u.includes('api-ipv4.ip.sb/geoip/104.16.10.20')) {
          return { body: { ip: '104.16.10.20', country_code: 'US', asn: 13335, organization: 'Cloudflare' } };
        }
        if (u.includes('ip-api.com')) {
          return { body: { status: 'success', query: '45.76.20.30', country: '日本', countryCode: 'JP', as: 'AS20473 Vultr' } };
        }
        if (u.includes('cdn-cgi/trace')) return { body: 'colo=NRT\nwarp=off\n' };
        if (u.includes('api.ipapi.is')) {
          return { body: { asn: { asn: 20473, type: 'hosting', country: 'US' }, company: { type: 'hosting' }, location: { country_code: 'JP' } } };
        }
        return { status: 404, body: '' };
      },
    });
    assert.strictEqual(webRes.donePayload.response.status, 200);
    const bodyJSON = JSON.parse(webRes.donePayload.response.body);
    assert.strictEqual(bodyJSON.ok, true);
    assert.strictEqual(bodyJSON.linkType.code, 'cf-cdn-origin');
    assert.strictEqual(bodyJSON.claimWarning, '名称标称专线，实测为 Cloudflare Anycast 公共边缘接入');
  });

  console.log(`\n==================================================`);
  console.log(`Core Multi-Client Test Summary: ${passed} passed, ${failed} failed`);
  console.log(`==================================================\n`);

  if (failed > 0) process.exit(1);
})();
