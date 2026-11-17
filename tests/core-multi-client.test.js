#!/usr/bin/env node
/**
 * Automated White-Box + Black-Box (VM Sandbox) Test Suite (v3.1.0)
 * License: GPL-3.0-or-later
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

function extractRenderedLines(html) {
  return String(html || '')
    .replace(/<hr[^>]*>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
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
  console.log('\n=== [1] Build System, GPL-3.0 Header Restraint & SHA-256 Isolation ===');

  await runTest('build.js --check passes at v3.1.0 with distinct SHA-256 hashes & clean GPL-3.0 headers', () => {
    assert.strictEqual(core.VERSION, '3.1.0');
    const out = execFileSync(process.execPath, [BUILD_SCRIPT, '--check'], { encoding: 'utf8' });
    assert.ok(out.includes('All 3 artifacts are up-to-date'));

    const uHead = fs.readFileSync(UNIVERSAL_FILE, 'utf8').slice(0, 320);
    const fgHead = fs.readFileSync(CLASH_FG_FILE, 'utf8').slice(0, 320);
    const bgHead = fs.readFileSync(CLASH_BG_FILE, 'utf8').slice(0, 320);

    assert.ok(uHead.includes('v3.1.0 · Universal Multi-Client'));
    assert.ok(fgHead.includes('v3.1.0 · Clash-Client FG-Interactive'));
    assert.ok(bgHead.includes('v3.1.0 · Clash-Client BG-Tunnel-Event'));
    assert.ok(uHead.includes('GPL-3.0'));
    assert.ok(!/可莉|xream\/scripts|深度融合|一等公民/i.test(uHead), 'Header must remain concise and restrained');

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

  console.log('\n=== [2] Chinese Geo Normalization, District Deduplication & ISP Trimming ===');

  await runTest('normalizeCNPlace & formatCompactLocation eliminate "Shanghai 电信" and "香港 Kowloon"', () => {
    // 34 provincial divisions & gateway cities in English / Pinyin
    assert.strictEqual(core.normalizeCNPlace('Shanghai'), '上海');
    assert.strictEqual(core.normalizeCNPlace('Shanghai Shi'), '上海');
    assert.strictEqual(core.normalizeCNPlace('Beijing'), '北京');
    assert.strictEqual(core.normalizeCNPlace('Tianjin'), '天津');
    assert.strictEqual(core.normalizeCNPlace('Chongqing'), '重庆');
    assert.strictEqual(core.normalizeCNPlace('Guangdong Province'), '广东');
    assert.strictEqual(core.normalizeCNPlace('Shenzhen'), '深圳');
    assert.strictEqual(core.normalizeCNPlace('Guangzhou'), '广州');
    assert.strictEqual(core.normalizeCNPlace('Jiangsu'), '江苏');
    assert.strictEqual(core.normalizeCNPlace('Nanjing'), '南京');
    assert.strictEqual(core.normalizeCNPlace('Zhejiang'), '浙江');
    assert.strictEqual(core.normalizeCNPlace('Hangzhou'), '杭州');
    assert.strictEqual(core.normalizeCNPlace('Fujian'), '福建');
    assert.strictEqual(core.normalizeCNPlace('Xiamen'), '厦门');
    assert.strictEqual(core.normalizeCNPlace("Xi'an"), '西安');
    assert.strictEqual(core.normalizeCNPlace('Inner Mongolia Autonomous Region'), '内蒙古');
    assert.strictEqual(core.normalizeCNPlace('Xinjiang'), '新疆');
    assert.strictEqual(core.normalizeCNPlace('广西壮族自治区'), '广西');

    // HK / MO / SG city-regions drop redundant/English district names
    assert.strictEqual(
      core.formatCompactLocation({ country: '香港', countryCode: 'HK', region: 'Kowloon', city: 'Kowloon' }),
      '香港'
    );
    assert.strictEqual(
      core.formatCompactLocation({ country: 'Hong Kong', countryCode: 'HK', region: 'Central and Western', city: 'Hong Kong' }),
      '香港'
    );
    assert.strictEqual(
      core.formatCompactLocation({ country: '新加坡', countryCode: 'SG', region: 'Central Singapore', city: 'Singapore' }),
      '新加坡'
    );
    assert.strictEqual(
      core.formatCompactLocation({ country: 'Macao', countryCode: 'MO', city: 'Macau' }),
      '澳门'
    );

    // Mainland CN deduplication & shortHop city extraction
    assert.strictEqual(
      core.formatCompactLocation({ country: 'China', countryCode: 'CN', region: 'Shanghai', city: 'Shanghai' }),
      '上海'
    );
    assert.strictEqual(
      core.formatCompactLocation({ country: 'China', countryCode: 'CN', region: 'Jiangsu', city: 'Nanjing' }),
      '江苏南京'
    );
    assert.strictEqual(
      core.formatCompactLocation({ country: 'China', countryCode: 'CN', region: 'Jiangsu', city: 'Nanjing' }, { shortHop: true }),
      '南京'
    );

    // Overseas cities stay compact without state/province bloat
    assert.strictEqual(
      core.formatCompactLocation({ country: 'United States', countryCode: 'US', region: 'California', city: 'Los Angeles' }),
      '美国 Los Angeles'
    );
    assert.strictEqual(
      core.formatCompactLocation({ country: 'United States', countryCode: 'US', region: 'California', city: 'Los Angeles' }, { shortHop: true }),
      '美国'
    );

    // ISP trimming strips corporate suffixes (LLC / Inc. / Ltd.)
    assert.strictEqual(core.simplifyISPName('Kirino LLC', '', 'HK'), 'Kirino');
    assert.strictEqual(core.simplifyISPName('PCCW Limited', '', 'HK'), 'PCCW');
    assert.strictEqual(core.simplifyISPName('Comcast Cable Communications, LLC', '', 'US'), 'Comcast');
  });

  console.log('\n=== [3] HostAdapter: Multi-Client Detection, $argument & Menu Routing ===');

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

  await runTest('resolveRunMode supports BOTH new concise menu tags and legacy menu tags', () => {
    assert.strictEqual(core.resolveRunMode({ MODE: 'unlock' }, { script: { name: '节点纯净度检测' } }), 'unlock');
    assert.strictEqual(core.resolveRunMode({}, { request: { url: 'http://net-lsp-x.com/' }, script: { name: '网页诊断面板' } }), 'bridge');

    // New v3.1.0 concise menu tags
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '节点链路查询' } }), 'info');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '节点纯净度检测' } }), 'purity');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '流媒体与解锁检测' } }), 'unlock');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '网络切换通知' } }), 'event');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '网页诊断面板' } }), 'info');

    // Legacy v3.0.0 menu tags
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '节点链路与入口查询' } }), 'info');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '节点纯净度深度检测' } }), 'purity');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '流媒体与 AI 解锁检测' } }), 'unlock');
    assert.strictEqual(core.resolveRunMode({}, { script: { name: '网络切换出口通知' } }), 'event');
    assert.strictEqual(core.resolveRunMode({}, {}), 'info');
  });

  await runTest('detectHostClient & Outbound/Timeout adapt cleanly across Loon, Clash, Surge, Stash, SR & Egern', () => {
    assert.strictEqual(core.detectHostClient({ CLIENT: 'loon' }, { config: { getConfig: () => '{}' } }), 'loon');
    assert.strictEqual(core.detectHostClient({ CLIENT: 'clash' }, { loon: 'iPhone 18.0 3.5.1(998)' }), 'clash');
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
    assert.strictEqual(core.detectHostClient({}, { loon: true, config: { getConfig: () => '{}' } }), 'clash');

    // True Loon
    assert.strictEqual(
      core.detectHostClient({}, { loon: 'iPhone16,2 18.1 3.5.1(998)', config: { getConfig: () => '{}' } }),
      'loon'
    );

    assert.strictEqual(core.computeHttpClientTimeout(8000, 'loon'), 8000);
    assert.strictEqual(core.computeHttpClientTimeout(8000, 'surge'), 8);
    assert.strictEqual(core.computeHttpClientTimeout(8500, 'stash'), 9);
  });

  console.log('\n=== [4] 10-Category Objective Link Classifier & Anti-Fraud Name Audit ===');

  await runTest('Covers all 10 objective link categories with concise v3.1.0 badges', () => {
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
        entrance: { status: 'ok', entranceIP: '100.88.1.5', geo: { isPrivate: true } },
        probe: { landing: { ip: '203.0.113.9', countryCode: 'JP', asn: 'AS2497' } },
      }).code,
      'lan-gateway'
    );

    const directRes = core.classifyLinkType({
      entrance: { status: 'ok', entranceIP: '203.0.113.10', geo: { countryCode: 'JP', asn: 'AS2497' } },
      probe: { landing: { ip: '203.0.113.10', countryCode: 'JP', asn: 'AS2497' } },
    });
    assert.strictEqual(directRes.code, 'direct');
    assert.strictEqual(directRes.badge, '单跳直连');

    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '203.0.113.10' },
        probe: {
          landing: { ip: '203.0.113.10', countryCode: 'JP', asn: 'AS13335' },
          cfTrace: { colo: 'NRT', warp: 'plus' },
        },
      }).code,
      'direct-warp'
    );

    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '162.159.192.1', geo: { countryCode: 'US', asn: 'AS13335' } },
        probe: { landing: { ip: '104.28.1.5', countryCode: 'HK', asn: 'AS13335' }, cfTrace: { colo: 'HKG', warp: 'on' } },
      }).code,
      'cf-warp-tunnel'
    );

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
    assert.strictEqual(gaRes.badge, '云全球加速中转');

    const sameCloudRes = core.classifyLinkType({
      entrance: {
        status: 'ok',
        entranceIP: '120.76.10.20',
        geo: { countryCode: 'CN', region: '广东', city: '深圳', ispDisplay: '阿里云', asn: 'AS37963' },
      },
      probe: { landing: { ip: '47.242.10.20', countryCode: 'HK', asn: 'AS45102' } },
    });
    assert.strictEqual(sameCloudRes.code, 'cn-same-cloud');
    assert.strictEqual(sameCloudRes.badge, '同云跨境中转');

    const bgpCloudRes = core.classifyLinkType({
      entrance: {
        status: 'ok',
        entranceIP: '106.75.10.20',
        geo: { countryCode: 'CN', region: '上海', city: '上海', ispDisplay: 'UCloud', asn: 'AS135377' },
      },
      probe: { landing: { ip: '218.102.10.20', countryCode: 'HK', asn: 'AS4760' } },
    });
    assert.strictEqual(bgpCloudRes.code, 'cn-bgp-cloud');
    assert.strictEqual(bgpCloudRes.badge, '国内 BGP 云中转');

    const ispRes = core.classifyLinkType({
      entrance: {
        status: 'ok',
        entranceIP: '221.178.10.20',
        geo: { countryCode: 'CN', region: '江苏', city: '镇江', ispDisplay: '中国移动', asn: 'AS56046' },
      },
      probe: { landing: { ip: '210.130.10.20', countryCode: 'JP', asn: 'AS2497' } },
    });
    assert.strictEqual(ispRes.code, 'cn-isp-transit');
    assert.strictEqual(ispRes.badge, '国内运营商中转');

    // Overseas cross-country jump + WARP vs local entry + WARP
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '45.207.1.2', geo: { countryCode: 'HK', asn: 'AS58453' } },
        probe: {
          landing: { ip: '104.28.200.10', countryCode: 'US', asn: 'AS13335' },
          cfTrace: { colo: 'LAX', warp: 'on' },
        },
      }).code,
      'intl-transit-warp'
    );
    assert.strictEqual(
      core.classifyLinkType({
        entrance: { status: 'ok', entranceIP: '45.207.1.2', geo: { countryCode: 'HK', asn: 'AS58453' } },
        probe: {
          landing: { ip: '104.28.200.11', countryCode: 'US', asn: 'AS13335' },
          cfTrace: { colo: 'HKG', warp: 'on' },
        },
      }).code,
      'overseas-direct-warp'
    );
  });

  await runTest('Anti-fraud test: Nodes named IEPL/IPLC never get IEPL badge, and falsified claims return concise natural warnings', () => {
    const aliCtx = {
      nodeName: '🇭🇰 旗舰深港 IEPL 专线 01',
      entrance: {
        status: 'ok',
        entranceIP: '120.76.22.33',
        geo: { countryCode: 'CN', region: '广东', city: '深圳', ispDisplay: '阿里云', asn: 'AS37963' },
      },
      probe: { landing: { ip: '218.102.33.44', country: '香港', countryCode: 'HK', asn: 'AS4760', isp: 'HKT' } },
      hostClient: 'loon',
    };
    assert.ok(!/IEPL|IPLC|专线/i.test(core.classifyLinkType(aliCtx).badge));
    assert.strictEqual(core.detectNameClaimMismatch(aliCtx.nodeName, aliCtx), null);

    assert.strictEqual(
      core.detectNameClaimMismatch('🇭🇰 深港 IEPL 专线 01', {
        entIP: '203.0.113.88',
        landingIP: '203.0.113.88',
        entCC: 'HK',
        entASN: 'AS4760',
      }),
      '节点名含专线/中转，实测出入口为同一 IP'
    );

    assert.strictEqual(
      core.detectNameClaimMismatch('🇭🇰 广港 IEPL 专线', {
        entIP: '104.16.88.1',
        landingIP: '45.76.10.20',
        entCC: 'US',
        entASN: 'AS13335',
      }),
      '节点名含专线，实测入口为 Cloudflare 公共边缘'
    );

    assert.strictEqual(
      core.detectNameClaimMismatch('🇯🇵 沪日 IPLC 02', {
        entIP: '45.207.10.2',
        landingIP: '210.130.10.9',
        entCC: 'HK',
        entASN: 'AS58453',
      }),
      '节点名含境内专线，实测首跳直连境外 (香港)'
    );
  });

  console.log('\n=== [5] Single-Screen Minimalist UI, Line-Count Cap & Zero-"未知"/Zero-Duplication Audit ===');

  await runTest('MODE=info popup stays within 7~9 lines, eliminates port/domain/CF-edge/BGP-bloat/footer noise, and formats cleanly', () => {
    const bgpTier1 = core.parseBGPState({
      data: {
        resource: '212.107.29.0/24',
        bgp_state: [
          { path: [174, 136766, 41378] },
          { path: [6461, 136766, 41378] },
          { path: [3257, 136766, 41378] },
        ],
      },
    });
    assert.strictEqual(bgpTier1.compactText, '国际 Tier-1 多线 (Cogent / Zayo / GTT)');

    const html = core.renderInfoSheetHTML({
      nodeName: '🇭🇰 香港专线 01',
      nodeInfo: { type: 'ss' },
      domestic: { ip: '49.77.226.174', location: '江苏南京', isp: '中国电信', fullTag: '江苏南京电信', shortTag: '南京电信' },
      entrance: {
        status: 'ok',
        entranceHost: 'fde63gz6-1y61.aws-agent.biz',
        entrancePort: '10011',
        entranceIP: '58.247.187.155',
        geo: { countryCode: 'CN', region: '上海', city: '上海', ispDisplay: '中国电信', asn: 'AS17621' },
      },
      probe: {
        landing: {
          ip: '212.107.29.67',
          country: '香港',
          countryCode: 'HK',
          region: 'Kowloon',
          city: 'Kowloon',
          isp: 'Kirino LLC',
          asn: 'AS41378',
        },
        bgp: bgpTier1,
        cfTrace: { colo: 'HKG', warp: 'off' },
        elapsedMs: 188,
      },
      hostClient: 'loon',
    });

    const lines = extractRenderedLines(html);
    assert.strictEqual(lines.length, 7, 'Standard transit info card should be exactly 7 lines, got: ' + lines.length);
    assert.ok(lines[1].includes('Shadowsocks · 国内运营商中转'));
    assert.strictEqual(lines[2], '🇨🇳 南京电信 ➔ 🇨🇳 上海电信 ➔ 🇭🇰 香港');
    assert.ok(lines[3].includes('49.77.226.174 · 江苏南京电信'));
    assert.ok(lines[4].includes('58.247.187.155 · 上海电信 AS17621'));
    assert.ok(lines[5].includes('212.107.29.67 · 香港 · Kirino AS41378'));
    assert.ok(lines[6].includes('国际 Tier-1 多线 (Cogent / Zayo / GTT)'));

    // Strictly assert all 6 real-device UI complaints in Problem A are eliminated
    assert.ok(!html.includes('fde63gz6'), 'Must NOT display random transit domain');
    assert.ok(!html.includes(':10011'), 'Must NOT display entrance port');
    assert.ok(!html.includes('Kowloon'), 'Must NOT display redundant HK English district');
    assert.ok(!html.includes('☁️ HKG'), 'Must NOT append CF POP to path bar when WARP is off');
    assert.ok(!html.includes('原生直出'), 'Must NOT display confusing [原生直出] when WARP is off');
    assert.ok(!html.includes('/24'), 'Must NOT display BGP /24 prefix');
    assert.ok(!html.includes('聚合网关'), 'Must NOT display separate aggregator row');
    assert.ok(!html.includes('%'), 'Must NOT display BGP upstream percentages');
    assert.ok(!html.includes('原生直走隧道'), 'Must NOT display footer jargon');
    assert.ok(!html.includes('▸'), 'Must NOT display noisy section headers');
    assert.ok(!/color\s*:\s*(#000|#fff|black|white)/i.test(html), 'Must adapt to iOS light/dark mode');

    // Verify optional rows appear ONLY when active (WARP=on + IPv6 + Claim Mismatch) and stay <= 9 lines
    const fullOptHtml = core.renderInfoSheetHTML({
      nodeName: '🇭🇰 深港 IEPL 直连伪标',
      nodeInfo: { type: 'vless' },
      domestic: { ip: '49.77.226.174', fullTag: '江苏南京电信', shortTag: '南京电信' },
      entrance: { status: 'ok', entranceIP: '212.107.29.67', geo: { countryCode: 'HK', asn: 'AS41378' } },
      probe: {
        landing: { ip: '212.107.29.67', country: '香港', countryCode: 'HK', isp: 'Kirino LLC', asn: 'AS41378' },
        ipv6: { ip: '2400:8902:f03c:93ff:fe12:3456:7890:abcd' },
        bgp: bgpTier1,
        cfTrace: { colo: 'HKG', warp: 'on' },
        elapsedMs: 195,
      },
      hostClient: 'loon',
    });
    const optLines = extractRenderedLines(fullOptHtml);
    assert.ok(optLines.length <= 9, 'Even with IPv6 + WARP + Warning, info card must stay <= 9 lines');
    assert.ok(fullOptHtml.includes('➔ <span style="color:#8b5cf6;font-weight:600">WARP</span>'));
    assert.ok(fullOptHtml.includes('支持 IPv6'));
    assert.ok(fullOptHtml.includes('2400:8902:…:abcd'), 'Long IPv6 must be compactly shortened');
    assert.ok(fullOptHtml.includes('已启用 (HKG)'));
    assert.ok(fullOptHtml.includes('节点名含专线/中转，实测出入口为同一 IP'));
  });

  await runTest('MODE=purity stays within 6~7 lines, parses ipinfo widget dual-ISP, and NEVER outputs "未知" or duplicates', () => {
    // 1. Dual-ISP residential from ipinfo.io/widget/demo/{ip}
    const ipinfoDual = core.parseIPInfoWidget({
      input: '73.15.20.25',
      data: {
        ip: '73.15.20.25',
        country: 'US',
        asn: { asn: 'AS7922', name: 'Comcast Cable', route: '73.15.0.0/16', type: 'isp' },
        company: { name: 'Comcast Cable', type: 'isp' },
        privacy: { vpn: false, proxy: false, tor: false, relay: false, hosting: false },
        abuse: { country: 'US', network: '73.15.0.0/16' },
      },
    });
    assert.strictEqual(ipinfoDual.hasDualTypes, true);
    assert.strictEqual(ipinfoDual.lineageLabel, '双 ISP 原生家宽');
    assert.strictEqual(ipinfoDual.asnTypeText, '住宅 (ISP)');
    assert.strictEqual(ipinfoDual.companyTypeText, '住宅 (ISP)');
    assert.strictEqual(ipinfoDual.isNativeGeo, true);

    const purityHtml1 = core.renderPuritySheetHTML({
      nodeName: '🇺🇸 美国原生家宽',
      probe: {
        landing: { ip: '73.15.20.25', country: 'United States', countryCode: 'US', region: 'California', city: 'Los Angeles', isp: 'Comcast Cable Communications, LLC', asn: 'AS7922' },
        purity: ipinfoDual,
        ipPure: core.parseIPPure({ ip: '73.15.20.25', asn: 7922, fraudScore: 8, isResidential: true, isBroadcast: false }),
        proxyCheck: null,
        ipScore: { totalBlacklists: 42, listedCount: 0, listedNames: [] },
      },
    });
    const pLines1 = extractRenderedLines(purityHtml1);
    assert.strictEqual(pLines1.length, 7, 'Purity card with dual types should be 7 lines');
    assert.ok(purityHtml1.includes('73.15.20.25 · 美国 Los Angeles · Comcast AS7922'));
    assert.ok(purityHtml1.includes('双 ISP 原生家宽'));
    assert.ok(purityHtml1.includes('ASN 住宅 (ISP) · 运营 住宅 (ISP)'));
    assert.ok(purityHtml1.includes('· 欺诈值 8'));
    assert.ok(purityHtml1.includes('无代理 / VPN / 滥用标记'));
    assert.ok(purityHtml1.includes('未命中'));
    assert.ok(!purityHtml1.includes('未知'));
    assert.ok(!purityHtml1.includes('非住宅'));
    assert.ok(!purityHtml1.includes('原生宣告'));
    assert.ok(!purityHtml1.includes('▰'));
    assert.ok(!purityHtml1.includes('出口 BGP'));
    assert.ok(!purityHtml1.includes('原生直走隧道'));

    // 2. Regression guard for Problem B.1: ipapi.is returns partial object WITHOUT asn.type / company.type
    //    AND ipinfo fails -> must HIDE 类型 row, NEVER output "未知 | 未知" or "普通网络", and use IPPure!
    const partialIpapi = core.parseIPAPIIs({
      ip: '212.107.29.67',
      asn: { asn: 41378, org: 'Kirino LLC' },
      company: { name: 'Kirino LLC' },
      location: { country_code: 'HK' },
    });
    assert.strictEqual(partialIpapi.hasDualTypes, false);
    assert.strictEqual(partialIpapi.asnTypeText, '');
    assert.strictEqual(partialIpapi.companyTypeText, '');
    assert.strictEqual(partialIpapi.lineageLabel, '');

    const purityHtml2 = core.renderPuritySheetHTML({
      nodeName: '🇭🇰 香港节点',
      probe: {
        landing: { ip: '212.107.29.67', country: '香港', countryCode: 'HK', city: 'Kowloon', isp: 'Kirino LLC', asn: 'AS41378' },
        purity: partialIpapi,
        ipPure: core.parseIPPure({ ip: '212.107.29.67', asn: 41378, fraudScore: 12, isResidential: false, isBroadcast: false }),
        proxyCheck: null,
        ipScore: { totalBlacklists: 42, listedCount: 0, listedNames: [] },
      },
    });
    const pLines2 = extractRenderedLines(purityHtml2);
    assert.strictEqual(pLines2.length, 6, 'Purity card without dual types must omit 类型 row (6 lines)');
    assert.ok(!purityHtml2.includes('未知'), 'Purity card must NEVER contain 未知');
    assert.ok(!purityHtml2.includes('普通网络'), 'Purity card must NEVER contain 普通网络');
    assert.ok(!purityHtml2.includes('类型'), 'Purity card must hide 类型 row when dual types unavailable');
    assert.ok(purityHtml2.includes('机房/商业网络'));
    assert.ok(purityHtml2.includes('原生 IP'));
  });

  console.log('\n=== [6] End-to-End Black-Box VM Simulations Across Clients ===');

  await runTest('Loon E2E (MODE=info): English "Shanghai" entrance normalized to "上海", GA [GA加速] tag, 7-line concise output', async () => {
    const res = await runScriptInSandbox(UNIVERSAL_FILE, {
      loon: 'iPhone16,2 18.2 3.5.1(998)',
      script: { name: '节点链路查询' },
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
      dnsHandler: (qOpts) => ({
        domain: qOpts.domain,
        answers: [{ name: qOpts.domain, type: 'A', value: '47.115.88.99', ttl: 60 }],
      }),
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
        // Simulate CN precision APIs timing out while international ip.sb returns English "Shanghai"!
        if (u.includes('api-ipv4.ip.sb/geoip/47.115.88.99')) {
          return {
            body: {
              ip: '47.115.88.99',
              country_code: 'CN',
              country: 'China',
              region: 'Shanghai',
              city: 'Shanghai',
              asn: 37963,
              organization: 'Alibaba Cloud',
            },
          };
        }
        if (u.includes('ip.netart.cn') || u.includes('speedtest.cn') || u.includes('pingan.com.cn')) {
          return { status: 503, body: '' };
        }
        if (u.includes('ip-api.com/json/?fields=')) {
          return {
            body: {
              status: 'success',
              query: '218.102.50.60',
              country: '香港',
              countryCode: 'HK',
              regionName: 'Kowloon',
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

    assert.strictEqual(res.donePayload.title, '节点链路查询');
    const html = res.donePayload.htmlMessage;
    assert.ok(html.includes('VLESS · <span style="color:#8b5cf6;font-weight:600">云全球加速中转</span>'));
    assert.ok(html.includes('🇨🇳 南京电信'));
    assert.ok(html.includes('🇨🇳 上海阿里云'), 'English Shanghai must be normalized to 上海');
    assert.ok(!html.includes('Shanghai'), 'English Shanghai must NEVER leak into UI');
    assert.ok(!html.includes('Kowloon'), 'HK district Kowloon must NEVER leak into UI');
    assert.ok(!html.includes(':14433'), 'Entrance port must NOT appear in UI');
    assert.ok(!html.includes('hk-ga.example.net'), 'Entrance domain must NOT appear as separate row');
    assert.ok(html.includes('[GA加速]'), 'GA CNAME hit must append [GA加速]');
    assert.strictEqual(extractRenderedLines(html).length, 7);

    const landingCall = res.httpCalls.find((c) => c.url.includes('ip-api.com/json/?fields='));
    assert.strictEqual(landingCall.node, '🇭🇰 阿里全球加速节点');
    assert.strictEqual(landingCall.timeout, 9000);
    assert.strictEqual(landingCall['auto-redirect'], false);
  });

  await runTest('Loon E2E (MODE=purity): ipapi.is 429 automatically triggers ipinfo.io/widget/demo/{ip} dual-ISP fallback, zero BGP call, <=5s sub-timeouts', async () => {
    const res = await runScriptInSandbox(UNIVERSAL_FILE, {
      loon: 'iPhone16,2 18.2 3.5.1(998)',
      script: { name: '节点纯净度检测' },
      argument: { MASK_IP: false, TIMEOUT_SEC: 9 },
      environment: { params: {} },
      configState: { running_model: 1, final: 'Proxy', selected: '🇺🇸 美国原生家宽' },
      onHttp: (method, req) => {
        const u = req.url;
        if (u.includes('stat.ripe.net')) {
          throw new Error('Purity mode must NOT request stat.ripe.net BGP upstreams!');
        }
        if (u.includes('ip-api.com/json/?fields=')) {
          return {
            body: {
              status: 'success',
              query: '73.15.20.25',
              country: '美国',
              countryCode: 'US',
              regionName: 'California',
              city: 'Los Angeles',
              isp: 'Comcast Cable Communications, LLC',
              as: 'AS7922 Comcast Cable Communications',
            },
          };
        }
        // ipapi.is rate limited -> should fallback to ipinfo.io/widget/demo/73.15.20.25
        if (u.includes('api.ipapi.is')) {
          return { status: 429, body: '{"error":"rate limited"}' };
        }
        if (u.includes('ipinfo.io/widget/demo/73.15.20.25')) {
          assert.strictEqual(req.headers.Referer, 'https://ipinfo.io/');
          return {
            body: {
              input: '73.15.20.25',
              data: {
                ip: '73.15.20.25',
                country: 'US',
                asn: { asn: 'AS7922', name: 'Comcast Cable', type: 'isp' },
                company: { name: 'Comcast Cable', type: 'isp' },
                privacy: { vpn: false, proxy: false, tor: false, relay: false, hosting: false },
                abuse: { country: 'US' },
              },
            },
          };
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
        return { status: 404, body: '' };
      },
    });

    assert.strictEqual(res.donePayload.title, '节点纯净度检测');
    const html = res.donePayload.htmlMessage;
    assert.ok(html.includes('双 ISP 原生家宽'));
    assert.ok(html.includes('原生 IP'));
    assert.ok(html.includes('ASN 住宅 (ISP) · 运营 住宅 (ISP)'));
    assert.ok(html.includes('· 欺诈值 8'));
    assert.ok(html.includes('未命中'));
    assert.ok(!html.includes('未知'));
    assert.strictEqual(extractRenderedLines(html).length, 7);

    // Ensure every purity sub-request timeout is capped at <= 5000ms even when TIMEOUT_SEC=9
    const subCalls = res.httpCalls.filter((c) => !c.url.includes('ip-api.com/json/?fields='));
    assert.ok(subCalls.length >= 4);
    for (const c of subCalls) {
      assert.ok(c.timeout <= 5000, `Purity sub-request ${c.url} timeout must be <= 5000ms, got ${c.timeout}`);
    }
  });

  await runTest('Clash-Client E2E: Fake $loon trap defeated + Bridge fallback to $config switch & policy restoration', async () => {
    const res = await runScriptInSandbox(CLASH_FG_FILE, {
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

    assert.ok(res.donePayload.htmlMessage.includes('单跳直连'));
    assert.ok(res.donePayload.htmlMessage.includes('节点名含专线/中转，实测出入口为同一 IP'));
    assert.ok(res.donePayload.htmlMessage.includes('中国优化 (电信 CN2)'));
  });

  await runTest('Surge & Stash E2E: Second-unit timeouts, Surge $httpAPI (Proxy) stripping & Stash header injection', async () => {
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
    assert.ok(surgeRes.donePayload.htmlMessage.includes('国内 BGP 云中转'));
    assert.ok(surgeRes.donePayload.htmlMessage.includes('120.76.99.88'));

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

  await runTest('Loon E2E: Streaming Unlock (clean single-screen, no footer) & Network-Changed Notification & Web Portal JSON', async () => {
    const unlockRes = await runScriptInSandbox(UNIVERSAL_FILE, {
      loon: 'iPhone16,2 18.2 3.5.1(998)',
      script: { name: '流媒体与解锁检测' },
      argument: { MASK_IP: false, TIMEOUT_SEC: 8 },
      environment: { params: { node: '🇸🇬 新加坡解锁节点', nodeInfo: { address: '103.20.30.40', port: 443, type: 'Hysteria2' } } },
      onHttp: (method, req) => {
        const u = req.url;
        if (u.includes('ip-api.com')) return { body: { status: 'success', query: '103.20.30.40', country: '新加坡', countryCode: 'SG', city: 'Singapore' } };
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
    assert.strictEqual(unlockRes.donePayload.title, '流媒体与解锁检测');
    const uHtml = unlockRes.donePayload.htmlMessage;
    assert.ok(uHtml.includes('完整解锁 [SG] (Web+App)'));
    assert.ok(uHtml.includes('完整解锁 [SG]'));
    assert.ok(uHtml.includes('已解锁 [SG]'));
    assert.ok(!uHtml.includes('原生直走隧道'), 'Unlock popup must NOT include footer jargon');
    assert.strictEqual(extractRenderedLines(uHtml).length, 10);

    // Network-changed Event on Loon (using new menu tag 网络切换通知)
    const eventRes = await runScriptInSandbox(UNIVERSAL_FILE, {
      loon: 'iPhone16,2 18.2 3.5.1(998)',
      script: { name: '网络切换通知' },
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

    // Web Portal JSON endpoint with claimWarning
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
    assert.strictEqual(bodyJSON.version, '3.1.0');
    assert.strictEqual(bodyJSON.linkType.code, 'cf-cdn-origin');
    assert.strictEqual(bodyJSON.claimWarning, '节点名含专线，实测入口为 Cloudflare 公共边缘');
  });

  console.log(`\n==================================================`);
  console.log(`Core Multi-Client Test Summary: ${passed} passed, ${failed} failed`);
  console.log(`==================================================\n`);

  if (failed > 0) process.exit(1);
})();
