#!/usr/bin/env node
/**
 * 跨客户端插件规范与附属脚本沙箱自动化校验套件 (v3.0.0)
 * 运行方式: node tests/plugin-syntax.test.js
 */
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');
const REPO_RAW_PREFIX = 'https://raw.githubusercontent.com/823155705/clash-client-node-info/main/';

const LOON_ALLOWED_SECTIONS = new Set([
  'Argument',
  'General',
  'IP Rewrite',
  'Rule',
  'Rewrite',
  'Host',
  'Script',
  'MitM',
]);

const LOON_FORBIDDEN_SECTIONS = new Set([
  'Panel',
  'Remote Rule',
  'MITM',
  'Rule Set',
  'Proxy',
  'Proxy Group',
]);

const LOON_RULE_TYPES = new Set([
  'DOMAIN',
  'DOMAIN-SUFFIX',
  'DOMAIN-KEYWORD',
  'USER-AGENT',
  'URL-REGEX',
  'IP-CIDR',
  'IP-CIDR6',
  'IP-ASN',
  'GEOIP',
  'FINAL',
]);

const LOON_PLUGIN_POLICIES = new Set([
  'DIRECT',
  'PROXY',
  'REJECT',
  'REJECT-DROP',
  'REJECT-TINYGIF',
  'REJECT-200',
  'REJECT-IMG',
  'REJECT-DICT',
  'REJECT-ARRAY',
]);

const LOON_V2_WITH_KEYS = new Set([
  'tag',
  'img_url',
  'timeout',
  'enable',
  'requires_body',
  'binary_body_mode',
]);

const DOMESTIC_DIRECT_DOMAINS = [
  'myip.ipip.net',
  'r.inews.qq.com',
  '4.ipw.cn',
  'ip.3322.net',
  'whois.pconline.com.cn',
  'ip.netart.cn',
  'api-v3.speedtest.cn',
  'rmb.pingan.com.cn',
];

let passed = 0;
let failed = 0;

function runTest(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL  ${name}`);
    console.error(`        ${err && err.stack ? err.stack : err}`);
  }
}

function walkFiles(dir, matcher, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(full, matcher, out);
    } else if (matcher(full)) {
      out.push(full);
    }
  }
  return out.sort();
}

function splitTopLevelCSV(line) {
  const parts = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i - 1] !== '\\') {
      inQuotes = !inQuotes;
      cur += ch;
    } else if (ch === ',' && !inQuotes) {
      parts.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim() !== '') parts.push(cur.trim());
  return parts;
}

/**
 * 校验单个 Loon .lpx 文本内容，返回错误数组（空数组表示完全合规）
 */
function validateLoonLpxContent(content, label = '<inline>') {
  const errors = [];
  const lines = content.split(/\r?\n/);

  const meta = new Map();
  const declaredArgs = new Set();
  let currentSection = null;

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNo = idx + 1;
    const raw = lines[idx];
    const trimmed = raw.trim();
    if (!trimmed) continue;

    // 元数据头 #!key=val
    if (trimmed.startsWith('#!')) {
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx < 2) {
        errors.push(`${label}:${lineNo} 非法插件头元数据语法: ${trimmed}`);
      } else {
        meta.set(trimmed.slice(2, eqIdx).trim(), trimmed.slice(eqIdx + 1).trim());
      }
      continue;
    }

    // 普通注释行
    if (trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith(';')) {
      continue;
    }

    // 全局违禁项扫描
    if (/\bRULE-SET\b/i.test(trimmed)) {
      errors.push(`${label}:${lineNo} Loon 插件严禁包含 RULE-SET: ${trimmed}`);
    }
    if (/script-update-interval/i.test(trimmed)) {
      errors.push(`${label}:${lineNo} Loon 插件严禁包含 script-update-interval: ${trimmed}`);
    }
    if (/%APPEND%/i.test(trimmed)) {
      errors.push(`${label}:${lineNo} Loon 插件严禁包含 %APPEND%: ${trimmed}`);
    }

    // 段落头 [Section]
    const secMatch = trimmed.match(/^\[([^\]]+)\]$/);
    if (secMatch) {
      const secName = secMatch[1];
      if (LOON_FORBIDDEN_SECTIONS.has(secName) || !LOON_ALLOWED_SECTIONS.has(secName)) {
        errors.push(`${label}:${lineNo} 非法或不受支持的 Loon 插件段落 [${secName}]`);
      }
      currentSection = secName;
      continue;
    }

    if (!currentSection) {
      errors.push(`${label}:${lineNo} 段落外的孤立配置行: ${trimmed}`);
      continue;
    }

    if (currentSection === 'Argument') {
      const argMatch = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(switch|select|input)\s*,(.+)$/);
      if (!argMatch) {
        errors.push(`${label}:${lineNo} [Argument] 声明格式错误: ${trimmed}`);
      } else {
        declaredArgs.add(argMatch[1]);
      }
    } else if (currentSection === 'Rule') {
      const parts = splitTopLevelCSV(trimmed);
      if (parts.length < 2) {
        errors.push(`${label}:${lineNo} [Rule] 规则字段不足: ${trimmed}`);
        continue;
      }
      const rType = parts[0];
      if (!LOON_RULE_TYPES.has(rType)) {
        errors.push(`${label}:${lineNo} [Rule] 不支持的规则类型 ${rType}: ${trimmed}`);
      }
      const policy = rType === 'FINAL' ? parts[1] : parts[2];
      if (!LOON_PLUGIN_POLICIES.has(policy)) {
        errors.push(`${label}:${lineNo} [Rule] Loon 插件策略不合法 (${policy}): ${trimmed}`);
      }
      if (rType === 'URL-REGEX') {
        const pattern = parts[1].replace(/^"|"$/g, '');
        try {
          new RegExp(pattern);
        } catch (e) {
          errors.push(`${label}:${lineNo} [Rule] URL-REGEX 正则编译失败: ${e.message}`);
        }
      }
      if (rType === 'IP-CIDR' && !/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(parts[1])) {
        errors.push(`${label}:${lineNo} [Rule] IP-CIDR 格式非法: ${parts[1]}`);
      }
      if (rType === 'IP-CIDR6' && !/^[0-9a-fA-F:]+\/\d{1,3}$/.test(parts[1])) {
        errors.push(`${label}:${lineNo} [Rule] IP-CIDR6 格式非法: ${parts[1]}`);
      }
    } else if (currentSection === 'Rewrite') {
      if (/\s+30[1278]\s*$/.test(trimmed)) {
        errors.push(`${label}:${lineNo} [Rewrite] 存在 Surge 风格末尾状态码（Loon 顺序错误）: ${trimmed}`);
      }
      const rwMatch = trimmed.match(
        /^(request|response)\s+if\s+\$\{url\}\s*~=\s*\/(.+)\/([a-z]*)\s+then\s+redirect\((30[1278]),\s*"([^"]+)"\)$/
      );
      if (!rwMatch) {
        errors.push(`${label}:${lineNo} [Rewrite] 未采用 Loon v2 标准 redirect 语法: ${trimmed}`);
      } else {
        try {
          new RegExp(rwMatch[2], rwMatch[3]);
        } catch (e) {
          errors.push(`${label}:${lineNo} [Rewrite] 正则语法错误: ${e.message}`);
        }
      }
    } else if (currentSection === 'Script') {
      const scMatch = trimmed.match(
        /^(generic|network-changed|cron\s+"[^"]+"|(?:request|response)\s+if\s+.+?)\s+then\s+script\("([^"]+)"(?:\s*,\s*\{(.+)\})?\)(?:\s+with\s+(.+))?$/
      );
      if (!scMatch) {
        errors.push(`${label}:${lineNo} [Script] 未采用 Loon v2 标准 script(...) 语法: ${trimmed}`);
        continue;
      }

      const trigger = scMatch[1];
      const argObjBody = scMatch[3];
      const withClause = scMatch[4] || '';

      // 校验 request/response 条件中的正则表达式
      const condRegexMatch = trigger.match(/\$\{url\}\s*~=\s*\/(.+)\/([a-z]*)$/);
      if (condRegexMatch) {
        try {
          new RegExp(condRegexMatch[1], condRegexMatch[2]);
        } catch (e) {
          errors.push(`${label}:${lineNo} [Script] 匹配正则编译失败: ${e.message}`);
        }
      }

      // 校验 PluginObject 参数对象 {${ARG1}, ${ARG2}}
      if (argObjBody !== undefined) {
        const argTokens = splitTopLevelCSV(argObjBody);
        if (argTokens.length === 0) {
          errors.push(`${label}:${lineNo} [Script] 空参数对象 {}`);
        }
        for (const tok of argTokens) {
          const varMatch = tok.match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/);
          if (!varMatch) {
            errors.push(`${label}:${lineNo} [Script] 插件参数对象内含非法项 "${tok}"（仅允许 \${ARG}）`);
          } else if (!declaredArgs.has(varMatch[1])) {
            errors.push(`${label}:${lineNo} [Script] 引用了未在 [Argument] 声明的变量 \${${varMatch[1]}}`);
          }
        }
      }

      // 校验 with 属性键值对（必须为 snake_case 且变量引用已声明）
      if (withClause) {
        const kvList = splitTopLevelCSV(withClause);
        const withMap = new Map();
        for (const kv of kvList) {
          const eq = kv.indexOf('=');
          if (eq <= 0) {
            errors.push(`${label}:${lineNo} [Script] with 子句属性格式非法: ${kv}`);
            continue;
          }
          const k = kv.slice(0, eq).trim();
          const v = kv.slice(eq + 1).trim();
          if (!LOON_V2_WITH_KEYS.has(k)) {
            errors.push(`${label}:${lineNo} [Script] with 子句包含不支持或非 snake_case 属性 "${k}"`);
          }
          withMap.set(k, v);

          const withVarMatch = v.match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/);
          if (withVarMatch && !declaredArgs.has(withVarMatch[1])) {
            errors.push(`${label}:${lineNo} [Script] with 属性 ${k} 引用了未声明变量 \${${withVarMatch[1]}}`);
          }
        }

        if (trigger === 'generic') {
          const img = (withMap.get('img_url') || '').replace(/^"|"$/g, '');
          if (!img.endsWith('.system') && !/^https?:\/\//i.test(img)) {
            errors.push(`${label}:${lineNo} [Script] generic 脚本 img_url 应使用 .system 后缀或远程图标: ${img}`);
          }
        }
      }
    } else if (currentSection === 'Host') {
      if (!/^[A-Za-z0-9.-]+\s*=\s*.+$/.test(trimmed)) {
        errors.push(`${label}:${lineNo} [Host] 语法错误: ${trimmed}`);
      }
    } else if (currentSection === 'MitM') {
      if (!/^hostname\s*=\s*[A-Za-z0-9.*,\s-]+$/.test(trimmed)) {
        errors.push(`${label}:${lineNo} [MitM] hostname 语法错误: ${trimmed}`);
      }
    }
  }

  const requiredMeta = [
    'name',
    'desc',
    'openUrl',
    'author',
    'tag',
    'system',
    'system_version',
    'loon_version',
    'homepage',
    'icon',
    'date',
  ];
  for (const k of requiredMeta) {
    if (!meta.has(k)) {
      errors.push(`${label} 缺少可莉/Loon 标准元数据字段 #!${k}=`);
    }
  }
  if (!meta.get('name')) errors.push(`${label} #!name 不能为空`);
  if (!meta.get('desc')) errors.push(`${label} #!desc 不能为空`);
  if (meta.get('loon_version') !== '3.5.1(983)') {
    errors.push(`${label} #!loon_version 必须标注为 3.5.1(983)，当前为: ${meta.get('loon_version')}`);
  }

  return { errors, meta, declaredArgs };
}

console.log('=== 1. 仓库插件清单完整性校验 ===');

const lpxFiles = walkFiles(ROOT, (f) => f.endsWith('.lpx')).map((f) => path.relative(ROOT, f));
const pluginFiles = walkFiles(ROOT, (f) => f.endsWith('.plugin')).map((f) => path.relative(ROOT, f));

runTest('发现全部 5 款 Loon 原生插件 (.lpx) 与 5 款 Clash-Client 插件 (.plugin)', () => {
  assert.deepEqual(lpxFiles, [
    'loon/plugins/kelee-google-tf-unlock.lpx',
    'loon/plugins/kelee-httpdns-guard.lpx',
    'loon/plugins/kelee-link-unlock.lpx',
    'loon/plugins/loon-ad-guard.lpx',
    'xream-loon-node-info.lpx',
  ]);
  assert.deepEqual(pluginFiles, [
    'plugins/clash-ad-guard.plugin',
    'plugins/kelee-google-tf-unlock.plugin',
    'plugins/kelee-httpdns-guard.plugin',
    'plugins/kelee-link-unlock.plugin',
    'xream-clash-node-info.plugin',
  ]);
});

console.log('\n=== 2. Loon (.lpx) 官方 v2 规范与可莉标准逐项审计 ===');

for (const rel of lpxFiles) {
  runTest(`Loon 插件语法与元数据合规: ${rel}`, () => {
    const content = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const { errors } = validateLoonLpxContent(content, rel);
    assert.deepEqual(errors, [], `发现违规项:\n  - ${errors.join('\n  - ')}`);
  });
}

runTest('校验器反向自测：能精准拦截 [Panel] / [Remote Rule] / RULE-SET / %APPEND% / 末尾302 / 未声明变量', () => {
  const badSample = [
    '#!name=Bad',
    '#!desc=Bad',
    '#!openUrl=',
    '#!author=Test',
    '#!tag=Test',
    '#!system=iOS',
    '#!system_version=',
    '#!loon_version=3.5.1(983)',
    '#!homepage=https://example.com',
    '#!icon=https://example.com/a.png',
    '#!date=2026-11-17',
    '[Argument]',
    'DECLARED_SW = switch, true, tag = 开关',
    '[Panel]',
    '[Remote Rule]',
    '[Rule]',
    'RULE-SET, https://example.com/a.list, REJECT',
    '[Rewrite]',
    '^https?:\\/\\/g\\.cn https://www.google.com 302',
    '[Script]',
    'generic then script("https://example.com/a.js", {${DECLARED_SW}, ${UNDECLARED_VAR}}) with tag="测试", img-url="globe.system", script-update-interval=86400',
    '[MitM]',
    'hostname = %APPEND% example.com',
  ].join('\n');

  const { errors } = validateLoonLpxContent(badSample, 'bad.lpx');
  assert.ok(errors.some((e) => e.includes('[Panel]')));
  assert.ok(errors.some((e) => e.includes('[Remote Rule]')));
  assert.ok(errors.some((e) => e.includes('RULE-SET')));
  assert.ok(errors.some((e) => e.includes('末尾状态码')));
  assert.ok(errors.some((e) => e.includes('UNDECLARED_VAR')));
  assert.ok(errors.some((e) => e.includes('script-update-interval')));
  assert.ok(errors.some((e) => e.includes('%APPEND%')));
  assert.ok(errors.some((e) => e.includes('img-url')));
});

runTest('xream-loon-node-info.lpx 核心配置专项核验（5路 v2 脚本 + 7原生参数 + 8直连规则）', () => {
  const content = fs.readFileSync(path.join(ROOT, 'xream-loon-node-info.lpx'), 'utf8');
  const { declaredArgs } = validateLoonLpxContent(content, 'xream-loon-node-info.lpx');

  assert.deepEqual(
    [...declaredArgs],
    [
      'SHOW_DOMESTIC',
      'SHOW_ENTRANCE',
      'CHECK_IPV6',
      'MASK_IP',
      'NOTIFY_ON_CHANGE',
      'TIMEOUT_SEC',
      'IPAPI_KEY',
    ]
  );

  // 确保未混入 Clash-Client 专属控制器参数
  assert.ok(!content.includes('CONTROLLER_PORT'));
  assert.ok(!content.includes('CONTROLLER_SECRET'));
  assert.ok(!content.includes('AUTO_SWITCH_FALLBACK'));
  assert.ok(!content.includes('force-http-engine-hosts'));

  // 全部 8 个国内直连检测域名齐备
  for (const domain of DOMESTIC_DIRECT_DOMAINS) {
    assert.match(content, new RegExp(`DOMAIN,\\s*${domain.replace(/\./g, '\\.')},\\s*DIRECT`));
  }

  // 5 条脚本全部指向 v3.0.0 通用入口产物
  const scriptMatches = content.match(
    /script\("https:\/\/raw\.githubusercontent\.com\/823155705\/clash-client-node-info\/main\/xream-node-info\.js\?v=3\.0\.0"/g
  );
  assert.equal(scriptMatches && scriptMatches.length, 5);
  assert.match(content, /tag="节点链路与入口查询",\s*img_url="globe\.asia\.australia\.system",\s*timeout=45/);
  assert.match(content, /tag="节点纯净度深度检测",\s*img_url="shield\.lefthalf\.filled\.system",\s*timeout=50/);
  assert.match(content, /tag="流媒体与 AI 解锁检测",\s*img_url="play\.tv\.system",\s*timeout=60/);
  assert.match(content, /with enable=\$\{NOTIFY_ON_CHANGE\},\s*tag="网络切换出口通知",\s*timeout=45/);
  assert.match(content, /request if \$\{url\} ~= \/\^https\?:\\\/\\\/net-lsp-x\\\.com\/i then script\(/);
});

runTest('4 款可莉 Loon 实用插件专项核验（无 RULE-SET、HTTPDNS 双栈+正则、TF requires_body snake_case）', () => {
  const adGuard = fs.readFileSync(path.join(ROOT, 'loon/plugins/loon-ad-guard.lpx'), 'utf8');
  assert.match(adGuard, /DOMAIN-KEYWORD,/);
  assert.match(adGuard, /DOMAIN-SUFFIX,/);
  assert.ok(!adGuard.includes('RULE-SET'));

  const httpdns = fs.readFileSync(path.join(ROOT, 'loon/plugins/kelee-httpdns-guard.lpx'), 'utf8');
  assert.match(httpdns, /DOMAIN-KEYWORD,\s*httpdns,\s*REJECT/);
  assert.match(httpdns, /IP-CIDR,\s*203\.107\.1\.0\/24,\s*REJECT,\s*no-resolve/);
  assert.match(httpdns, /IP-CIDR6,\s*[0-9a-fA-F:]+\/\d+,\s*REJECT,\s*no-resolve/);
  assert.match(httpdns, /URL-REGEX,\s*"\^https\?:\\\/\\\//);
  // 确保不误杀本套件使用的阿里 DoH 223.5.5.5 / 223.6.6.6 标准 JSON 接口
  const urlRegexLine = httpdns.split(/\r?\n/).find((l) => l.trim().startsWith('URL-REGEX,'));
  const urlPattern = splitTopLevelCSV(urlRegexLine)[1].replace(/^"|"$/g, '');
  const rawIpHttpdnsRe = new RegExp(urlPattern);
  assert.equal(rawIpHttpdnsRe.test('http://203.107.1.33/100000/d?host=m.taobao.com'), true);
  assert.equal(rawIpHttpdnsRe.test('http://180.76.76.200/v4/resolve?dn=baidu.com'), true);
  assert.equal(rawIpHttpdnsRe.test('https://223.5.5.5/resolve?name=example.com&type=A'), false);
  assert.equal(rawIpHttpdnsRe.test('http://223.6.6.6/resolve?name=example.com&type=A'), false);

  const linkUnlock = fs.readFileSync(path.join(ROOT, 'loon/plugins/kelee-link-unlock.lpx'), 'utf8');
  assert.match(linkUnlock, /plugins\/kelee-link-unlock\.js\?v=3\.0\.0/);
  assert.match(linkUnlock, /with tag="外部链接直跳解锁",\s*timeout=10/);

  const googleTf = fs.readFileSync(path.join(ROOT, 'loon/plugins/kelee-google-tf-unlock.lpx'), 'utf8');
  assert.match(googleTf, /DOMAIN,\s*testflight\.apple\.com,\s*PROXY/);
  assert.match(googleTf, /redirect\(307,\s*"https:\/\/www\.google\.com"\)/);
  assert.match(googleTf, /redirect\(307,\s*"https:\/\/maps\.google\.com"\)/);
  assert.match(googleTf, /plugins\/kelee-tf-unlock\.js\?v=3\.0\.0"\)\s*with requires_body=true/);
});

console.log('\n=== 3. Clash-Client (.plugin) 兼容性与 v3.0.0 升级校验 ===');

for (const rel of pluginFiles) {
  runTest(`Clash-Client 插件结构与参数引用校验: ${rel}`, () => {
    const content = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    for (const key of ['name', 'desc', 'author', 'homepage', 'icon', 'date']) {
      assert.match(content, new RegExp(`^#!${key}=.+`, 'm'), `${rel} 缺少 #!${key}`);
    }

    // 收集 [Argument] 声明并核对 argument="..." 中的 {ARG} 占位符
    const declared = new Set();
    let inArg = false;
    for (const line of content.split(/\r?\n/)) {
      const t = line.trim();
      if (/^\[.+\]$/.test(t)) {
        inArg = t === '[Argument]';
        continue;
      }
      if (inArg && t && !t.startsWith('#')) {
        const m = t.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=/);
        if (m) declared.add(m[1]);
      }
      const argStrMatch = t.match(/argument="([^"]+)"/);
      if (argStrMatch) {
        for (const ph of argStrMatch[1].matchAll(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g)) {
          assert.ok(declared.has(ph[1]), `${rel} 引用了未声明的 [Argument] 参数 {${ph[1]}}`);
        }
      }
    }
  });
}

runTest('xream-clash-node-info.plugin v3.0.0 平滑升级专项核验（CLIENT=clash + 前后台双产物隔离 + 8直连规则）', () => {
  const content = fs.readFileSync(path.join(ROOT, 'xream-clash-node-info.plugin'), 'utf8');
  assert.match(content, /10类零忽悠证据分级拓扑与名称验伪/);
  assert.match(content, /四源风控/);
  assert.match(content, /#!date=2026-11-17/);

  for (const domain of DOMESTIC_DIRECT_DOMAINS) {
    assert.match(content, new RegExp(`DOMAIN,${domain.replace(/\./g, '\\.')},DIRECT`));
  }

  const fgRefs = content.match(/xream-clash-node-info\.js\?v=3\.0\.0/g) || [];
  const bgRefs = content.match(/xream-clash-node-bg\.js\?v=3\.0\.0/g) || [];
  assert.equal(fgRefs.length, 3, '3 个前台 generic 菜单必须继续指向 xream-clash-node-info.js?v=3.0.0');
  assert.equal(bgRefs.length, 2, '2 个后台脚本必须继续指向 xream-clash-node-bg.js?v=3.0.0');

  const clientHints = content.match(/argument="CLIENT=clash&MODE=/g) || [];
  assert.equal(clientHints.length, 5, '全部 5 条脚本均须显式注入 CLIENT=clash&');
});

console.log('\n=== 4. 外链脚本引用对齐与无 atob 纯 JavaScriptCore 沙箱仿真测试 ===');

runTest('所有 .lpx / .plugin 引用的仓库远程脚本均带 ?v=3.0.0 且本地已存在文件均可无错编译', () => {
  const allPluginContents = [...lpxFiles, ...pluginFiles].map((rel) => ({
    rel,
    content: fs.readFileSync(path.join(ROOT, rel), 'utf8'),
  }));

  const referencedRelScripts = new Set();
  for (const { rel, content } of allPluginContents) {
    const urlMatches = content.matchAll(
      /https:\/\/raw\.githubusercontent\.com\/823155705\/clash-client-node-info\/main\/([^\s",)]+)/g
    );
    for (const m of urlMatches) {
      const fullTarget = m[1];
      assert.match(fullTarget, /\?v=3\.0\.0$/, `${rel} 脚本引用未统一升级至 ?v=3.0.0: ${fullTarget}`);
      referencedRelScripts.add(fullTarget.split('?')[0]);
    }
  }

  // plugins/ 下的脚本必须本地存在；根目录核心脚本若在当前工作区存在则一并校验语法
  for (const scriptRel of referencedRelScripts) {
    const abs = path.join(ROOT, scriptRel);
    if (scriptRel.startsWith('plugins/')) {
      assert.ok(fs.existsSync(abs), `缺少附属脚本文件: ${scriptRel}`);
    }
    if (fs.existsSync(abs)) {
      const code = fs.readFileSync(abs, 'utf8');
      new vm.Script(code, { filename: scriptRel });
    }
  }
});

function executeInJscSandbox(scriptRelPath, requestObj) {
  const code = fs.readFileSync(path.join(ROOT, scriptRelPath), 'utf8');
  let donePayload = undefined;

  const sandbox = Object.create(null);
  sandbox.$request = requestObj;
  sandbox.$done = (res) => {
    donePayload = res;
  };
  sandbox.atob = undefined;
  sandbox.btoa = undefined;
  sandbox.Buffer = undefined;

  const ctx = vm.createContext(sandbox);
  // 显式抹除沙箱 globalThis 上可能挂载的 Node 18+ 全局 atob / btoa / Buffer
  vm.runInContext(
    'delete globalThis.atob; delete globalThis.btoa; delete globalThis.Buffer;',
    ctx
  );
  const hasAtobInSandbox = vm.runInContext('typeof atob', ctx);
  assert.equal(hasAtobInSandbox, 'undefined', '沙箱必须完全不存在全局 atob');

  vm.runInContext(code, ctx, { filename: scriptRelPath, timeout: 2000 });
  return donePayload;
}

runTest('plugins/kelee-link-unlock.js 源码级零 atob / Buffer 依赖检查', () => {
  const src = fs.readFileSync(path.join(ROOT, 'plugins/kelee-link-unlock.js'), 'utf8');
  // 剥离注释后检查不含 atob 或 Buffer
  const codeOnly = src.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '');
  assert.equal(/\batob\b/.test(codeOnly), false, '业务代码不得引用 atob');
  assert.equal(/\bBuffer\b/.test(codeOnly), false, '业务代码不得引用 Node Buffer');
});

runTest('无 atob 沙箱：标准 Base64（含 = 填充）外链精准解码并返回 302', () => {
  const dest = 'https://github.com/xream/scripts?tab=readme-ov-file';
  const b64 = Buffer.from(dest, 'utf8').toString('base64'); // 含 '='
  const res = executeInJscSandbox('plugins/kelee-link-unlock.js', {
    url: `https://link.juejin.cn/?target=${encodeURIComponent(b64)}`,
  });
  assert.equal(res?.response?.status, 302);
  assert.equal(res?.response?.headers?.Location, dest);
  assert.equal(res?.response?.headers?.['Cache-Control'], 'no-store');
});

runTest('无 atob 沙箱：URL-safe Base64（含 - 与 _ 且缺省 = 补齐）外链精准解码并返回 302', () => {
  // '>>>' 编码产生 '+' -> '-'，'???' 编码产生 '/' -> '_'，末尾单字符使长度非 4 倍数
  const dest = 'https://example.org/a?x=>>>&y=???1';
  const urlSafeUnpadded = Buffer.from(dest, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  assert.ok(urlSafeUnpadded.includes('-') && urlSafeUnpadded.includes('_'));
  assert.notEqual(urlSafeUnpadded.length % 4, 0);

  const res = executeInJscSandbox('plugins/kelee-link-unlock.js', {
    url: `https://weixin110.qq.com/cgi-bin/mmspamsupport-bin/newredirectconfirmcgi?url=${urlSafeUnpadded}`,
  });
  assert.equal(res?.response?.status, 302);
  assert.equal(res?.response?.headers?.Location, dest);
});

runTest('无 atob 沙箱：含 UTF-8 中文查询串的 Base64 外链与多重 URL 编码外链均精准 302', () => {
  const utf8Dest = 'https://www.google.com/search?q=节点纯净度检测&hl=zh-CN';
  const utf8B64 = Buffer.from(utf8Dest, 'utf8').toString('base64').replace(/=+$/, '');
  const res1 = executeInJscSandbox('plugins/kelee-link-unlock.js', {
    url: `https://c.pc.qq.com/middlem.html?pfurl=${utf8B64}`,
  });
  assert.equal(res1?.response?.status, 302);
  assert.equal(res1?.response?.headers?.Location, utf8Dest);

  const plainDest = 'https://developer.apple.com/documentation/networkextension';
  const doubleEncoded = encodeURIComponent(encodeURIComponent(plainDest));
  const res2 = executeInJscSandbox('plugins/kelee-link-unlock.js', {
    url: `https://link.zhihu.com/?target=${doubleEncoded}`,
  });
  assert.equal(res2?.response?.status, 302);
  assert.equal(res2?.response?.headers?.Location, plainDest);
});

runTest('无 atob 沙箱：非法参数或无目标外链时安全放行 $done({})', () => {
  const res1 = executeInJscSandbox('plugins/kelee-link-unlock.js', {
    url: 'https://weixin110.qq.com/cgi-bin/mmspamsupport-bin/newredirectconfirmcgi?main_type=5',
  });
  assert.deepEqual({ ...res1 }, {});

  const res2 = executeInJscSandbox('plugins/kelee-link-unlock.js', {
    url: 'https://link.csdn.net/?target=not_a_valid_url_at_all_12345',
  });
  assert.deepEqual({ ...res2 }, {});
});

runTest('plugins/kelee-tf-unlock.js 沙箱：精准改写 storefrontId 并保留请求体其余字段', () => {
  const res = executeInJscSandbox('plugins/kelee-tf-unlock.js', {
    url: 'https://testflight.apple.com/v3/accounts/abc-123/install',
    body: JSON.stringify({ storefrontId: '143465-19,29', appAdamId: '987654321' }),
  });
  const parsed = JSON.parse(res.body);
  assert.equal(parsed.storefrontId, '143441-1,29');
  assert.equal(parsed.appAdamId, '987654321');

  const fallback = executeInJscSandbox('plugins/kelee-tf-unlock.js', {
    url: 'https://testflight.apple.com/v3/accounts/abc-123/install',
    body: 'invalid-json',
  });
  assert.deepEqual({ ...fallback }, {});
});

console.log(`\n=== 校验汇总: ${passed} passed, ${failed} failed ===`);
if (failed > 0) {
  process.exit(1);
}
