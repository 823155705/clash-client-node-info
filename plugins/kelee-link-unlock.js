/**
 * 外链中转拦截页直跳脚本 — Loon & Clash-Client 多端通用版 (v3.0.0)
 * 移植自可莉插件仓库「微信外部链接解锁 / QQ链接解锁」，扩展支持知乎、微博、CSDN、掘金、简书外链直跳。
 * 内置纯 JS Base64 / URL-safe Base64 解码器，完全不依赖浏览器 atob 或 Node Buffer，100% 兼容 JavaScriptCore。
 */
(function () {
  'use strict';

  const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function decodeBase64Pure(input) {
    if (!input || typeof input !== 'string') return '';
    let str = input.trim().replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    if (!str || str.length % 4 === 1 || /[^A-Za-z0-9+/]/.test(str)) return '';
    while (str.length % 4 !== 0) str += '=';

    const bytes = [];
    for (let i = 0; i < str.length; i += 4) {
      const c0 = B64_CHARS.indexOf(str.charAt(i));
      const c1 = B64_CHARS.indexOf(str.charAt(i + 1));
      const ch2 = str.charAt(i + 2);
      const ch3 = str.charAt(i + 3);
      const c2 = ch2 === '=' ? 0 : B64_CHARS.indexOf(ch2);
      const c3 = ch3 === '=' ? 0 : B64_CHARS.indexOf(ch3);
      if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) return '';

      const triplet = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
      bytes.push((triplet >> 16) & 0xff);
      if (ch2 !== '=') bytes.push((triplet >> 8) & 0xff);
      if (ch3 !== '=') bytes.push(triplet & 0xff);
    }

    let pct = '';
    for (let i = 0; i < bytes.length; i++) {
      pct += '%' + ('00' + bytes[i].toString(16)).slice(-2);
    }
    try {
      return decodeURIComponent(pct);
    } catch (_) {
      let raw = '';
      for (let i = 0; i < bytes.length; i++) {
        raw += String.fromCharCode(bytes[i]);
      }
      return raw;
    }
  }

  function decodeURIComponentMulti(str) {
    let s = str;
    for (let i = 0; i < 2; i++) {
      try {
        const dec = decodeURIComponent(s);
        if (dec === s) break;
        s = dec;
      } catch (_) {
        break;
      }
    }
    return s;
  }

  function tryDecode(val) {
    if (!val) return '';
    const s = decodeURIComponentMulti(String(val).trim());
    if (/^https?:\/\//i.test(s)) return s;

    // 兼容标准 Base64、URL-safe Base64（- / _）及缺省 '=' 补齐
    if (/^[A-Za-z0-9+/=_-]{12,}$/.test(s)) {
      const raw = decodeBase64Pure(s);
      if (raw) {
        if (/^https?:\/\//i.test(raw)) return raw;
        const unwrapped = decodeURIComponentMulti(raw.trim());
        if (/^https?:\/\//i.test(unwrapped)) return unwrapped;
      }
    }
    return '';
  }

  function extractTargetURL(reqURL) {
    const qIdx = reqURL.indexOf('?');
    if (qIdx < 0) return '';
    const search = reqURL.slice(qIdx + 1).split('#')[0];
    const keys = ['pfurl', 'url', 'target', 'toasturl', 'u', 'gourl', 'dest', 'link'];
    const map = {};
    search.split('&').forEach((kv) => {
      const eq = kv.indexOf('=');
      if (eq > 0) {
        map[kv.slice(0, eq).toLowerCase()] = kv.slice(eq + 1);
      }
    });
    for (const k of keys) {
      if (map[k]) {
        const hit = tryDecode(map[k]);
        if (hit) return hit;
      }
    }
    return '';
  }

  try {
    const url = (typeof $request !== 'undefined' && $request && $request.url) || '';
    const target = extractTargetURL(url);
    if (target && target !== url) {
      $done({
        response: {
          status: 302,
          headers: {
            Location: target,
            'Cache-Control': 'no-store',
          },
          body: '',
        },
      });
      return;
    }
  } catch (_) {}

  $done({});
})();
