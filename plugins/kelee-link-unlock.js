/**
 * 外链中转拦截页直跳脚本 — Clash-Client 适配版
 * 移植自可莉插件仓库「微信外部链接解锁 / QQ链接解锁」，扩展支持知乎、微博、CSDN、掘金、简书外链直跳
 */
(function () {
  'use strict';

  function tryDecode(val) {
    if (!val) return '';
    let s = String(val).trim();
    for (let i = 0; i < 2; i++) {
      try {
        const dec = decodeURIComponent(s);
        if (dec === s) break;
        s = dec;
      } catch (_) {
        break;
      }
    }
    if (/^https?:\/\//i.test(s)) return s;
    // 部分平台采用 Base64 编码目标 URL
    if (/^[A-Za-z0-9+/=_-]{12,}$/.test(s) && typeof atob === 'function') {
      try {
        const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(b64);
        if (/^https?:\/\//i.test(raw)) return raw;
      } catch (_) {}
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
    const url = ($request && $request.url) || '';
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
