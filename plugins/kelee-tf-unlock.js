/**
 * TestFlight 区域限制解锁脚本 — Clash-Client 适配版
 * 移植自可莉插件仓库「TestFlight地区解锁」
 */
(function () {
  'use strict';
  try {
    if (typeof $request !== 'undefined' && $request && $request.body) {
      const obj = JSON.parse($request.body);
      if (obj && typeof obj === 'object') {
        obj.storefrontId = '143441-1,29';
        $done({ body: JSON.stringify(obj) });
        return;
      }
    }
  } catch (_) {}
  $done({});
})();
