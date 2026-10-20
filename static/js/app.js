/* ==========================================================================
   AD 域控管理系统 - 前端公共库
   设计原则：
   1. 所有写操作走 ADM.post()，统一错误提示（后端已翻译成中文）。
   2. 高危操作统一走 ADM.confirmDanger()，弹窗 + 二次勾选，提交时带 confirm=1。
   3. 不依赖 jQuery，离线内网可用。
   ========================================================================== */
(function (window, document) {
  'use strict';

  // Bootstrap 下拉菜单全局改用 Popper 的 fixed 定位策略：
  // 菜单挂在视口坐标系上，不再被 .table-responsive 等溢出容器裁剪（表格末行的
  // 操作下拉此前会因超出表格边界而被截断，导致无法选择菜单项）。
  if (window.bootstrap && window.bootstrap.Dropdown) {
    window.bootstrap.Dropdown.Default.popperConfig = { strategy: 'fixed' };
  }

  const ADM = {};

  /* ---------------- 提示 ---------------- */
  function toastWrap() {
    let w = document.querySelector('.adm-toast-wrap');
    if (!w) {
      w = document.createElement('div');
      w.className = 'adm-toast-wrap';
      document.body.appendChild(w);
    }
    return w;
  }

  ADM.toast = function (msg, type, timeout) {
    const wrap = toastWrap();
    const el = document.createElement('div');
    el.className = 'adm-toast' + (type === 'error' ? ' err' : type === 'warning' ? ' warn' : '');
    const icon = type === 'error' ? '✕' : type === 'warning' ? '!' : '✓';
    el.innerHTML = '<span style="font-weight:700;color:' +
      (type === 'error' ? '#f04438' : type === 'warning' ? '#f79009' : '#12b76a') + '">' + icon + '</span>' +
      '<div style="flex:1;white-space:pre-wrap;word-break:break-word"></div>' +
      '<button class="close-x" aria-label="关闭">✕</button>';
    el.querySelector('div').textContent = msg;
    el.querySelector('.close-x').onclick = () => el.remove();
    wrap.appendChild(el);
    const ttl = timeout || (type === 'error' ? 7000 : 3200);
    setTimeout(() => { if (el.parentNode) el.remove(); }, ttl);
    return el;
  };
  ADM.ok = (m) => ADM.toast(m, 'success');
  ADM.err = (m) => ADM.toast(m, 'error');
  ADM.warn = (m) => ADM.toast(m, 'warning');

  /* ---------------- 请求 ---------------- */
  async function request(url, opts) {
    opts = opts || {};
    const init = {
      method: opts.method || 'GET',
      headers: Object.assign({ 'X-Requested-With': 'XMLHttpRequest' }, opts.headers || {}),
      credentials: 'same-origin'
    };
    if (opts.body instanceof FormData) {
      init.body = opts.body;
    } else if (opts.data) {
      const fd = new FormData();
      Object.keys(opts.data).forEach(k => {
        const v = opts.data[k];
        if (v === undefined || v === null) return;
        if (Array.isArray(v)) v.forEach(x => fd.append(k, x));
        else fd.append(k, v);
      });
      init.body = fd;
    }
    let resp, json;
    try {
      resp = await fetch(url, init);
    } catch (e) {
      ADM.err('网络请求失败：' + e.message);
      return { ok: false, message: '网络请求失败' };
    }
    const ct = resp.headers.get('Content-Type') || '';
    if (ct.includes('application/json')) {
      try { json = await resp.json(); } catch (e) { json = { ok: false, message: '响应解析失败' }; }
    } else if (resp.status === 401) {
      jQueryFreeRedirect();
      return { ok: false, message: '登录已过期' };
    } else {
      json = { ok: resp.ok, message: resp.ok ? '操作成功' : ('HTTP ' + resp.status) };
    }
    if (resp.status === 401) {
      ADM.err('登录已过期，请重新登录');
      setTimeout(() => { window.location.href = '/login'; }, 800);
      return json;
    }
    if (!json.ok && !opts.silent) ADM.err(json.message || '操作失败');
    if (json.ok && !opts.silent) ADM.ok(json.message || '操作成功');
    return json;
  }

  function jQueryFreeRedirect() { window.location.href = '/login'; }

  ADM.get = (url, opts) => request(url, Object.assign({ method: 'GET' }, opts || {}));
  ADM.post = (url, data, opts) => request(url, Object.assign({ method: 'POST', data: data }, opts || {}));
  ADM.upload = (url, formData, opts) => request(url, Object.assign({ method: 'POST', body: formData }, opts || {}));

  /* ---------------- 高危确认 ---------------- */
  let confirmQueue = Promise.resolve();

  ADM.confirmDanger = function (opts) {
    // 串行化，避免多个弹窗叠加
    confirmQueue = confirmQueue.then(() => new Promise((resolve) => {
      const o = Object.assign({
        title: '高危操作确认',
        message: '该操作将直接变更 AD 域数据，且无法自动回滚。',
        detail: '',
        items: [],
        requireCheck: true,
        checkText: '我已确认以上信息无误，了解该操作的影响并自愿继续',
        confirmText: '确认执行',
        requireInput: null,      // 填写指定文字才允许执行
        inputHint: ''
      }, opts || {});

      const id = 'cd_' + Date.now();
      const html =
        '<div class="modal fade danger-modal" id="' + id + '" tabindex="-1">' +
        '<div class="modal-dialog modal-dialog-centered"><div class="modal-content">' +
        '<div class="modal-header"><h5 class="modal-title">⚠ ' + esc(o.title) + '</h5>' +
        '<button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>' +
        '<div class="modal-body">' +
        '<div class="mb-2">' + esc(o.message) + '</div>' +
        (o.items.length ? '<ul class="mb-2 ps-3">' + o.items.map(i => '<li>' + esc(i) + '</li>').join('') + '</ul>' : '') +
        (o.detail ? '<div class="code-box mb-2">' + esc(o.detail) + '</div>' : '') +
        (o.requireCheck ? '<div class="form-check mt-3"><input class="form-check-input" type="checkbox" id="' + id + '_chk">' +
          '<label class="form-check-label" for="' + id + '_chk">' + esc(o.checkText) + '</label></div>' : '') +
        (o.requireInput ? '<div class="mt-2"><label class="form-label">' + esc(o.inputHint) + '</label>' +
          '<input class="form-control" id="' + id + '_in" autocomplete="off"></div>' : '') +
        '</div><div class="modal-footer">' +
        '<button type="button" class="btn btn-light btn-sm" data-bs-dismiss="modal">取消</button>' +
        '<button type="button" class="btn btn-danger btn-sm" id="' + id + '_ok" disabled>' + esc(o.confirmText) + '</button>' +
        '</div></div></div></div>';
      const host = document.createElement('div');
      host.innerHTML = html;
      const modalEl = host.firstChild;
      document.body.appendChild(modalEl);
      const modal = new window.bootstrap.Modal(modalEl, { backdrop: 'static' });
      const btn = modalEl.querySelector('#' + id + '_ok');
      const chk = modalEl.querySelector('#' + id + '_chk');
      const inp = modalEl.querySelector('#' + id + '_in');
      function refresh() {
        let enable = true;
        if (o.requireCheck && chk && !chk.checked) enable = false;
        if (o.requireInput && inp && inp.value.trim() !== o.requireInput) enable = false;
        btn.disabled = !enable;
      }
      if (chk) chk.addEventListener('change', refresh);
      if (inp) inp.addEventListener('input', refresh);
      let decided = false;
      btn.onclick = () => { decided = true; modal.hide(); resolve(true); };
      modalEl.addEventListener('hidden.bs.modal', () => {
        modalEl.remove();
        if (!decided) resolve(false);
      });
      modal.show();
    }));
    return confirmQueue;
  };

  /* ---------------- 普通表单弹窗（通用提交） ---------------- */
  ADM.formModal = function (opts) {
    const o = Object.assign({ title: '', body: '', okText: '保存', size: '' }, opts || {});
    const id = 'fm_' + Date.now();
    const host = document.createElement('div');
    host.innerHTML =
      '<div class="modal fade" id="' + id + '" tabindex="-1"><div class="modal-dialog modal-dialog-centered ' + o.size + '">' +
      '<div class="modal-content"><div class="modal-header"><h5 class="modal-title">' + esc(o.title) + '</h5>' +
      '<button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>' +
      '<form class="modal-body">' + o.body + '</form>' +
      '<div class="modal-footer"><button type="button" class="btn btn-light btn-sm" data-bs-dismiss="modal">取消</button>' +
      '<button type="button" class="btn btn-primary btn-sm" data-role="ok">' + esc(o.okText) + '</button></div>' +
      '</div></div></div>';
    const modalEl = host.firstChild;
    document.body.appendChild(modalEl);
    const modal = new window.bootstrap.Modal(modalEl);
    const form = modalEl.querySelector('form');
    modalEl.querySelector('[data-role=ok]').onclick = async () => {
      const btn = modalEl.querySelector('[data-role=ok]');
      btn.disabled = true;
      try {
        const proceed = await (o.onSubmit ? o.onSubmit(form) : true);
        if (proceed !== false) modal.hide();
      } finally { btn.disabled = false; }
    };
    modalEl.addEventListener('hidden.bs.modal', () => modalEl.remove());
    modal.show();
    const first = form.querySelector('input:not([type=hidden]),select,textarea');
    if (first) setTimeout(() => first.focus(), 200);
    return { modal, form, el: modalEl };
  };

  /* ---------------- 右键菜单 ---------------- */
  let _ctxEl = null;
  let _ctxCleanup = null;
  function closeContextMenu() {
    if (_ctxCleanup) { _ctxCleanup(); _ctxCleanup = null; }
    if (_ctxEl) { _ctxEl.remove(); _ctxEl = null; }
  }
  // items: [{label, danger, disabled, onClick}]，用 '-' 表示分隔线
  ADM.contextMenu = function (items, x, y) {
    closeContextMenu();
    const menu = document.createElement('div');
    menu.className = 'adm-ctx-menu';
    items.forEach(it => {
      if (!it) return;
      if (it === '-') {
        const sep = document.createElement('div');
        sep.className = 'adm-ctx-sep';
        menu.appendChild(sep);
        return;
      }
      const el = document.createElement('div');
      el.className = 'adm-ctx-item' + (it.danger ? ' danger' : '') + (it.disabled ? ' disabled' : '');
      el.textContent = it.label;
      if (!it.disabled) el.onclick = () => { closeContextMenu(); if (it.onClick) it.onClick(); };
      menu.appendChild(el);
    });
    document.body.appendChild(menu);
    const r = menu.getBoundingClientRect();
    let px = x, py = y;
    if (px + r.width > window.innerWidth - 8) px = Math.max(8, window.innerWidth - r.width - 8);
    if (py + r.height > window.innerHeight - 8) py = Math.max(8, window.innerHeight - r.height - 8);
    menu.style.left = px + 'px';
    menu.style.top = py + 'px';
    _ctxEl = menu;

    // 关闭监听：持久注册 + 显式移除，避免 once 监听器在下一次右键时
    // 冒泡到 document 误关闭新菜单（"只能右键一次"的根因）。
    const onDocClick = () => closeContextMenu();
    const onDocCtx = () => closeContextMenu();
    const onDocScroll = () => closeContextMenu();
    // 延迟注册，避免本次右键事件冒泡到 document 立即触发关闭
    setTimeout(() => {
      document.addEventListener('click', onDocClick);
      document.addEventListener('contextmenu', onDocCtx);
      document.addEventListener('scroll', onDocScroll, true);
    }, 0);
    _ctxCleanup = () => {
      document.removeEventListener('click', onDocClick);
      document.removeEventListener('contextmenu', onDocCtx);
      document.removeEventListener('scroll', onDocScroll, true);
    };
  };

  /* ---------------- 工具 ---------------- */
  function esc(s) {
    return String(s === undefined || s === null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  ADM.esc = esc;

  ADM.formData = function (formEl) {
    const fd = new FormData(formEl);
    const out = {};
    for (const [k, v] of fd.entries()) {
      if (out[k] === undefined) out[k] = v;
      else if (Array.isArray(out[k])) out[k].push(v);
      else out[k] = [out[k], v];
    }
    return out;
  };

  ADM.btnLoading = function (btn, loading, text) {
    if (!btn) return;
    if (loading) {
      btn.dataset._html = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>' + (text || '处理中…');
    } else {
      btn.disabled = false;
      if (btn.dataset._html) btn.innerHTML = btn.dataset._html;
    }
  };

  /* ---------------- 表格全选 ---------------- */
  ADM.initSelectAll = function (tableSelector, onChange) {
    const table = document.querySelector(tableSelector);
    if (!table) return;
    const all = table.querySelector('thead input[type=checkbox]');
    const boxes = () => Array.from(table.querySelectorAll('tbody input[type=checkbox]'));
    if (all) all.addEventListener('change', () => {
      boxes().forEach(b => { b.checked = all.checked; });
      if (onChange) onChange(ADM.selectedIds(table));
    });
    table.addEventListener('change', (e) => {
      if (e.target.matches('tbody input[type=checkbox]')) {
        const list = boxes();
        if (all) {
          all.checked = list.length > 0 && list.every(b => b.checked);
          all.indeterminate = !all.checked && list.some(b => b.checked);
        }
        if (onChange) onChange(ADM.selectedIds(table));
      }
    });
  };
  ADM.selectedIds = function (tableSelector) {
    const table = typeof tableSelector === 'string' ? document.querySelector(tableSelector) : tableSelector;
    return Array.from(table.querySelectorAll('tbody input[type=checkbox]:checked')).map(b => b.value);
  };

  /* ---------------- 密码显示 / 随机生成 ---------------- */
  ADM.togglePwd = function (inputId, btn) {
    const el = document.getElementById(inputId);
    if (!el) return;
    const isPwd = el.type === 'password';
    el.type = isPwd ? 'text' : 'password';
    if (btn) btn.textContent = isPwd ? '隐藏' : '显示';
  };

  ADM.randomPassword = function (len) {
    const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ', lower = 'abcdefghijkmnpqrstuvwxyz';
    const digits = '23456789', symbols = '@#$%&*+-_';
    const all = upper + lower + digits + symbols;
    len = len || 14;
    let pwd;
    const rnd = (n) => Math.floor(Math.random() * n);
    do {
      pwd = '';
      for (let i = 0; i < len; i++) pwd += all[rnd(all.length)];
    } while (!(/[A-Z]/.test(pwd) && /[a-z]/.test(pwd) && /[0-9]/.test(pwd) && /[^A-Za-z0-9]/.test(pwd)));
    return pwd;
  };

  /* ---------------- 复制 ---------------- */
  ADM.copy = async function (text) {
    try {
      await navigator.clipboard.writeText(text);
      ADM.ok('已复制到剪贴板');
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); ta.remove();
      ADM.ok('已复制到剪贴板');
    }
  };

  /* ---------------- 侧边栏 ---------------- */
  ADM.initShell = function () {
    const btn = document.querySelector('.adm-hamburger');
    const sb = document.querySelector('.adm-sidebar');
    if (btn && sb) btn.addEventListener('click', () => sb.classList.toggle('open'));
    const out = document.querySelector('[data-action=logout]');
    if (out) out.addEventListener('click', async (e) => {
      e.preventDefault();
      const r = await ADM.post('/logout', {}, { silent: true });
      window.location.href = (r && r.data && r.data.redirect) || '/login';
    });

    // 登录会话空闲超时：无操作 N 分钟自动退出（0 = 永不超时，不启用）
    const timeoutMin = parseInt(window.__SESSION_TIMEOUT, 10) || 0;
    if (timeoutMin > 0) {
      let lastAct = Date.now();
      ['click', 'keydown', 'mousemove', 'scroll', 'touchstart'].forEach(function (ev) {
        document.addEventListener(ev, function () { lastAct = Date.now(); }, { passive: true });
      });
      setInterval(function () {
        if ((Date.now() - lastAct) / 60000 >= timeoutMin) {
          fetch('/logout', { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin' })
            .catch(function () {});
          window.location.href = '/login?timeout=1';
        }
      }, 15000);
    }
  };

  window.ADM = ADM;
  document.addEventListener('DOMContentLoaded', ADM.initShell);
})(window, document);
