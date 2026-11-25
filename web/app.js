const $ = (sel, root = document) => root.querySelector(sel);

const els = {
  fileState: $('#file-state'),
  reloadBtn: $('#reload-btn'),
  shutdownBtn: $('#shutdown-btn'),
  hostCount: $('#host-count'),
  search: $('#search-input'),
  hostList: $('#host-list'),
  filePath: $('#file-path'),
  errorBanner: $('#error-banner'),
  empty: $('#empty-state'),
  emptyTitle: $('.empty-title'),
  emptyText: $('.empty-text'),
  emptyNewBtn: $('#empty-new-btn'),
  emptyImportBtn: $('#empty-import-btn'),
  form: $('#host-form'),
  formTitle: $('#form-title'),
  dirtyBadge: $('#dirty-badge'),
  newBtn: $('#new-btn'),
  importBtn: $('#import-btn'),
  saveBtn: $('#save-btn'),
  testBtn: $('#test-btn'),
  deleteBtn: $('#delete-btn'),
  probeInline: $('#probe-inline'),
  resultPanel: $('#result-panel'),
  probeResult: $('#probe-result'),
  alias: $('#alias'),
  address: $('#address'),
  port: $('#port'),
  username: $('#username'),
  password: $('#password'),
  passwordHint: $('#password-hint'),
  keyPath: $('#key_path'),
  hostKey: $('#hostKey'),
  shellInit: $('#shell_init'),
  purpose: $('#purpose'),
  disabled: $('#disabled'),
  critical: $('#critical'),
  xfer: $('#xfer'),
  elevate: $('#elevate'),
  elevateGroup: $('#elevate-group'),
  elevateUser: $('#elevate_user'),
  elevatePassword: $('#elevate_password'),
  importDialog: $('#import-dialog'),
  importSummary: $('#import-summary'),
  importList: $('#import-list'),
  importCount: $('#import-count'),
  importConfirm: $('#import-confirm'),
  deleteDialog: $('#delete-dialog'),
  deleteText: $('#delete-text'),
  deleteConfirm: $('#delete-confirm'),
  toast: $('#toast'),
};

const state = {
  token: '',
  hosts: [],
  path: '',
  file: null,
  error: '',
  selected: null,
  creating: false,
  dirty: false,
  busy: false,
  noToken: false,
};

const ACTION_TEXT = {
  save: '保存中…',
  probe: '探测中…',
  test: '连接中…',
  import: '导入中…',
};

/* ---------------------------------------------------------------- token + api */
function readToken() {
  const hash = new URLSearchParams(location.hash.replace(/^#/, ''));
  const fromHash = hash.get('token');
  if (fromHash) {
    sessionStorage.setItem('sshmarshal.token', fromHash);
    history.replaceState(null, '', location.pathname + location.search);
    return fromHash;
  }
  const fromQuery = new URLSearchParams(location.search).get('token');
  if (fromQuery) {
    sessionStorage.setItem('sshmarshal.token', fromQuery);
    return fromQuery;
  }
  return sessionStorage.getItem('sshmarshal.token') || '';
}

async function api(path, { method = 'GET', body } = {}) {
  if (!state.token) throw new Error('缺少访问令牌：请从 hosts_web.py 打印的地址打开页面');
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Token': state.token },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (res.status === 401) {
    sessionStorage.removeItem('sshmarshal.token');
    state.token = '';
    throw new Error('访问令牌已失效：请从 hosts_web.py 重新打印的地址打开');
  }
  if (!res.ok || !data || data.ok === false) {
    throw new Error((data && data.error) || `请求失败（HTTP ${res.status}）`);
  }
  return data;
}

/* ---------------------------------------------------------------- helpers */
function fmtTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString('zh-CN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
  });
}

function toast(message, kind = 'success') {
  els.toast.textContent = message;
  els.toast.dataset.kind = kind;
  els.toast.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { els.toast.hidden = true; }, kind === 'error' ? 6000 : 4000);
}

function setBusy(busy, action = '') {
  state.busy = busy;
  const buttons = [
    els.saveBtn, els.testBtn, els.deleteBtn, els.probeInline, els.reloadBtn, els.shutdownBtn,
    els.newBtn, els.importBtn, els.importConfirm, els.emptyNewBtn, els.emptyImportBtn,
  ];
  for (const button of buttons) {
    if (!button) continue;
    button.disabled = busy || state.noToken;
  }
  const active = { save: els.saveBtn, probe: els.probeInline, test: els.testBtn, import: els.importConfirm }[action];
  if (busy && active) {
    active.dataset.label = active.textContent;
    active.textContent = ACTION_TEXT[action];
  }
  if (!busy) {
    for (const button of [els.saveBtn, els.probeInline, els.testBtn, els.importConfirm]) {
      if (button && button.dataset.label) {
        button.textContent = button.dataset.label;
        delete button.dataset.label;
      }
    }
  }
}

function setDirty(value) {
  state.dirty = value;
  els.dirtyBadge.hidden = !value;
}

function renderHeader() {
  if (state.noToken) {
    els.fileState.textContent = '未连接';
  } else if (state.error) {
    els.fileState.textContent = '清单读取失败';
  } else if (!state.file || !state.file.exists) {
    els.fileState.textContent = '清单尚未创建';
  } else {
    els.fileState.textContent = `${state.hosts.length} 台主机 · 已保存 ${fmtTime(state.file.mtime)}`;
  }
  els.filePath.textContent = state.path || '—';
  els.filePath.title = state.path || '';
  els.hostCount.textContent = String(state.hosts.length);
  els.errorBanner.hidden = !state.error;
  els.errorBanner.textContent = state.error ? `清单读取失败：${state.error}` : '';
}

function flag(text) {
  const span = document.createElement('span');
  span.className = 'flag';
  span.textContent = text;
  return span;
}

function renderList() {
  els.hostList.replaceChildren();
  if (state.noToken) {
    const box = document.createElement('div');
    box.className = 'host-empty';
    box.textContent = '未连接本地服务';
    els.hostList.append(box);
    return;
  }
  const query = els.search.value.trim().toLowerCase();
  const hosts = query
    ? state.hosts.filter((host) => [host.alias, host.address, host.username]
      .some((value) => String(value || '').toLowerCase().includes(query)))
    : state.hosts;
  if (!hosts.length) {
    const box = document.createElement('div');
    box.className = 'host-empty';
    box.textContent = state.hosts.length ? '没有匹配的主机' : '清单里还没有主机';
    els.hostList.append(box);
    return;
  }
  for (const host of hosts) {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'host-row' + (host.flags.disabled ? ' is-disabled' : '');
    row.setAttribute('role', 'option');
    row.setAttribute('aria-selected', String(host.alias === state.selected));
    row.dataset.alias = host.alias;

    const aliasLine = document.createElement('div');
    aliasLine.className = 'host-alias';
    const aliasText = document.createElement('span');
    aliasText.textContent = host.alias;
    aliasLine.append(aliasText);

    const addr = document.createElement('div');
    addr.className = 'host-addr';
    addr.textContent = `${host.address || '—'}:${host.port || 22}${host.username ? ` · ${host.username}` : ''}`;

    const flags = document.createElement('div');
    flags.className = 'host-flags';
    if (host.flags.disabled) flags.append(flag('停用'));
    if (host.flags.critical) flags.append(flag('查清单'));
    if (!host.flags.xfer) flags.append(flag('禁传'));
    if (host.flags.elevate) flags.append(flag('提权'));

    row.append(aliasLine, addr, flags);
    row.addEventListener('click', () => selectHost(host.alias));
    els.hostList.append(row);
  }
}

/* ---------------------------------------------------------------- form */
function getAuth() {
  return $('input[name="auth"]:checked')?.value || 'password';
}

function setAuth(value) {
  for (const radio of document.querySelectorAll('input[name="auth"]')) {
    radio.checked = radio.value === value;
  }
}

function updateConditional() {
  const auth = getAuth();
  for (const field of document.querySelectorAll('[data-auth]')) {
    field.hidden = field.dataset.auth !== auth;
  }
  els.elevateGroup.hidden = !els.elevate.checked;
}

function fillForm(host) {
  const entry = host || {};
  const flags = entry.flags || { disabled: false, critical: false, xfer: true, elevate: false };
  els.alias.value = host ? host.alias : '';
  els.alias.disabled = Boolean(host);
  els.address.value = entry.address || '';
  els.port.value = String(entry.port || 22);
  els.username.value = entry.username || '';
  setAuth(entry.auth || 'password');
  els.password.value = '';
  els.keyPath.value = entry.key_path || '';
  els.hostKey.value = entry.hostKey || '';
  els.shellInit.value = entry.shell_init || '';
  els.purpose.value = entry.purpose || '';
  els.disabled.checked = Boolean(flags.disabled);
  els.critical.checked = Boolean(flags.critical);
  els.xfer.checked = flags.xfer !== false;
  els.elevate.checked = Boolean(flags.elevate);
  els.elevateUser.value = entry.elevate_user || 'root';
  els.elevatePassword.value = '';
  if (host) {
    els.formTitle.textContent = `编辑 ${host.alias}`;
    els.password.placeholder = host.has_password ? '留空＝沿用原口令' : '当前没有口令，建议填写';
    els.passwordHint.textContent = host.has_password
      ? '留空＝沿用原口令；页面不回填明文。'
      : '当前没有口令。填写后保存。';
  } else {
    els.formTitle.textContent = '新建主机';
    els.password.placeholder = '新主机需要填写';
    els.passwordHint.textContent = '新主机需要填写；也可以改用私钥。';
  }
  for (const panel of [els.resultPanel, els.probeResult]) {
    panel.hidden = true;
    panel.replaceChildren();
    panel.classList.remove('result--warn');
  }
  updateConditional();
}

function showForm() {
  els.empty.hidden = true;
  els.form.hidden = false;
}

function hideForm() {
  els.form.hidden = true;
  els.empty.hidden = false;
}

function readForm() {
  return {
    alias: els.alias.value.trim(),
    entry: {
      address: els.address.value.trim(),
      port: els.port.value.trim() || '22',
      username: els.username.value.trim(),
      auth: getAuth(),
      password: els.password.value,
      key_path: els.keyPath.value.trim(),
      hostKey: els.hostKey.value.trim(),
      purpose: els.purpose.value.trim(),
      shell_init: els.shellInit.value.trim(),
      disabled: els.disabled.checked,
      critical: els.critical.checked,
      xfer: els.xfer.checked,
      elevate: els.elevate.checked,
      elevate_user: els.elevateUser.value.trim() || 'root',
      elevate_password: els.elevatePassword.value,
    },
  };
}

function applyState(next) {
  state.path = next.path;
  state.file = next.file;
  state.error = next.error || '';
  state.hosts = next.hosts || [];
  if (state.selected && !state.hosts.some((host) => host.alias === state.selected)) {
    state.selected = null;
    state.creating = false;
  }
  renderHeader();
  renderList();
}

function selectHost(alias, force = false) {
  if (!force && state.busy) return;
  if (!force && alias === state.selected && !state.creating) return;
  if (!force && state.dirty && !window.confirm('有未保存的修改，放弃并切换吗？')) return;
  const host = state.hosts.find((item) => item.alias === alias);
  if (!host) return;
  state.selected = alias;
  state.creating = false;
  fillForm(host);
  setDirty(false);
  renderList();
  showForm();
}

function newHost(force = false) {
  if (!force && state.busy) return;
  if (!force && state.dirty && !window.confirm('有未保存的修改，放弃并新建吗？')) return;
  state.selected = null;
  state.creating = true;
  fillForm(null);
  setDirty(false);
  renderList();
  showForm();
  els.alias.focus();
}

/* ---------------------------------------------------------------- results */
function resultLine(label, value, mono = false) {
  const row = document.createElement('div');
  row.className = 'result-line';
  const left = document.createElement('span');
  left.className = 'result-note';
  left.textContent = label;
  const right = document.createElement('span');
  right.className = mono ? 'result-fp' : 'result-strong';
  right.textContent = value;
  row.append(left, right);
  return row;
}

function resultNote(text) {
  const note = document.createElement('div');
  note.className = 'result-note';
  note.textContent = text;
  return note;
}

function showResult(title, children, actions = [], warn = false, panel = els.resultPanel) {
  panel.replaceChildren();
  panel.classList.toggle('result--warn', warn);
  const heading = document.createElement('div');
  heading.className = 'result-title';
  heading.textContent = title;
  panel.append(heading, ...children);
  if (actions.length) {
    const row = document.createElement('div');
    row.className = 'result-actions';
    row.append(...actions);
    panel.append(row);
  }
  panel.hidden = false;
}

function fillFingerprint(fingerprint) {
  els.hostKey.value = fingerprint;
  setDirty(true);
  toast('指纹已填入，记得保存。');
}

/* ---------------------------------------------------------------- actions */
async function saveHost() {
  if (state.busy) return;
  const { alias, entry } = readForm();
  if (!alias) {
    toast('别名不能为空', 'error');
    els.alias.focus();
    return;
  }
  setBusy(true, 'save');
  try {
    const data = await api('/api/hosts', {
      method: 'POST',
      body: { alias, entry, is_new: state.creating },
    });
    state.creating = false;
    state.selected = alias;
    applyState(data.state);
    const saved = state.hosts.find((host) => host.alias === alias);
    if (saved) fillForm(saved);
    setDirty(false);
    showForm();
    renderList();
    const children = [];
    if (data.warnings && data.warnings.length) children.push(resultNote(`提示：${data.warnings.join('；')}`));
    showResult('已保存', children);
    if (!children.length) els.resultPanel.hidden = true;
    toast(`已保存 ${alias}。`, 'success');
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(false);
  }
}

async function probeHost() {
  if (state.busy) return;
  const { entry } = readForm();
  if (!entry.address) {
    toast('先填地址', 'error');
    els.address.focus();
    return;
  }
  setBusy(true, 'probe');
  try {
    const data = await api('/api/probe', {
      method: 'POST',
      body: { address: entry.address, port: entry.port },
    });
    const pinned = els.hostKey.value.trim();
    const changed = Boolean(pinned) && pinned !== data.fingerprint;
    fillFingerprint(data.fingerprint);
    const children = [
      resultLine('算法', data.key_type),
      resultLine('实际指纹', data.fingerprint, true),
    ];
    if (pinned) children.push(resultLine('原固定值', pinned, true));
    if (changed) {
      children.push(resultNote('已直接填入输入框；与实际指纹不一致，保存前请自己核对（可能是主机重装或中间人）。'));
    } else if (!pinned) {
      children.push(resultNote('已直接填入输入框，保存后生效。'));
    } else {
      children.push(resultNote('与已固定的一致，已直接填入输入框。'));
    }
    showResult(`指纹探测 · ${data.elapsed_ms}ms（未发送凭据）`, children, [], changed, els.probeResult);
  } catch (error) {
    showResult('指纹探测失败', [resultNote(error.message)], [], true, els.probeResult);
    toast('指纹探测失败，详情见下方。', 'error');
  } finally {
    setBusy(false);
  }
}

async function testHost() {
  if (state.busy) return;
  const { entry } = readForm();
  if (!entry.address) {
    toast('先填地址', 'error');
    els.address.focus();
    return;
  }
  if (!entry.hostKey) {
    toast('hostKey 为空：先探测指纹并确认，再连测。', 'error');
    els.hostKey.focus();
    return;
  }
  setBusy(true, 'test');
  try {
    const data = await api('/api/test', {
      method: 'POST',
      body: { alias: state.selected, entry, hostKey: entry.hostKey },
    });
    const result = data.result || {};
    if (result.ok) {
      const children = [
        resultLine('耗时', `${result.elapsed_ms}ms`),
        resultLine('系统', result.os || '未知'),
        resultLine('架构', result.arch || '未知'),
      ];
      if (result.server) children.push(resultLine('SSH', result.server));
      showResult('连接成功', children);
      toast(`连接成功 · ${result.elapsed_ms}ms`, 'success');
    } else {
      const children = [resultNote(result.error || '连接失败')];
      if (result.reason) children.push(resultLine('原因', result.reason));
      showResult('连接失败', children, [], true);
      toast('连接失败', 'error');
    }
  } catch (error) {
    showResult('连接失败', [resultNote(error.message)], [], true);
    toast('连接失败，详情见下方。', 'error');
  } finally {
    setBusy(false);
  }
}

async function deleteHost() {
  if (state.busy || !state.selected) return;
  els.deleteText.textContent = `将 ${state.selected} 从清单里删除。删除会直接写入清单文件，不再生成备份。`;
  els.deleteDialog.showModal();
}

async function confirmDelete() {
  const alias = state.selected;
  if (!alias) return;
  els.deleteDialog.close();
  setBusy(true);
  try {
    const data = await api('/api/delete', { method: 'POST', body: { alias } });
    const next = state.hosts.find((host) => host.alias !== alias)?.alias || null;
    state.selected = next;
    state.creating = false;
    applyState(data.state);
    if (next) {
      selectHost(next, true);
    } else {
      hideForm();
      renderList();
    }
    toast(`已删除 ${alias}。`, 'success');
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(false);
  }
}

async function reloadState({ silent = false } = {}) {
  if (state.busy) return;
  if (state.dirty && !window.confirm('有未保存的修改，重新载入会放弃它们。继续吗？')) return;
  setDirty(false);
  setBusy(true);
  try {
    const data = await api('/api/state');
    applyState(data);
    if (state.selected && state.hosts.some((host) => host.alias === state.selected)) {
      selectHost(state.selected, true);
    } else if (state.hosts.length) {
      selectHost(state.hosts[0].alias, true);
    } else {
      state.selected = null;
      state.creating = false;
      hideForm();
      renderList();
    }
    if (!silent) toast('已重新载入。', 'success');
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(false);
  }
}

/* ---------------------------------------------------------------- import */
function updateImportCount() {
  const count = els.importList.querySelectorAll('input[type="checkbox"]:checked:not(:disabled)').length;
  els.importCount.textContent = `已选 ${count} 台`;
  els.importConfirm.disabled = state.busy || state.noToken || count === 0;
}

function renderImport(data) {
  els.importSummary.textContent = `known_hosts ${data.known_hosts} 台 · ssh config ${data.ssh_config} 条`
    + (data.hashed ? ` · ${data.hashed} 条 hashed 记录无法反查` : '');
  els.importList.replaceChildren();
  if (!data.candidates.length) {
    const empty = document.createElement('div');
    empty.className = 'dialog-note';
    empty.textContent = '没有扫描到主机。';
    els.importList.append(empty);
    updateImportCount();
    return;
  }
  for (const cand of data.candidates) {
    const row = document.createElement('label');
    row.className = 'import-row' + (cand.importable ? '' : ' is-skip');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = cand.alias;
    checkbox.disabled = !cand.importable;
    checkbox.checked = cand.importable;
    checkbox.addEventListener('change', updateImportCount);
    const main = document.createElement('div');
    main.className = 'import-main';
    const alias = document.createElement('div');
    alias.className = 'import-alias';
    alias.textContent = cand.alias;
    const addr = document.createElement('div');
    addr.className = 'import-addr';
    addr.textContent = `${cand.entry.address}:${cand.entry.port}${cand.entry.username ? ` · ${cand.entry.username}` : ' · 缺用户名'}`;
    main.append(alias, addr);
    const notes = [...(cand.notes || []), ...(cand.reasons || [])].filter(Boolean);
    if (notes.length) {
      const note = document.createElement('div');
      note.className = 'import-notes';
      note.textContent = notes.join('；');
      main.append(note);
    }
    row.append(checkbox, main);
    els.importList.append(row);
  }
  updateImportCount();
}

async function openImport() {
  if (state.busy) return;
  if (state.dirty && !window.confirm('有未保存的修改，导入后会放弃它们。继续吗？')) return;
  setBusy(true);
  try {
    const data = await api('/api/candidates');
    renderImport(data);
    els.importDialog.showModal();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(false);
    updateImportCount();
  }
}

async function confirmImport() {
  const aliases = [...els.importList.querySelectorAll('input[type="checkbox"]:checked:not(:disabled)')]
    .map((input) => input.value);
  if (!aliases.length) {
    toast('先选至少一台。', 'error');
    return;
  }
  setBusy(true, 'import');
  try {
    const data = await api('/api/import', { method: 'POST', body: { aliases } });
    els.importDialog.close();
    applyState(data.state);
    if (data.added.length) {
      selectHost(data.added[0], true);
      toast(`已导入 ${data.added.length} 台。`, 'success');
    } else {
      toast('没有导入任何主机。', 'error');
    }
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(false);
  }
}

/* ---------------------------------------------------------------- misc */
async function shutdown() {
  if (!window.confirm('关闭本地服务？页面将无法继续操作。')) return;
  try {
    await api('/api/shutdown', { method: 'POST', body: {} });
    setBusy(true);
    els.fileState.textContent = '服务已关闭';
    els.errorBanner.hidden = false;
    els.errorBanner.textContent = '本地服务已关闭。可以关闭这个页面。';
    toast('服务已关闭。', 'success');
  } catch (error) {
    toast(error.message, 'error');
  }
}

function noToken() {
  state.noToken = true;
  els.emptyTitle.textContent = '缺少访问令牌';
  els.emptyText.textContent = '请从 hosts_web.py 启动时打印的地址打开页面（地址里带 #token=…）。';
  els.errorBanner.hidden = false;
  els.errorBanner.textContent = '页面没有访问令牌，无法调用本地接口。';
  els.fileState.textContent = '未连接';
  setBusy(true);
  hideForm();
  renderList();
}

function bindEvents() {
  els.newBtn.addEventListener('click', () => newHost());
  els.emptyNewBtn.addEventListener('click', () => newHost());
  els.importBtn.addEventListener('click', openImport);
  els.emptyImportBtn.addEventListener('click', openImport);
  els.reloadBtn.addEventListener('click', () => reloadState());
  els.shutdownBtn.addEventListener('click', shutdown);
  els.search.addEventListener('input', renderList);
  els.form.addEventListener('submit', (event) => {
    event.preventDefault();
    saveHost();
  });
  els.probeInline.addEventListener('click', probeHost);
  els.testBtn.addEventListener('click', testHost);
  els.deleteBtn.addEventListener('click', deleteHost);
  els.deleteConfirm.addEventListener('click', confirmDelete);
  els.importConfirm.addEventListener('click', confirmImport);
  els.elevate.addEventListener('change', updateConditional);
  for (const radio of document.querySelectorAll('input[name="auth"]')) {
    radio.addEventListener('change', updateConditional);
  }
  els.form.addEventListener('input', () => setDirty(true));
  els.form.addEventListener('change', () => setDirty(true));
  for (const button of document.querySelectorAll('[data-close]')) {
    button.addEventListener('click', () => {
      document.getElementById(button.dataset.close)?.close();
    });
  }
  for (const dialog of document.querySelectorAll('dialog')) {
    dialog.addEventListener('click', (event) => {
      if (event.target === dialog) dialog.close();
    });
  }
  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
      if (!els.form.hidden && !document.querySelector('dialog[open]')) {
        event.preventDefault();
        saveHost();
      }
    }
  });
  window.addEventListener('hashchange', () => {
    // 服务重启后新地址只差一个 #token=…：同标签页打开不会重新加载文档，这里强制刷一次。
    if (/token=/.test(location.hash)) location.reload();
  });
  window.addEventListener('beforeunload', (event) => {
    if (!state.dirty) return;
    event.preventDefault();
    event.returnValue = '';
  });
}

async function init() {
  state.token = readToken();
  bindEvents();
  if (!state.token) {
    noToken();
    return;
  }
  setBusy(true);
  try {
    const data = await api('/api/state');
    applyState(data);
    if (state.hosts.length) {
      selectHost(state.hosts[0].alias, true);
    } else {
      state.selected = null;
      state.creating = false;
      hideForm();
      renderList();
    }
  } catch (error) {
    if (!state.token) {
      noToken();
      return;
    }
    els.errorBanner.hidden = false;
    els.errorBanner.textContent = `无法连接本地服务：${error.message}`;
    els.fileState.textContent = '连接失败';
    hideForm();
  } finally {
    setBusy(false);
  }
}

init();
