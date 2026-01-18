const appVersionEl = document.getElementById('app-version');
const proxyStatusEl = document.getElementById('proxy-status');
const proxyPortLabelEl = document.getElementById('proxy-port-label');
const rulesCountEl = document.getElementById('rules-count');
const sessionCountEl = document.getElementById('session-count');
const proxyForm = document.getElementById('proxy-form');
const proxyPortInput = document.getElementById('proxy-port');
const proxyStopBtn = document.getElementById('proxy-stop');
const httpsModeEl = document.getElementById('https-mode');
const httpsCaStatusEl = document.getElementById('https-ca-status');
const httpsInterceptInput = document.getElementById('https-intercept');
const caPathInput = document.getElementById('ca-path');
const caGenerateBtn = document.getElementById('ca-generate');
const caCopyBtn = document.getElementById('ca-copy');
const ruleForm = document.getElementById('rule-form');
const ruleActionType = document.getElementById('rule-action-type');
const ruleTextField = document.getElementById('rule-text-field');
const ruleResourceField = document.getElementById('rule-resource-field');
const ruleRedirectField = document.getElementById('rule-redirect-field');
const ruleStatusField = document.getElementById('rule-status-field');
const rulesList = document.getElementById('rules-list');
const resourcesList = document.getElementById('resources-list');
const resourceForm = document.getElementById('resource-form');
const resourceFileInput = document.getElementById('resource-file');
const resourceTypeInput = document.getElementById('resource-type');
const resourceNameInput = document.getElementById('resource-name');
const sessionsList = document.getElementById('sessions-list');
const sessionsClearBtn = document.getElementById('sessions-clear');
const ruleResourceSelect = document.getElementById('rule-action-resource');
const ruleNameInput = document.getElementById('rule-name');
const rulePriorityInput = document.getElementById('rule-priority');
const ruleUrlInput = document.getElementById('rule-url');
const ruleMethodInput = document.getElementById('rule-method');
const ruleContentTypeInput = document.getElementById('rule-content-type');
const ruleHeadersInput = document.getElementById('rule-headers');
const ruleBodyContainsInput = document.getElementById('rule-body-contains');
const ruleActionBodyInput = document.getElementById('rule-action-body');
const ruleActionLocationInput = document.getElementById('rule-action-location');
const ruleActionStatusInput = document.getElementById('rule-action-status');
const ruleSubmitBtn = document.getElementById('rule-submit');
const ruleCancelBtn = document.getElementById('rule-cancel');
const sessionsFilterInput = document.getElementById('sessions-filter');
const sessionsAppliedOnlyInput = document.getElementById('sessions-applied-only');
const sessionDetailEl = document.getElementById('session-detail');

const api = window.packetforge?.api;

let rulesCache = [];
let editingRuleId = null;
let editingRuleEnabled = true;
let sessionsCache = [];
let activeSessionId = null;

function setText(el, value) {
  if (!el) {
    return;
  }
  el.textContent = value;
}

function formatRule(rule) {
  const parts = [];
  if (Number.isFinite(rule.priority) && rule.priority !== 0) {
    parts.push(`P${rule.priority}`);
  }
  if (rule.when?.method) {
    parts.push(rule.when.method);
  }
  if (rule.when?.urlIncludes) {
    parts.push(rule.when.urlIncludes);
  }
  if (rule.when?.contentType) {
    parts.push(rule.when.contentType);
  }
  if (rule.when?.headers) {
    parts.push(`headers:${Object.keys(rule.when.headers).length}`);
  }
  if (rule.when?.bodyIncludes) {
    parts.push(`body~${truncate(rule.when.bodyIncludes, 18)}`);
  }
  return parts.length > 0 ? parts.join(' · ') : 'Any request';
}

function formatSessionTitle(session) {
  const method = session.method || 'GET';
  const status = Number.isFinite(session.status) ? session.status : 'n/a';
  return `${method} ${status}`;
}

function formatDuration(value) {
  if (!Number.isFinite(value)) {
    return 'n/a';
  }
  if (value < 1000) {
    return `${value} ms`;
  }
  return `${(value / 1000).toFixed(2)} s`;
}

function formatBytes(value) {
  if (!Number.isFinite(value)) {
    return 'n/a';
  }
  if (value < 1024) {
    return `${value} B`;
  }
  const kb = value / 1024;
  if (kb < 1024) {
    return `${kb.toFixed(1)} KB`;
  }
  const mb = kb / 1024;
  return `${mb.toFixed(1)} MB`;
}

function truncate(value, max) {
  if (!value || typeof value !== 'string') {
    return '';
  }
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, Math.max(0, max - 3))}...`;
}

function parseHeadersInput(value) {
  if (!value || typeof value !== 'string') {
    return undefined;
  }
  const lines = value.split('\n');
  const headers = {};
  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }
    const [namePart, ...rest] = trimmed.split(':');
    const name = namePart.trim();
    if (!name) {
      return;
    }
    const remainder = rest.join(':').trim();
    headers[name] = remainder ? remainder : true;
  });

  return Object.keys(headers).length > 0 ? headers : undefined;
}

function formatHeadersInput(headers) {
  if (!headers || typeof headers !== 'object') {
    return '';
  }
  return Object.entries(headers)
    .map(([key, value]) => (value === true ? key : `${key}: ${value}`))
    .join('\n');
}

function updateActionFields() {
  const actionType = ruleActionType?.value;
  if (!ruleTextField || !ruleResourceField || !ruleRedirectField || !ruleStatusField) {
    return;
  }
  const showResource = actionType === 'replaceResource';
  const showBody = actionType === 'replaceBody' || actionType === 'block' || actionType === 'redirect';
  const showRedirect = actionType === 'redirect';
  const showStatus = actionType === 'block' || actionType === 'redirect';

  ruleResourceField.classList.toggle('hidden', !showResource);
  ruleTextField.classList.toggle('hidden', !showBody);
  ruleRedirectField.classList.toggle('hidden', !showRedirect);
  ruleStatusField.classList.toggle('hidden', !showStatus);
}

function startEditingRule(rule) {
  if (!ruleForm) {
    return;
  }
  editingRuleId = rule.id;
  editingRuleEnabled = rule.enabled !== false;
  if (ruleNameInput) {
    ruleNameInput.value = rule.name || '';
  }
  if (rulePriorityInput) {
    rulePriorityInput.value = Number.isFinite(rule.priority) ? String(rule.priority) : '0';
  }
  if (ruleUrlInput) {
    ruleUrlInput.value = rule.when?.urlIncludes || '';
  }
  if (ruleMethodInput) {
    ruleMethodInput.value = rule.when?.method || '';
  }
  if (ruleContentTypeInput) {
    ruleContentTypeInput.value = rule.when?.contentType || '';
  }
  if (ruleHeadersInput) {
    ruleHeadersInput.value = formatHeadersInput(rule.when?.headers);
  }
  if (ruleBodyContainsInput) {
    ruleBodyContainsInput.value = rule.when?.bodyIncludes || '';
  }
  if (ruleActionType) {
    ruleActionType.value = rule.action?.type || 'replaceBody';
  }
  updateActionFields();
  if (ruleActionBodyInput) {
    ruleActionBodyInput.value = rule.action?.body || '';
  }
  if (ruleResourceSelect) {
    ruleResourceSelect.value = rule.action?.resourceId || '';
  }
  if (ruleActionLocationInput) {
    ruleActionLocationInput.value = rule.action?.location || '';
  }
  if (ruleActionStatusInput) {
    ruleActionStatusInput.value = rule.action?.status ?? '';
  }
  if (ruleSubmitBtn) {
    ruleSubmitBtn.textContent = 'Update Rule';
  }
  if (ruleCancelBtn) {
    ruleCancelBtn.classList.remove('hidden');
  }
}

function stopEditingRule() {
  editingRuleId = null;
  editingRuleEnabled = true;
  if (ruleForm) {
    ruleForm.reset();
  }
  updateActionFields();
  if (ruleSubmitBtn) {
    ruleSubmitBtn.textContent = 'Add Rule';
  }
  if (ruleCancelBtn) {
    ruleCancelBtn.classList.add('hidden');
  }
}

async function refreshStatus() {
  if (!api) {
    return;
  }
  const status = await api.proxy.status();
  setText(proxyStatusEl, status.running ? 'Running' : 'Stopped');
  setText(proxyPortLabelEl, `${status.port}`);
  if (proxyPortInput && status.port) {
    proxyPortInput.value = String(status.port);
  }
  const httpsEnabled = status.httpsMode === 'mitm';
  setText(httpsModeEl, httpsEnabled ? 'Intercept' : 'Tunnel');
  if (httpsInterceptInput) {
    httpsInterceptInput.checked = httpsEnabled;
  }
}

async function refreshCa() {
  if (!api) {
    return;
  }
  const status = await api.certs.status();
  setText(httpsCaStatusEl, status.ready ? 'Ready' : 'Not generated');
  if (caPathInput) {
    caPathInput.value = status.ready ? status.caCertPath : '';
  }
}

async function refreshRules() {
  if (!api) {
    return;
  }
  const rules = await api.rules.list();
  rulesCache = rules;
  setText(rulesCountEl, `${rules.length}`);
  if (!rulesList) {
    return;
  }
  rulesList.innerHTML = '';
  rules.forEach((rule) => {
    const item = document.createElement('li');
    item.className = 'list-item';
    item.innerHTML = `
      <div class="list-item__header">
        <span class="list-item__title">${rule.name}</span>
        <div class="list-item__actions">
          <button class="button button--ghost" data-action="edit" data-id="${rule.id}">
            Edit
          </button>
          <button class="button button--ghost" data-action="toggle" data-id="${rule.id}">
            ${rule.enabled === false ? 'Enable' : 'Disable'}
          </button>
          <button class="button button--ghost" data-action="delete" data-id="${rule.id}">
            Delete
          </button>
        </div>
      </div>
      <div class="list-item__meta">${formatRule(rule)}</div>
      <div class="list-item__meta">Action: ${rule.action?.type || 'none'}</div>
    `;
    if (rule.enabled === false) {
      item.style.opacity = '0.6';
    }
    rulesList.appendChild(item);
  });

  if (editingRuleId && !rules.some((rule) => rule.id === editingRuleId)) {
    stopEditingRule();
  }
  renderSessionDetail();
}

async function refreshResources() {
  if (!api) {
    return;
  }
  const resources = await api.resources.list();
  if (resourcesList) {
    resourcesList.innerHTML = '';
    resources.forEach((resource) => {
      const item = document.createElement('li');
      item.className = 'list-item';
      item.innerHTML = `
        <div class="list-item__header">
          <span class="list-item__title">${resource.name}</span>
          <div class="list-item__actions">
            <button class="button button--ghost" data-action="delete" data-id="${resource.id}">
              Delete
            </button>
          </div>
        </div>
        <div class="list-item__meta">${resource.contentType}</div>
      `;
      resourcesList.appendChild(item);
    });
  }

  if (ruleResourceSelect) {
    ruleResourceSelect.innerHTML = '';
    const emptyOption = document.createElement('option');
    emptyOption.value = '';
    emptyOption.textContent = 'Select resource';
    ruleResourceSelect.appendChild(emptyOption);
    resources.forEach((resource) => {
      const option = document.createElement('option');
      option.value = resource.id;
      option.textContent = `${resource.name} (${resource.contentType})`;
      ruleResourceSelect.appendChild(option);
    });
  }
}

function resolveRuleName(ruleId) {
  if (!ruleId) {
    return 'None';
  }
  const rule = rulesCache.find((item) => item.id === ruleId);
  return rule?.name || ruleId;
}

function getFilteredSessions() {
  const filterText = sessionsFilterInput?.value?.trim().toLowerCase() || '';
  const appliedOnly = sessionsAppliedOnlyInput?.checked;
  return sessionsCache.filter((session) => {
    if (appliedOnly && !session.applied) {
      return false;
    }
    if (!filterText) {
      return true;
    }
    const haystack = `${session.method || ''} ${session.status || ''} ${session.url || ''}`.toLowerCase();
    return haystack.includes(filterText);
  });
}

function renderSessionDetail() {
  if (!sessionDetailEl) {
    return;
  }
  const session = sessionsCache.find((item) => item.id === activeSessionId);
  sessionDetailEl.innerHTML = '';
  if (!session) {
    sessionDetailEl.textContent = 'Select a session to inspect.';
    sessionDetailEl.classList.add('muted');
    return;
  }
  sessionDetailEl.classList.remove('muted');

  const rows = [
    ['Method', session.method || 'n/a'],
    ['Status', Number.isFinite(session.status) ? String(session.status) : 'n/a'],
    ['URL', session.url || 'n/a'],
    ['Content-Type', session.contentType || 'n/a'],
    ['Duration', formatDuration(session.durationMs)],
    ['Size', formatBytes(session.sizeBytes)],
    ['Rule', resolveRuleName(session.matchedRuleId)],
    ['Modified', session.applied ? 'Yes' : 'No']
  ];

  rows.forEach(([label, value]) => {
    const row = document.createElement('div');
    row.className = 'detail__row';
    const labelEl = document.createElement('span');
    labelEl.className = 'label';
    labelEl.textContent = label;
    const valueEl = document.createElement('span');
    valueEl.className = 'value';
    valueEl.textContent = value;
    row.appendChild(labelEl);
    row.appendChild(valueEl);
    sessionDetailEl.appendChild(row);
  });
}

function renderSessions() {
  if (!sessionsList) {
    return;
  }
  const filtered = getFilteredSessions();
  const maxItems = 50;
  sessionsList.innerHTML = '';
  filtered.slice(0, maxItems).forEach((session) => {
    const item = document.createElement('li');
    item.className = 'list-item list-item--selectable';
    if (session.id === activeSessionId) {
      item.classList.add('is-active');
    }
    item.dataset.id = session.id;

    const header = document.createElement('div');
    header.className = 'list-item__header';
    const title = document.createElement('span');
    title.className = 'list-item__title';
    title.textContent = formatSessionTitle(session);
    header.appendChild(title);

    const actions = document.createElement('div');
    actions.className = 'list-item__actions';
    if (session.applied) {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = 'Modified';
      actions.appendChild(chip);
    }
    header.appendChild(actions);

    const meta = document.createElement('div');
    meta.className = 'list-item__meta';
    meta.textContent = session.url || '';

    item.appendChild(header);
    item.appendChild(meta);
    sessionsList.appendChild(item);
  });

  setText(sessionCountEl, `${sessionsCache.length}`);
  renderSessionDetail();
}

async function refreshSessions() {
  if (!api || !sessionsList) {
    return;
  }
  const sessions = await api.sessions.list();
  sessionsCache = sessions;
  renderSessions();
}

function appendSession(session) {
  sessionsCache = [session, ...sessionsCache];
  const maxEntries = 200;
  if (sessionsCache.length > maxEntries) {
    sessionsCache = sessionsCache.slice(0, maxEntries);
  }
  renderSessions();
}

async function handleProxyStart(event) {
  event.preventDefault();
  if (!api) {
    return;
  }
  const port = Number.parseInt(proxyPortInput?.value, 10) || 8080;
  const httpsIntercept = Boolean(httpsInterceptInput?.checked);
  await api.proxy.start({ port, httpsIntercept });
  await refreshStatus();
}

async function handleProxyStop() {
  if (!api) {
    return;
  }
  await api.proxy.stop();
  await refreshStatus();
}

async function handleHttpsToggle() {
  if (!api || !httpsInterceptInput) {
    return;
  }
  const enabled = Boolean(httpsInterceptInput.checked);
  if (enabled) {
    await api.certs.ensure();
  }
  await api.proxy.configure({ httpsIntercept: enabled });
  await refreshStatus();
  await refreshCa();
}

async function handleCaGenerate() {
  if (!api) {
    return;
  }
  await api.certs.ensure();
  await refreshCa();
}

function handleCaCopy() {
  if (!api || !caPathInput || !caCopyBtn) {
    return;
  }
  const value = caPathInput.value?.trim();
  if (!value) {
    return;
  }
  api.utils?.copyText?.(value);
  const original = caCopyBtn.textContent;
  caCopyBtn.textContent = 'Copied';
  window.setTimeout(() => {
    if (caCopyBtn.textContent === 'Copied') {
      caCopyBtn.textContent = original || 'Copy Path';
    }
  }, 1500);
}

async function handleRuleSubmit(event) {
  event.preventDefault();
  if (!api || !ruleForm) {
    return;
  }

  const name = ruleNameInput?.value?.trim() || 'Untitled Rule';
  const priorityValue = Number.parseInt(rulePriorityInput?.value, 10);
  const priority = Number.isFinite(priorityValue) ? priorityValue : 0;
  const urlIncludes = ruleUrlInput?.value?.trim() || '';
  const method = ruleMethodInput?.value?.trim() || '';
  const contentType = ruleContentTypeInput?.value?.trim() || '';
  const headers = parseHeadersInput(ruleHeadersInput?.value || '');
  const bodyIncludes = ruleBodyContainsInput?.value?.trim() || '';
  const actionType = ruleActionType?.value || 'replaceBody';
  const body = ruleActionBodyInput?.value ?? '';
  const location = ruleActionLocationInput?.value?.trim() || '';
  const statusValue = Number.parseInt(ruleActionStatusInput?.value, 10);
  const status = Number.isFinite(statusValue) ? statusValue : undefined;
  const resourceId = ruleResourceSelect?.value ?? '';

  const rule = {
    name,
    enabled: editingRuleId ? editingRuleEnabled : true,
    priority,
    when: {
      method: method || undefined,
      urlIncludes: urlIncludes || undefined,
      contentType: contentType || undefined,
      headers: headers || undefined,
      bodyIncludes: bodyIncludes || undefined
    },
    action: {
      type: actionType
    }
  };

  if (actionType === 'replaceResource') {
    rule.action.resourceId = resourceId || undefined;
    rule.action.body = '';
  } else if (actionType === 'redirect') {
    rule.action.location = location || undefined;
    rule.action.body = body;
    rule.action.bodyType = 'text';
  } else if (actionType === 'block') {
    rule.action.body = body;
    rule.action.bodyType = 'text';
  } else {
    rule.action.body = body;
    rule.action.bodyType = 'text';
  }
  if (status !== undefined) {
    rule.action.status = status;
  }

  if (editingRuleId) {
    await api.rules.update({ id: editingRuleId, patch: rule });
    stopEditingRule();
  } else {
    await api.rules.create(rule);
    ruleForm.reset();
    updateActionFields();
  }
  await refreshRules();
}

function handleRuleCancel() {
  stopEditingRule();
}

async function handleRulesListClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  const action = target.dataset.action;
  const id = target.dataset.id;
  if (!action || !id || !api) {
    return;
  }

  if (action === 'delete') {
    await api.rules.remove(id);
    await refreshRules();
  } else if (action === 'toggle') {
    const rules = await api.rules.list();
    const rule = rules.find((item) => item.id === id);
    if (!rule) {
      return;
    }
    await api.rules.update({ id, patch: { enabled: !rule.enabled } });
    await refreshRules();
  } else if (action === 'edit') {
    const rule = rulesCache.find((item) => item.id === id);
    if (!rule) {
      return;
    }
    startEditingRule(rule);
  }
}

async function handleResourceSubmit(event) {
  event.preventDefault();
  if (!api || !resourceForm || !resourceFileInput) {
    return;
  }
  const file = resourceFileInput.files?.[0];
  if (!file) {
    return;
  }
  const contentType = resourceTypeInput?.value?.trim() || file.type || 'application/octet-stream';
  const name = resourceNameInput?.value?.trim() || file.name || 'Resource';

  const dataBase64 = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (typeof result === 'string') {
        const base64 = result.split(',')[1] || '';
        resolve(base64);
      } else {
        resolve('');
      }
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });

  await api.resources.create({
    name,
    contentType,
    dataBase64
  });

  resourceForm.reset();
  await refreshResources();
}

async function handleResourcesListClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  const action = target.dataset.action;
  const id = target.dataset.id;
  if (!action || !id || !api) {
    return;
  }

  if (action === 'delete') {
    await api.resources.remove(id);
    await refreshResources();
  }
}

function handleSessionsListClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  const item = target.closest('[data-id]');
  if (!(item instanceof HTMLElement)) {
    return;
  }
  const id = item.dataset.id;
  if (!id) {
    return;
  }
  activeSessionId = id;
  renderSessions();
}

function handleSessionsFilter() {
  renderSessions();
}

async function handleSessionsClear() {
  if (!api) {
    return;
  }
  await api.sessions.clear();
  activeSessionId = null;
  await refreshSessions();
}

function bootstrap() {
  if (appVersionEl && window.packetforge?.appVersion) {
    appVersionEl.textContent = window.packetforge.appVersion;
  }

  updateActionFields();

  ruleActionType?.addEventListener('change', updateActionFields);
  proxyForm?.addEventListener('submit', handleProxyStart);
  proxyStopBtn?.addEventListener('click', handleProxyStop);
  httpsInterceptInput?.addEventListener('change', handleHttpsToggle);
  caGenerateBtn?.addEventListener('click', handleCaGenerate);
  caCopyBtn?.addEventListener('click', handleCaCopy);
  ruleForm?.addEventListener('submit', handleRuleSubmit);
  ruleCancelBtn?.addEventListener('click', handleRuleCancel);
  rulesList?.addEventListener('click', handleRulesListClick);
  resourceForm?.addEventListener('submit', handleResourceSubmit);
  resourcesList?.addEventListener('click', handleResourcesListClick);
  sessionsClearBtn?.addEventListener('click', handleSessionsClear);
  sessionsList?.addEventListener('click', handleSessionsListClick);
  sessionsFilterInput?.addEventListener('input', handleSessionsFilter);
  sessionsAppliedOnlyInput?.addEventListener('change', handleSessionsFilter);

  api?.onSession?.((session) => {
    appendSession(session);
  });

  api?.onProxyStatus?.((status) => {
    setText(proxyStatusEl, status.running ? 'Running' : 'Stopped');
    setText(proxyPortLabelEl, `${status.port}`);
    const httpsEnabled = status.httpsMode === 'mitm';
    setText(httpsModeEl, httpsEnabled ? 'Intercept' : 'Tunnel');
    if (httpsInterceptInput) {
      httpsInterceptInput.checked = httpsEnabled;
    }
  });

  void refreshStatus();
  void refreshCa();
  void refreshRules();
  void refreshResources();
  void refreshSessions();
}

bootstrap();
