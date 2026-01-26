// 导入 i18n 系统
import { initI18n, setLanguage, t, getCurrentLanguage } from './i18n.js';

// 初始化 i18n
initI18n();

// 语言切换器
const languageSelector = document.getElementById('language-selector');
if (languageSelector) {
  // 设置当前语言
  languageSelector.value = getCurrentLanguage();

  // 监听语言切换
  languageSelector.addEventListener('change', (e) => {
    setLanguage(e.target.value);
  });
}

const appVersionEl = document.getElementById('app-version');
const rulesCountEl = document.getElementById('rules-count');
const sessionCountEl = document.getElementById('session-count');
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
const sessionsPauseBtn = document.getElementById('sessions-pause');
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
const sessionsHideUdpInput = document.getElementById('sessions-hide-udp');
const sessionsMaxEntriesInput = document.getElementById('sessions-max-entries');
const sessionDetailEl = document.getElementById('session-detail');
const sessionModalEl = document.getElementById('session-modal');
const sessionModalTitleEl = document.getElementById('session-modal-title');
const sessionModalCloseBtn = document.getElementById('session-modal-close');
const captureDirInput = document.getElementById('capture-dir');
const captureDirBrowseBtn = document.getElementById('capture-dir-browse');
const captureMaxSizeInput = document.getElementById('capture-max-size');
const ffmpegPathInput = document.getElementById('ffmpeg-path');
const ffmpegBrowseBtn = document.getElementById('ffmpeg-browse');
const autoConvertSelect = document.getElementById('auto-convert');
const mitmStatusEl = document.getElementById('mitm-status');

const api = window.packetforge?.api;
if (!api) {
  console.error('API bridge not found!');
  alert('Critical Error: API bridge not initialized. The application may not work correctly.');
}

let rulesCache = [];
let editingRuleId = null;
let editingRuleEnabled = true;
let sessionsCache = [];
let activeSessionId = null;
const BODY_PREVIEW_BYTES = 64 * 1024;
const bodyPreviewCache = new Map();

function setText(el, value) {
  if (!el) {
    return;
  }
  el.textContent = value;
}

function updateHttpsModeLabel(enabled) {
  if (!httpsModeEl) {
    return;
  }
  setText(httpsModeEl, enabled ? t('proxy.https.enabled') : t('proxy.https.disabled'));
}

function updatePauseButton() {
  if (!sessionsPauseBtn) {
    return;
  }
  if (!mitmState.running) {
    sessionsPauseBtn.disabled = true;
    sessionsPauseBtn.textContent = t('sessions.pause');
    return;
  }
  sessionsPauseBtn.disabled = false;
  sessionsPauseBtn.textContent = mitmState.paused ? t('sessions.resume') : t('sessions.pause');
}

function updateMitmStatusLabel(status) {
  if (!status || !mitmStatusEl) {
    return;
  }
  if (status.running) {
    setText(mitmStatusEl, status.paused ? t('mitm.status.paused') : t('mitm.status.active'));
  } else {
    setText(mitmStatusEl, t('mitm.status.inactive'));
  }
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

function bytesToMb(value) {
  if (!Number.isFinite(value)) {
    return null;
  }
  const mb = value / (1024 * 1024);
  if (mb <= 0) {
    return null;
  }
  return Math.round(mb * 10) / 10;
}

function parseMaxBytesInput(value) {
  const mb = Number.parseFloat(value);
  if (!Number.isFinite(mb) || mb <= 0) {
    return null;
  }
  return Math.round(mb * 1024 * 1024);
}

function parseSessionMaxEntries(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return Math.min(5000, Math.max(20, parsed));
}

function parseKbpsInput(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 0;
  }
  return parsed;
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

let sessionModalOpen = false;

function openSessionModal() {
  if (!sessionModalEl) {
    return;
  }
  sessionModalEl.classList.add('is-open');
  sessionModalOpen = true;
}

function closeSessionModal() {
  if (!sessionModalEl) {
    return;
  }
  sessionModalEl.classList.remove('is-open');
  sessionModalOpen = false;
}

function buildBodyRow(label, body) {
  if (!body || typeof body !== 'object') {
    return null;
  }
  const hasPath = typeof body.path === 'string' && body.path.trim();
  const hasBytes = Number.isFinite(body.totalBytes) && body.totalBytes > 0;
  const hasSaved = Number.isFinite(body.savedBytes) && body.savedBytes > 0;
  if (!hasPath && !hasBytes && !hasSaved) {
    return null;
  }
  return {
    label,
    body: {
      path: hasPath ? body.path : null,
      totalBytes: hasBytes ? body.totalBytes : undefined,
      savedBytes: hasSaved ? body.savedBytes : undefined,
      truncated: Boolean(body.truncated)
    }
  };
}

function formatBodySummary(body) {
  if (!body) {
    return 'n/a';
  }
  const parts = [];
  const saved = Number.isFinite(body.savedBytes) ? body.savedBytes : null;
  const total = Number.isFinite(body.totalBytes) ? body.totalBytes : null;
  if (Number.isFinite(saved) && Number.isFinite(total) && total > saved) {
    parts.push(`${formatBytes(saved)} / ${formatBytes(total)}`);
  } else if (Number.isFinite(total)) {
    parts.push(formatBytes(total));
  } else if (Number.isFinite(saved)) {
    parts.push(formatBytes(saved));
  }
  if (body.path) {
    parts.push(truncate(body.path, 60));
  }
  if (body.truncated) {
    parts.push('truncated');
  }
  return parts.length > 0 ? parts.join(' · ') : 'n/a';
}

function formatHeaderValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item)).join(', ');
  }
  if (value === undefined || value === null) {
    return '';
  }
  return String(value);
}

function formatHeaders(headers) {
  if (!headers || typeof headers !== 'object') {
    return '';
  }
  const entries = Object.entries(headers)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) {
    return '';
  }
  return entries.map(([key, value]) => `${key}: ${formatHeaderValue(value)}`).join('\n');
}

function formatPreviewText(preview) {
  if (!preview?.ok) {
    return preview?.error ? `Preview error: ${preview.error}` : 'Preview unavailable';
  }
  const suffixes = [];
  if (!preview.isText) {
    suffixes.push('[binary preview as base64]');
  }
  if (preview.truncated) {
    suffixes.push('... (truncated)');
  }
  const body = preview.isText ? preview.text ?? '' : preview.base64 ?? '';
  if (!suffixes.length) {
    return body;
  }
  return `${body}\n${suffixes.join('\n')}`;
}

async function loadBodyPreview({ path, contentType, targetId, sessionId }) {
  if (!api?.utils?.readFile || !path || !targetId) {
    return;
  }
  const key = `${path}|${contentType || ''}`;
  let preview = bodyPreviewCache.get(key);
  if (!preview) {
    preview = await api.utils.readFile({
      path,
      maxBytes: BODY_PREVIEW_BYTES,
      contentType
    });
    bodyPreviewCache.set(key, preview);
  }
  if (sessionId && sessionId !== activeSessionId) {
    return;
  }
  const target = document.getElementById(targetId);
  if (!target) {
    return;
  }
  target.textContent = formatPreviewText(preview);
}

function formatMediaFlag(value) {
  if (value === true) {
    return t('common.yes');
  }
  if (value === false) {
    return t('common.no');
  }
  return 'n/a';
}

function formatMediaInfo(media) {
  if (!media || typeof media !== 'object') {
    return '';
  }
  const parts = [];
  if (media.container) {
    parts.push(media.container.toUpperCase());
  }
  if (typeof media.headerSeen === 'boolean') {
    parts.push(`Header ${formatMediaFlag(media.headerSeen)}`);
  }
  if ('sequenceHeader' in media) {
    parts.push(`Seq ${formatMediaFlag(media.sequenceHeader)}`);
  }
  if ('keyframe' in media) {
    parts.push(`Keyframe ${formatMediaFlag(media.keyframe)}`);
  }
  return parts.join(' | ');
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

async function refreshSettings() {
  if (!api?.settings?.get) {
    return;
  }
  const settings = await api.settings.get();
  const capture = settings?.capture;
  const media = settings?.media;
  const sessions = settings?.sessions;
  if (captureDirInput) {
    captureDirInput.value = capture?.dir || '';
  }
  if (captureMaxSizeInput) {
    const mb = bytesToMb(capture?.maxBytes) ?? 100;
    captureMaxSizeInput.value = String(mb);
  }
  if (ffmpegPathInput) {
    ffmpegPathInput.value = media?.ffmpegPath || '';
  }
  if (autoConvertSelect) {
    const mode = media?.autoConvert;
    autoConvertSelect.value =
      mode === 'remux' || mode === 'h264' || mode === 'off' ? mode : 'off';
  }
  if (sessionsMaxEntriesInput) {
    const maxEntries =
      Number.isFinite(sessions?.maxEntries) && sessions.maxEntries > 0
        ? sessions.maxEntries
        : 200;
    sessionsMaxEntriesInput.value = String(maxEntries);
  }
}

async function persistSettings() {
  if (!api?.settings?.update) {
    return;
  }
  const dir = captureDirInput?.value?.trim() || '';
  const fallbackBytes = 100 * 1024 * 1024;
  const maxBytes = parseMaxBytesInput(captureMaxSizeInput?.value) ?? fallbackBytes;
  const ffmpegPath = ffmpegPathInput?.value?.trim() || '';
  const autoConvert = autoConvertSelect?.value || 'off';
  const maxEntries =
    sessionsMaxEntriesInput && parseSessionMaxEntries(sessionsMaxEntriesInput.value);
  const patch = {
    capture: {
      dir,
      maxBytes
    },
    media: {
      ffmpegPath,
      autoConvert
    }
  };
  if (maxEntries) {
    patch.sessions = {
      maxEntries
    };
  }
  await api.settings.update(patch);
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
  const hideUdp = sessionsHideUdpInput?.checked;
  return sessionsCache.filter((session) => {
    if (appliedOnly && !session.applied) {
      return false;
    }
    if (hideUdp) {
      const method = String(session.method || '').toUpperCase();
      if (method === 'UDP' || String(session.url || '').toLowerCase().startsWith('udp:')) {
        return false;
      }
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
    return false;
  }
  const session = sessionsCache.find((item) => item.id === activeSessionId);
  sessionDetailEl.innerHTML = '';
  if (!session) {
    sessionDetailEl.textContent = t('sessions.detail.empty');
    sessionDetailEl.classList.add('muted');
    if (sessionModalTitleEl) {
      sessionModalTitleEl.textContent = t('sessions.detail');
    }
    return false;
  }
  sessionDetailEl.classList.remove('muted');
  if (sessionModalTitleEl) {
    const statusLabel = Number.isFinite(session.status) ? session.status : 'n/a';
    sessionModalTitleEl.textContent = `${session.method || 'GET'} ${statusLabel}`;
  }

  const rows = [
    { label: 'Method', value: session.method || 'n/a' },
    { label: 'Status', value: Number.isFinite(session.status) ? String(session.status) : 'n/a' },
    { label: 'URL', value: session.url || 'n/a' },
    { label: 'Content-Type', value: session.contentType || 'n/a' },
    { label: 'Duration', value: formatDuration(session.durationMs) },
    { label: 'Size', value: formatBytes(session.sizeBytes) },
    { label: 'Rule', value: resolveRuleName(session.matchedRuleId) },
    { label: 'Modified', value: session.applied ? 'Yes' : 'No' }
  ];
  const previewTasks = [];

  const requestHeadersText = formatHeaders(session.requestHeaders);
  if (requestHeadersText) {
    rows.push({
      label: 'Request Headers',
      block: requestHeadersText
    });
  }

  const requestBodyRow = buildBodyRow('Request Body', {
    path: session.requestBodyPath,
    totalBytes: session.requestBodyBytes,
    savedBytes: session.requestBodySavedBytes,
    truncated: session.requestBodyTruncated
  });
  if (requestBodyRow) {
    rows.push(requestBodyRow);
  }
  const responseBodyRow = buildBodyRow('Response Body', {
    path: session.responseBodyPath,
    totalBytes: session.responseBodyBytes,
    savedBytes: session.responseBodySavedBytes,
    truncated: session.responseBodyTruncated
  });
  if (responseBodyRow) {
    rows.push(responseBodyRow);
  }

  const requestBodyPath =
    typeof session.requestBodyPath === 'string' ? session.requestBodyPath.trim() : '';
  const requestBodyTotal =
    Number.isFinite(session.requestBodyBytes) ? session.requestBodyBytes : 0;
  const requestBodySaved =
    Number.isFinite(session.requestBodySavedBytes) ? session.requestBodySavedBytes : 0;
  let requestBodyHint = 'No request body.';
  if (requestBodyTotal > 0 || requestBodySaved > 0) {
    requestBodyHint = 'Request body not saved.';
  }
  if (session.method === 'HTTPS' || session.method === 'CONNECT') {
    requestBodyHint = 'HTTPS not decrypted; body unavailable.';
  }
  const requestPreviewId = `request-preview-${session.id}`;
  if (session.requestBodyPreview?.ok) {
    rows.push({
      label: 'Request Body Preview',
      block: formatPreviewText(session.requestBodyPreview)
    });
  } else {
    rows.push({
      label: 'Request Body Preview',
      block: requestBodyPath ? 'Loading...' : requestBodyHint,
      blockId: requestBodyPath ? requestPreviewId : undefined
    });
    if (requestBodyPath) {
      const requestContentType = formatHeaderValue(session.requestHeaders?.['content-type']);
      previewTasks.push({
        path: requestBodyPath,
        contentType: requestContentType,
        targetId: requestPreviewId,
        sessionId: session.id
      });
    }
  }

  if (session.responseBodyPath) {
    const targetId = `response-preview-${session.id}`;
    const responseContentType =
      formatHeaderValue(session.responseHeaders?.['content-type']) || session.contentType || '';
    rows.push({
      label: 'Response Body Preview',
      block: 'Loading...',
      blockId: targetId
    });
    previewTasks.push({
      path: session.responseBodyPath,
      contentType: responseContentType,
      targetId,
      sessionId: session.id
    });
  }

  const convertedRow = buildBodyRow('Converted Media', {
    path: session.responseMediaConvertedPath
  });
  if (convertedRow) {
    rows.push(convertedRow);
  }
  if (session.responseMediaConvertedMode) {
    rows.push({ label: 'Convert Mode', value: session.responseMediaConvertedMode });
  }
  if (session.responseMediaConvertError) {
    rows.push({
      label: 'Convert Error',
      value: truncate(String(session.responseMediaConvertError), 120)
    });
  }

  const mediaInfo = formatMediaInfo(session.responseMedia);
  if (mediaInfo) {
    rows.push({ label: 'Media', value: mediaInfo });
  }

  rows.forEach((row) => {
    const rowEl = document.createElement('div');
    rowEl.className = 'detail__row';
    const labelEl = document.createElement('span');
    labelEl.className = 'label';
    labelEl.textContent = row.label;
    rowEl.appendChild(labelEl);

    if (row.block !== undefined) {
      rowEl.classList.add('detail__row--block');
      const valueWrap = document.createElement('div');
      valueWrap.className = 'detail__value detail__value--block';
      const pre = document.createElement('pre');
      pre.className = 'detail__pre';
      if (row.blockId) {
        pre.id = row.blockId;
      }
      pre.textContent = row.block || '';
      valueWrap.appendChild(pre);
      if (api?.utils?.copyText) {
        const copyBtn = document.createElement('button');
        copyBtn.className = 'button button--ghost button--small';
        copyBtn.type = 'button';
        copyBtn.textContent = t('common.copy');
        copyBtn.addEventListener('click', (event) => {
          event.preventDefault();
          api.utils.copyText(pre.textContent || '');
        });
        valueWrap.appendChild(copyBtn);
      }
      rowEl.appendChild(valueWrap);
      sessionDetailEl.appendChild(rowEl);
      return;
    }

    if (row.body) {
      const valueWrap = document.createElement('div');
      valueWrap.className = 'detail__value';
      const summaryText = formatBodySummary(row.body);
      const summaryEl = document.createElement('span');
      summaryEl.textContent = summaryText;
      if (row.body.path) {
        summaryEl.title = row.body.path;
      }
      valueWrap.appendChild(summaryEl);

      if (row.body.path && api?.utils?.copyText) {
        const copyBtn = document.createElement('button');
        copyBtn.className = 'button button--ghost button--small';
        copyBtn.type = 'button';
        copyBtn.textContent = t('common.copy');
        copyBtn.addEventListener('click', (event) => {
          event.preventDefault();
          api.utils.copyText(row.body.path);
        });
        valueWrap.appendChild(copyBtn);
      }
      if (row.body.path && api?.utils?.showItemInFolder) {
        const openBtn = document.createElement('button');
        openBtn.className = 'button button--ghost button--small';
        openBtn.type = 'button';
        openBtn.textContent = t('common.open');
        openBtn.addEventListener('click', (event) => {
          event.preventDefault();
          api.utils.showItemInFolder(row.body.path);
        });
        valueWrap.appendChild(openBtn);
      }

      rowEl.appendChild(valueWrap);
      sessionDetailEl.appendChild(rowEl);
      return;
    }

    const valueEl = document.createElement('span');
    valueEl.className = 'value';
    valueEl.textContent = row.value;
    rowEl.appendChild(valueEl);
    sessionDetailEl.appendChild(rowEl);
  });
  previewTasks.forEach((task) => {
    void loadBodyPreview(task);
  });
  return true;
}

function renderSessions() {
  if (!sessionsList) {
    return;
  }
  const filtered = getFilteredSessions();
  const maxItems =
    parseSessionMaxEntries(sessionsMaxEntriesInput?.value) ?? 50;
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
  const hasSession = renderSessionDetail();
  if (!hasSession && sessionModalOpen) {
    closeSessionModal();
  }
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
  const maxEntries = parseSessionMaxEntries(sessionsMaxEntriesInput?.value) ?? 200;
  if (sessionsCache.length > maxEntries) {
    sessionsCache = sessionsCache.slice(0, maxEntries);
  }
  renderSessions();
}

function updateSession(session) {
  if (!session?.id) {
    return;
  }
  const index = sessionsCache.findIndex((item) => item.id === session.id);
  if (index === -1) {
    return;
  }
  sessionsCache[index] = { ...sessionsCache[index], ...session };
  renderSessions();
}

async function handleHttpsToggle() {
  if (!api || !httpsInterceptInput) {
    return;
  }
  const enabled = Boolean(httpsInterceptInput.checked);
  try {
    if (mitmState.running) {
      alert('Please stop MITM before toggling HTTPS intercept.');
      httpsInterceptInput.checked = !enabled;
      return;
    }
    if (enabled) {
      await api.certs.ensure();
    }
    mitmState.httpsIntercept = enabled;
    updateHttpsModeLabel(enabled);
    updateHttpsPortsAvailability(enabled, mitmState.httpsObserve);
    await refreshCa();
  } catch (error) {
    console.error('Failed to toggle HTTPS:', error);
    alert(`Failed to toggle HTTPS: ${error.message || error}`);
    // Revert checkbox
    httpsInterceptInput.checked = !enabled;
  }
}

async function handleHttpsObserveToggle() {
  if (!mitmHttpsObserveInput) {
    return;
  }
  const enabled = Boolean(mitmHttpsObserveInput.checked);
  if (mitmState.running) {
    alert('Please stop MITM before toggling HTTPS observe mode.');
    mitmHttpsObserveInput.checked = !enabled;
    return;
  }
  mitmState.httpsObserve = enabled;
  updateHttpsPortsAvailability(mitmState.httpsIntercept, mitmState.httpsObserve);
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
  openSessionModal();
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
  closeSessionModal();
  await refreshSessions();
}

async function handleSessionsPause() {
  if (!api?.mitm?.pause || !api?.mitm?.resume) {
    return;
  }
  if (!mitmState.running) {
    alert('MITM is not running.');
    return;
  }
  try {
    if (mitmState.paused) {
      await api.mitm.resume();
    } else {
      await api.mitm.pause();
    }
  } catch (error) {
    const action = mitmState.paused ? 'resume' : 'pause';
    alert(`Failed to ${action} MITM: ${error.message || error}`);
  }
}

async function handleSessionsMaxEntries() {
  await persistSettings();
  await refreshSessions();
}

async function handleCaptureBrowse() {
  if (!api?.utils?.selectDirectory || !captureDirInput) {
    return;
  }
  const selected = await api.utils.selectDirectory();
  if (selected) {
    captureDirInput.value = selected;
    await persistSettings();
  }
}

async function handleFfmpegBrowse() {
  if (!api?.utils?.selectFile || !ffmpegPathInput) {
    return;
  }
  const filters = [
    {
      name: 'FFmpeg',
      extensions: ['exe']
    }
  ];
  const selected = await api.utils.selectFile({ filters });
  if (selected) {
    ffmpegPathInput.value = selected;
    await persistSettings();
  }
}

function bootstrap() {
  if (appVersionEl && window.packetforge?.appVersion) {
    appVersionEl.textContent = window.packetforge.appVersion;
  }

  updateActionFields();
  updateHttpsModeLabel(mitmState?.httpsIntercept ?? false);
  updatePauseButton();

  ruleActionType?.addEventListener('change', updateActionFields);
  httpsInterceptInput?.addEventListener('change', handleHttpsToggle);
  caGenerateBtn?.addEventListener('click', handleCaGenerate);
  caCopyBtn?.addEventListener('click', handleCaCopy);
  ruleForm?.addEventListener('submit', handleRuleSubmit);
  ruleCancelBtn?.addEventListener('click', handleRuleCancel);
  rulesList?.addEventListener('click', handleRulesListClick);
  resourceForm?.addEventListener('submit', handleResourceSubmit);
  resourcesList?.addEventListener('click', handleResourcesListClick);
  sessionsClearBtn?.addEventListener('click', handleSessionsClear);
  sessionsPauseBtn?.addEventListener('click', handleSessionsPause);
  sessionsMaxEntriesInput?.addEventListener('change', handleSessionsMaxEntries);
  sessionsList?.addEventListener('click', handleSessionsListClick);
  sessionsFilterInput?.addEventListener('input', handleSessionsFilter);
  sessionsAppliedOnlyInput?.addEventListener('change', handleSessionsFilter);
  sessionsHideUdpInput?.addEventListener('change', handleSessionsFilter);
  sessionModalCloseBtn?.addEventListener('click', closeSessionModal);
  sessionModalEl?.addEventListener('click', (event) => {
    const target = event.target;
    if (target instanceof HTMLElement && target.dataset.action === 'close') {
      closeSessionModal();
    }
  });
  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && sessionModalOpen) {
      closeSessionModal();
    }
  });
  document.addEventListener('languageChanged', () => {
    updateHttpsModeLabel(mitmState?.httpsIntercept ?? false);
    updateMitmStatusLabel(mitmState);
    updatePauseButton();
  });
  captureDirBrowseBtn?.addEventListener('click', handleCaptureBrowse);
  captureDirInput?.addEventListener('change', persistSettings);
  captureMaxSizeInput?.addEventListener('change', persistSettings);
  ffmpegBrowseBtn?.addEventListener('click', handleFfmpegBrowse);
  ffmpegPathInput?.addEventListener('change', persistSettings);
  autoConvertSelect?.addEventListener('change', persistSettings);

  api?.onSession?.((session) => {
    appendSession(session);
  });
  api?.onSessionUpdated?.((session) => {
    updateSession(session);
  });

  void refreshCa();
  void refreshSettings();
  void refreshRules();
  void refreshResources();
  void refreshSessions();

  // MITM 功能初始化
  initMitm();
}

// ============================================================================
// MITM 功能
// ============================================================================

let mitmHttpPortsInput;
let mitmHttpsPortsInput;
let mitmHttpsObserveInput;

function updateHttpsPortsAvailability(enabled, observe) {
  if (!mitmHttpsPortsInput) {
    return;
  }
  mitmHttpsPortsInput.disabled = !(enabled || observe);
}

let mitmState = {
  interfaces: [],
  selectedInterface: null,
  gateway: null,
  devices: [],
  selectedDevices: new Set(),
  running: false,
  httpsIntercept: false,
  httpsObserve: false,
  paused: false,
  pendingStart: false
};

function initMitm() {
  const mitmPrivilegesEl = document.getElementById('mitm-privileges');
  const mitmInterfaceEl = document.getElementById('mitm-interface');
  const mitmTargetsCountEl = document.getElementById('mitm-targets-count');

  const mitmInterfaceSelect = document.getElementById('mitm-interface-select');
  const mitmRefreshInterfacesBtn = document.getElementById('mitm-refresh-interfaces');
  const mitmDetectGatewayBtn = document.getElementById('mitm-detect-gateway');
  const mitmScanNetworkBtn = document.getElementById('mitm-scan-network');
  const mitmRequestPrivilegesBtn = document.getElementById('mitm-request-privileges');
  const mitmStartBtn = document.getElementById('mitm-start');
  const mitmStopBtn = document.getElementById('mitm-stop');

  const mitmGatewayInfo = document.getElementById('mitm-gateway-info');
  const mitmDevicesList = document.getElementById('mitm-devices-list');
  const mitmProxyPortInput = document.getElementById('mitm-proxy-port');
  const mitmUploadKbpsInput = document.getElementById('mitm-upload-kbps');
  const mitmDownloadKbpsInput = document.getElementById('mitm-download-kbps');
  mitmHttpPortsInput = document.getElementById('mitm-http-ports');
  mitmHttpsPortsInput = document.getElementById('mitm-https-ports');
  mitmHttpsObserveInput = document.getElementById('mitm-https-observe');
  mitmHttpsObserveInput?.addEventListener('change', handleHttpsObserveToggle);

  function applyMitmStatus(status) {
    if (!status) {
      return;
    }
    mitmState.running = Boolean(status.running);
    mitmState.paused = Boolean(status.paused);
    updateMitmStatusLabel(status);
    setText(mitmInterfaceEl, status.interface || '-');
    setText(mitmTargetsCountEl, status.targets?.length?.toString() || '0');

    const allowHttpsUpdate = !mitmState.pendingStart || status.running;
    if (allowHttpsUpdate && typeof status.httpsIntercept === 'boolean') {
      mitmState.httpsIntercept = status.httpsIntercept;
      if (httpsInterceptInput) {
        httpsInterceptInput.checked = status.httpsIntercept;
      }
      updateHttpsModeLabel(status.httpsIntercept);
    }
    if (allowHttpsUpdate && typeof status.httpsObserve === 'boolean') {
      mitmState.httpsObserve = status.httpsObserve;
      if (mitmHttpsObserveInput) {
        mitmHttpsObserveInput.checked = status.httpsObserve;
      }
    }
    updateHttpsPortsAvailability(mitmState.httpsIntercept, mitmState.httpsObserve);
    updatePauseButton();
  }

  // 检查权限
  async function checkPrivileges() {
    try {
      const result = await window.packetforge.api.mitm.checkPrivileges();
      if (result.elevated) {
        setText(mitmPrivilegesEl, 'Elevated ✓');
        mitmRequestPrivilegesBtn?.classList.add('hidden');
      } else {
        setText(mitmPrivilegesEl, 'Not Elevated');
        mitmRequestPrivilegesBtn?.classList.remove('hidden');
      }
    } catch (error) {
      setText(mitmPrivilegesEl, 'Error');
      console.error('[mitm] Failed to check privileges:', error);
    }
  }

  // 刷新网络接口列表
  async function refreshInterfaces() {
    try {
      const interfaces = await window.packetforge.api.mitm.listInterfaces();
      mitmState.interfaces = interfaces;

      // 清空并重新填充下拉列表
      mitmInterfaceSelect.innerHTML = '<option value="">Select interface...</option>';
      for (const iface of interfaces) {
        const option = document.createElement('option');
        option.value = iface.name;
        option.textContent = `${iface.name} - ${iface.ip}`;
        mitmInterfaceSelect.appendChild(option);
      }

      console.log('[mitm] Found interfaces:', interfaces);
    } catch (error) {
      console.error('[mitm] Failed to list interfaces:', error);
    }
  }

  // 检测网关
  async function detectGateway() {
    if (!mitmState.selectedInterface) {
      alert('Please select a network interface first');
      return;
    }

    try {
      const gateway = await window.packetforge.api.mitm.getGateway(mitmState.selectedInterface.name);
      if (gateway) {
        mitmState.gateway = gateway;
        setText(mitmGatewayInfo, `${gateway.ip} (${gateway.mac || 'MAC unknown'})`);
        console.log('[mitm] Gateway detected:', gateway);
      } else {
        setText(mitmGatewayInfo, 'Gateway not found');
      }
    } catch (error) {
      setText(mitmGatewayInfo, 'Error detecting gateway');
      console.error('[mitm] Failed to detect gateway:', error);
    }
  }

  // 扫描网络
  async function scanNetwork() {
    if (!mitmState.selectedInterface) {
      alert('Please select a network interface first');
      return;
    }

    setText(mitmDevicesList, 'Scanning...');

    try {
      const devices = await window.packetforge.api.mitm.scanNetwork(mitmState.selectedInterface.name);
      mitmState.devices = devices;
      renderDevices();
      console.log('[mitm] Found devices:', devices);
    } catch (error) {
      setText(mitmDevicesList, 'Scan failed');
      console.error('[mitm] Failed to scan network:', error);
    }
  }

  // 渲染设备列表
  function renderDevices() {
    if (mitmState.devices.length === 0) {
      setText(mitmDevicesList, 'No devices found. Try scanning again.');
      return;
    }

    mitmDevicesList.innerHTML = '';

    for (const device of mitmState.devices) {
      const deviceEl = document.createElement('div');
      deviceEl.className = 'device-item';

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.id = `device-${device.ip}`;
      checkbox.checked = mitmState.selectedDevices.has(device.ip);
      checkbox.addEventListener('change', () => {
        if (checkbox.checked) {
          mitmState.selectedDevices.add(device.ip);
        } else {
          mitmState.selectedDevices.delete(device.ip);
        }
        updateTargetsCount();
      });

      const label = document.createElement('label');
      label.htmlFor = `device-${device.ip}`;
      label.textContent = `${device.ip} (${device.mac})`;
      if (device.hostname) {
        label.textContent += ` - ${device.hostname}`;
      }

      deviceEl.appendChild(checkbox);
      deviceEl.appendChild(label);
      mitmDevicesList.appendChild(deviceEl);
    }
  }

  // 更新目标数量
  function updateTargetsCount() {
    setText(mitmTargetsCountEl, mitmState.selectedDevices.size.toString());
  }

  // 启动 MITM
  async function startMitm() {
    if (!mitmState.selectedInterface) {
      alert('Please select a network interface');
      return;
    }

    if (!mitmState.gateway) {
      alert('Please detect gateway first');
      return;
    }

    if (mitmState.selectedDevices.size === 0) {
      alert('Please select at least one target device');
      return;
    }

    // 构造目标列表
    const targets = mitmState.devices.filter((d) => mitmState.selectedDevices.has(d.ip));

    try {
      mitmState.pendingStart = true;
      const proxyPort = Number.parseInt(mitmProxyPortInput.value, 10) || 8888;
      const httpPorts = mitmHttpPortsInput?.value ?? '';
      const httpsPorts = mitmHttpsPortsInput?.value ?? '';
      const uploadKbps = parseKbpsInput(mitmUploadKbpsInput?.value);
      const downloadKbps = parseKbpsInput(mitmDownloadKbpsInput?.value);
      if (mitmHttpsObserveInput) {
        mitmState.httpsObserve = Boolean(mitmHttpsObserveInput.checked);
      }
      const captureDir = captureDirInput?.value?.trim() || '';
      const captureMaxBytes =
        parseMaxBytesInput(captureMaxSizeInput?.value) ?? 100 * 1024 * 1024;

      const status = await window.packetforge.api.mitm.start({
        interface: mitmState.selectedInterface.name,
        gateway: mitmState.gateway,
        targets,
        proxyPort,
        httpsIntercept: mitmState.httpsIntercept,
        httpsObserve: mitmState.httpsObserve,
        httpPorts,
        httpsPorts,
        throttle: {
          uploadKbps,
          downloadKbps
        },
        capture: {
          dir: captureDir,
          maxBytes: captureMaxBytes
        }
      });

      if (status) {
        applyMitmStatus(status);
      } else {
        mitmState.running = true;
      }
      console.log('[mitm] MITM started');
    } catch (error) {
      alert(`Failed to start MITM: ${error.message}`);
      console.error('[mitm] Failed to start:', error);
    } finally {
      mitmState.pendingStart = false;
    }
  }

  // 停止 MITM
  async function stopMitm() {
    try {
      await window.packetforge.api.mitm.stop();
      mitmState.running = false;
      console.log('[mitm] MITM stopped');
    } catch (error) {
      alert(`Failed to stop MITM: ${error.message}`);
      console.error('[mitm] Failed to stop:', error);
    }
  }

  // 请求权限
  async function requestPrivileges() {
    try {
      const relaunch = window.packetforge.api.app?.relaunchAsAdmin;
      if (!relaunch) {
        alert('Relaunch as admin is not available in this build.');
        return;
      }
      const result = await relaunch();
      if (result?.alreadyElevated) {
        alert('Already running as Administrator.');
        await checkPrivileges();
        return;
      }
      if (result?.success) {
        alert('Relaunching as Administrator...');
        return;
      }
      alert(`Failed to relaunch as Administrator: ${result?.error || 'Unknown error'}`);
      await checkPrivileges();
    } catch (error) {
      alert(`Failed to relaunch as Administrator: ${error.message}`);
      console.error('[mitm] Failed to relaunch as admin:', error);
    }
  }

  // 事件监听
  mitmInterfaceSelect?.addEventListener('change', () => {
    const selectedName = mitmInterfaceSelect.value;
    mitmState.selectedInterface = mitmState.interfaces.find((i) => i.name === selectedName);
    if (mitmState.selectedInterface) {
      setText(mitmInterfaceEl, mitmState.selectedInterface.name);
    }
  });

  mitmRefreshInterfacesBtn?.addEventListener('click', refreshInterfaces);
  mitmDetectGatewayBtn?.addEventListener('click', detectGateway);
  mitmScanNetworkBtn?.addEventListener('click', scanNetwork);
  mitmRequestPrivilegesBtn?.addEventListener('click', requestPrivileges);
  mitmStartBtn?.addEventListener('click', startMitm);
  mitmStopBtn?.addEventListener('click', stopMitm);

  // 监听 MITM 状态变化
  window.packetforge.api.onMitmStatus?.((status) => {
    applyMitmStatus(status);
  });

  // 监听设备发现
  window.packetforge.api.onMitmDeviceDiscovered?.((device) => {
    console.log('[mitm] Device discovered:', device);
  });

  // 监听错误
  window.packetforge.api.onMitmError?.((error) => {
    alert(`MITM Error: ${error.message}`);
    console.error('[mitm] Error:', error);
  });

  // 初始化
  void checkPrivileges();
  void refreshInterfaces();
  updateHttpsPortsAvailability(mitmState.httpsIntercept, mitmState.httpsObserve);
  window.packetforge.api.mitm
    .status()
    .then((status) => applyMitmStatus(status))
    .catch((error) => {
      console.error('[mitm] Failed to load status:', error);
    });
}

bootstrap();
