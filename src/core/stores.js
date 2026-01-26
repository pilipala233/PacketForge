import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const writeQueues = new Map();

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

async function withWriteLock(filePath, task) {
  const previous = writeQueues.get(filePath) ?? Promise.resolve();
  let release;
  const current = new Promise((resolve) => {
    release = resolve;
  });
  writeQueues.set(filePath, current);

  try {
    await previous;
    return await task();
  } finally {
    release();
    if (writeQueues.get(filePath) === current) {
      writeQueues.delete(filePath);
    }
  }
}

async function readJson(filePath, fallback) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return fallback;
    }
    throw error;
  }
}

async function writeJson(filePath, data) {
  return withWriteLock(filePath, async () => {
    const tempPath = `${filePath}.${randomUUID()}.tmp`;
    await ensureDir(path.dirname(filePath));
    await fs.writeFile(tempPath, JSON.stringify(data, null, 2), 'utf8');
    try {
      await fs.rename(tempPath, filePath);
    } catch (error) {
      if (error?.code === 'EPERM' || error?.code === 'EEXIST' || error?.code === 'EACCES') {
        try {
          await fs.copyFile(tempPath, filePath);
        } finally {
          await fs.unlink(tempPath).catch(() => {});
        }
        return;
      }
      await fs.unlink(tempPath).catch(() => {});
      throw error;
    }
  });
}

function normalizeRuleInput(input) {
  const priority = Number(input.priority ?? 0);
  const normalizedPriority = Number.isFinite(priority) ? priority : 0;
  const headers = input.when?.headers;
  const normalizedHeaders = {};
  if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
    for (const [key, value] of Object.entries(headers)) {
      const name = key.trim();
      if (!name) {
        continue;
      }
      if (value === true || value === '') {
        normalizedHeaders[name] = true;
        continue;
      }
      if (value === null || value === undefined) {
        continue;
      }
      normalizedHeaders[name] = String(value);
    }
  }

  const bodyIncludes =
    typeof input.when?.bodyIncludes === 'string' ? input.when.bodyIncludes.trim() : '';

  return {
    name: input.name?.trim() || 'Untitled Rule',
    enabled: input.enabled !== false,
    priority: normalizedPriority,
    when: {
      method: input.when?.method || undefined,
      urlIncludes: input.when?.urlIncludes || undefined,
      contentType: input.when?.contentType || undefined,
      headers: Object.keys(normalizedHeaders).length > 0 ? normalizedHeaders : undefined,
      bodyIncludes: bodyIncludes || undefined
    },
    action: {
      type: input.action?.type || 'replaceBody',
      body: input.action?.body ?? '',
      bodyType: input.action?.bodyType ?? 'text',
      contentType: input.action?.contentType ?? undefined,
      resourceId: input.action?.resourceId ?? undefined,
      status: input.action?.status ?? undefined,
      location: input.action?.location ?? undefined
    }
  };
}

export function createRulesStore(filePath) {
  let state = { rules: [] };

  async function load() {
    state = await readJson(filePath, { rules: [] });
    if (!Array.isArray(state.rules)) {
      state.rules = [];
    }
    return state.rules;
  }

  async function persist() {
    await writeJson(filePath, state);
  }

  function list() {
    return state.rules;
  }

  async function add(input) {
    const now = new Date().toISOString();
    const normalized = normalizeRuleInput(input ?? {});
    const rule = {
      id: randomUUID(),
      createdAt: now,
      updatedAt: now,
      ...normalized
    };
    state.rules.push(rule);
    await persist();
    return rule;
  }

  async function update(id, patch) {
    const rule = state.rules.find((item) => item.id === id);
    if (!rule) {
      return null;
    }

    const { when, action, ...rest } = patch ?? {};
    Object.assign(rule, rest);
    if (when) {
      rule.when = { ...rule.when, ...when };
    }
    if (action) {
      rule.action = { ...rule.action, ...action };
    }
    rule.updatedAt = new Date().toISOString();
    await persist();
    return rule;
  }

  async function remove(id) {
    const next = state.rules.filter((item) => item.id !== id);
    if (next.length === state.rules.length) {
      return false;
    }
    state.rules = next;
    await persist();
    return true;
  }

  return { load, list, add, update, remove };
}

export function createResourcesStore(filePath) {
  let state = { resources: [] };

  async function load() {
    state = await readJson(filePath, { resources: [] });
    if (!Array.isArray(state.resources)) {
      state.resources = [];
    }
    return state.resources;
  }

  async function persist() {
    await writeJson(filePath, state);
  }

  function list() {
    return state.resources;
  }

  function get(id) {
    return state.resources.find((item) => item.id === id) ?? null;
  }

  async function add(input) {
    const now = new Date().toISOString();
    const resource = {
      id: randomUUID(),
      name: input.name?.trim() || 'Resource',
      contentType: input.contentType?.trim() || 'application/octet-stream',
      dataBase64: input.dataBase64 ?? '',
      createdAt: now,
      updatedAt: now
    };
    state.resources.push(resource);
    await persist();
    return resource;
  }

  async function remove(id) {
    const next = state.resources.filter((item) => item.id !== id);
    if (next.length === state.resources.length) {
      return false;
    }
    state.resources = next;
    await persist();
    return true;
  }

  return { load, list, get, add, remove };
}

const MIN_SESSION_ENTRIES = 20;
const MAX_SESSION_ENTRIES = 5000;

function clampSessionEntries(value, fallback = 200) {
  const parsed = Number.isFinite(value) ? Math.trunc(value) : Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(MAX_SESSION_ENTRIES, Math.max(MIN_SESSION_ENTRIES, parsed));
}

export function createSessionsStore(filePath, { maxEntries = 200 } = {}) {
  let maxEntriesLimit = clampSessionEntries(maxEntries, 200);
  let state = { sessions: [] };

  async function load() {
    state = await readJson(filePath, { sessions: [] });
    if (!Array.isArray(state.sessions)) {
      state.sessions = [];
    }
    if (state.sessions.length > maxEntriesLimit) {
      state.sessions = state.sessions.slice(0, maxEntriesLimit);
      await persist();
    }
    return state.sessions;
  }

  async function persist() {
    await writeJson(filePath, state);
  }

  function list() {
    return state.sessions;
  }

  async function add(entry) {
    const now = new Date().toISOString();
    const session = {
      id: randomUUID(),
      createdAt: now,
      ...entry
    };
    state.sessions.unshift(session);
    if (state.sessions.length > maxEntriesLimit) {
      state.sessions = state.sessions.slice(0, maxEntriesLimit);
    }
    await persist();
    return session;
  }

  async function update(id, patch) {
    const session = state.sessions.find((item) => item.id === id);
    if (!session) {
      return null;
    }
    Object.assign(session, patch ?? {});
    session.updatedAt = new Date().toISOString();
    await persist();
    return session;
  }

  async function clear() {
    state.sessions = [];
    await persist();
    return true;
  }

  async function setMaxEntries(nextLimit) {
    maxEntriesLimit = clampSessionEntries(nextLimit, maxEntriesLimit);
    if (state.sessions.length > maxEntriesLimit) {
      state.sessions = state.sessions.slice(0, maxEntriesLimit);
      await persist();
    }
    return maxEntriesLimit;
  }

  function getMaxEntries() {
    return maxEntriesLimit;
  }

  return { load, list, add, update, clear, setMaxEntries, getMaxEntries };
}

export function createSettingsStore(filePath, { defaults = {} } = {}) {
  let state = { ...defaults };

  async function load() {
    const loaded = await readJson(filePath, defaults);
    state = { ...defaults, ...loaded };
    if (defaults.capture && typeof defaults.capture === 'object') {
      const capture = loaded?.capture;
      state.capture = {
        ...defaults.capture,
        ...(capture && typeof capture === 'object' && !Array.isArray(capture) ? capture : {})
      };
    }
    if (defaults.media && typeof defaults.media === 'object') {
      const media = loaded?.media;
      state.media = {
        ...defaults.media,
        ...(media && typeof media === 'object' && !Array.isArray(media) ? media : {})
      };
    }
    if (defaults.sessions && typeof defaults.sessions === 'object') {
      const sessions = loaded?.sessions;
      state.sessions = {
        ...defaults.sessions,
        ...(sessions && typeof sessions === 'object' && !Array.isArray(sessions) ? sessions : {})
      };
    }
    return state;
  }

  async function persist() {
    await writeJson(filePath, state);
  }

  function get() {
    return state;
  }

  async function update(patch) {
    if (!patch || typeof patch !== 'object') {
      return state;
    }
    const next = { ...state, ...patch };
    if (patch.capture && typeof patch.capture === 'object' && !Array.isArray(patch.capture)) {
      next.capture = { ...(state.capture ?? {}), ...patch.capture };
    }
    if (patch.media && typeof patch.media === 'object' && !Array.isArray(patch.media)) {
      next.media = { ...(state.media ?? {}), ...patch.media };
    }
    if (patch.sessions && typeof patch.sessions === 'object' && !Array.isArray(patch.sessions)) {
      next.sessions = { ...(state.sessions ?? {}), ...patch.sessions };
    }
    state = next;
    await persist();
    return state;
  }

  return { load, get, update };
}
