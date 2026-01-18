import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
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
  const tempPath = `${filePath}.tmp`;
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(tempPath, JSON.stringify(data, null, 2), 'utf8');
  await fs.rename(tempPath, filePath);
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

export function createSessionsStore(filePath, { maxEntries = 200 } = {}) {
  let state = { sessions: [] };

  async function load() {
    state = await readJson(filePath, { sessions: [] });
    if (!Array.isArray(state.sessions)) {
      state.sessions = [];
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
    if (state.sessions.length > maxEntries) {
      state.sessions = state.sessions.slice(0, maxEntries);
    }
    await persist();
    return session;
  }

  async function clear() {
    state.sessions = [];
    await persist();
    return true;
  }

  return { load, list, add, clear };
}
