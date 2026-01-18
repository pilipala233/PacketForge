import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createResourcesStore, createRulesStore, createSessionsStore } from '../src/core/stores.js';

async function withTempDir(fn) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'packetforge-'));
  try {
    return await fn(base);
  } finally {
    await fs.rm(base, { recursive: true, force: true });
  }
}

test('rules store adds, updates, removes', async () => {
  await withTempDir(async (dir) => {
    const store = createRulesStore(path.join(dir, 'rules.json'));
    await store.load();

    const created = await store.add({
      name: 'Test',
      priority: 5,
      when: { urlIncludes: '/a', headers: { 'X-Test': '1' }, bodyIncludes: 'hello' },
      action: { type: 'redirect', location: 'https://example.com', status: 302 }
    });
    assert.equal(store.list().length, 1);
    assert.equal(created.priority, 5);
    assert.equal(created.when.headers['X-Test'], '1');
    assert.equal(created.when.bodyIncludes, 'hello');
    assert.equal(created.action.location, 'https://example.com');

    const updated = await store.update(created.id, { enabled: false });
    assert.equal(updated.enabled, false);

    const removed = await store.remove(created.id);
    assert.equal(removed, true);
    assert.equal(store.list().length, 0);
  });
});

test('resources store adds and removes', async () => {
  await withTempDir(async (dir) => {
    const store = createResourcesStore(path.join(dir, 'resources.json'));
    await store.load();

    const created = await store.add({
      name: 'Sample',
      contentType: 'text/plain',
      dataBase64: Buffer.from('hello').toString('base64')
    });
    assert.equal(store.list().length, 1);
    assert.equal(store.get(created.id).name, 'Sample');

    const removed = await store.remove(created.id);
    assert.equal(removed, true);
    assert.equal(store.list().length, 0);
  });
});

test('sessions store caps entries', async () => {
  await withTempDir(async (dir) => {
    const store = createSessionsStore(path.join(dir, 'sessions.json'), { maxEntries: 2 });
    await store.load();

    await store.add({ url: 'a' });
    await store.add({ url: 'b' });
    await store.add({ url: 'c' });

    assert.equal(store.list().length, 2);
    assert.equal(store.list()[0].url, 'c');
  });
});
