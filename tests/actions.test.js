import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveAction } from '../src/core/actions.js';

test('resolveAction replaces body with text', () => {
  const response = { status: 200, headers: {}, body: Buffer.from('ok'), contentType: 'text/plain' };
  const action = { type: 'replaceBody', body: 'hello', bodyType: 'text' };

  const result = resolveAction(action, response, null);

  assert.equal(result.modified, true);
  assert.equal(result.body.toString('utf8'), 'hello');
});

test('resolveAction replaces body with resource', () => {
  const response = { status: 200, headers: {}, body: Buffer.from('ok'), contentType: 'text/plain' };
  const resourcesStore = {
    get: () => ({ dataBase64: Buffer.from('image', 'utf8').toString('base64'), contentType: 'image/png' })
  };
  const action = { type: 'replaceResource', resourceId: 'r1' };

  const result = resolveAction(action, response, resourcesStore);

  assert.equal(result.modified, true);
  assert.equal(result.contentType, 'image/png');
  assert.equal(result.body.toString('utf8'), 'image');
});

test('resolveAction blocks response with default status', () => {
  const response = { status: 200, headers: {}, body: Buffer.from('ok'), contentType: 'text/plain' };
  const action = { type: 'block' };

  const result = resolveAction(action, response, null);

  assert.equal(result.modified, true);
  assert.equal(result.status, 403);
  assert.equal(result.body.toString('utf8'), 'Blocked');
});

test('resolveAction redirects with location', () => {
  const response = { status: 200, headers: {}, body: Buffer.from('ok'), contentType: 'text/plain' };
  const action = { type: 'redirect', location: 'https://example.com' };

  const result = resolveAction(action, response, null);

  assert.equal(result.modified, true);
  assert.equal(result.status, 302);
  assert.equal(result.headers.location, 'https://example.com');
});
