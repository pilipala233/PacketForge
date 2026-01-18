import test from 'node:test';
import assert from 'node:assert/strict';
import {
  collectRuleCandidates,
  matchRule,
  normalizeContentType,
  selectRule
} from '../src/core/rules.js';

test('matchRule matches method and urlIncludes', () => {
  const rule = {
    when: { method: 'GET', urlIncludes: '/assets/' }
  };
  const request = { method: 'get', url: 'https://example.com/assets/app.js' };

  assert.equal(matchRule(rule, request), true);
});

test('matchRule fails when contentType mismatches', () => {
  const rule = {
    when: { contentType: 'image/png' }
  };
  const request = { method: 'GET', url: 'https://example.com/a.png', contentType: 'image/jpeg' };

  assert.equal(matchRule(rule, request), false);
});

test('selectRule returns first matching rule', () => {
  const rules = [
    { when: { urlIncludes: '/a' }, priority: 0 },
    { when: { urlIncludes: '/b' }, priority: 5 }
  ];

  const request = { method: 'GET', url: 'https://example.com/b' };

  assert.equal(selectRule(rules, request), rules[1]);
});

test('selectRule skips disabled rules', () => {
  const rules = [
    { id: 'a', enabled: false, when: { urlIncludes: '/test' } },
    { id: 'b', enabled: true, when: { urlIncludes: '/test' } }
  ];

  const request = { method: 'GET', url: 'https://example.com/test' };
  assert.equal(selectRule(rules, request), rules[1]);
});

test('selectRule prefers higher priority', () => {
  const rules = [
    { id: 'a', when: { urlIncludes: '/test' }, priority: 1 },
    { id: 'b', when: { urlIncludes: '/test' }, priority: 10 }
  ];

  const request = { method: 'GET', url: 'https://example.com/test' };
  assert.equal(selectRule(rules, request), rules[1]);
});

test('normalizeContentType removes charset', () => {
  assert.equal(normalizeContentType('text/html; charset=utf-8'), 'text/html');
});

test('matchRule compares contentType case-insensitively', () => {
  const rule = {
    when: { contentType: 'Text/Html' }
  };

  const request = { method: 'GET', url: 'https://example.com', contentType: 'text/html; charset=utf-8' };
  assert.equal(matchRule(rule, request), true);
});

test('matchRule matches headers contains', () => {
  const rule = {
    when: { headers: { 'User-Agent': 'Mozilla', Accept: true } }
  };

  const request = {
    method: 'GET',
    url: 'https://example.com',
    headers: { 'user-agent': 'Mozilla/5.0', accept: 'text/html' }
  };
  assert.equal(matchRule(rule, request), true);
});

test('collectRuleCandidates marks rules needing body', () => {
  const rules = [
    { id: 'a', when: { urlIncludes: '/test', bodyIncludes: 'hello' } },
    { id: 'b', when: { urlIncludes: '/other' } }
  ];
  const request = { method: 'GET', url: 'https://example.com/test' };
  const result = collectRuleCandidates(rules, request);
  assert.equal(result.matches.length, 0);
  assert.equal(result.needsBody.length, 1);
});

test('matchRule matches bodyIncludes with bodyText', () => {
  const rule = {
    when: { urlIncludes: '/test', bodyIncludes: 'hello' }
  };
  const request = {
    method: 'GET',
    url: 'https://example.com/test',
    bodyText: 'Say hello world'
  };
  assert.equal(matchRule(rule, request), true);
});
