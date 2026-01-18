function normalizeContentType(value) {
  if (!value || typeof value !== 'string') {
    return '';
  }

  return value.split(';')[0].trim().toLowerCase();
}

function normalizeHeaderValue(value) {
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  if (value === undefined || value === null) {
    return '';
  }
  return String(value);
}

function normalizeHeaders(headers) {
  if (!headers || typeof headers !== 'object') {
    return {};
  }
  const normalized = {};
  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = normalizeHeaderValue(value);
  }
  return normalized;
}

function matchHeaders(ruleHeaders, actualHeaders) {
  if (!ruleHeaders || typeof ruleHeaders !== 'object') {
    return true;
  }
  const actual = normalizeHeaders(actualHeaders);
  for (const [key, expected] of Object.entries(ruleHeaders)) {
    const name = key.toLowerCase();
    const actualValue = actual[name];
    if (expected === true || expected === '') {
      if (!actualValue) {
        return false;
      }
      continue;
    }
    const expectedText = String(expected).toLowerCase();
    if (!actualValue || !actualValue.toLowerCase().includes(expectedText)) {
      return false;
    }
  }
  return true;
}

function matchBody(ruleBody, bodyText) {
  if (!ruleBody || typeof ruleBody !== 'string') {
    return { match: true, needsBody: false };
  }
  const expected = ruleBody.trim();
  if (!expected) {
    return { match: true, needsBody: false };
  }
  if (bodyText === undefined || bodyText === null) {
    return { match: false, needsBody: true };
  }
  return {
    match: bodyText.toLowerCase().includes(expected.toLowerCase()),
    needsBody: false
  };
}

function getPriority(rule) {
  const value = Number(rule?.priority ?? 0);
  return Number.isFinite(value) ? value : 0;
}

export function evaluateRule(rule, context) {
  if (!rule?.when || !context || rule.enabled === false) {
    return { match: false, needsBody: false };
  }

  if (rule.when.method) {
    const ruleMethod = rule.when.method.toUpperCase();
    const reqMethod = (context.method || '').toUpperCase();
    if (ruleMethod !== reqMethod) {
      return { match: false, needsBody: false };
    }
  }

  if (rule.when.urlIncludes) {
    if (!context.url || !context.url.includes(rule.when.urlIncludes)) {
      return { match: false, needsBody: false };
    }
  }

  if (rule.when.contentType) {
    const targetType = normalizeContentType(rule.when.contentType);
    const actualType = normalizeContentType(context.contentType);
    if (!actualType || actualType !== targetType) {
      return { match: false, needsBody: false };
    }
  }

  if (!matchHeaders(rule.when.headers, context.headers)) {
    return { match: false, needsBody: false };
  }

  if (rule.when.bodyIncludes) {
    const result = matchBody(rule.when.bodyIncludes, context.bodyText);
    return result.match ? { match: true, needsBody: false } : result;
  }

  return { match: true, needsBody: false };
}

export function matchRule(rule, context) {
  return evaluateRule(rule, context).match;
}

export function collectRuleCandidates(rules, context) {
  const matches = [];
  const needsBody = [];
  if (!Array.isArray(rules)) {
    return { matches, needsBody };
  }
  for (const rule of rules) {
    const result = evaluateRule(rule, context);
    if (result.match) {
      matches.push(rule);
    } else if (result.needsBody) {
      needsBody.push(rule);
    }
  }
  return { matches, needsBody };
}

export function selectBestRule(rules) {
  let best = null;
  let bestPriority = -Infinity;
  if (!Array.isArray(rules)) {
    return null;
  }
  for (const rule of rules) {
    const priority = getPriority(rule);
    if (!best || priority > bestPriority) {
      best = rule;
      bestPriority = priority;
    }
  }
  return best;
}

export function selectRule(rules, context) {
  const { matches } = collectRuleCandidates(rules, context);
  return selectBestRule(matches);
}

export { normalizeContentType };
