const PORT_MIN = 1;
const PORT_MAX = 65535;

function toPortNumber(value) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return null;
}

function clampPort(value) {
  if (!Number.isFinite(value)) {
    return null;
  }
  if (value < PORT_MIN || value > PORT_MAX) {
    return null;
  }
  return value;
}

function addPort(spec, value) {
  const port = clampPort(toPortNumber(value));
  if (!port) {
    return;
  }
  spec.ports.push(port);
}

function addRange(spec, start, end) {
  const startNum = toPortNumber(start);
  const endNum = toPortNumber(end);
  if (!Number.isFinite(startNum) || !Number.isFinite(endNum)) {
    return;
  }
  const rangeStart = Math.max(PORT_MIN, Math.min(startNum, endNum));
  const rangeEnd = Math.min(PORT_MAX, Math.max(startNum, endNum));
  if (rangeStart > rangeEnd) {
    return;
  }
  if (rangeStart === rangeEnd) {
    spec.ports.push(rangeStart);
    return;
  }
  spec.ranges.push({ start: rangeStart, end: rangeEnd });
}

function applyPortInput(spec, value) {
  if (value === undefined || value === null) {
    return;
  }
  if (typeof value === 'number') {
    addPort(spec, value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => applyPortInput(spec, item));
    return;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      return;
    }
    const tokens = trimmed.split(/[,\s]+/);
    for (const token of tokens) {
      if (!token) {
        continue;
      }
      const lower = token.toLowerCase();
      if (lower === '*' || lower === 'all') {
        addRange(spec, PORT_MIN, PORT_MAX);
        continue;
      }
      const dashIndex = token.indexOf('-');
      if (dashIndex > 0) {
        const startPart = token.slice(0, dashIndex);
        const endPart = token.slice(dashIndex + 1);
        if (!startPart || !endPart) {
          continue;
        }
        addRange(spec, startPart, endPart);
        continue;
      }
      addPort(spec, token);
    }
    return;
  }
  if (typeof value === 'object') {
    if (Array.isArray(value.ports)) {
      value.ports.forEach((port) => addPort(spec, port));
    }
    if (Array.isArray(value.ranges)) {
      value.ranges.forEach((range) => addRange(spec, range?.start, range?.end));
    }
  }
}

function mergeRanges(ranges) {
  if (!Array.isArray(ranges) || ranges.length === 0) {
    return [];
  }
  const sorted = ranges
    .map((range) => ({
      start: clampPort(Math.min(range.start, range.end)),
      end: clampPort(Math.max(range.start, range.end))
    }))
    .filter((range) => range.start && range.end)
    .sort((a, b) => a.start - b.start);

  const merged = [];
  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (!last || range.start > last.end + 1) {
      merged.push({ ...range });
      continue;
    }
    last.end = Math.max(last.end, range.end);
  }
  return merged;
}

function normalizeSpec(spec) {
  const ports = Array.from(new Set(spec.ports))
    .map((port) => clampPort(port))
    .filter((port) => port)
    .sort((a, b) => a - b);

  const ranges = mergeRanges(spec.ranges);

  if (ranges.length === 1 && ranges[0].start === PORT_MIN && ranges[0].end === PORT_MAX) {
    return { ports: [], ranges };
  }

  const filteredPorts = ports.filter((port) => {
    return !ranges.some((range) => port >= range.start && port <= range.end);
  });

  return { ports: filteredPorts, ranges };
}

export function parsePortSpec(input, fallback) {
  const spec = { ports: [], ranges: [] };
  const hasInput =
    !(input === undefined || input === null) &&
    !(typeof input === 'string' && input.trim() === '') &&
    !(Array.isArray(input) && input.length === 0);

  if (hasInput) {
    applyPortInput(spec, input);
  } else if (fallback !== undefined) {
    applyPortInput(spec, fallback);
  }

  return normalizeSpec(spec);
}

export function hasPortSpec(spec) {
  return Boolean(
    spec &&
      ((Array.isArray(spec.ports) && spec.ports.length > 0) ||
        (Array.isArray(spec.ranges) && spec.ranges.length > 0))
  );
}

export function isAllPorts(spec) {
  if (!spec || !Array.isArray(spec.ranges) || spec.ranges.length !== 1) {
    return false;
  }
  const range = spec.ranges[0];
  if (!range || range.start !== PORT_MIN || range.end !== PORT_MAX) {
    return false;
  }
  return !Array.isArray(spec.ports) || spec.ports.length === 0;
}

export function portMatches(port, spec) {
  if (!Number.isInteger(port) || !hasPortSpec(spec)) {
    return false;
  }
  if (spec.ports && spec.ports.includes(port)) {
    return true;
  }
  if (spec.ranges) {
    return spec.ranges.some((range) => port >= range.start && port <= range.end);
  }
  return false;
}

export function buildPortFilter(field, spec) {
  if (!hasPortSpec(spec)) {
    return '';
  }
  const parts = [];
  for (const port of spec.ports || []) {
    parts.push(`${field} == ${port}`);
  }
  for (const range of spec.ranges || []) {
    parts.push(`(${field} >= ${range.start} and ${field} <= ${range.end})`);
  }
  if (parts.length === 1) {
    return parts[0];
  }
  return `(${parts.join(' or ')})`;
}
