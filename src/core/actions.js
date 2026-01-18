function toBuffer(body, bodyType) {
  if (bodyType === 'base64') {
    return Buffer.from(body ?? '', 'base64');
  }

  return Buffer.from(body ?? '', 'utf8');
}

export function resolveAction(action, response, resourcesStore) {
  if (!action) {
    return { ...response, modified: false };
  }

  switch (action.type) {
    case 'replaceBody': {
      const body = toBuffer(action.body, action.bodyType);
      return {
        ...response,
        status: action.status ?? response.status,
        body,
        contentType: action.contentType ?? response.contentType,
        modified: true
      };
    }
    case 'replaceResource': {
      const resource = resourcesStore?.get?.(action.resourceId);
      if (!resource) {
        return { ...response, modified: false, error: 'resource_not_found' };
      }

      return {
        ...response,
        status: action.status ?? response.status,
        body: Buffer.from(resource.dataBase64 ?? '', 'base64'),
        contentType: resource.contentType ?? response.contentType,
        modified: true
      };
    }
    case 'redirect': {
      const location = action.location || '';
      const body = toBuffer(action.body ?? '', action.bodyType);
      return {
        ...response,
        status: action.status ?? 302,
        headers: {
          ...(response.headers || {}),
          location
        },
        body,
        contentType: action.contentType ?? (body.length > 0 ? 'text/plain; charset=utf-8' : response.contentType),
        modified: true
      };
    }
    case 'block': {
      const body = toBuffer(action.body ?? 'Blocked', action.bodyType);
      return {
        ...response,
        status: action.status ?? 403,
        body,
        contentType: action.contentType ?? 'text/plain; charset=utf-8',
        modified: true
      };
    }
    default:
      return { ...response, modified: false };
  }
}
