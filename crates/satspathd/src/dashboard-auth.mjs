// Interim dashboard auth: a token entered once, held only in this module's closure.
// No cookies, browser storage, token-returning endpoint, or HTML interpolation.
const PUBLIC_POSTS = new Set([
  '/v1/receive', '/v1/send', '/v1/dns/resolve',
  '/v1/transparency/verify/inclusion', '/v2/resolve',
]);

export function requiresAuthentication(method, pathname) {
  const verb = method.toUpperCase();
  if (['GET', 'HEAD', 'OPTIONS'].includes(verb)) return false;
  // Mirror the backend's public mutation exceptions, not an owner allowlist.
  return !PUBLIC_POSTS.has(pathname);
}

export function createDashboardClient({ origin, fetchImpl = globalThis.fetch, onLock = () => {} }) {
  const base = new URL(origin);
  let token = null;
  let generation = 0;
  const secureOrigin = base.protocol === 'https:' ||
    (base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname));

  function lock() { generation++; token = null; onLock(); }
  function target(path) {
    const url = new URL(path, base);
    if (url.origin !== base.origin || url.username || url.password) {
      throw new Error('Dashboard requests must stay on this daemon origin.');
    }
    return url;
  }

  async function request(path, options = {}) {
    const url = target(path);
    const method = (options.method ?? 'GET').toUpperCase();
    const headers = new Headers(options.headers);
    if (headers.has('authorization')) throw new Error('Authorization is managed by the dashboard.');
    const authenticated = requiresAuthentication(method, url.pathname);
    if (authenticated) {
      if (!secureOrigin) throw new Error('Dashboard sign-in requires HTTPS or a loopback address.');
      if (!token) throw new Error('Unlock this tab before changing node settings.');
      headers.set('Authorization', `Bearer ${token}`);
    }
    // Never forward credentials to redirect destinations, even on the same origin.
    const requestGeneration = generation;
    let response;
    try {
      response = await fetchImpl(url.href, {
        ...options, method, headers, credentials: 'omit', mode: 'same-origin', redirect: 'error',
      });
    } catch { throw new Error('Dashboard request failed. Check the connection.'); }
    if (authenticated && response.status === 401) {
      if (generation === requestGeneration) lock();
      throw new Error('Dashboard authorization expired or was rejected. Unlock this tab again.');
    }
    return response;
  }

  async function unlock(value) {
    lock();
    if (!secureOrigin) throw new Error('Dashboard sign-in requires HTTPS or a loopback address.');
    if (typeof value !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value.trim())) {
      throw new Error('Enter the local daemon admin token (64 hexadecimal characters).');
    }
    const candidate = value.trim();
    const unlockGeneration = generation;
    try {
      const response = await fetchImpl(target('/v1/dashboard/auth').href, {
        method: 'POST', headers: new Headers({ Authorization: `Bearer ${candidate}` }),
        credentials: 'omit', mode: 'same-origin', redirect: 'error',
      });
      if (!response.ok) throw new Error('rejected');
      if (generation !== unlockGeneration) throw new Error('cancelled');
      token = candidate;
    } catch {
      // Do not propagate a transport exception that could contain request headers.
      throw new Error('Dashboard sign-in failed. Check the local token and connection.');
    }
  }

  return { request, unlock, lock };
}
