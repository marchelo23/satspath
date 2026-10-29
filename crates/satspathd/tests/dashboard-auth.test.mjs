import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createDashboardClient, requiresAuthentication } from '../src/dashboard-auth.mjs';

const adminToken = 'a'.repeat(64);
const origin = 'http://127.0.0.1:9737';
const ownerMutations = [
  ['POST', '/v1/send'], ['GET', '/v1/invites'], ['GET', '/v1/invites/notifications'],
  ['POST', '/v1/claim'],
  ['POST', '/v1/profile/challenge'], ['POST', '/v1/profile/verify'],
  ['POST', '/v1/onboarding/challenge'], ['POST', '/v1/onboarding/verify'],
  ['POST', '/v1/profile/methods/proof'],
  ['PUT', '/v1/profile'], ['POST', '/v1/profile/methods'],
  ['POST', '/v1/profile/rotate-key'], ['POST', '/v1/broadcast'],
  ['POST', '/v1/p2p/resolve'], ['POST', '/v1/invites/notifications/id/read'],
];

test('one unlock authenticates all owner mutations but no public requests', async () => {
  const calls = [];
  const client = createDashboardClient({ origin, fetchImpl: async (url, options) => {
    calls.push({ url, options }); return { ok: true, status: 200 };
  }});
  await client.unlock(adminToken);
  assert.equal(calls[0].options.headers.get('authorization'), `Bearer ${adminToken}`);
  for (const [method, path] of ownerMutations) {
    await client.request(path, { method });
    assert.equal(calls.at(-1).options.headers.get('authorization'), `Bearer ${adminToken}`);
  }
  for (const path of ['/health', '/v1/control', '/v1/transparency/status', '/v1/claim?invite_id=id']) {
    await client.request(path);
    assert.equal(calls.at(-1).options.headers.has('authorization'), false);
  }
  for (const path of ['/v1/receive', '/v1/dns/resolve', '/v1/transparency/verify/inclusion', '/v1/transparency/verify/catena', '/v1/profile/recover', '/v2/resolve']) {
    await client.request(path, { method: 'POST' });
    assert.equal(calls.at(-1).options.headers.has('authorization'), false);
  }
  assert.equal(requiresAuthentication('POST', '/v1/future-owner-action'), true);
});

test('expired registration and claim challenges request a fresh authorization', async () => {
  const html = await readFile(new URL('../src/index.html', import.meta.url), 'utf8');
  for (const name of ['pendingDomainRegistration', 'pendingDomainClaim']) {
    const declaration = html.match(new RegExp(`const verifying = ${name}([\\s\\S]*?);`));
    assert.ok(declaration, name);
    const check = new Function(name, 'candidate', 'Date', `return Boolean(${name}${declaration[1]});`);
    const clock = { now: () => 200_000 };
    assert.equal(check(null, 'unchanged', clock), false);
    assert.equal(check({ candidate: 'unchanged', expires_at: 199 }, 'unchanged', clock), false);
    assert.equal(check({ candidate: 'unchanged', expires_at: 200 }, 'unchanged', clock), false);
    assert.equal(check({ candidate: 'unchanged', expires_at: 201 }, 'unchanged', clock), true);
    assert.equal(check({ candidate: 'changed', expires_at: 201 }, 'unchanged', clock), false);
    assert.match(html, new RegExp(`${name} = \\{candidate, challenge_id: [^,]+, expires_at:`));
  }
});

test('lock and 401 remove authorization; public access remains usable', async () => {
  let status = 200;
  const client = createDashboardClient({ origin, fetchImpl: async () => ({ ok: status === 200, status }) });
  await assert.rejects(client.request('/v1/profile', { method: 'PUT' }), /Unlock/);
  await client.request('/health');
  await client.unlock(adminToken);
  status = 401;
  await assert.rejects(client.request('/v1/profile', { method: 'PUT' }), /authorization/);
  status = 200;
  await assert.rejects(client.request('/v1/profile', { method: 'PUT' }), /Unlock/);
  await client.unlock(adminToken);
  client.lock();
  await assert.rejects(client.request('/v1/profile', { method: 'PUT' }), /Unlock/);
});

test('no off-origin credentials, insecure remote sign-in, or redirect forwarding', async () => {
  let seen;
  const client = createDashboardClient({ origin, fetchImpl: async (_, options) => { seen = options; return { ok: true, status: 200 }; } });
  await client.unlock(adminToken);
  await assert.rejects(client.request('https://example.com/v1/profile', { method: 'PUT' }), /origin/);
  await assert.rejects(client.request('//example.com/health'), /origin/);
  await assert.rejects(client.request('/health', { headers: { Authorization: `Bearer ${adminToken}` } }), /managed/);
  await client.request('/v1/profile', { method: 'PUT', redirect: 'follow', credentials: 'include', mode: 'cors' });
  assert.equal(seen.redirect, 'error');
  assert.equal(seen.credentials, 'omit');
  assert.equal(seen.mode, 'same-origin');
  const remote = createDashboardClient({ origin: 'http://192.0.2.1:9737', fetchImpl: async () => ({ ok: true, status: 200 }) });
  await assert.rejects(remote.unlock(adminToken), /HTTPS/);
  await remote.request('/health');
  for (const address of ['https://example.com', 'http://localhost:9737', 'http://[::1]:9737']) {
    await createDashboardClient({ origin: address, fetchImpl: async () => ({ ok: true, status: 200 }) }).unlock(adminToken);
  }
});

test('sign-in failure never surfaces the token or transport exception', async () => {
  const client = createDashboardClient({ origin, fetchImpl: async () => { throw new Error(adminToken); } });
  await assert.rejects(client.unlock(adminToken), error => !error.message.includes(adminToken));
  await assert.rejects(client.request('/v1/broadcast', { method: 'POST' }), /Unlock/);
});

test('navigation or lock during sign-in cannot resurrect the token', async () => {
  let complete;
  const client = createDashboardClient({ origin, fetchImpl: () => new Promise(resolve => { complete = resolve; }) });
  const unlocking = client.unlock(adminToken);
  client.lock();
  complete({ ok: true, status: 200 });
  await assert.rejects(unlocking, /sign-in failed/);
  await assert.rejects(client.request('/v1/broadcast', { method: 'POST' }), /Unlock/);
});

test('successful dashboard unlock retries notifications without a tab change', async () => {
  const html = await readFile(new URL('../src/index.html', import.meta.url), 'utf8');
  const handler = html.match(/\$\('dashboard-auth-form'\)\.addEventListener\('submit', async event => \{([\s\S]*?)\n  \}\);/);
  assert.ok(handler, 'dashboard submit handler exists');
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const submit = new AsyncFunction('event', 'authInput', '$', 'dashboardAuth', 'loadNotifications', handler[1]);
  for (const success of [true, false]) {
    let complete;
    let notifications = 0;
    const elements = new Map();
    const $ = id => {
      if (!elements.has(id)) elements.set(id, { classList: { add() {}, remove() {} } });
      return elements.get(id);
    };
    const dashboardAuth = { unlock: () => new Promise((resolve, reject) => {
      complete = () => success ? resolve() : reject(new Error('rejected'));
    }) };
    const pending = submit({ preventDefault() {} }, { value: adminToken }, $, dashboardAuth, () => { notifications++; });
    assert.equal(notifications, 0, 'do not request notifications before unlock succeeds');
    complete();
    await pending;
    assert.equal(notifications, success ? 1 : 0, 'retry only after successful unlock');
    assert.equal($('dashboard-unlock').disabled, false);
  }
});

// Execute the page's actual lock callback and notification loader with a tiny DOM.
async function notificationHarness(apiFetch) {
  const html = await readFile(new URL('../src/index.html', import.meta.url), 'utf8');
  const onLock = html.match(/onLock: \(\) => \{([\s\S]*?)\n  \}\}\);/);
  const loader = html.match(/const loadNotifications = async \(\) => \{([\s\S]*?)\n  \};/);
  assert.ok(onLock);
  assert.ok(loader);
  const elements = new Map();
  const $ = id => {
    if (!elements.has(id)) {
      const classes = new Set(['hidden']);
      elements.set(id, {
        innerHTML: '', querySelectorAll: () => [],
        classList: { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c) },
      });
    }
    return elements.get(id);
  };
  const hide = el => { el.classList.add('hidden'); el.classList.remove('show'); };
  const show = el => { el.classList.remove('hidden'); el.classList.add('show'); };
  const create = new Function('$', 'authInput', 'apiFetch', 'hide', 'show', 'esc', 'fillSend', 'dismissNotification', `
    let notificationGeneration = 0;
    const lock = () => { ${onLock[1]} };
    const loadNotifications = async () => { ${loader[1]} };
    return { lock, loadNotifications };
  `);
  return { ...create($, { value: '' }, apiFetch, hide, show, String, () => {}, () => {}), box: $('s-notifications') };
}

const privateNote = { read: false, display_hint: 'private-identifier', amount_sats: 5000, notification_id: 'note-1' };

test('locking clears and hides already rendered private notifications', async () => {
  const view = await notificationHarness(async () => ({ ok: true, json: async () => [privateNote] }));
  await view.loadNotifications();
  assert.match(view.box.innerHTML, /private-identifier/);
  assert.equal(view.box.classList.contains('hidden'), false);
  view.lock();
  assert.equal(view.box.innerHTML, '');
  assert.equal(view.box.classList.contains('hidden'), true);
  assert.equal(view.box.classList.contains('show'), false);
});

for (const stage of ['fetch', 'json']) {
  test(`locking discards notifications pending at the ${stage} boundary`, async () => {
    let complete;
    let started;
    let parses = 0;
    const ready = new Promise(resolve => { started = resolve; });
    const pending = new Promise(resolve => { complete = resolve; });
    const response = { ok: true, json: async () => {
      parses++;
      if (stage === 'json') { started(); return pending; }
      return [privateNote];
    } };
    const view = await notificationHarness(async () => {
      if (stage === 'fetch') { started(); return pending; }
      return response;
    });
    const loading = view.loadNotifications();
    await ready;
    view.lock();
    complete(stage === 'fetch' ? response : [privateNote]);
    await loading;
    assert.equal(view.box.innerHTML, '');
    assert.equal(view.box.classList.contains('hidden'), true);
    assert.equal(parses, stage === 'fetch' ? 0 : 1);
  });
}

test('dashboard uses only the centralized helper and no persistent token storage', async () => {
  const html = await readFile(new URL('../src/index.html', import.meta.url), 'utf8');
  const module = await readFile(new URL('../src/dashboard-auth.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /\bfetch\s*\(/);
  assert.doesNotMatch(html, /onclick="/);
  assert.doesNotMatch(html + module, /localStorage|sessionStorage/);
  assert.match(html, /window\.addEventListener\('pagehide', dashboardAuth\.lock\)/);
  assert.match(html, /type="password"/);
  assert.match(html, /authInput\.value = ''; \/\/ Clear/);
  assert.doesNotMatch(html + module, new RegExp(adminToken));
});
