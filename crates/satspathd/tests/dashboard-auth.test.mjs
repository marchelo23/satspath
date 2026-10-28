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
