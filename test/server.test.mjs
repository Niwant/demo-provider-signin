import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, validateConfig } from '../server.mjs';

const apiKey = 'unit-test-key-not-a-real-secret-123456789';
const config = {
  prism: { tenant_id: '970592', base_url: 'https://uatapi.prismhr.com/api', credentials: { username: 'test-user', password: 'test-password', peo_id: 'test-peo' }, context: { companies: [{ client_id: '132' }] } },
  isol: { tenant_id: '255938', base_url: 'https://myisolved.com', credentials: { client_id: 'test-id', client_secret: 'test-secret' }, context: { companies: [{ client_id: '4046', legal_id: '5806' }] } },
  ukg: { tenant_id: '833341', base_url: 'https://secure2.saashr.com/ta', credentials: { client_id: 'test-id', client_secret: 'test-secret' }, context: { companies: [{ company_id: '33704016' }] } },
};
async function running(t, options = {}) {
  const server = createServer({ apiKey, config, ...options });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return async (body, headers = {}, path = '/signin') => fetch(base + path, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': apiKey, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });

test('unauthorized and unsupported selectors never reach a provider', async t => {
  let calls = 0;
  const request = await running(t, { transport: () => { calls++; throw new Error('Unexpected upstream call'); } });
  assert.equal((await request({ tenant: 'prism' }, { 'x-api-key': 'wrong' })).status, 401);
  for (const body of [{ tenant: 'other' }, { tenant: '__proto__' }, { tenant: 'prism', company_id: '999' }, { tenant: null }, []]) {
    assert.equal((await request(body)).status, 400);
  }
  assert.equal(calls, 0);
});

test('Prism uses form login and returns sessionId plus scoped client IDs without credentials', async t => {
  const request = await running(t, { transport: async (url, options) => {
    assert.equal(url, 'https://uatapi.prismhr.com/api/login/v1/createPeoSession');
    assert.equal(options.body.get('peoId'), 'test-peo');
    assert.equal(options.body.get('username'), 'test-user');
    assert.equal(options.redirect, 'error');
    return json({ sessionId: 'test-session', errorCode: '0', username: 'must-not-leak', password: 'must-not-leak' });
  } });
  const response = await request({ tenant: 'Prism Tenant' });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.json();
  assert.deepEqual(body.auth, { sessionId: 'test-session' });
  assert.deepEqual(body.context, { companies: [{ client_id: '132' }] });
  assert.equal(body.usage.header_name, 'sessionId');
  assert.equal(body.tenant_id, '970592');
  assert.ok(!JSON.stringify(body).includes('must-not-leak'));
});

test('isolved uses Basic client credentials and preserves returned access/refresh token metadata', async t => {
  const request = await running(t, { transport: async (url, options) => {
    assert.equal(url, 'https://myisolved.com/api/token');
    assert.equal(options.headers.Authorization, `Basic ${Buffer.from('test-id:test-secret').toString('base64')}`);
    assert.equal(options.body.get('grant_type'), 'client_credentials');
    return json({ access_token: 'test-access', refresh_token: 'test-refresh', expires_in: 600, scope: 'test-scope', client_secret: 'must-not-leak' });
  } });
  const response = await request({ tenant: '255938' });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.auth, { access_token: 'test-access', refresh_token: 'test-refresh', expires_in: 600, scope: 'test-scope', token_type: 'Bearer' });
  assert.deepEqual(body.context.companies[0], { client_id: '4046', legal_id: '5806' });
  assert.ok(!JSON.stringify(body).includes('must-not-leak'));
});

test('UKG authentication is fixed to the configured demo company; no refresh token is invented', async t => {
  const request = await running(t, { transport: async (url, options) => {
    assert.equal(url, 'https://secure2.saashr.com/ta/rest/v2/companies/33704016/oauth2/token');
    assert.equal(options.body.get('client_id'), 'test-id');
    return json({ access_token: 'test-ukg-token', expires_in: 3600, token_type: 'Bearer' });
  } });
  const response = await request({ tenant: 'UKG' });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.context.companies[0].company_id, '33704016');
  assert.equal(Object.hasOwn(body.auth, 'refresh_token'), false);
});

test('provider errors, malformed JSON, missing tokens, and oversized responses never echo provider bodies', async t => {
  const cases = [
    async () => json({ error: 'test-password' }, 401),
    async () => new Response('test-secret'),
    async () => json({ errorCode: 'FAIL', errorMessage: 'test-password', sessionId: 'test-session' }),
    async () => json({ errorCode: '0' }),
    async () => json({ access_token: 'test-access', extra: 'x'.repeat(20000) }),
  ];
  for (const transport of cases) {
    const request = await running(t, { transport });
    const response = await request({ tenant: 'prism' });
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), { error: 'provider_authentication_failed', provider: 'prism' });
  }
});

test('rate limiting stops repeated token issuance and resets after one minute', async t => {
  let now = 100000; let calls = 0;
  const request = await running(t, { rateLimit: 2, clock: () => now, transport: async () => { calls++; return json({ sessionId: 'test-session' }); } });
  assert.equal((await request({ tenant: 'prism' })).status, 200);
  assert.equal((await request({ tenant: 'prism' })).status, 200);
  const limited = await request({ tenant: 'prism' });
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('retry-after'), '60');
  assert.equal(calls, 2);
  now += 60000;
  assert.equal((await request({ tenant: 'prism' })).status, 200);
});

test('body limits, content types, and routing prevent unintended upstream requests', async t => {
  const request = await running(t, { transport: () => { throw new Error('Unexpected upstream call'); } });
  assert.equal((await request('{')).status, 400);
  assert.equal((await request({ tenant: 'prism' }, { 'content-type': 'text/plain' })).status, 415);
  assert.equal((await request('x'.repeat(1025))).status, 413);
  assert.equal((await request({ tenant: 'prism' }, {}, '/unknown')).status, 404);
});

test('configuration rejects other tenants, addresses, and identifiers', () => {
  assert.throws(() => createServer({ apiKey: 'short', config }));
  for (const change of [
    c => { c.prism.tenant_id = '811652'; },
    c => { c.ukg.base_url = 'http://secure2.saashr.com/ta'; },
    c => { c.isol.base_url = 'https://localhost'; },
    c => { c.isol.base_url = 'https://myisolved.com@localhost'; },
    c => { c.ukg.context.companies[0].company_id = '../other'; },
    c => { delete c.prism.credentials.password; },
  ]) {
    const copy = structuredClone(config); change(copy);
    assert.throws(() => validateConfig(copy));
  }
});
