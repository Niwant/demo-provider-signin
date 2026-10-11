import http from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const DEMOS = Object.freeze({
  prism: { tenant: '970592', host: 'uatapi.prismhr.com', fields: ['username', 'password', 'peo_id'] },
  isol: { tenant: '255938', host: 'myisolved.com', fields: ['client_id', 'client_secret'] },
  ukg: { tenant: '833341', host: 'secure2.saashr.com', fields: ['client_id', 'client_secret'] },
});
const ALIASES = Object.freeze({ prism: 'prism', prismhr: 'prism', isol: 'isol', isolved: 'isol', ukg: 'ukg', 'ukg-ready': 'ukg' });
const TENANTS = Object.freeze({ ...ALIASES, '970592': 'prism', '255938': 'isol', '833341': 'ukg', 'prism tenant': 'prism', 'isolved tenant': 'isol', 'isol tenant': 'isol', 'ukg tenant': 'ukg' });
const TOKEN_FIELDS = ['access_token', 'refresh_token', 'token_type', 'expires_in', 'scope'];
const MAX_BODY = 1024;
const MAX_UPSTREAM = 16384;
const digest = value => createHash('sha256').update(value).digest();

export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Invalid provider configuration');
  const safe = {};
  for (const [provider, demo] of Object.entries(DEMOS)) {
    const item = config[provider];
    if (!item || String(item.tenant_id) !== demo.tenant) throw new Error(`Incorrect demo tenant for ${provider}`);
    const url = new URL(item.base_url);
    if (url.protocol !== 'https:' || url.hostname !== demo.host || url.port || url.username || url.password || url.search || url.hash) {
      throw new Error(`Unapproved demo address for ${provider}`);
    }
    const credentials = item.credentials;
    if (!credentials || demo.fields.some(field => typeof credentials[field] !== 'string' || !credentials[field].trim())) {
      throw new Error(`Missing demo credentials for ${provider}`);
    }
    const context = item.context;
    if (!context || !Array.isArray(context.companies) || !context.companies.length) throw new Error(`Missing demo identifiers for ${provider}`);
    const companies = context.companies.map(company => {
      const fields = provider === 'isol' ? ['client_id', 'legal_id'] : provider === 'ukg' ? ['company_id'] : ['client_id'];
      if (fields.some(field => typeof company[field] !== 'string' || !/^[A-Za-z0-9_-]+$/.test(company[field]))) {
        throw new Error(`Invalid demo identifiers for ${provider}`);
      }
      return Object.fromEntries(fields.map(field => [field, company[field]]));
    });
    if (provider === 'ukg' && companies.length !== 1) throw new Error('UKG must have exactly one demo company');
    safe[provider] = {
      tenant_id: demo.tenant,
      base_url: url.href.replace(/\/$/, ''),
      credentials: Object.fromEntries(demo.fields.map(field => [field, credentials[field]])),
      context: { companies },
    };
  }
  return safe;
}

function requestFor(provider, config) {
  const creds = config.credentials;
  const headers = { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' };
  if (provider === 'prism') {
    return {
      url: `${config.base_url}/login/v1/createPeoSession`, headers,
      body: new URLSearchParams({ username: creds.username, password: creds.password, peoId: creds.peo_id }),
    };
  }
  if (provider === 'isol') {
    headers.Authorization = `Basic ${Buffer.from(`${creds.client_id}:${creds.client_secret}`).toString('base64')}`;
    return { url: `${config.base_url}/api/token`, headers, body: new URLSearchParams({ grant_type: 'client_credentials' }) };
  }
  const company = config.context.companies[0].company_id;
  return {
    url: `${config.base_url}/rest/v2/companies/${encodeURIComponent(company)}/oauth2/token`, headers,
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: creds.client_id, client_secret: creds.client_secret }),
  };
}

async function limitedJson(stream, maxBytes) {
  let size = 0;
  const chunks = [];
  for await (const chunk of stream) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > maxBytes) throw new Error('Payload too large');
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export async function authenticate(provider, config, transport = fetch) {
  const request = requestFor(provider, config);
  const response = await transport(request.url, {
    method: 'POST', headers: request.headers, body: request.body,
    redirect: 'error', signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error('Provider authentication failed');
  }
  const data = await limitedJson(response.body, MAX_UPSTREAM);
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid provider response');
  if (provider === 'prism') {
    const code = String(data.errorCode ?? '');
    if (!['', '0', 'SUCCESS', 'success'].includes(code) || typeof data.sessionId !== 'string' || !data.sessionId.trim()) {
      throw new Error('Provider authentication failed');
    }
    return { sessionId: data.sessionId };
  }
  if (typeof data.access_token !== 'string' || !data.access_token.trim()) throw new Error('Missing provider token');
  const auth = {};
  for (const field of TOKEN_FIELDS) {
    const value = data[field];
    if (value === undefined) continue;
    if ((field === 'expires_in' && ['number', 'string'].includes(typeof value)) || (field !== 'expires_in' && typeof value === 'string')) auth[field] = value;
  }
  auth.token_type ??= 'Bearer';
  return auth;
}

export function createServer({ apiKey, config, transport = fetch, rateLimit = 30, clock = Date.now }) {
  if (typeof apiKey !== 'string' || apiKey.length < 32 || apiKey.length > 256) throw new Error('API key must contain 32–256 characters');
  const providers = validateConfig(config);
  const keyHash = digest(apiKey);
  let attempts = [];
  const server = http.createServer(async (req, res) => {
    const send = (status, payload, extra = {}) => {
      const body = JSON.stringify(payload);
      res.writeHead(status, {
        'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        'Cache-Control': 'no-store', Pragma: 'no-cache', 'X-Content-Type-Options': 'nosniff', ...extra,
      });
      res.end(body);
    };
    if (req.method === 'GET' && req.url === '/healthz') return send(200, { status: 'ok' });
    if (req.url !== '/signin') return send(404, { error: 'not_found' });
    if (req.method !== 'POST') return send(405, { error: 'method_not_allowed' }, { Allow: 'POST' });
    const key = req.headers['x-api-key'];
    if (typeof key !== 'string' || key.length > 256 || !timingSafeEqual(digest(key), keyHash)) {
      req.resume();
      return send(401, { error: 'invalid_api_key' });
    }
    const now = clock();
    attempts = attempts.filter(time => now - time < 60000);
    if (attempts.length >= rateLimit) {
      req.resume();
      return send(429, { error: 'rate_limited' }, { 'Retry-After': '60' });
    }
    attempts.push(now);
    if (req.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') {
      req.resume();
      return send(415, { error: 'json_required' });
    }
    if (Number(req.headers['content-length']) > MAX_BODY) {
      req.resume();
      return send(413, { error: 'body_too_large' });
    }
    let body;
    try { body = await limitedJson(req, MAX_BODY); }
    catch { return send(400, { error: 'invalid_request_body' }); }
    if (!body || Array.isArray(body) || typeof body !== 'object' || Object.keys(body).length !== 1 ||
        !(typeof body.tenant === 'string' || typeof body.provider === 'string')) {
      return send(400, { error: 'tenant_required' });
    }
    const name = (body.tenant ?? body.provider).trim().toLowerCase();
    const provider = Object.hasOwn(TENANTS, name) ? TENANTS[name] : null;
    if (!provider) return send(400, { error: 'unsupported_tenant' });
    const selected = providers[provider];
    try {
      const auth = await authenticate(provider, selected, transport);
      return send(200, {
        provider, tenant_id: selected.tenant_id, base_url: selected.base_url, auth, context: selected.context,
        usage: provider === 'prism'
          ? { header_name: 'sessionId', header_prefix: '' }
          : { header_name: 'Authorization', header_prefix: `${auth.token_type} ` },
      });
    } catch {
      return send(502, { error: 'provider_authentication_failed', provider });
    }
  });
  server.requestTimeout = 20000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 40;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const server = createServer({ apiKey: process.env.SIGNIN_API_KEY, config: JSON.parse(process.env.PROVIDER_CONFIG_JSON || 'null') });
    const port = Number(process.env.PORT || 10000);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
    server.listen(port, '0.0.0.0', () => console.log('Demo sign-in server ready'));
    for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 20000).unref();
    });
  } catch {
    console.error('Server configuration is missing or invalid; startup refused');
    process.exitCode = 1;
  }
}
