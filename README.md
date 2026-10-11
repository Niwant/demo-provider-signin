# Demo provider sign-in

Small, standalone server for the three explicitly selected demo tenants. It keeps
provider credentials on the server and returns short-lived provider authentication
details and the demo company identifiers needed to make subsequent API calls.
It does not read from or modify full-stack at runtime and has no database dependency.

## API

Hosted endpoint: `https://tada-demo-provider-signin.onrender.com/signin`.
The organizer provides the API key privately; it is not published in this repository.

`POST /signin` requires an `X-API-Key` header and a JSON object containing only
`tenant`. Use `prism`, `ukg`, or `isol`. The seeded tenant IDs and names are also
accepted. For compatibility, a single `provider` field works as an alternative;
do not send both fields.

```sh
curl -X POST 'https://tada-demo-provider-signin.onrender.com/signin' \
  -H "X-API-Key: $DEMO_SIGNIN_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"tenant":"ukg"}'
```

The response includes `provider`, `tenant_id`, `base_url`, `auth`, `context.companies`,
and `usage` (the header name/prefix for subsequent provider calls):

| Tenant selector | Authentication returned | Company identifiers returned |
| --- | --- | --- |
| `prism` / `970592` / `Prism Tenant` | `auth.sessionId`; use the `sessionId` header | `client_id` for the active seeded companies |
| `isol` / `255938` / `Isolved Tenant` | `auth.access_token`, token type, expiry, scope and refresh token when actually issued | `client_id` and `legal_id` |
| `ukg` / `833341` / `UKG tenant` | `auth.access_token`, token type, expiry, scope and refresh token when actually issued | `company_id` for the single seeded demo company |

No refresh token is fabricated. With client-credentials authentication, call this
endpoint again when an access token expires; Prism users call again when their
session expires. Record-specific endpoints also need employee/payroll IDs, which
callers discover through the provider APIs. Provider responses are limited to
authentication fields; passwords, client secrets, and raw error bodies are never
returned or logged. Auth responses use `Cache-Control: no-store`.

These provider tokens retain the permissions of the configured integration
accounts. This service does not turn a write-capable token into a read-only token
or narrow Prism/isolved account permissions to the company IDs returned here.
Use provider-restricted demo credentials if that restriction is required.

## Configuration

Use Node.js 22 or newer. No third-party packages are required.

- `SIGNIN_API_KEY`: a cryptographically random key of at least 32 characters.
- `PROVIDER_CONFIG_JSON`: secret JSON configuration for all three fixed tenants.
- `PORT`: listening port; defaults to `10000`. The server binds to `0.0.0.0`.

Each configuration entry has `tenant_id`, `base_url`, `credentials`, and
`context.companies`. Credential fields: Prism uses `username`, `password`,
`peo_id`; isolved and UKG use `client_id`, `client_secret`. The upstream addresses
and tenant IDs are allowlisted to the inspected demo seed. UKG has exactly one
configured company; request bodies cannot select other tenants or upstream URLs.
Configuration must be supplied privately in Render environment settings or a
local environment file; never commit it to this repository.

```sh
npm test
node --env-file=.env server.mjs
```

There is one business API, `POST /signin`, plus `GET /healthz` for Render health
checks. Public schema/debug endpoints are not exposed. The server allows 30
authenticated attempts per minute per process and times out upstream auth after
15 seconds. It returns `401` for an invalid API key, `400` for invalid selectors,
`413` for an oversized request, `415` for a non-JSON request, `429` for the rate
limit, and a generic `502` for upstream authentication failures. Token responses
are not cached. The server refuses startup if configuration is invalid.

## Render

Deploy as a separate Node web service with build command `npm test`, start command
`npm start`, and health-check path `/healthz`. Put both secret variables in the
service environment. A free instance can sleep between requests, so the first
sign-in may take longer after inactivity. Provider IP allowlists may need to include
the service's outbound IPs. Verify each tenant's authentication after deployment;
passing the mock-backed tests does not prove live provider access.
