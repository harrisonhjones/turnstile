# Turnstile

Turnstile is a standalone **access-control service**. It issues **API keys**,
evaluates a **statement-based policy engine**, enforces **rate limits**, and
records an **audit trail** — over **gRPC/Connect**, for reuse across many
projects.

A turnstile admits the authorized (auth), meters each pass (rate limiting), and
counts every entry (audit): the four responsibilities in one image.

## What it does

A host service (e.g. an API proxy) delegates authorization to Turnstile instead
of embedding it. On each request the host calls one RPC:

```
Check(client_token, action, resources, count_rate_limit) -> { allowed, principal, decision, rate_limit }
```

- **Authentication** — `client_token` is an opaque bearer key (`tsk_…`).
  Turnstile stores only its SHA-256 hash. Unknown, disabled, and expired keys
  all collapse to a single generic `UNAUTHENTICATED` result (no
  token-existence leak).
- **Authorization** — a deny-wins, first-allow, default-deny evaluation of the
  key's statements beneath a global **deny-only ceiling**. Actions and resources
  are opaque, service-namespaced strings (`beeper:sendMessage`,
  `beeper:chat:!abc`); Turnstile never parses them, so one project's grants can
  never authorize another's.
- **Rate limiting** — per-key and service-wide token buckets that must both
  pass. A denied authz never burns rate budget (reserve-then-confirm).
- **Audit** — hosts report one entry per completed request via the
  `ReportAudit` stream (status and latency aren't known until the host
  finishes); Turnstile persists them in the background and prunes on a retention
  loop.

`Check` does authn + authz + rate limiting in a single round-trip. Identity
lookups use `Authenticate` (whoami). Operators manage keys, the global policy,
and browse audit through admin-guarded management RPCs and an embedded web UI.

## Transport

The API is served with [Connect](https://connectrpc.com): it is
gRPC-wire-compatible for the `Check` hot path *and* speaks gRPC-Web + plain
HTTP/1.1 JSON, so management calls are `curl`- and browser-friendly. The proto
package is `turnstile.v1` (see `proto/turnstile/v1/turnstile.proto`).

## Quick start

```sh
# Build the binary (generates protos, builds the UI, compiles the backend).
mage build:all

# Or just run it during development (hot reload if `air` is installed).
mage run:backend
```

On first start against an empty database, Turnstile seeds a default global
policy and a **bootstrap admin credential**, logging the admin token **once**:

```
level=WARN msg="created bootstrap admin credential — store this token now, it will not be shown again" admin_token=tsa_...
```

Store that token — it guards the management RPCs and the web UI. Deleting every
admin credential and restarting re-seeds a fresh one (the intentional
lockout-recovery path). Then open the management UI:

```
http://localhost:8080/ui/
```

## Configuration

All configuration is via environment variables, seeded from an optional `.env`
file (`cp .env.example .env`); real environment variables always win. Every
value is optional with a sane default. See [`.env.example`](.env.example) for
the full list (listen address, DB path, audit retention, and the host→Turnstile
service credential / mTLS options).

## Layout

```
cmd/turnstile/       entrypoint: config, store, bootstrap, serve, graceful shutdown
proto/turnstile/v1/  .proto sources
gen/turnstile/v1/    buf-generated Go + Connect stubs
internal/
  token/             key/credential type, gen/hash, authentication, authorizer, policy cache, bootstrap
  policy/            domain-agnostic statement engine + validation
  ratelimit/         per-key + service-wide limiter manager
  audit/             background writer + retention
  store/             SQLite schema + accessors
  server/            Connect handlers wiring it all together
  management/ui/     embedded Ionic React admin SPA
```

## Documentation

- [DEVELOPMENT.md](DEVELOPMENT.md) — build/dev workflow, mage targets, testing.
- [ARCHITECTURE.md](ARCHITECTURE.md) — how the pieces fit and why.
- [docs/client-integration.md](docs/client-integration.md) — how a host service
  calls `Check` and streams `ReportAudit`.

Low-level details live in Godoc, not in markdown — read the package docs
(`go doc ./internal/...`).
