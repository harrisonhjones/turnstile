# Architecture

Turnstile is one small Connect service over a SQLite database. This document
covers how the pieces fit and the decisions worth knowing before changing them.
Low-level specifics live in Godoc.

## Transport

The API is served with [Connect](https://connectrpc.com) from a single port. One
handler speaks three protocols: gRPC (HTTP/2 wire framing) for the `Check` hot
path, gRPC-Web, and the Connect HTTP/1.1 JSON protocol — so management calls are
`curl`- and browser-friendly (the web console uses the JSON protocol directly).
Without TLS the server is wrapped in `h2c` so the gRPC hot path works over
plaintext HTTP/2; with TLS, HTTP/2 is negotiated via ALPN. The proto package is
`turnstile.v1` (`proto/turnstile/v1/turnstile.proto`); Go + Connect stubs are
generated with `buf` into `gen/` and committed.

Swapping Connect for raw `google.golang.org/grpc` would be possible — the
`internal/*` core is transport-neutral — but Connect's multi-protocol support is
why management is usable without a gRPC client.

## The request paths

```
                         ┌─────────────────────────────────────────┐
   host service          │                 Turnstile                │
  ┌────────────┐  Check  │  server (Connect handlers)                │
  │            ├────────►│    ├─ token.Authenticator  (authn)        │
  │  proxy /   │         │    ├─ token.Authorizer     (authz)        │──► store (SQLite)
  │  gateway   │◄────────┤    │     └─ policy.Evaluate + PolicyCache  │      api_keys
  │            │ verdict │    └─ ratelimit.Manager    (limits)       │      admin_credentials
  │            │         │                                           │      global_policy
  │            ├────────►│  ReportAudit (stream) ─► audit.Writer ────┼──►   audit_log
  └────────────┘  audit  │                                           │
                         │  management RPCs (admin-guarded) ─────────┼──► store
                         │  /ui/  embedded Ionic React SPA           │
                         └─────────────────────────────────────────┘
```

- **`Check`** (hot path) runs authn → authz → rate limiting and returns a
  verdict. It never writes audit, because status and latency are unknown until
  the host finishes serving the request.
- **`Authenticate`** resolves a token to a `Principal` (whoami), nothing more.
- **`ReportAudit`** is a client stream: the host buffers completed requests and
  pushes them up afterward.
- **Management RPCs** (`CreateKey`, …, `UpdatePolicy`, `QueryAudit`) require an
  admin credential and back the web UI.

## Packages

| Package | Responsibility |
|---|---|
| `internal/policy` | The domain-agnostic statement engine: `Evaluate` (deny-wins → first allow → default deny), wildcard matching, and validation (well-formedness + global deny-only). Knows nothing about any host's vocabulary. |
| `internal/token` | Token/credential generation + hashing, `Authenticator` (API keys and admin credentials), `Authorizer` (merges global ceiling under the key), the in-memory `PolicyCache`, and first-run `BootstrapIfEmpty`. |
| `internal/ratelimit` | `Manager` of per-key and service-wide token buckets, resolved from policy, with live rate updates and reserve-then-confirm semantics. |
| `internal/audit` | Background `Writer` (drains at shutdown) and the retention prune loop. |
| `internal/store` | SQLite schema + typed accessors over `*sql.DB`. |
| `internal/server` | Connect handlers wiring the above together, plus the proto↔domain conversion layer. |
| `internal/management` | Serves the embedded SPA (`go:embed`), with a placeholder until the UI is built. |
| `internal/config` | Environment + `.env` configuration. |

## Repository layout

```
cmd/turnstile/       entrypoint: config, store, bootstrap, serve, graceful shutdown
proto/turnstile/v1/  .proto sources
gen/turnstile/v1/    buf-generated Go + Connect stubs (committed)
internal/
  token/             key/credential type, gen/hash, authentication, authorizer, policy cache, bootstrap
  policy/            domain-agnostic statement engine + validation
  ratelimit/         per-key + service-wide limiter manager
  audit/             background writer + retention
  store/             SQLite schema + accessors
  server/            Connect handlers + shutdown gate wiring it all together
  config/            environment + .env configuration
  management/ui/     embedded Ionic React admin SPA (→ ui/dist via go:embed)
magefile.go          build:/run:/gen/fmt:/vet:/test:/check/clean:/resetDB targets
```

## Key decisions

**One shared instance; isolation by namespacing.** Every action/resource is a
prefixed string (`beeper:sendMessage`). The engine matches opaque strings, so
`beeper:*` can never authorize `plaid:*`. There is no realm/tenant construct —
the prefix is host vocabulary that Turnstile never parses. This is what keeps
`internal/policy` domain-agnostic and reusable across projects.

**Two policy layers, global is a deny-only ceiling.** Statements are evaluated
global-first, then per-key, as one merged list: the first matching allow from
anywhere grants access. A global *allow* would therefore be additive to every
key, so `ValidateGlobalStatements` rejects allow statements — the global layer
can only take capabilities away. The global policy is cached in memory
(`PolicyCache`) and refreshed on `UpdatePolicy`, so the hot path never reads the
DB for policy.

**Denied authz never burns rate budget.** `Check` consults the rate limiter only
after authn and authz pass, and only when `count_rate_limit` is set. The limiter
itself uses reserve-then-confirm: it reserves on both the per-key and
service-wide buckets, and if either would block it cancels both reservations, so
a block on one never charges the other.

**Rate-limit state is central.** Because a service-wide cap is truly global
across a host's replicas and across projects sharing a key, counter state lives
in Turnstile. Config (the limits) could be synced to an edge cache later, but
counter state is real-time and shared, so enforcement stays central — at the
cost of one round-trip on the hot path.

**Generic authentication failure.** Unknown, disabled, and expired keys all map
to a single `UNAUTHENTICATED` decision (and a single client-facing error on
`Authenticate`), so a caller can't distinguish "no such token" from a real but
disabled/expired one. The specific reason is logged for operators.

**Guarding the guard.** Two credentials gate access, enforced per-RPC:
management RPCs require an admin credential (`tsa_…`) in `Authorization: Bearer`
metadata; the host-facing RPCs optionally require a shared service credential
(`SERVICE_CREDENTIAL`) or are protected by mTLS. A bootstrap admin credential is
seeded and logged once on first run; deleting all of them re-seeds on restart —
there is no "can't delete the last one" guard, by design, so an operator can
always recover from lockout.

**Only the hash is stored.** API keys and admin credentials are opaque,
high-entropy strings; only their SHA-256 hash is persisted and looked up, so
there is no plaintext secret at rest and no constant-time-comparison concern.
`CreateKey` returns the plaintext once.

## Management UI security note

The embedded SPA is a plain API client: it authenticates by sending the admin
credential as a `Bearer` header and stores that credential in the browser's
`localStorage`. `localStorage` is readable by any script in the origin, so an
XSS (or a compromised SPA dependency) could exfiltrate a long-lived,
full-privilege admin credential. This is an accepted tradeoff for an
operator-only console that is expected to be reached over localhost or a trusted
network; React's default escaping mitigates injection. If the console is ever
exposed more broadly, move the token to memory-only (re-prompt on reload) or a
short-lived `HttpOnly`+`Secure`+`SameSite` session cookie.

## Persistence

SQLite via the pure-Go `modernc.org/sqlite` driver. Connection pragmas
(`busy_timeout`, `foreign_keys`, `journal_mode=WAL`, `_txlock=immediate`) are
applied through the DSN so they take effect on every pooled connection.
Read-modify-write on a key (`UpdateAPIKeyFunc`) runs in a single
`BEGIN IMMEDIATE` transaction to close the lost-update window; the global policy
uses an optimistic version check.

## Graceful shutdown

On SIGINT/SIGTERM the server stops the retention loop, calls `Server.Shutdown`
(which lets in-flight handlers finish), then drains the audit writer's
background writes **before** the deferred `db.Close`, so last-request entries
aren't lost to a closing database.

## Out of scope (deliberately)

Library/embedded mode, a sidecar with config sync + local authz (rate-limit
counters would stay central or become per-replica approximate), Envoy
`ext_authz`/RLS shims, and non-SQLite backends. The `internal/*` core is kept
transport-neutral so an in-process mode stays possible later.
