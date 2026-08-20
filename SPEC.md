# Turnstile — build spec & kickoff

Turnstile is a standalone **access-control service**: it issues **API keys**,
evaluates a **statement-based policy engine**, enforces **rate limits**, and
records an **audit trail** — over **gRPC/Connect**, for reuse across many
projects. A turnstile admits the authorized (auth), meters each pass (rate
limiting), and counts every entry (audit): the four responsibilities in one
image.

## How to use this doc

This is a **greenfield build spec** for a fresh repo
(`github.com/harrisonhjones/turnstile`). Point an agent at this file in an empty
workspace and build up the milestones in order.

**Provenance / reference implementation.** Turnstile is extracted from the
`beeper-api-proxy` project, which already contains working versions of the core
logic (its `internal/{auth,policy,ratelimit,audit}` packages and the
keys/policy/audit slice of `internal/store`) and the stack conventions below
(mage targets, air, embedded Ionic React UI, SQLite setup, bootstrap key). If
that repo is available, **port from it**; otherwise build fresh from this spec.
The one deliberate change on extraction: the policy engine must be
**domain-agnostic** — it matches opaque `action`/`resource` strings and knows
nothing about any specific app's vocabulary.

## Locked decisions

1. **One shared instance** for all projects. Isolation is by **action
   namespacing** — every action/resource string is prefixed with the owning
   service, e.g. `beeper:sendMessage`, `beeper:chat:!abc`. The engine matches
   opaque strings, so `beeper:*` can't authorize another project; no realm/tenant
   construct. The prefix is host-app vocabulary; Turnstile never parses it.
2. **Denied authz never burns rate budget** — reserve-then-confirm; budget is
   consumed only when authn + authz pass.
3. **Transport: Connect (`connectrpc.com`)** — recommended default. It's
   gRPC-wire-compatible for the `Check` hot path *and* speaks gRPC-Web + plain
   HTTP/1.1-JSON, so the management API is `curl`- and browser-friendly. Swap for
   raw `google.golang.org/grpc` if a more standard stack is preferred.
4. **Module:** `github.com/harrisonhjones/turnstile`; proto package
   `turnstile.v1`.

## Tech stack & project conventions

Mirror `beeper-api-proxy`:

- **Go** (latest toolchain; `go.mod` pins it). Pure-Go SQLite via
  `modernc.org/sqlite` (no CGO).
- **mage** for build/dev tasks, namespaced so they act on the whole project, the
  Go backend, or the web UI. Target set to implement:
  - `build:{all,backend,ui}` — `build:all` = generate protos → build UI → compile binary.
  - `run:{backend,ui}` — `run:backend` uses **air** for hot reload if on `PATH`; `run:ui` runs Vite.
  - `gen` (or `generate`) — run **buf** to generate Go + Connect stubs from the protos.
  - `fmt:{all,backend,ui}`, `vet:{all,backend,ui}` (gofmt/`go vet` + golangci-lint; oxlint/oxfmt for UI).
  - `test:{unit,integration}`, `check` (vet + unit — the CI gate).
  - `clean:{all,backend,ui}`, `resetDB` (delete the SQLite file + WAL/SHM sidecars, honoring `DB_PATH`).
- **Proto tooling:** `buf` with `buf.gen.yaml` generating `protoc-gen-go` +
  `protoc-gen-connect-go` into an internal `gen/` package. Protos live in
  `proto/turnstile/v1/`.
- **Config:** environment variables seeded from a `.env` (copy `.env.example`);
  real env always wins. All values optional with sane defaults.
- **Embedded management UI:** an **Ionic React** SPA (Vite + TypeScript) under
  `internal/management/ui/`, compiled to `ui/dist` and served via `go:embed`.
  Only a `.gitkeep` is tracked; a placeholder page is served until the UI is
  built. Vite dev server proxies API calls to the backend for hot reload.
- **Server hygiene:** graceful shutdown (drain in-flight audit writes before
  closing the DB); SQLite connection pragmas applied via the DSN
  (`busy_timeout`, `foreign_keys`, `journal_mode=WAL`, `_txlock=immediate`) so
  they take effect on every pooled connection.
- **Docs:** `README.md`, `DEVELOPMENT.md`, `ARCHITECTURE.md`; low-level details
  in Godoc, not markdown.

## Domain model

- **API key:** opaque bearer token (`tsk_…`); store only the SHA-256 hash and
  look up by hash (no plaintext, no timing concern). A key has: name, note,
  statements, rate-limit overrides, disabled flag, optional expiry, timestamps,
  optional owner-namespace tag (management convenience only).
- **Statement (policy):** `{ effect: allow|deny, actions: [...], resources: [...] }`
  over namespaced strings; resources are `type:id` with a single trailing `*`
  wildcard, and an object may be named by several resources at once (match any).
  **Evaluation:** deny-wins → first allow → default deny.
- **Two policy layers:** each key has its own statements; there is one **global
  policy**, evaluated first, that is a **deny-only ceiling** (reject allow
  statements there — a global allow would be additive to every key). Cache the
  global policy in memory; refresh on update.
- **Rate limits:** per action, two independent levels that both must pass —
  **per-key** (key overrides → instance defaults) and **service-wide** (aggregate
  cap). Requests/minute + optional burst. Token buckets (`golang.org/x/time/rate`).
- **Audit:** one row per authenticated request (api_key_id, denormalized
  api_key_name, method, path, action, resource, non-sensitive request summary,
  status, latency, timestamp). Background writer; retention prune loop.

## RPC surface (`turnstile.v1`)

Service→Turnstile auth is **mTLS** (or a service credential in metadata), not a
request field. `Check` does authn+authz+ratelimit in one round-trip but does
**not** write audit (status/latency aren't known until the host finishes — hosts
report audit afterward).

```proto
syntax = "proto3";
package turnstile.v1;
import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";

service Turnstile {
  rpc Check(CheckRequest) returns (CheckResponse);          // hot path
  rpc Authenticate(AuthenticateRequest) returns (Principal); // identity only (whoami)
  rpc ReportAudit(stream AuditEntry) returns (ReportAuditSummary);

  // Management (admin credential required)
  rpc CreateKey(CreateKeyRequest) returns (Key);
  rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
  rpc GetKey(GetKeyRequest) returns (Key);
  rpc UpdateKey(UpdateKeyRequest) returns (Key);
  rpc DeleteKey(DeleteKeyRequest) returns (google.protobuf.Empty);
  rpc GetPolicy(GetPolicyRequest) returns (Policy);
  rpc UpdatePolicy(UpdatePolicyRequest) returns (Policy);   // optimistic version check
  rpc QueryAudit(QueryAuditRequest) returns (QueryAuditResponse);
}

message CheckRequest {
  string client_token = 1;         // the API key presented by the end user/agent
  string action       = 2;         // service-namespaced, e.g. "beeper:sendMessage"
  repeated string resources = 3;   // e.g. ["beeper:chat:!abc"]; matched as OR
  bool count_rate_limit = 4;       // consume budget (only when authn+authz pass)
}
message CheckResponse {
  bool allowed = 1;
  Principal principal = 2;
  Decision decision = 3;
  RateLimitVerdict rate_limit = 4;
}
enum Decision { ALLOWED = 0; UNAUTHENTICATED = 1; POLICY_DENIED = 2; RATE_LIMITED = 3; }
message RateLimitVerdict { bool limited = 1; int64 retry_after_ms = 2; }
message Principal { string key_id = 1; string name = 2; string note = 3; }

message AuthenticateRequest { string client_token = 1; }

message AuditEntry {
  string api_key_id = 1;
  string api_key_name = 2;         // denormalized; survives rename/delete
  string method = 3;               // "REST"|"MCP"|… (host-defined)
  string path = 4;
  string action = 5;               // namespaced
  string resource = 6;
  string request_summary = 7;      // non-sensitive; never message text
  int32  response_status = 8;
  int64  latency_ms = 9;
  google.protobuf.Timestamp timestamp = 10;
}
message ReportAuditSummary { int64 accepted = 1; }

// Key / Statement / Policy / RateLimit / Query* messages: model per the domain
// section (effect+actions[]+resources[]; per-key + service-wide limits with
// default + perAction; disabled/expiresAt; policy version for optimistic
// concurrency; audit filters + cursor).
```

- **Generic auth failure:** `UNAUTHENTICATED` never distinguishes
  unknown/disabled/expired (no token-existence leak).
- **CreateKey returns the plaintext token once**; only the hash is stored.

## Service & admin auth (guarding the guard)

- **Host → Turnstile:** mTLS or a service credential in metadata — used for audit
  attribution and management scoping; authorization keys off the namespaced
  action, not the caller.
- **Admin (management RPCs):** a bootstrap admin credential. First start against
  an empty DB seeds it and logs it **once**; deleting all admin credentials
  re-seeds on next start (the intentional lockout-recovery path — no
  "can't delete the last one" guard).

## Rate-limit state (why there's no sidecar yet)

Because Turnstile is central, token-bucket **counter state lives in Turnstile** —
correct (a global limit is truly global across a host's replicas and across
projects sharing a key) at the cost of a round-trip on the hot path. This is the
one thing that can't be lazily cached at the edge: config (limits) could sync,
but counter state is real-time and shared. Keep enforcement central for now.

## Suggested repo layout

```
github.com/harrisonhjones/turnstile
  cmd/turnstile/           entrypoint: config, open store, bootstrap, serve, graceful shutdown
  proto/turnstile/v1/      .proto sources
  gen/turnstile/v1/        buf-generated Go + Connect stubs
  internal/
    token/                 key type, gen/hash, authentication, Principal + ctx helpers
    policy/                domain-agnostic statement engine + validation
    ratelimit/             limiter manager + resolution
    audit/                 writer, retention, query
    store/                 schema + accessors over *sql.DB (SQLite)
    server/                Connect handlers wiring the above (Check/Authenticate/ReportAudit/management)
    management/ui/         embedded Ionic React admin SPA (→ ui/dist via go:embed)
  magefile.go              build:/run:/gen/fmt:/vet:/test:/check/clean:/resetDB
  buf.gen.yaml, buf.yaml
  .env.example
  README.md DEVELOPMENT.md ARCHITECTURE.md
```

## Management UI scope

An embedded Ionic React SPA (same shape as beeper-api-proxy's) for an operator:
create/list/edit/disable **keys** and view their granted statements + rate-limit
overrides; view/edit the **global policy** (deny-only ceiling); browse/filter the
**audit log** (by key, action-namespace prefix, status, time). Signs in with an
admin credential. It talks to Turnstile over the Connect HTTP/JSON protocol.

## Build milestones (do in order)

1. **Skeleton:** module + mage targets + `.env` config + SQLite store with schema
   (`api_keys`, `global_policy`, `audit_log`) and connection pragmas; graceful
   shutdown. Bootstrap admin credential on first run.
2. **Policy engine:** `Statement`, `Evaluate` (deny-wins), wildcard matching,
   global deny-only validation — with thorough unit tests. Domain-agnostic.
3. **Keys + auth:** token gen/hash, key CRUD in the store, `Authenticate`, the
   policy-backed authorizer, in-memory global-policy cache.
4. **Proto + Connect server:** define `turnstile.v1`, `buf generate`, implement
   `Check` + `Authenticate` + management RPCs; mTLS/service-credential + admin
   auth.
5. **Rate limiting:** per-key + service-wide limiters, resolved from policy;
   wire into `Check` (reserve-then-confirm; deny doesn't burn budget).
6. **Audit:** `ReportAudit` streaming intake, background writer, `QueryAudit`,
   retention prune loop.
7. **Management UI:** embedded Ionic React app for keys/policy/audit; `go:embed`
   + placeholder + Vite dev flow.
8. **Docs:** README/DEVELOPMENT/ARCHITECTURE; a short client-integration guide
   (how a host service calls `Check` and streams `ReportAudit`).

## Out of scope (deferred; noted so we don't design them out)

- **Library/embedded mode** — keep the `internal/*` core transport-neutral so a
  future in-process mode stays possible, but don't build it now.
- **Sidecar + config sync** — pull keys/policy/limits to a local cache and
  evaluate authz locally; audit streams up; rate-limit counters stay central (or
  accept per-replica approximation). Directions differ:

  | Data | Direction | Cadence-syncable |
  |---|---|---|
  | keys, policy, rate-limit *limits* | pull (center → edge) | yes |
  | audit events | push (host → center) | yes (buffer/stream) |
  | rate-limit *counters* | shared, real-time | no — central or approximate |

- **Envoy `ext_authz` / RLS shims**, **non-SQLite backends**.

## Client integration (host apps, e.g. beeper-api-proxy)

A host replaces in-process authorization with a Turnstile client: both its HTTP
middleware and any non-HTTP entrypoints (e.g. an MCP guard) call `Check(token,
"svc:action", resources, count_rate_limit=true)`; a `whoami` maps to
`Authenticate`; completed requests are buffered and streamed via `ReportAudit`.
The host keeps its own **action/resource vocabulary** (the `svc:` prefix and the
resource builders) — Turnstile only sees strings. Expect one extra round-trip per
request until (if ever) the sidecar cache lands.
