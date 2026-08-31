# Administration

This guide is for **operators**: running Turnstile, minting and managing API
keys, editing the global policy, browsing the audit log, and securing the
host→Turnstile connection (mTLS or network isolation).

For the other side — how a host *service* calls `Check`/`Authenticate` — see
[CLIENT-INTEGRATION.md](CLIENT-INTEGRATION.md).

All management RPCs are `POST /turnstile.v1.Turnstile/<Method>` (Connect
HTTP/JSON) and require a **management key** — an API key whose own policy allows
the matching `turnstile:<op>` action — as an `Authorization: Bearer` header
(see [Management access](#management-access-and-scoped-roles) below). The
examples below use `curl`; the same operations are available in the web console
at `/ui/`.

## Running the service

Build and start it (see the [README](README.md) for the quickstart and
[DEVELOPMENT.md](DEVELOPMENT.md) for build tooling):

```sh
mage build:backend && ./turnstile
```

Configuration is entirely via environment variables (all optional, sane
defaults), seeded from an optional `.env` file. The full reference is in
[DEVELOPMENT.md](DEVELOPMENT.md#configuration); the operational essentials:

- `LISTEN_ADDR` (`:8080`) — bind address; serves the Connect API, the console at
  `/ui/`, `/health`, and (when enabled) `/metrics`.
- `DB_PATH` (`turnstile.db`) — SQLite file.
- `AUDIT_RETENTION_DAYS` (`365`) — audit rows older than this are pruned; `0`
  keeps them forever.
- `METRICS_ENABLED` (`true`) — expose Prometheus metrics at `/metrics`; set
  `false`/`0`/`off`/`no` to disable.

`/health` is unauthenticated and returns `{"status":"ok"}` for liveness checks.

`/metrics` (when enabled) is unauthenticated too and exposes the standard Go
runtime/process collectors plus `turnstile_http_requests_total`,
`turnstile_http_request_duration_seconds`, `turnstile_check_decisions_total`
(labelled by decision: `allowed`, `policy_denied`, `rate_limited`,
`unauthenticated`), and `turnstile_audit_dropped_total` (audit rows dropped when
the write queue is full — nonzero means sustained audit loss under load). It
shares the main listener.

**Securing it.** Following Prometheus convention, the endpoint carries no
built-in auth — the metrics hold operational counts, not secrets, and the
standard practice is to control *who can reach it* rather than authenticate the
scrape. In order of preference:

- **Network isolation** — the usual answer: only allow your Prometheus host to
  reach the listener (security group / firewall rule / private subnet / k8s
  `NetworkPolicy`). Loopback-only doesn't fit here, since Prometheus normally
  scrapes from another machine.
- **mTLS** — if you run Turnstile with `TLS_CLIENT_CA_FILE` (see below),
  `/metrics` is already behind client-certificate auth like every other route;
  Prometheus scrapes it with a `tls_config` client cert/key.
- **A reverse proxy / sidecar** — put nginx/Envoy (or `kube-rbac-proxy` in
  Kubernetes) in front to add TLS + basic-auth/bearer auth without changing
  Turnstile. Prometheus supports `basic_auth`, `authorization`, and `tls_config`
  in its `scrape_configs`, so any of these works on the scraper side.

If none of these fit your deployment, set `METRICS_ENABLED=false`.

### The bootstrap management key

On first start against an **empty key store**, Turnstile seeds a default policy
and a **bootstrap management key** — a full-admin key (`allow turnstile:* on *`)
— logging the token **once**:

```json
{"time":"2026-08-25T12:00:00Z","level":"WARN","msg":"created bootstrap management key — store this token now, it will not be shown again","token":"tsk_..."}
```

Save it — it guards every management RPC and the web console. Only its SHA-256
hash is stored, so it cannot be recovered later. The bootstrap key has no special
status: it is an ordinary key, deletable and rotatable like any other.

**Break-glass recovery.** If every key that can manage is lost, restart the
service with the `-bootstrap` flag (or `TURNSTILE_BOOTSTRAP=true` in the
environment). On start it mints a *fresh* full-admin key and logs its token
**once** (again under the `token` field), even when keys already exist — so
whoever controls the process can always recover:

```sh
./turnstile -bootstrap
# or:  TURNSTILE_BOOTSTRAP=true ./turnstile
```

There is intentionally no "can't delete the last admin" guard — break-glass is
the recovery net.

### Management access and scoped roles

Management authorization is just policy. Each management RPC checks that the
**caller's own key** allows a `turnstile:`-namespaced action; the key is
evaluated against **its own statements only** (the global deny-only ceiling does
**not** gate `turnstile:` actions). The `turnstile:` namespace is reserved for
this — host services must not use it for their own vocabulary.

The action vocabulary, and the resource each authorizes against:

| Action | RPC | Resource |
|---|---|---|
| `turnstile:create-key` | `CreateKey` | `*` |
| `turnstile:get-key` | `GetKey` | the target key's id |
| `turnstile:list-keys` | `ListKeys` | `*` |
| `turnstile:update-key` | `UpdateKey` | the target key's id |
| `turnstile:rotate-key` | `RotateKey` | the target key's id |
| `turnstile:delete-key` | `DeleteKey` | the target key's id |
| `turnstile:read-policy` | `GetPolicy` | `*` |
| `turnstile:update-policy` | `UpdatePolicy` | `*` |
| `turnstile:query-audit` | `QueryAudit` | `*` |

Per-key operations (`get`/`update`/`rotate`/`delete`) authorize against the
**target key's id**, which *is* its authorization resource
(`turnstile:key:<random-hex>`); collection/policy/audit operations authorize
against `*`. Roles are therefore just policies on a key:

- **Full admin** — `allow turnstile:* on *`.
- **Auditor** — `allow turnstile:query-audit on *` (read-only; cannot escalate).

Grant these with `CreateKey`/`UpdateKey` like any other statements.

> **Statement-editing grants are admin-equivalent.** Management is evaluated
> against the caller key's *own* statements (the global deny-only ceiling does
> not apply), so any key that can edit a key's `statements` — i.e. **any**
> `turnstile:update-key` grant (even one scoped to a single key id, including its
> own) or a `turnstile:update-policy` grant — can rewrite those statements to
> `allow turnstile:* on *` and mint full admin. Policy cannot fence this off.
> **Treat any `create`/`update`/`rotate`/`delete-key` or `update-policy` grant as
> equivalent to full admin** and scope it accordingly. Only the read-only actions
> (`get-key`, `list-keys`, `read-policy`, `query-audit`) are safe to delegate
> narrowly.

**Rotating a management (or client) key.** `RotateKey` regenerates a key's secret
in place — same id, policy, rate limits, and name — and returns the new plaintext
token once; the old token stops working immediately. Governed by
`turnstile:rotate-key` on that key's id.

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/RotateKey \
  -H "Content-Type: application/json" -H "Authorization: Bearer $MGMT_TOKEN" \
  -d '{"id": "turnstile:key:..."}'
# -> { ..., "plaintextToken": "tsk_..." }   (shown once)
```

## Managing keys

A **client token** (`tsk_…`) is an end user's / agent's API key: it carries the
policy statements and rate-limit overrides that `Check` evaluates. Mint one with
`CreateKey`:

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/CreateKey \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -d '{
    "name": "photos-reader",
    "note": "read-only access for the reporting job",
    "statements": [
      { "effect": "ALLOW", "actions": ["photos:listAlbums", "photos:getAlbum"], "resources": ["photos:*"] }
    ],
    "rateLimits": { "photos:getAlbum": { "perMinute": 60 } }
  }'
```

The response includes `plaintextToken` **once** — store it and hand it to the
host/client; only the hash is persisted, so it can never be shown again. (See
[CLIENT-INTEGRATION.md](CLIENT-INTEGRATION.md#namespacing) for how to choose the
action/resource strings in `statements`.)

A statement's `effect` is `ALLOW` or `DENY`. `note` is a free-form human label
for the key. A key's `rateLimits` is a plain map of `action → limit` (per-action
overrides only; the baseline comes from the global policy's per-key defaults).

Other key operations (each gated by its own `turnstile:` action):

```sh
# List keys (omit includeDisabled to hide disabled ones).
curl -sS .../ListKeys   -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" -d '{"includeDisabled": true}'

# Fetch one key.
curl -sS .../GetKey     -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" -d '{"id": "turnstile:key:..."}'

# Disable a key (a partial update: unset fields are left unchanged).
curl -sS .../UpdateKey  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" -d '{"id": "turnstile:key:...", "disabled": true}'

# Delete a key.
curl -sS .../DeleteKey  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" -d '{"id": "turnstile:key:..."}'
```

`UpdateKey` is a true partial update: absent scalar fields are left unchanged.
`statements` replaces only when present; a non-empty `rateLimits` map replaces
the overrides (use `clearRateLimits: true` to remove them all); and expiry is set
via `expiresAt` or removed via `clearExpiry`. A disabled or expired key fails
authentication (indistinguishably from an unknown token).

## Managing the global policy

There is one **global policy**: a deny-only ceiling evaluated before every key's
statements, plus the rate-limit configuration. Because it is a ceiling, only
`deny` statements are allowed (an allow would be additive to every key, so
`UpdatePolicy` rejects allow statements). Read it with `GetPolicy`, then write it
back with `UpdatePolicy`:

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/UpdatePolicy \
  -H "Content-Type: application/json" -H "Authorization: Bearer $MGMT_TOKEN" \
  -d '{
    "statements": [ { "effect": "DENY", "actions": ["photos:deleteAlbum"], "resources": ["*"] } ],
    "rateLimits": { "perKey": { "default": { "perMinute": 120 } }, "serviceWide": { "default": { "perMinute": 600 } } },
    "expectedVersion": 1
  }'
```

`expectedVersion` is the optimistic-concurrency guard: pass the `version` from
your last `GetPolicy`; a mismatch returns `aborted` (someone else updated it —
re-fetch and retry).

> **`UpdatePolicy` replaces the whole policy (PUT semantics), not a patch.** Both
> `statements` and `rateLimits` are written wholesale, with no "leave unchanged"
> option: omit `rateLimits` and you clear **all** rate limiting; omit
> `statements` and you clear the deny ceiling. Always base the request on a fresh
> `GetPolicy` (which you need anyway for `expectedVersion`) and send the full,
> modified policy back — don't hand-write a partial body.

**Rate limits** apply at two independent levels that must both pass: `perKey`
(the per-key baseline every key inherits) and `serviceWide` (an aggregate cap
across all keys). Here in the global policy, each is a `default` plus optional
`perAction` overrides, in requests per minute. An individual key can then tighten
or loosen specific actions via its own `rateLimits` map (`CreateKey`/`UpdateKey`)
— that map is per-action only; a key has no blanket default of its own.

## Auditing

Turnstile records the audit trail itself; there is no host-reported intake. It
has two sources:

- **`Check` decisions.** The `Check` hot path writes one row per decision —
  `ALLOWED`, `POLICY_DENIED`, `RATE_LIMITED`, or `UNAUTHENTICATED` — recorded
  asynchronously off the hot path. An unauthenticated `Check` has an empty
  `api_key_id`.
- **Management-plane self-audit.** Turnstile records its own management actions
  directly: every **mutation** on success (`create`/`update`/`rotate`/`delete`-key
  and `update-policy`) and every **denied** attempt (an authenticated key that
  lacked the `turnstile:` grant → decision `POLICY_DENIED`). Successful reads
  (`list`/`get`/`query-audit`/`read-policy`) are not audited, to keep the log
  signal-heavy. The entry's `api_key_id` is the caller's key and `action` is the
  `turnstile:<op>`.

Each entry has just five fields: `api_key_id`, `action`, `resource`, `decision`,
and `timestamp`. Query the log with `QueryAudit`, filterable by key
(`apiKeyId`), action-namespace prefix (`actionPrefix`), decision, and time range
(`after`/`before`), with keyset pagination (e.g. `"actionPrefix": "turnstile:"`
for just the management trail):

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/QueryAudit \
  -H "Content-Type: application/json" -H "Authorization: Bearer $MGMT_TOKEN" \
  -d '{
    "actionPrefix": "photos:",
    "decision": "POLICY_DENIED",
    "after": "2026-08-01T00:00:00Z",
    "limit": 100
  }'
# -> {"entries":[...], "nextCursor": "12345"}
```

Pass `nextCursor` back as `cursor` for the following page (`0`/absent when
exhausted). The same view is available in the web console's Audit tab. Retention
(`AUDIT_RETENTION_DAYS`) bounds how far back the log goes.

## Securing host → Turnstile

Authorization keys off the namespaced action and the presented client token —
never the calling host's identity. The service-facing RPCs (`Check`,
`Authenticate`) are **open at the application layer** — there is
no service credential to configure. Control *which hosts* may reach them at the
transport/network layer, with **optional mTLS** and/or network isolation.

### mTLS (optional)

Serve HTTPS and require client certificates, so only hosts holding a cert signed
by your CA can connect at all. Set:

- `TLS_CERT_FILE` + `TLS_KEY_FILE` — the server's certificate and key (both
  required together); enabling these serves HTTPS and negotiates HTTP/2 via ALPN.
- `TLS_CLIENT_CA_FILE` — a PEM bundle of CA certs; when set, Turnstile requires
  and verifies a client certificate against it (`RequireAndVerifyClientCert`).
  TLS ≥ 1.2 is enforced.

```sh
TLS_CERT_FILE=server.crt \
TLS_KEY_FILE=server.key \
TLS_CLIENT_CA_FILE=client-ca.crt \
  ./turnstile
```

A minimal self-signed set for a dev/test cluster (use your real PKI in
production):

```sh
# Client CA + a client cert signed by it (each host gets one).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 365 -nodes \
  -keyout client-ca.key -out client-ca.crt -subj "/CN=turnstile-client-ca"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout host.key -out host.csr -subj "/CN=photos-service"
openssl x509 -req -in host.csr -CA client-ca.crt -CAkey client-ca.key \
  -CAcreateserial -days 365 -out host.crt

# Server cert (use a CN/SAN matching how hosts address Turnstile).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 365 -nodes \
  -keyout server.key -out server.crt -subj "/CN=turnstile.internal"
```

Hosts then present `host.crt`/`host.key` on the connection — the client
certificate is the host's identity. See
[CLIENT-INTEGRATION.md](CLIENT-INTEGRATION.md#authenticating-the-host) for the
client side.

Without mTLS the service-facing RPCs are reachable by anyone who can connect, so
rely on network isolation (e.g. a private subnet) in that case.

## The web console

The management UI is served at `http://localhost:8080/ui/` (root redirects
there). Sign in with a management key; it drives the same management RPCs
described above to create/edit keys, edit the policy, and browse audit. It is a
plain API client — see the security note in
[ARCHITECTURE.md](ARCHITECTURE.md#management-ui-security-note).
