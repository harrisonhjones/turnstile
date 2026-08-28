# Client integration

This guide is for **host services** (an API proxy, gateway, MCP/RPC server, …)
integrating with Turnstile: how to authorize requests, resolve identities, and
report audit. For the operator side — running the service, minting the keys you
use here, editing policy, and browsing audit — see
[ADMINISTRATION.md](ADMINISTRATION.md).

A host replaces its in-process authorization with three interactions:

1. **On each request** — call `Check(token, "svc:action", resources, count_rate_limit=true)`.
2. **For a whoami** — call `Authenticate(token)`.
3. **After a request completes** — buffer audit entries and POST a batch via `ReportAudit`.

The host keeps its own **action/resource vocabulary**; Turnstile only ever sees
opaque strings.

## Namespacing

Prefix every action and resource with your service name so grants can't leak
across projects that share the instance:

```
action:    "photos:getAlbum"
resources: ["photos:album:a1b2", "photos:account:acct_42"]
```

Turnstile never parses the prefix — it is pure convention that keeps `photos:*`
grants from ever matching another service's `payments:*` actions. A single object
can be named by several resources; `Check` treats the list as OR, so an
account-scoped grant (`photos:account:acct_*`) covers every album within it.

> **Always pass at least one resource.** A policy statement matches by resource
> pattern, so a `Check` with an empty `resources` list evaluates to a deny even
> under an allow-all key. For an action that doesn't name a concrete object, use
> a stable synthetic resource (e.g. `photos:account:acct_42`, or a capability-style
> `photos:reports:*`) so the statement has something to match.

## Credentials

- **Client token** (`tsk_…`) — the end user's / agent's API key that your host
  received and passes to `Check`/`Authenticate`. An operator mints it with
  `CreateKey` (see [ADMINISTRATION.md](ADMINISTRATION.md#managing-keys)); it
  carries the policy and rate limits Turnstile evaluates.
- **Admin credential** (`tsa_…`) — guards the management RPCs; used by operators
  and the web console, **not** by a host on the hot path.

Authorization keys off the namespaced action and the client token — never your
host's identity.

## Authenticating the host

Separately from the end user's `client_token`, your host may need to authenticate
*itself* to Turnstile so only trusted hosts can reach the service-facing RPCs.
Depending on how the operator configured the service
([ADMINISTRATION.md](ADMINISTRATION.md#securing-host--turnstile)):

- **Service credential** — send the shared secret as an `Authorization: Bearer`
  header on `Check`/`Authenticate`/`ReportAudit`.
- **mTLS** — present your client certificate on the connection (configure your
  HTTP client's TLS with the cert/key the operator issued you).
- **Neither** — nothing extra to send; the endpoint is guarded by network
  isolation.

## The hot path with curl

Every unary RPC is a `POST` to `/turnstile.v1.Turnstile/<Method>` with a JSON
body:

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/Check \
  -H "Content-Type: application/json" \
  -d '{
    "clientToken": "tsk_...",
    "action": "photos:getAlbum",
    "resources": ["photos:album:a1b2"],
    "countRateLimit": true
  }'
# -> {"allowed":true,"principal":{"keyId":"key_...","name":"photos-reader"},"decision":"ALLOWED","rateLimit":{}}
```

`decision` is one of `ALLOWED`, `UNAUTHENTICATED`, `POLICY_DENIED`,
`RATE_LIMITED`. On `RATE_LIMITED`, `rateLimit.retryAfterMs` tells the client how
long to back off. Set `countRateLimit=false` for a dry authorization check that
consumes no budget. (Unknown, disabled, and expired tokens all return
`UNAUTHENTICATED` — you can't distinguish them, by design.)

## The hot path from Go (gRPC-compatible Connect client)

```go
import (
	"connectrpc.com/connect"
	"net/http"

	turnstilev1 "harrisonhjones.com/turnstile/gen/turnstile/v1"
	"harrisonhjones.com/turnstile/gen/turnstile/v1/turnstilev1connect"
)

client := turnstilev1connect.NewTurnstileClient(http.DefaultClient, "http://localhost:8080")

// In your middleware, for each incoming request:
resp, err := client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
	ClientToken:    userToken,                       // the tsk_ key the caller presented
	Action:         "photos:getAlbum",
	Resources:      []string{"photos:album:" + albumID},
	CountRateLimit: true,
}))
if err != nil { /* transport error → 502 */ }

switch resp.Msg.Decision {
case turnstilev1.Decision_ALLOWED:
	// proceed
case turnstilev1.Decision_UNAUTHENTICATED:
	// 401
case turnstilev1.Decision_POLICY_DENIED:
	// 403
case turnstilev1.Decision_RATE_LIMITED:
	// 429, Retry-After: resp.Msg.RateLimit.RetryAfterMs
}
```

If you want gRPC wire framing (HTTP/2) instead of the Connect protocol, pass
`connect.WithGRPC()` to `NewTurnstileClient`. `Authenticate` is the same shape as
`Check` and returns just the `Principal` — use it for a `whoami` with no
authorization or rate-limit side effects.

## Reporting audit

Status and latency aren't known until the host finishes serving, so audit is
reported *after* the fact. `ReportAudit` is a **unary** call taking a batch of
entries, so — like the rest of the API — you can send it as plain JSON. Buffer
entries and POST them periodically:

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/ReportAudit \
  -H "Content-Type: application/json" \
  -d '{
    "entries": [
      {
        "apiKeyId": "key_...",
        "apiKeyName": "photos-reader",
        "method": "REST",
        "path": "/albums/a1b2",
        "action": "photos:getAlbum",
        "resource": "photos:album:a1b2",
        "requestSummary": "GET /albums/a1b2",
        "responseStatus": 200,
        "latencyMs": 12
      }
    ]
  }'
# -> {"accepted":"1"}     (int64 is JSON-encoded as a string, per protobuf JSON)
```

Or from the Go client:

```go
resp, err := client.ReportAudit(ctx, connect.NewRequest(&turnstilev1.ReportAuditRequest{
	Entries: []*turnstilev1.AuditEntry{
		{
			ApiKeyId:       e.keyID,
			ApiKeyName:     e.keyName,   // denormalized; survives rename/delete
			Method:         "REST",      // or "MCP", host-defined
			Path:           e.path,
			Action:         e.action,    // namespaced
			Resource:       e.resource,
			RequestSummary: e.summary,   // non-sensitive; NEVER message text
			ResponseStatus: int32(e.status),
			LatencyMs:      e.latencyMS,
			Timestamp:      timestamppb.New(e.at), // omit and the server stamps at receipt
		},
	},
}))
// resp.Msg.Accepted = count stored
```

Keep `requestSummary` free of sensitive content (message bodies, secrets). A
single call is capped at 10,000 entries and is **all-or-nothing** — a batch over
the cap is rejected whole with `ResourceExhausted`, so split larger batches
across calls. Operators query it back through `QueryAudit` or the web console
(see [ADMINISTRATION.md](ADMINISTRATION.md#auditing)).

## Migration sketch

To move a host off in-process authorization: both its HTTP middleware and any
non-HTTP entrypoint (e.g. a tool/RPC guard) call `Check` with the same
namespaced vocabulary the host already uses internally; a `whoami` maps to
`Authenticate`; completed requests are buffered and batch-reported via `ReportAudit`.
The host keeps its own `<service>:` prefix and resource builders — Turnstile only
sees strings. Expect one extra round-trip per request until (if ever) an edge
cache lands.
