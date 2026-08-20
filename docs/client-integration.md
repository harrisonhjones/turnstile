# Client integration

This guide shows how a host service (an API proxy, gateway, MCP server, …)
delegates authorization to Turnstile. A host replaces its in-process
authorization with three interactions:

1. **On each request** — call `Check(token, "svc:action", resources, count_rate_limit=true)`.
2. **For a whoami** — call `Authenticate(token)`.
3. **After a request completes** — buffer an audit entry and stream it via `ReportAudit`.

The host keeps its own **action/resource vocabulary**; Turnstile only ever sees
opaque strings.

## Namespacing

Prefix every action and resource with your service name so grants can't leak
across projects that share the instance:

```
action:    "beeper:sendMessage"
resources: ["beeper:chat:!abc", "beeper:account:wa123"]
```

Turnstile never parses the prefix — it is pure convention that keeps `beeper:*`
grants from ever matching another service's `plaid:*` actions. A single object
can be named by several resources; `Check` treats the list as OR, so an
account-scoped grant (`beeper:account:wa*`) covers every chat within it.

> **Always pass at least one resource.** A policy statement matches by resource
> pattern, so a `Check` with an empty `resources` list evaluates to a deny even
> under an allow-all key. For an action that doesn't name a concrete object, use
> a stable synthetic resource (e.g. `beeper:account:wa123`, or a capability-style
> `beeper:reports:*`) so the statement has something to match.

## Two credentials

- **Admin credential** (`tsa_…`) — guards the management RPCs. Seeded and logged
  once on first run; used by operators and the web UI, not by hosts on the hot
  path.
- **Client token** (`tsk_…`) — an end user's / agent's API key, minted by an
  operator via `CreateKey`. This is what the host passes to `Check`.

Optionally, a host authenticates *itself* to Turnstile with a shared
`SERVICE_CREDENTIAL` (sent as `Authorization: Bearer` metadata on
`Check`/`Authenticate`/`ReportAudit`) or with mTLS. This is separate from the
end user's `client_token` — authorization keys off the namespaced action and the
client token, never the calling host's identity.

## Management with curl (Connect HTTP/JSON)

Every unary RPC is a `POST` to `/turnstile.v1.Turnstile/<Method>` with a JSON
body. Create a client key (requires the admin credential):

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/CreateKey \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "name": "beeper-reader",
    "note": "read-only access for the reporting job",
    "ownerNamespace": "beeper",
    "statements": [
      { "effect": "EFFECT_ALLOW", "actions": ["beeper:listChats", "beeper:listMessages"], "resources": ["beeper:*"] }
    ],
    "rateLimits": { "perAction": { "beeper:listMessages": { "perMinute": 60 } } }
  }'
```

The response includes `plaintextToken` **once** — store it; only the hash is
persisted. Give that token to the client/host.

Tighten the global deny-only ceiling (allow statements are rejected here):

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/UpdatePolicy \
  -H "Content-Type: application/json" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "statements": [ { "effect": "EFFECT_DENY", "actions": ["beeper:deleteMessage"], "resources": ["*"] } ],
    "rateLimits": { "perKey": { "default": { "perMinute": 120 } }, "serviceWide": { "default": { "perMinute": 600 } } },
    "expectedVersion": 1
  }'
```

`expectedVersion` is the optimistic-concurrency guard: pass the `version` you
last read from `GetPolicy`; a mismatch returns `aborted`.

> **`UpdatePolicy` replaces the whole policy (PUT semantics), not a patch.** Both
> `statements` and `rateLimits` are written wholesale, with no "leave unchanged"
> option: omit `rateLimits` and you clear **all** rate limiting; omit
> `statements` and you clear the deny ceiling. Always base the request on a fresh
> `GetPolicy` (which you need anyway for `expectedVersion`) and send the full,
> modified policy back — don't hand-write a partial body.

## The hot path with curl

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/Check \
  -H "Content-Type: application/json" \
  -d '{
    "clientToken": "tsk_...",
    "action": "beeper:listMessages",
    "resources": ["beeper:chat:!abc"],
    "countRateLimit": true
  }'
# -> {"allowed":true,"principal":{"keyId":"key_...","name":"beeper-reader"},"decision":"ALLOWED","rateLimit":{}}
```

`decision` is one of `ALLOWED`, `UNAUTHENTICATED`, `POLICY_DENIED`,
`RATE_LIMITED`. On `RATE_LIMITED`, `rateLimit.retryAfterMs` tells the client how
long to back off. Set `countRateLimit=false` for a dry authorization check that
consumes no budget.

## The hot path from Go (gRPC-compatible Connect client)

```go
import (
	"connectrpc.com/connect"
	"net/http"

	turnstilev1 "github.com/harrisonhjones/turnstile/gen/turnstile/v1"
	"github.com/harrisonhjones/turnstile/gen/turnstile/v1/turnstilev1connect"
)

client := turnstilev1connect.NewTurnstileClient(http.DefaultClient, "http://localhost:8080")

// In your middleware, for each incoming request:
resp, err := client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
	ClientToken:    userToken,                       // the tsk_ key the caller presented
	Action:         "beeper:sendMessage",
	Resources:      []string{"beeper:chat:" + chatID},
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
`connect.WithGRPC()` to `NewTurnstileClient`.

## Reporting audit

Status and latency aren't known until the host finishes serving, so audit is
reported *after* the fact — buffer entries and stream them up periodically:

```go
stream := client.ReportAudit(ctx)
for _, e := range buffered {
	_ = stream.Send(&turnstilev1.AuditEntry{
		ApiKeyId:       e.keyID,
		ApiKeyName:     e.keyName,   // denormalized; survives rename/delete
		Method:         "REST",      // or "MCP", host-defined
		Path:           e.path,
		Action:         e.action,    // namespaced
		Resource:       e.resource,
		RequestSummary: e.summary,   // non-sensitive; NEVER message text
		ResponseStatus: int32(e.status),
		LatencyMs:      e.latencyMS,
		Timestamp:      timestamppb.New(e.at),
	})
}
summary, err := stream.CloseAndReceive() // summary.Msg.Accepted = count stored
```

Keep `requestSummary` free of sensitive content (message bodies, secrets). Query
it back through the admin-guarded `QueryAudit` RPC or the web UI, filterable by
key, action-namespace prefix, method, status, and time range.

## Migration sketch (e.g. beeper-api-proxy)

Both the HTTP middleware and any non-HTTP entrypoint (an MCP guard) call `Check`
with the same namespaced vocabulary the host already uses internally; `whoami`
maps to `Authenticate`; completed requests are buffered and streamed via
`ReportAudit`. The host keeps its `svc:` prefix and resource builders — Turnstile
only sees strings. Expect one extra round-trip per request until (if ever) an
edge cache lands.
