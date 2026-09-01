# Client integration

This guide is for **host services** (an API proxy, gateway, MCP/RPC server, …)
integrating with Turnstile: how to authorize requests and resolve identities.
For the operator side — running the service, minting the keys you use here,
editing policy, and browsing audit — see [ADMINISTRATION.md](ADMINISTRATION.md).

A host replaces its in-process authorization with two interactions:

1. **On each request** — call `Check(token, "svc:action", resource, count_rate_limit=true)`.
2. **For a whoami** — call `Authenticate(token)`.

There is no audit call to make: Turnstile records an audit row for each
authenticated `Check` decision itself, server-side (unauthenticated Checks
aren't audited — they carry no key). The host keeps its own **action/resource
vocabulary**; Turnstile only ever sees opaque strings.

## Namespacing

Prefix every action and resource with your service name so grants can't leak
across projects that share the instance:

```
action:   "photos:getAlbum"
resource: "photos:album:a1b2"
```

Turnstile never parses the prefix — it is pure convention that keeps `photos:*`
grants from ever matching another service's `payments:*` actions. Each `Check`
names a **single** target resource. To authorize a whole class of objects, don't
pass a list — grant the key a statement whose `resources` pattern matches them
(a single trailing `*` wildcard), e.g. an allow on `photos:album:*`, or an
account-scoped `photos:account:acct_42:*`, covers every matching resource.

> **`resource` is required.** A policy statement matches by resource pattern, so
> a `Check` with an empty `resource` evaluates to a deny even under an allow-all
> key. For an action that doesn't name a concrete object, pass a stable synthetic
> resource (e.g. `photos:account:acct_42`, or a capability-style
> `photos:reports:list`) so the statement has something to match.

## Credentials

- **Client token** (`tsk_…`) — the end user's / agent's API key that your host
  received and passes to `Check`/`Authenticate`. An operator mints it with
  `CreateKey` (see [ADMINISTRATION.md](ADMINISTRATION.md#managing-keys)); it
  carries the policy and rate limits Turnstile evaluates.

There is only one credential type: an API key (`tsk_…`). A *management* key is
just such a key whose own policy grants `turnstile:` actions; it's used by
operators and the web console, **not** by a host on the hot path (see
[ADMINISTRATION.md](ADMINISTRATION.md#management-access-and-scoped-roles)).

Authorization keys off the namespaced action and the client token — never your
host's identity.

## Authenticating the host

The service-facing RPCs (`Check`/`Authenticate`) are **open at the
application layer** — there is no per-host credential to send. Access is
controlled at the transport/network layer, so depending on how the operator
configured the service
([ADMINISTRATION.md](ADMINISTRATION.md#securing-host--turnstile)):

- **mTLS** — present your client certificate on the connection (configure your
  HTTP client's TLS with the cert/key the operator issued you).
- **Network isolation only** — nothing extra to send; reachability is restricted
  by network controls (e.g. a private subnet).

## The hot path with curl

Every unary RPC is a `POST` to `/turnstile.v1.Turnstile/<Method>` with a JSON
body:

```sh
curl -sS http://localhost:8080/turnstile.v1.Turnstile/Check \
  -H "Content-Type: application/json" \
  -d '{
    "clientToken": "tsk_...",
    "action": "photos:getAlbum",
    "resource": "photos:album:a1b2",
    "countRateLimit": true
  }'
# -> {"allowed":true,"principal":{"keyId":"turnstile:key:...","name":"photos-reader"},"decision":"ALLOWED","rateLimit":{}}
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
	Resource:       "photos:album:" + albumID,
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

## Audit

There is nothing for the host to send: Turnstile records the audit trail itself.
Every `Check` writes one row for its decision (`ALLOWED`, `POLICY_DENIED`,
`RATE_LIMITED`, or `UNAUTHENTICATED`) asynchronously, off the hot path, and the
management RPCs self-audit their own mutations and denied attempts. Operators
query it back through `QueryAudit` or the web console (see
[ADMINISTRATION.md](ADMINISTRATION.md#auditing)).

## Migration sketch

To move a host off in-process authorization: both its HTTP middleware and any
non-HTTP entrypoint (e.g. a tool/RPC guard) call `Check` with the same
namespaced vocabulary the host already uses internally; a `whoami` maps to
`Authenticate`. Audit needs no host wiring — Turnstile records each `Check`
decision itself. The host keeps its own `<service>:` prefix and resource
builders — Turnstile only sees strings. Expect one extra round-trip per request
until (if ever) an edge cache lands.
