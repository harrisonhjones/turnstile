# Turnstile — Adversarial Code Review

Reviewer: automated code review (adversarial pass against `SPEC.md` + general
correctness/security). `go build ./...`, `go vet ./...`, and `go test ./...`
all pass on Go 1.26.

## Summary

Turnstile is, overall, a carefully written service. The security-critical
primitives are sound: tokens/credentials are stored only as SHA-256 hashes and
looked up by hash, the service credential uses `crypto/subtle` constant-time
comparison, SQL is parameterized with correct `LIKE` escaping, the deny-wins
policy engine and the deny-only global ceiling are correct and validated, the
generic-authentication-failure requirement is honored at the RPC layer, and the
reserve-then-confirm rate-limit refund is both correct and tested. No plaintext
token leak was found.

I did not find a Critical or clear-cut High **security** hole. The most
important defects are functional/robustness issues: a confirmed timestamp
ordering bug that silently corrupts audit time-range queries and retention, a
graceful-shutdown gap over plaintext h2c that voids the audit-drain guarantee,
and an unbounded goroutine/DoS surface in the audit intake path.

Counts by severity: Critical 0 · High 1 · Medium 4 · Low 6 · Nit 3.

Verdict legend: **CONFIRMED** = verified against the code with a concrete
failure path; **PLAUSIBLE** = credible but not fully proven (e.g. depends on
deployment or load).

---

## High

### H1. Audit time-range filters and retention compare RFC3339Nano strings lexically — wrong at sub-second boundaries (CONFIRMED)

- `internal/store/util.go:39-44` (`formatTime` uses `time.RFC3339Nano`)
- `internal/store/audit.go:106-113` (`After`/`Before` → `timestamp >= ?` / `<= ?`)
- `internal/store/audit.go:50-52` (`DeleteAuditEntriesBefore` → `timestamp < ?`)

Timestamps are stored as `TEXT` in `RFC3339Nano`, which **omits trailing zero
fractional digits (and the dot entirely for a whole second)**. SQLite compares
`TEXT` with binary collation, so lexical order diverges from chronological order
whenever sub-second precision is involved. I verified this directly:

```
"2026-06-01T12:00:00Z"            (12:00:00.000)
"2026-06-01T12:00:00.5Z"          (12:00:00.500)
"2026-06-01T12:00:00.123456789Z"
lexical sort → [ ....00.123456789Z, ....00.5Z, ....00Z ]   // .0 sorts LAST
"...00Z" >= "...00.5Z"  → true    // but 12:00:00.0 is BEFORE 12:00:00.5
```

Concrete failure: `QueryAudit` with `after = 2026-06-01T12:00:00.5Z` will
**incorrectly include** an entry timestamped `12:00:00.0Z` (string `...00Z` >=
string `...00.5Z`), and can **incorrectly exclude** entries with fractional
seconds relative to a whole-second bound. Retention (`timestamp < cutoff`) can
likewise over-/under-delete by up to ~1s at the boundary. Host-reported audit
timestamps routinely carry sub-second precision, so this is reachable in normal
operation. `ORDER BY id` shields the page ordering, but the range predicates are
silently wrong.

Severity: functional correctness of a security-audit feature, silent (no error),
confirmed. Blast radius is bounded to sub-second boundaries, which is why it is
High rather than Critical.

Fix: store timestamps in an order-preserving representation — either a
fixed-width format with a constant number of fractional digits (e.g.
`t.UTC().Format("2006-01-02T15:04:05.000000000Z")`) applied on both write and
query-bound formatting, or (preferred) store epoch nanoseconds as `INTEGER`.
Note the same `formatTime` is reused for query bounds, so any fix must be
symmetric on write and read.

---

## Medium

### M1. Graceful shutdown does not drain in-flight h2c requests; the audit-drain guarantee is void on the plaintext path (PLAUSIBLE→CONFIRMED by design)

- `cmd/turnstile/main.go:126-129` (plaintext path wraps the mux in `h2c.NewHandler`)
- `cmd/turnstile/main.go:167-173` (`srv.Shutdown` then `auditWriter.Wait()`)

When TLS is not configured, the hot path runs over h2c, which serves HTTP/2 on a
**hijacked** connection. Go's `http.Server.Shutdown` does not track hijacked
connections — it can return while h2c streams are still executing. The comment
at `main.go:170-172` asserts "all handlers have finished and no new audit writes
will be queued," which is **false for h2c**. A `ReportAudit` (or `Check`) handler
still running after `Shutdown` returns can call `auditWriter.Write` *after*
`auditWriter.Wait()` has already returned, and the deferred `db.Close()` (`main.go:48`)
can then run mid-write, dropping/erroring those writes — exactly the loss the
drain was meant to prevent. Under TLS (HTTP/2 via ALPN, non-hijacked) the drain
works as intended.

Fix: track h2c connections for shutdown (e.g. drive `http2.Server` via a
`ConfigureServer`/connection-state hook, or gate new requests behind an
"accepting" flag and wait for in-flight handlers before `Wait()`), or at minimum
stop accepting new streams and give `Wait()` a bounded window before `Close`.

### M2. Unbounded goroutine-per-entry audit writer + uncapped ReportAudit stream (CONFIRMED)

- `internal/audit/writer.go:32-40` (`Write` spawns one goroutine per entry)
- `internal/server/server.go:207-214` (`ReportAudit` loops `stream.Receive()` with no bound, calling `Write` per entry)

Every audit entry spawns its own goroutine doing an independent 5s-timeout DB
insert. A single client can stream arbitrarily many entries in one `ReportAudit`
call; each spawns a goroutine and a concurrent SQLite write. Because SQLite
serializes writers (with `busy_timeout=5s`), a burst produces a thundering herd
that can exhaust the 5s timeout and silently drop entries (logged only), consume
unbounded memory/goroutines, and — because commit order is nondeterministic
across goroutines — scramble `id` order relative to arrival/timestamp (undercuts
the "newest first" contract of `QueryAudit`). This is a DoS/robustness surface on
a host-facing RPC.

Fix: replace the goroutine-per-entry model with a bounded worker (single
consumer or small pool) draining a buffered channel; apply backpressure or a
max-entries bound on `ReportAudit`; drain the channel in `Wait()`.

### M3. Admin credential persisted in `localStorage` (CONFIRMED)

- `internal/management/ui/src/api.ts:17,27-35`

The long-lived admin bearer credential is written to `localStorage`
(`turnstile_admin_token`) and mirrored in a module global. `localStorage` is
readable by any script in the origin, so any XSS (including a compromised
dependency in the embedded SPA) exfiltrates a full-privilege, non-expiring admin
credential. React's default escaping mitigates injection, but "admin token in
`localStorage`" is the classic token-theft amplifier for an admin console.

Fix: prefer an in-memory-only token (lost on reload, re-prompt) or a short-lived
server-issued session cookie with `HttpOnly`+`Secure`+`SameSite`. If persistence
is required, document the accepted risk explicitly.

### M4. `touchLastUsed` debounce is per-request-snapshot, so it degenerates under concurrency (CONFIRMED, low impact)

- `internal/token/authenticator.go:80-92` (and `touchAdminLastUsed` 94-106)

The debounce checks the `LastUsedAt` on the just-loaded key snapshot. On the
`Check` hot path, many concurrent requests for the same key in the first minute
(or before the first write lands) each observe a stale/nil `LastUsedAt` and each
launch a background write goroutine. Result: a goroutine + `UPDATE` storm against
`api_keys` for a hot key, competing with audit writes for the single SQLite
writer. Functionally harmless (best-effort field) but a real contention source on
the hot path.

Fix: keep an in-memory per-key "last touched" map guarded by a mutex/`sync.Map`
so the debounce is process-global, not per-request.

---

## Low

### L1. A `Check` with no resources is always denied, even under an allow-all statement (CONFIRMED, design)

- `internal/policy/policy.go:91-101`

`Statement.matches` returns `false` when `resources` is empty (the resource loop
never runs). So `Check(action, resources=[])` is an unconditional implicit deny
even when the key holds `{allow, actions:[*], resources:[*]}`. If any host action
is naturally resource-less, it can never be authorized. This may be intentional
("every action names a resource"), but it is an easy footgun and is undocumented
at the API boundary.

Fix: document that `resources` is required, or treat empty-resources as matching
a resource pattern of `*` only when the statement's resources contain `*`.

### L2. Rate-limiter limiter maps grow unbounded (PLAUSIBLE)

- `internal/ratelimit/manager.go:16-19,88-95,99-114`

`keyLim[keyID][action]` and `svcLim[action]` entries are created on demand and
only ever removed by `ForgetKey` (key delete). A long-lived shared instance with
many keys × many distinct action strings accumulates limiters indefinitely
(memory growth). No eviction/TTL for idle limiters.

Fix: periodically evict limiters that are at full capacity (idle) — the standard
`x/time/rate` cache pattern.

### L3. `UpdatePolicy` cache/limiter refresh is non-atomic (CONFIRMED, benign)

- `internal/server/management.go:234-235`

`policyCache.Set(gp)` and `rateLimiter.SetGlobal(limits)` take separate locks, so
a concurrent `Check` between them can evaluate against the new policy but old
limits (or vice versa). Only a momentary inconsistency, not a correctness
violation, but worth a note.

### L4. Audit "newest first" is by `id`, not timestamp (CONFIRMED)

- `internal/store/audit.go:119-124`

Ordering/pagination is by `id DESC`. Because entries are inserted by concurrent
background goroutines (M2), `id` order does not necessarily match `timestamp`
order within a burst, so "newest first" is approximate. Keyset pagination itself
remains stable.

### L5. `GlobalStatements()` copies on every authorize call (CONFIRMED, perf)

- `internal/token/policycache.go:33-42`, `internal/token/authorizer.go:29-32`

Each `Authorize`/`GrantsAction` allocates a copy of the global statements plus a
merged slice. On the hot path this is avoidable allocation; the cache could hand
back an immutable shared slice (never mutated in place) instead of copying.

### L6. Timing side-channel: known-token vs unknown-token work differs (CONFIRMED, practically irrelevant)

- `internal/token/authenticator.go:44-56`

For a known key the code does an extra row fetch + JSON unmarshal of statements/
rate-limits that an unknown-hash lookup skips, a measurable timing difference in
principle. Because tokens are 256-bit random and looked up by hash, this is not
practically exploitable for enumeration; noted only for completeness (the spec's
"no timing concern" claim is about the compare, not the post-lookup work).

---

## Nit

- **N1.** `ratelimit.Limit.unlimited()` treats `PerMinute < 0` as unlimited
  (`config.go:35`) but `validate()` rejects negatives (`config.go:120-121`). Only
  `0` is a reachable "unlimited" — harmless but inconsistent.
- **N2.** `UpdateKeyRequest.rate_limits` uses a bare `RateLimitConfig` (message
  presence) while `statements` uses a `StatementList` wrapper; sending `{}` for
  rate_limits replaces with an empty config (falls back to global defaults),
  which is a subtle "absent vs empty" contract worth documenting
  (`proto` + `internal/server/management.go:153-160`).
- **N3.** `ExtractBearer` accepts `strings.TrimSpace` of the remainder, so
  `"Bearer  spaced"` yields `"spaced"`; fine, but tokens are never expected to
  contain surrounding whitespace — matches the test, just noting the leniency.

---

## Notable test-coverage gaps

The existing suite is good on happy paths and the headline invariants (deny-wins,
global ceiling at the authorizer level, rate-limit no-burn-on-deny, version
conflict, plaintext-once, CRUD, pagination). Gaps that would catch real
regressions:

1. **Generic auth failure at the RPC layer (security invariant).** Only "bad
   token → UNAUTHENTICATED" is asserted (`server_test.go:118-124`). There is no
   test that a **disabled** or **expired** key also returns exactly
   `UNAUTHENTICATED` with no distinguishing signal via `Check`/`Authenticate`.
   The whole point of the requirement (indistinguishability) is untested at the
   boundary.
2. **`Check` must not write audit.** No test asserts the audit table stays empty
   after `Check` calls.
3. **Service-credential gating.** `requireService` (`server.go:95-104`) has no
   test — neither the reject path (wrong/missing credential when configured) nor
   the open path.
4. **Audit time-range filters.** No test exercises `After`/`Before` — a test with
   sub-second timestamps would have caught H1.
5. **Global deny ceiling through the real `Check` path.** Only unit-tested at
   `Authorizer` (`token_test.go:108`); no end-to-end test that a key allow +
   global deny yields `POLICY_DENIED` over the wire.
6. **No `-race` / concurrency tests** for the shared `ratelimit.Manager`, the
   audit `Writer` drain, or `UpdateAPIKeyFunc` under racing writers — precisely
   the components the spec flags as concurrency-sensitive.
7. **LIKE-escaping** (`escapeLike`) is untested; a `path_prefix`/`action_prefix`
   containing `%` or `_` should match literally.
8. **`UpdateKey` semantics**: mutual exclusion of `expires_at`+`clear_expiry`,
   and partial-update "leave unchanged" behavior, are untested at the RPC layer.
9. **TLS/mTLS config** (`buildTLSConfig`) is untested.

---

## Things done well (brief, factual)

- Hash-only credential storage with lookup by hash; no plaintext persisted;
  `plaintext_token` set only by `CreateKey` and never by `keyToPB`.
- Constant-time service-credential comparison via `crypto/subtle`
  (`server.go:100`).
- Reserve-then-confirm rate limiting with correct cross-limiter refund, and a
  focused regression test proving a block on one limiter does not burn the other
  (`ratelimit_test.go:57-88`).
- Deny-wins / first-allow / default-deny engine and deny-only global validation,
  with clear docs and good unit coverage; namespace isolation tested.
- Parameterized SQL throughout; correct single-pass `LIKE` metacharacter escaping
  with an explicit `ESCAPE '\'` clause.
- Read-modify-write key updates in a single `BEGIN IMMEDIATE` transaction, with a
  clear rationale for `_txlock=immediate` and per-connection DSN pragmas.
- Generic-failure collapse implemented consistently in the handlers
  (`isAuthnFailure` + generic messages) and admin auth.
- UI correctly models proto3-JSON int64-as-string (`version`, `cursor`,
  `nextCursor`, `latencyMs`) and camelCase/enum-string shapes; Connect error
  `{code,message}` + HTTP-401 handling is consistent with the backend.
</content>
</invoke>
