# Turnstile — Code Review Fix Plan

**Status:** Passes 1 and 2 complete (2026-08-20).
- **Pass 1:** H1 (epoch-nanos timestamps), M2 (bounded audit writer + ReportAudit
  cap), test gaps 1–8.
- **Pass 2:** M1 (h2c-safe shutdown gate: reject-new + cancel + bounded drain),
  M4 (process-global touch debounce), L2 (idle-limiter eviction), L7
  (`auto_vacuum=INCREMENTAL` + post-prune `incremental_vacuum`), TLS-config test.
- **Document-only applied:** M3 (admin-token storage note), L1 (resource-less
  Check), N1, N2 — see below and the noted source comments/docs.

`go vet`, `gofmt`, and `go test -race ./...` all pass; `mage build:all` succeeds;
the binary bootstraps, serves, and shuts down cleanly (verified `auto_vacuum=2`
and no shutdown hang). **Remaining:** L3, L5 (benign/perf, deferred); L6, N3
(won't fix).

This document turns the findings in [`code-review.md`](code-review.md) into a
concrete remediation plan. For each item: what's wrong, the proposed fix at a
high level, rough effort/risk, and a recommendation (**Fix now** / **Defer** /
**Won't fix**). Nothing here has been implemented yet.

**Recommended first pass (correctness + robustness + locking in invariants):**
H1, M2, and the top test gaps. **Second pass (hardening):** M1, M4, L2.
**Document-only:** M3, L1, N2. **Won't fix:** L6.

Legend: Effort S/M/L ≈ under an hour / a few hours / larger.

---

## High

### H1 — Audit timestamp range filters & retention compare RFC3339Nano strings lexically

**Issue.** Timestamps are stored as `TEXT` via `time.RFC3339Nano`
(`internal/store/util.go` `formatTime`). `RFC3339Nano` drops trailing-zero
fractional digits (and the dot for a whole second), so `"…00Z"` sorts lexically
*after* `"…00.5Z"` even though it is chronologically *before*. SQLite compares
TEXT with binary collation, so the `timestamp >= ?` / `<= ?` predicates in
`QueryAudit` (`internal/store/audit.go`) and `timestamp < ?` in
`DeleteAuditEntriesBefore` are wrong by up to ~1s at sub-second boundaries.
Verified empirically: for `a=12:00:00.000`, `b=12:00:00.500`, `sa >= sb` is
`true`. `ORDER BY id` hides the effect on page ordering, but the range filters
and retention are silently incorrect.

**Proposed fix (decided: epoch-nanos INTEGER).** Store the audit timestamp as
**epoch nanoseconds in an `INTEGER` column** rather than TEXT. Integer
comparison is unambiguous (no lexical hazard at all), so the `after`/`before`
filters and retention `<` become correct by construction. It is also ~3× smaller
than TEXT on both the column and the `idx_audit_timestamp` index, and comparisons
in the index are faster. As a greenfield service there is no migration to
reason about.

Chosen over the fixed-width-TEXT alternative (`2006-01-02T15:04:05.000000000Z`)
because that would *increase* row size versus today and INTEGER is strictly
better on ordering, size, and index cost. The only tradeoff is that raw
timestamps aren't human-readable via the `sqlite3` CLI — `QueryAudit` still
returns proper RFC3339 timestamps over the wire, so operators never see the
integers.

**Scope.** `audit_log.timestamp` column type in `schema.sql`; the audit
insert/scan and filter-bound formatting in `internal/store/audit.go` (convert
`time.Time` ↔ `UnixNano` there rather than via the shared `formatTime`, which
stays RFC3339 for the other tables' human-readable columns). Add a regression
test with sub-second timestamps straddling a whole-second bound. **Effort S.
Risk low.** **Fix now.**

---

## Medium

### M1 — Graceful shutdown doesn't drain in-flight h2c requests

**Issue.** On the plaintext path the mux is wrapped in `h2c.NewHandler`
(`cmd/turnstile/main.go`), which serves HTTP/2 on a **hijacked** connection —
one the `net/http` server no longer tracks. `http.Server.Shutdown` only waits on
tracked connections, so it can return while `Check`/`ReportAudit` streams are
still running. The subsequent `auditWriter.Wait()` → deferred `db.Close()` can
then race a still-executing handler's `auditWriter.Write`, dropping the very
last-moment entries the drain exists to protect. TLS/mTLS deployments are
unaffected (ALPN-negotiated HTTP/2 connections are tracked).

**Proposed fix (high level).** Introduce an explicit request-quiescence gate
rather than relying on `Shutdown` to see hijacked conns — with **active
cancellation and a bounded wait, never an unbounded `wg.Wait()`**:

1. A single Connect interceptor (wrapping unary *and* streaming handlers) that,
   per RPC: rejects new calls with `Unavailable` once an atomic "accepting" flag
   is false; otherwise derives the handler's context from a **root context we
   own**, increments a `sync.WaitGroup` on entry, and decrements on return.
2. On shutdown: flip "accepting" to false → **cancel the root context** (so a
   long-lived handler blocked in `ReportAudit`'s `stream.Receive()` returns with
   a context error and unwinds promptly, without waiting on the client) → call
   `srv.Shutdown` (drains tracked conns) → wait on the request WaitGroup **raced
   against the shutdown deadline** (a goroutine does `wg.Wait()` and closes a
   `done` chan; `select` on `done` vs a timer) → then `auditWriter.Wait()` (also
   bounded) → `db.Close()`.

**Why the bounded wait matters (raised in review):** `ReportAudit` is
client-streaming, so a client that holds the stream open — or a hostile client
that refuses to close — would keep a handler running and make a bare `wg.Wait()`
block shutdown *forever*. Cancellation makes the common case exit immediately;
the deadline is the hard backstop so shutdown can never hang even if something is
stuck mid-`db` call. If the window elapses we proceed anyway and at worst drop a
few last-moment best-effort audit writes — the semantics we already accept today.

This makes the drain guarantee hold on both transports and makes the ordering
comment in `main.go` true. **Effort M. Risk medium** (touches the serving path;
needs a shutdown-race test — including a "stuck stream" case — ideally under
`-race`). **Defer to a second pass** unless plaintext is the primary deployment.

### M2 — Unbounded goroutine-per-entry audit writer + uncapped ReportAudit stream

**Issue.** `audit.Writer.Write` spawns one goroutine per entry
(`internal/audit/writer.go`), and `ReportAudit` loops `stream.Receive()` with no
length bound (`internal/server/server.go`). A single client can stream unbounded
entries; each spawns a goroutine racing for SQLite's single writer, which can
exhaust the 5s `busy_timeout` (silently dropping entries), balloon
memory/goroutines, and scramble `id` insert order (undercutting `QueryAudit`
"newest first").

**Proposed fix (high level).** Replace the goroutine-per-entry model with a
**bounded background writer**:

1. `Writer` owns a buffered channel and a single consumer goroutine (or a tiny
   fixed pool) that serializes inserts — matching SQLite's single-writer reality
   and giving deterministic `id` order.
2. `Write` enqueues (non-blocking with a bounded buffer; if full, either apply
   backpressure or drop-with-metric — I'll make the policy explicit and logged).
3. `Wait()` closes the channel and waits for the consumer to drain — same
   shutdown contract as today, but bounded.
4. Cap `ReportAudit` at a max entries-per-call (and/or enforce backpressure), so
   one call can't be unbounded; return a clear error past the cap.

**Scope.** `internal/audit/writer.go`, `internal/server/server.go` (stream cap),
minor `main.go` (start the consumer). **Effort M. Risk low–medium.** **Fix
now** — it's a host-facing robustness/DoS surface and also fixes L4's `id`
ordering.

### M3 — Admin credential persisted in `localStorage`

**Issue.** The long-lived, full-privilege admin token is stored in
`localStorage` (`internal/management/ui/src/api.ts`), readable by any script in
the origin — so any XSS (or a compromised SPA dependency) exfiltrates a
non-expiring admin credential.

**Proposed fix.** Two options, in preference order:

- **In-memory-only token:** keep it in a module variable / React state, re-prompt
  on reload. Zero backend change; removes the persistent exfiltration target at
  the cost of re-pasting the token after a refresh.
- **Server-issued short-lived session** (`HttpOnly`+`Secure`+`SameSite` cookie):
  proper fix, but needs a new session endpoint and is out of proportion for an
  operator console right now.

**Recommendation.** **Document the accepted risk now** (it's an operator-only,
localhost-by-default console), and note the in-memory option as the low-cost
hardening if we want it. I'll add a short security note to the UI README /
ARCHITECTURE rather than change behavior, unless you want the in-memory switch.
**Effort S (doc) / S–M (in-memory).**

### M4 — `touchLastUsed` debounce is per-request-snapshot

**Issue.** The last-used debounce checks `LastUsedAt` on the just-loaded key
snapshot (`internal/token/authenticator.go`). Under concurrent `Check` for a hot
key in the first minute, each request sees a stale/nil timestamp and launches its
own background `UPDATE` goroutine — a write storm competing with audit writes for
the single SQLite writer. Functionally harmless (best-effort field).

**Proposed fix.** Keep a process-global "last touched" map (`sync.Map` or a
mutex-guarded `map[string]time.Time`) on the `Authenticator`, so the debounce is
global rather than per-request; only the first observer within the window spawns
a write. Optionally fold these writes into the same bounded writer from M2.
**Effort S. Risk low.** **Defer to second pass** (bundles naturally with M2).

---

## Low

### L1 — `Check` with no resources is always denied
**Issue.** `Statement.matches` returns false when `resources` is empty
(`internal/policy/policy.go`), so a resource-less `Check` is an unconditional
deny even under allow-all. **Fix:** this is intended ("every action names a
resource"), so **document it** at the `CheckRequest` API boundary (proto comment
+ client-integration guide) rather than change matching semantics. **Effort S.
Document-only.**

### L2 — Rate-limiter maps grow unbounded
**Issue.** `keyLim`/`svcLim` entries are created on demand and only removed on
key delete (`internal/ratelimit/manager.go`); a long-lived instance accumulates
idle limiters. **Fix:** periodic eviction of limiters that are at full capacity
(the standard `x/time/rate` idle-cache sweep), guarded by the existing mutex.
**Effort S–M. Defer** (only matters at large key×action cardinality over long
uptime).

### L3 — `UpdatePolicy` cache/limiter refresh is non-atomic
**Issue.** `policyCache.Set` and `rateLimiter.SetGlobal`
(`internal/server/management.go`) take separate locks, so a concurrent `Check`
can briefly see new policy + old limits. Momentary, self-healing. **Fix:**
accept as-is with a comment, or combine both behind one policy-epoch holder if we
ever need atomicity. **Effort S. Defer / won't fix** (benign).

### L4 — Audit "newest first" is by `id`, not timestamp
**Issue.** `ORDER BY id DESC` approximates newest-first only as well as insert
order tracks time (`internal/store/audit.go`). **Fix:** largely **resolved by
M2** (single-consumer writer restores monotonic `id` vs arrival). If strict
time-ordering is required, add a `(timestamp, id)` index and order by that. **No
separate work if M2 lands.**

### L5 — `GlobalStatements()` copies on every authorize call
**Issue.** Each `Authorize`/`GrantsAction` copies the global statements and
builds a merged slice (`internal/token/policycache.go`, `authorizer.go`) — hot-
path allocation. **Fix:** have the cache hand back an immutable shared slice
(treated as read-only, replaced wholesale on update, never mutated in place) and
avoid the intermediate copy. **Effort S. Defer** (perf-only; measure first).

### L7 — Audit retention deletes rows but never reclaims file space
**Issue.** `audit.RunRetention` bounds row *count* by deleting entries older than
`AUDIT_RETENTION_DAYS`, but a SQLite `DELETE` only frees pages for reuse — it
does not shrink the database file. After a spike, the file stays at its
high-water mark indefinitely (freed pages are reused by new rows, so it doesn't
grow without bound, but it also doesn't shrink). Surfaced during the H1
discussion; independent of the timestamp representation. **Fix:** enable
`PRAGMA auto_vacuum = INCREMENTAL` at schema-creation time (must be set before
tables exist, so effectively a fresh-DB pragma) and run `PRAGMA
incremental_vacuum` periodically from the retention loop after a prune; or run a
full `VACUUM` on a slow cadence. **Effort S–M. Defer** (bounded by retention;
only matters if a one-time spike must be reclaimed). Note: `auto_vacuum` can't be
turned on for an existing DB without a `VACUUM`, so decide before first release.

### L6 — Timing side-channel: known vs unknown token work differs
**Issue.** A known key does an extra row fetch + JSON unmarshal an unknown-hash
lookup skips (`internal/token/authenticator.go`). **Won't fix** — tokens are
256-bit random and looked up by hash, so this is not exploitable for enumeration;
the reviewer rates it practically irrelevant and I agree.

---

## Nits

- **N1** — `Limit.unlimited()` treats `PerMinute < 0` as unlimited but
  `validate()` rejects negatives, so only `0` is reachable. **Fix:** tidy the
  comment/condition so "unlimited" is unambiguously `<= 0` by validation, or
  document that only `0` reaches it. Document-only. 
- **N2** — `UpdateKeyRequest.rate_limits` uses bare message-presence while
  `statements` uses a `StatementList` wrapper; sending `{}` replaces with an
  empty config. **Fix:** document the "absent vs empty" contract in the proto
  comment. Document-only.
- **N3** — `ExtractBearer` trims inner whitespace leniently; harmless, matches
  the test. **No action.**

---

## Test-coverage gaps to close (bundled with the fixes above)

These are the highest-value additions; several would have caught real defects.

1. **Generic auth failure at the RPC boundary** — assert that **disabled** and
   **expired** keys return exactly `UNAUTHENTICATED` via `Check` and a generic
   `Unauthenticated` via `Authenticate`, indistinguishable from an unknown token.
   (Security invariant; currently only "unknown → UNAUTHENTICATED" is tested.)
2. **`Check` writes no audit** — assert the audit table stays empty after
   `Check` calls.
3. **Service-credential gating** — with `SERVICE_CREDENTIAL` set: reject wrong/
   missing on `Check`/`Authenticate`/`ReportAudit`; accept correct; and the open
   path when unset.
4. **Audit time-range filters (H1 regression)** — sub-second timestamps
   straddling a whole-second bound; would have caught H1.
5. **Global deny ceiling over the wire** — end-to-end `Check` where a key allow +
   global deny yields `POLICY_DENIED`.
6. **`-race`/concurrency** — `ratelimit.Manager` under concurrent `Allow`, the
   audit `Writer` drain, and `UpdateAPIKeyFunc` under racing writers (run the
   suite with `-race`).
7. **`escapeLike`** — `path_prefix`/`action_prefix` containing `%` or `_` match
   literally.
8. **`UpdateKey` semantics** — `expires_at`+`clear_expiry` mutual exclusion and
   partial-update "leave unchanged" at the RPC layer.
9. **`buildTLSConfig`** — cert/key pairing and mTLS client-CA loading.

Items 1–5 and 7–8 are plain additions to the existing `server_test.go` /
`store_test.go`; item 6 is a `-race` run plus a couple of targeted concurrent
tests.

---

## Suggested sequencing

1. **Pass 1 (correctness + lock-in):** H1 (+ its regression test), M2 (+ stream
   cap), test gaps 1–5, 7–8. Run `go test -race ./...`.
2. **Pass 2 (hardening):** M1, M4, L2; test gap 6 with dedicated concurrent
   tests; TLS test (gap 9).
3. **Docs:** L1, M3 note, N1, N2.
