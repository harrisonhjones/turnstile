-- All timestamp columns are stored as epoch NANOSECONDS (INTEGER), not text:
-- integer comparison orders chronologically and every table shares one
-- representation (an RFC3339 TEXT column compares lexically, which diverges from
-- chronological order once trailing-zero fractions are trimmed). Times are
-- surfaced as RFC3339 on the wire, so operators never see the raw integers.

-- API keys (client tokens presented on the Check hot path). The token itself is
-- never stored; only its SHA-256 hash. statements holds the key's policy as a
-- JSON array of policy.Statement; rate_limits is a JSON action→Limit map of the
-- key's per-action overrides. note is a free-form human label.
CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    key_hash        TEXT NOT NULL UNIQUE,
    statements      TEXT NOT NULL DEFAULT '[]',
    rate_limits     TEXT NOT NULL DEFAULT '{}',
    note            TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER,
    expires_at      INTEGER,
    disabled        INTEGER NOT NULL DEFAULT 0
);
-- No explicit index on key_hash: the UNIQUE constraint already creates one, and
-- lookups are by key_hash, so a second index would only add write cost.

-- There is no separate admin-credentials table: the management API is guarded by
-- the same api_keys and policy engine as everything else. A key manages
-- Turnstile when its statements allow the relevant "turnstile:<op>" action. First
-- start against an empty api_keys table seeds a full-admin bootstrap key and logs
-- its token once; the -bootstrap flag / TURNSTILE_BOOTSTRAP env mints a fresh one
-- for break-glass recovery.

-- Global service policy. Single row enforced via the fixed id = 1. statements is
-- a deny-only ceiling; constraints is a JSON document holding rate limits.
CREATE TABLE IF NOT EXISTS global_policy (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    version     INTEGER NOT NULL,
    statements  TEXT NOT NULL DEFAULT '[]',
    constraints TEXT NOT NULL DEFAULT '{}',
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT
);

-- Audit log. One row per decision, recorded by Turnstile itself: `Check` writes
-- one per hot-path decision, and the management RPCs self-audit mutations and
-- denied attempts. api_key_id is the acting key (empty for an unauthenticated
-- Check); action + resource are what was evaluated; decision is the outcome
-- (ALLOWED / POLICY_DENIED / RATE_LIMITED / UNAUTHENTICATED). The timestamp
-- column matters most here: it is filtered on time ranges and pruned by
-- retention, so the INTEGER-nanos representation (see the note above) keeps those
-- correct at sub-second boundaries.
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  INTEGER NOT NULL,
    api_key_id TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL DEFAULT '',
    resource   TEXT NOT NULL DEFAULT '',
    decision   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_log (api_key_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp);
