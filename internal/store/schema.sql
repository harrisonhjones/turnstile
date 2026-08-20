-- API keys (client tokens presented on the Check hot path). The token itself is
-- never stored; only its SHA-256 hash. statements holds the key's policy as a
-- JSON array of policy.Statement; rate_limits is a JSON ratelimit.Config of the
-- key's own overrides. owner_namespace is a management-convenience tag only —
-- authorization keys off the namespaced action, never this field.
CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    key_hash        TEXT NOT NULL UNIQUE,
    statements      TEXT NOT NULL DEFAULT '[]',
    rate_limits     TEXT NOT NULL DEFAULT '{}',
    note            TEXT NOT NULL DEFAULT '',
    owner_namespace TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    last_used_at    TEXT,
    expires_at      TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0
);
-- No explicit index on key_hash: the UNIQUE constraint already creates one, and
-- lookups are by key_hash, so a second index would only add write cost.

-- Admin credentials guard the management RPCs. Like API keys, only the SHA-256
-- hash of the credential is stored. First start against an empty DB seeds a
-- bootstrap credential and logs it once; deleting every row re-seeds on the
-- next start (the intentional lockout-recovery path — there is no guard against
-- deleting the last one).
CREATE TABLE IF NOT EXISTS admin_credentials (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    cred_hash    TEXT NOT NULL UNIQUE,
    note         TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);
-- As with api_keys.key_hash, the UNIQUE(cred_hash) constraint already provides
-- the lookup index; no separate index is needed.

-- Global service policy. Single row enforced via the fixed id = 1. statements is
-- a deny-only ceiling; constraints is a JSON document holding rate limits.
CREATE TABLE IF NOT EXISTS global_policy (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    version     INTEGER NOT NULL,
    statements  TEXT NOT NULL DEFAULT '[]',
    constraints TEXT NOT NULL DEFAULT '{}',
    updated_at  TEXT NOT NULL,
    updated_by  TEXT
);

-- Audit log. One row per authenticated request, reported by hosts after a
-- request completes. api_key_name is denormalized so entries remain meaningful
-- after a key is renamed or deleted. request_summary holds selected
-- non-sensitive parameters (never message text).
--
-- timestamp is stored as epoch NANOSECONDS (INTEGER), not text: integer
-- comparison is unambiguous, so time-range filters and retention are correct at
-- sub-second boundaries (an RFC3339 TEXT column compares lexically, which
-- diverges from chronological order once trailing-zero fractions are trimmed).
-- It is also smaller on the column and its index. QueryAudit returns RFC3339
-- over the wire, so operators never see the raw integers.
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       INTEGER NOT NULL,
    api_key_id      TEXT NOT NULL,
    api_key_name    TEXT NOT NULL,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    action          TEXT NOT NULL DEFAULT '',
    resource        TEXT NOT NULL DEFAULT '',
    request_summary TEXT NOT NULL DEFAULT '',
    response_status INTEGER NOT NULL,
    latency_ms      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_log (api_key_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp);
