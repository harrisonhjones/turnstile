// Wire types mirroring the turnstile.v1 protobuf messages in proto3 JSON form
// (camelCase field names, enums as strings). These are the shapes exchanged over
// the Connect HTTP/JSON protocol; see api.ts.

export type Effect = "ALLOW" | "DENY";

export type Decision = "ALLOWED" | "UNAUTHENTICATED" | "POLICY_DENIED" | "RATE_LIMITED";

export interface Statement {
  effect: Effect;
  actions: string[];
  resources: string[];
  note?: string;
}

export interface Limit {
  perMinute?: number;
  burst?: number;
}

export interface RateLimitConfig {
  default?: Limit;
  perAction?: Record<string, Limit>;
}

export interface RateLimits {
  perKey?: RateLimitConfig;
  serviceWide?: RateLimitConfig;
}

// PerActionLimits is a key's own rate-limit overrides: a plain action→Limit map.
// (Unlike the global policy's RateLimitConfig, a key has no blanket default.)
export type PerActionLimits = Record<string, Limit>;

export interface Key {
  id: string;
  name: string;
  note?: string;
  statements?: Statement[];
  rateLimits?: PerActionLimits;
  disabled?: boolean;
  createdAt?: string; // RFC3339
  lastUsedAt?: string;
  expiresAt?: string;
  plaintextToken?: string; // only set on CreateKey
}

export interface CreateKeyRequest {
  name: string;
  note?: string;
  statements?: Statement[];
  rateLimits?: PerActionLimits;
  disabled?: boolean;
  expiresAt?: string;
}

export interface UpdateKeyRequest {
  id: string;
  name?: string;
  note?: string;
  disabled?: boolean;
  statements?: { statements: Statement[] };
  rateLimits?: PerActionLimits;
  expiresAt?: string;
  clearExpiry?: boolean;
  clearRateLimits?: boolean;
}

export interface ListKeysResponse {
  keys?: Key[];
}

export interface Policy {
  statements?: Statement[];
  rateLimits?: RateLimits;
  version?: string; // int64 is serialized as a string in proto3 JSON
  updatedAt?: string;
  updatedBy?: string;
}

export interface UpdatePolicyRequest {
  statements?: Statement[];
  rateLimits?: RateLimits;
  expectedVersion?: string;
}

export interface AuditEntry {
  apiKeyId?: string;
  action?: string;
  resource?: string;
  decision?: Decision;
  timestamp?: string;
}

export interface QueryAuditRequest {
  apiKeyId?: string;
  actionPrefix?: string;
  decision?: Decision;
  after?: string;
  before?: string;
  limit?: number;
  cursor?: string; // int64
}

export interface QueryAuditResponse {
  entries?: AuditEntry[];
  nextCursor?: string; // int64; "0" or absent when exhausted
}
