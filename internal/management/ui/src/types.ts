// Wire types mirroring the turnstile.v1 protobuf messages in proto3 JSON form
// (camelCase field names, enums as strings). These are the shapes exchanged over
// the Connect HTTP/JSON protocol; see api.ts.

export type Effect = "EFFECT_ALLOW" | "EFFECT_DENY";

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

export interface Key {
  id: string;
  name: string;
  note?: string;
  statements?: Statement[];
  rateLimits?: RateLimitConfig;
  disabled?: boolean;
  ownerNamespace?: string;
  createdAt?: string; // RFC3339
  lastUsedAt?: string;
  expiresAt?: string;
  plaintextToken?: string; // only set on CreateKey
}

export interface CreateKeyRequest {
  name: string;
  note?: string;
  statements?: Statement[];
  rateLimits?: RateLimitConfig;
  disabled?: boolean;
  ownerNamespace?: string;
  expiresAt?: string;
}

export interface UpdateKeyRequest {
  id: string;
  name?: string;
  note?: string;
  disabled?: boolean;
  ownerNamespace?: string;
  statements?: { statements: Statement[] };
  rateLimits?: RateLimitConfig;
  expiresAt?: string;
  clearExpiry?: boolean;
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
  apiKeyName?: string;
  method?: string;
  path?: string;
  action?: string;
  resource?: string;
  requestSummary?: string;
  responseStatus?: number;
  latencyMs?: string; // int64
  timestamp?: string;
}

export interface QueryAuditRequest {
  apiKeyId?: string;
  method?: string;
  pathPrefix?: string;
  actionPrefix?: string;
  status?: number;
  after?: string;
  before?: string;
  limit?: number;
  cursor?: string; // int64
}

export interface QueryAuditResponse {
  entries?: AuditEntry[];
  nextCursor?: string; // int64; "0" or absent when exhausted
}
