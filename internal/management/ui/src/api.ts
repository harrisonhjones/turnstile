// Thin client over the turnstile.v1 Connect service using the Connect HTTP/JSON
// protocol: every unary RPC is a POST to /turnstile.v1.Turnstile/<Method> with a
// JSON body (proto3 JSON) and an Authorization: Bearer <token> header. No
// generated client or RPC library — just fetch. The management key is held in
// memory and mirrored to localStorage, so the UI is a plain API client.
import type {
  CreateKeyRequest,
  Key,
  ListKeysResponse,
  Policy,
  QueryAuditRequest,
  QueryAuditResponse,
  UpdateKeyRequest,
  UpdatePolicyRequest,
} from "./types";

const TOKEN_KEY = "turnstile_management_key";

export const Auth = {
  token: null as string | null,

  load(): string | null {
    this.token = localStorage.getItem(TOKEN_KEY);
    return this.token;
  },

  set(token: string) {
    this.token = token;
    localStorage.setItem(TOKEN_KEY, token);
  },

  clear() {
    this.token = null;
    localStorage.removeItem(TOKEN_KEY);
  },
};

// The Connect service path prefix. Kept absolute so the dev-server proxy and the
// embedded (/ui/) deployment both reach the backend at the same route.
const SERVICE = "/turnstile.v1.Turnstile";

// APIError carries the HTTP status and the Connect error code/message. Connect
// reports errors as a non-2xx response with a { code, message } JSON body.
export class APIError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message || code || `HTTP ${status}`);
    this.status = status;
    this.code = code;
  }
}

// connectRPC invokes one unary RPC and returns its response message. It always
// sends the management key as a bearer token; this UI only calls management RPCs,
// each of which authorizes the key against a turnstile: action.
export async function connectRPC<Req, Resp>(method: string, body: Req): Promise<Resp> {
  const resp = await fetch(SERVICE + "/" + method, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + (Auth.token || ""),
    },
    body: JSON.stringify(body ?? {}),
  });

  const text = await resp.text();
  const data = text ? safeParse(text) : {};
  if (!resp.ok) {
    const code = (data.code as string) || "";
    const message = (data.message as string) || `HTTP ${resp.status}`;
    throw new APIError(resp.status, code, message);
  }
  return data as Resp;
}

function safeParse(text: string): Record<string, unknown> {
  try {
    return JSON.parse(text);
  } catch {
    return { code: "bad_response", message: text };
  }
}

// ---- Typed RPC wrappers ----

export const API = {
  createKey: (req: CreateKeyRequest) => connectRPC<CreateKeyRequest, Key>("CreateKey", req),

  listKeys: (includeDisabled: boolean) =>
    connectRPC<{ includeDisabled: boolean }, ListKeysResponse>("ListKeys", { includeDisabled }),

  getKey: (id: string) => connectRPC<{ id: string }, Key>("GetKey", { id }),

  updateKey: (req: UpdateKeyRequest) => connectRPC<UpdateKeyRequest, Key>("UpdateKey", req),

  rotateKey: (id: string) => connectRPC<{ id: string }, Key>("RotateKey", { id }),

  deleteKey: (id: string) => connectRPC<{ id: string }, Record<string, never>>("DeleteKey", { id }),

  getPolicy: () => connectRPC<Record<string, never>, Policy>("GetPolicy", {}),

  updatePolicy: (req: UpdatePolicyRequest) =>
    connectRPC<UpdatePolicyRequest, Policy>("UpdatePolicy", req),

  queryAudit: (req: QueryAuditRequest) =>
    connectRPC<QueryAuditRequest, QueryAuditResponse>("QueryAudit", req),
};
