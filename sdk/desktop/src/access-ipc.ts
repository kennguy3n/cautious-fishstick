/**
 * access-ipc.ts — Electron IPC contract for the ShieldNet 360 Access
 * Platform desktop extension.
 *
 * The desktop extension is consumed by a host Electron application. The
 * renderer process talks to the main process over IPC (`ipcRenderer.invoke`
 * / `ipcMain.handle`), and the main process makes HTTPS REST calls to
 * `ztna-api`. There is **no on-device inference** — no `onnxruntime`, no
 * native inference binaries, no bundled model files (`.mlmodel`,
 * `.tflite`, `.onnx`, `.gguf`). The "AI" surface (`askAI`) is a REST
 * passthrough to `/access/explain` and `/access/suggest`, which the
 * backend forwards to the `access-ai-agent` Python skill server via A2A.
 * This rule is enforced by `scripts/check_no_model_files.sh` in CI.
 *
 * REST endpoint mapping (per PROPOSAL.md §11.3 and §11.4):
 *   requestAccess.create     → POST   /access/requests
 *   requestAccess.list       → GET    /access/requests
 *   requestAccess.approve    → POST   /access/requests/:id/approve
 *   requestAccess.deny       → POST   /access/requests/:id/deny
 *   requestAccess.cancel     → POST   /access/requests/:id/cancel
 *   listGrants               → GET    /access/grants
 *   queryPolicy.explain      → POST   /access/explain
 *   askAI.suggestResources   → POST   /access/suggest
 *
 * Both the main process (which implements `AccessIPC`) and the renderer
 * process (which consumes it through a `contextBridge` preload) should
 * import the same type definitions from this module.
 */

// --- IPC channel names -----------------------------------------------------

/**
 * Stable IPC channel name constants. The renderer addresses these via
 * `ipcRenderer.invoke(channel, payload)`; the main process registers
 * handlers with `ipcMain.handle(channel, listener)`.
 */
export const AccessIPCChannel = {
  RequestAccessCreate: 'access:requestAccess.create',
  RequestAccessList: 'access:requestAccess.list',
  RequestAccessApprove: 'access:requestAccess.approve',
  RequestAccessDeny: 'access:requestAccess.deny',
  RequestAccessCancel: 'access:requestAccess.cancel',
  ListGrants: 'access:listGrants',
  QueryPolicyExplain: 'access:queryPolicy.explain',
  AskAISuggest: 'access:askAI.suggestResources',
} as const;

export type AccessIPCChannelName = (typeof AccessIPCChannel)[keyof typeof AccessIPCChannel];

// --- Domain types ----------------------------------------------------------

/**
 * Lifecycle state of an access request. Mirrors the Go-side
 * `access.RequestState` constants in
 * `internal/services/access/request_state_machine.go`.
 */
export type AccessRequestState =
  | 'requested'
  | 'approved'
  | 'denied'
  | 'cancelled'
  | 'provisioning'
  | 'provisioned'
  | 'provision_failed'
  | 'active'
  | 'revoked'
  | 'expired';

/**
 * Coarse risk bucket for an access request. Values mirror the Go-side
 * `models.RequestRiskLow` / `RequestRiskMedium` / `RequestRiskHigh`
 * constants in `internal/models/access_request.go`. The server stores
 * risk as a string bucket; finer-grained numeric scoring is a Phase 4
 * AI-agent concern.
 */
export type AccessRequestRiskScore = 'low' | 'medium' | 'high';

/** Persisted access request row (mirrors the `access_requests` table). */
export interface AccessRequest {
  readonly id: string;
  readonly workspaceId: string;
  readonly requesterUserId: string;
  readonly targetUserId?: string | null;
  /**
   * Identifier of the connector (upstream SaaS / IdP / cloud account) the
   * request targets. Non-null on the wire — `ConnectorID` is declared
   * `not null` in `internal/models/access_request.go`.
   */
  readonly connectorId: string;
  readonly resourceExternalId: string;
  readonly role?: string | null;
  readonly justification?: string | null;
  readonly state: AccessRequestState;
  readonly riskScore?: AccessRequestRiskScore | null;
  readonly riskFactors?: readonly string[] | null;
  readonly workflowId?: string | null;
  /** ISO-8601 timestamp (RFC 3339). */
  readonly createdAt: string;
  readonly updatedAt?: string | null;
}

/** Active upstream grant (mirrors `access_grants`). */
export interface AccessGrant {
  readonly id: string;
  readonly workspaceId: string;
  readonly userId: string;
  readonly connectorId: string;
  readonly resourceExternalId: string;
  readonly role?: string | null;
  readonly grantedAt: string;
  readonly expiresAt?: string | null;
  readonly lastUsedAt?: string | null;
  readonly revokedAt?: string | null;
}

/** Plain-English explanation produced server-side. */
export interface PolicyExplanation {
  readonly policyId: string;
  readonly summary: string;
  readonly rationale: readonly string[];
  readonly affectedResources: readonly string[];
}

/** Recommended resource for the calling user. */
export interface Suggestion {
  readonly id: string;
  readonly resourceExternalId: string;
  readonly displayName: string;
  readonly reason: string;
  readonly confidence?: number | null;
}

// --- Request / response payloads ------------------------------------------

/** Request payload for `POST /access/requests`. */
export interface AccessRequestPayload {
  readonly resourceExternalId: string;
  readonly role?: string | null;
  readonly justification?: string | null;
  /** Optional target user (admin-on-behalf-of). */
  readonly targetUserId?: string | null;
}

/** Successful response from `POST /access/requests`. */
export interface AccessRequestResponse {
  readonly request: AccessRequest;
}

/** Filter for `GET /access/requests`. */
export interface AccessRequestListFilter {
  readonly state?: AccessRequestState;
  readonly requesterUserId?: string;
  readonly resourceExternalId?: string;
}

/** Response from `GET /access/requests`. */
export interface AccessRequestListResponse {
  readonly requests: readonly AccessRequest[];
  /** Server-supplied pagination cursor, when present. */
  readonly nextCursor?: string | null;
}

/** Body for `POST /access/requests/:id/deny`. */
export interface AccessRequestDenyPayload {
  readonly reason: string;
}

/** Filter for `GET /access/grants`. */
export interface AccessGrantListFilter {
  readonly userId?: string;
  readonly connectorId?: string;
}

/** Response from `GET /access/grants`. */
export interface GrantListResponse {
  readonly grants: readonly AccessGrant[];
  readonly nextCursor?: string | null;
}

/** Request for `POST /access/explain`. */
export interface PolicyQueryPayload {
  readonly policyId: string;
}

/** Response from `POST /access/explain`. */
export interface PolicyQueryResponse {
  readonly explanation: PolicyExplanation;
}

/** Response from `POST /access/suggest`. */
export interface AIQueryResponse {
  readonly suggestions: readonly Suggestion[];
}

// --- IPC surface -----------------------------------------------------------

/**
 * Main-process IPC surface. Implementations live in the host Electron
 * application and forward calls to `ztna-api` over HTTPS. Renderer-side
 * code never imports the implementation directly — it goes through the
 * `contextBridge`-exposed `AccessIPC` proxy.
 *
 * All methods return promises; transport / decode / status-code failures
 * are surfaced as rejected promises with `AccessIPCError` instances.
 */
export interface AccessIPC {
  /** `POST /access/requests` — create a new access request. */
  readonly requestAccess: AccessRequestIPC;

  /** `GET /access/grants` — list active grants visible to the caller. */
  listGrants(filter?: AccessGrantListFilter): Promise<GrantListResponse>;

  /**
   * `POST /access/explain` — plain-English explanation of a policy.
   * REST passthrough; no on-device inference.
   */
  queryPolicy(payload: PolicyQueryPayload): Promise<PolicyQueryResponse>;

  /**
   * `POST /access/suggest` — recommended resources for the calling user.
   * REST passthrough; no on-device inference.
   */
  askAI(): Promise<AIQueryResponse>;
}

/** Nested namespace for the `/access/requests` family of endpoints. */
export interface AccessRequestIPC {
  create(payload: AccessRequestPayload): Promise<AccessRequestResponse>;
  list(filter?: AccessRequestListFilter): Promise<AccessRequestListResponse>;
  approve(id: string): Promise<AccessRequestResponse>;
  deny(id: string, payload: AccessRequestDenyPayload): Promise<AccessRequestResponse>;
  cancel(id: string): Promise<AccessRequestResponse>;
}

// --- Error type ------------------------------------------------------------

/** Discriminated kinds for `AccessIPCError`. */
export type AccessIPCErrorKind =
  | 'transport'
  | 'http'
  | 'decoding'
  | 'invalid_input'
  | 'unauthenticated'
  | 'not_configured';

/**
 * Typed error thrown across the IPC boundary. The main process should
 * serialize a plain object with these fields; the renderer rehydrates it
 * via the preload script.
 */
export class AccessIPCError extends Error {
  readonly kind: AccessIPCErrorKind;
  readonly statusCode?: number;
  readonly body?: string;

  constructor(
    kind: AccessIPCErrorKind,
    message: string,
    options: { statusCode?: number; body?: string; cause?: unknown } = {},
  ) {
    // Forward `cause` to `Error`'s ES2022 constructor so `error.cause`
    // is set by the built-in (no manual assignment needed). When the
    // caller did not supply a cause we pass `undefined` to avoid
    // creating an enumerable `cause: undefined` own-property on the
    // error instance.
    super(
      message,
      options.cause !== undefined ? { cause: options.cause } : undefined,
    );
    this.name = 'AccessIPCError';
    this.kind = kind;
    if (options.statusCode !== undefined) {
      this.statusCode = options.statusCode;
    }
    if (options.body !== undefined) {
      this.body = options.body;
    }
  }
}
