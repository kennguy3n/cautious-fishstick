//
// AccessSDKProtocol.swift — iOS Access SDK contract.
//
// This file defines the `AccessSDKClient` protocol that every concrete
// implementation in a host iOS application must satisfy. The SDK is a
// **thin REST client** — every method maps 1:1 to an HTTP endpoint on
// `ztna-api` (see `docs/architecture.md` §10).
//
// There is **no on-device inference** in this SDK. There are no
// `import CoreML` / `import MLX` statements and no bundled model files
// (`.mlmodel`, `.tflite`, `.onnx`, `.gguf`). The "AI" methods (`explainPolicy`,
// `suggestResources`) are REST calls to `/access/explain` and
// `/access/suggest`, which the backend forwards to the `access-ai-agent`
// Python skill server via A2A. This rule is enforced by
// `scripts/check_no_model_files.sh` in CI.
//
// REST endpoint mapping (per docs/architecture.md):
//   createRequest      → POST   /access/requests
//   listRequests       → GET    /access/requests
//   approveRequest     → POST   /access/requests/:id/approve
//   denyRequest        → POST   /access/requests/:id/deny
//   cancelRequest      → POST   /access/requests/:id/cancel
//   listGrants         → GET    /access/grants
//   explainPolicy      → POST   /access/explain
//   suggestResources   → POST   /access/suggest
//

import Foundation

/// Async REST surface for the ShieldNet 360 Access Platform.
///
/// Concrete implementations are expected to bind to `URLSession` (or a
/// drop-in replacement) and serialize / deserialize the `Models.swift` types.
/// Errors should be surfaced as Swift `throws` — typed `AccessSDKError`
/// values are recommended for transport / decode / status-code failures.
public protocol AccessSDKClient: Sendable {
    /// Create a new access request.
    ///
    /// `POST /access/requests` — body `{ resource_external_id, role,
    /// justification }`. Returns the persisted `AccessRequest` row,
    /// including server-assigned `id` and initial `state`.
    func createRequest(
        resource: String,
        role: String?,
        justification: String?
    ) async throws -> AccessRequest

    /// List access requests, optionally filtered.
    ///
    /// `GET /access/requests?state=…&requester=…&resource=…` — empty filter
    /// returns the caller's own requests.
    func listRequests(
        state: AccessRequestState?,
        requester: String?,
        resource: String?
    ) async throws -> [AccessRequest]

    /// Approve a pending request (subject to workflow rules).
    ///
    /// `POST /access/requests/:id/approve` — returns the updated row, which
    /// will typically transition into `provisioning` or `approved`.
    func approveRequest(id: String) async throws -> AccessRequest

    /// Deny a pending request with an operator-supplied reason.
    ///
    /// `POST /access/requests/:id/deny` — body `{ reason }`.
    func denyRequest(id: String, reason: String) async throws -> AccessRequest

    /// Requester cancels their own pending request.
    ///
    /// `POST /access/requests/:id/cancel` — only the original requester may
    /// call this; the server returns 403 otherwise.
    func cancelRequest(id: String) async throws -> AccessRequest

    /// List the caller's active upstream grants.
    ///
    /// `GET /access/grants?user_id=…&connector_id=…` — `userID` is honored
    /// only for admins; non-admin callers always see their own grants.
    func listGrants(
        userID: String?,
        connectorID: String?
    ) async throws -> [AccessGrant]

    /// Plain-English explanation of a policy.
    ///
    /// `POST /access/explain` — body `{ policy_id }`. The backend forwards
    /// the request to the `policy_recommendation` A2A skill on
    /// `access-ai-agent`. **REST only** — no on-device inference.
    func explainPolicy(policyID: String) async throws -> PolicyExplanation

    /// Recommended resources for the calling user.
    ///
    /// `POST /access/suggest` — empty body. The backend computes
    /// suggestions server-side (via `policy_recommendation` A2A skill).
    /// **REST only** — no on-device inference.
    func suggestResources() async throws -> [Suggestion]
}

/// Typed error surface for SDK consumers. Concrete clients are encouraged to
/// throw these values so host applications can branch on them in a
/// type-safe way.
public enum AccessSDKError: Error, Sendable, Equatable {
    /// Network / transport failure (timeouts, DNS, TLS).
    case transport(String)

    /// Non-2xx HTTP response from `ztna-api`. `body` is the raw response
    /// body if the server provided one (typically the canonical
    /// `{"error": {...}}` envelope produced by `internal/handlers/errors.go`).
    case http(statusCode: Int, body: String?)

    /// Response body could not be decoded into the expected model type.
    case decoding(String)

    /// Caller-side invariant violation (e.g. empty `resource` string).
    case invalidInput(String)

    /// The caller is not authenticated. Implementations should refresh
    /// credentials and retry once.
    case unauthenticated

    /// The host application has not yet been configured (base URL, token).
    case notConfigured
}
