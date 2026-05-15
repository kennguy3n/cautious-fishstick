/*
 * AccessSDKClient.kt — Android Access SDK contract.
 *
 * REST-only client for the ShieldNet 360 Access Platform `ztna-api`. This
 * package defines the `AccessSDKClient` interface plus the request /
 * response data classes that mirror the JSON payloads documented in
 * `docs/architecture.md` §11.4.
 *
 * REST endpoint mapping (per docs/architecture.md):
 *   createRequest      → POST   /access/requests
 *   listRequests       → GET    /access/requests
 *   approveRequest     → POST   /access/requests/:id/approve
 *   denyRequest        → POST   /access/requests/:id/deny
 *   cancelRequest      → POST   /access/requests/:id/cancel
 *   listGrants         → GET    /access/grants
 *   explainPolicy      → POST   /access/explain
 *   suggestResources   → POST   /access/suggest
 *
 * There is **no on-device inference** in this SDK. There are no
 * `org.tensorflow.lite` imports, no `ai.onnxruntime` imports, no bundled
 * model files (`.mlmodel`, `.tflite`, `.onnx`, `.gguf`). The "AI" methods
 * (`explainPolicy`, `suggestResources`) are REST calls to `/access/explain`
 * and `/access/suggest`, which the backend forwards to the
 * `access-ai-agent` Python skill server via A2A. This rule is enforced by
 * `scripts/check_no_model_files.sh` in CI. See `docs/architecture.md` §11.2 and
 * `docs/sdk.md`.
 */
package com.shieldnet360.access

import java.time.Instant

/**
 * Lifecycle state of an `AccessRequest`. Values mirror the Go-side
 * `access.RequestState` constants in
 * `internal/services/access/request_state_machine.go`.
 *
 * Each constant carries the lowercase wire string the server emits (e.g.
 * `"requested"`, `"provision_failed"`). The [fromWire] factory parses
 * server JSON without depending on any external serialization library —
 * the SDK is deliberately library-free so host apps can pick their own
 * (Moshi / kotlinx.serialization / Gson) and adapt via [value].
 */
enum class AccessRequestState(val value: String) {
    REQUESTED("requested"),
    APPROVED("approved"),
    DENIED("denied"),
    CANCELLED("cancelled"),
    PROVISIONING("provisioning"),
    PROVISIONED("provisioned"),
    PROVISION_FAILED("provision_failed"),
    ACTIVE("active"),
    REVOKED("revoked"),
    EXPIRED("expired");

    companion object {
        /**
         * Parse a server-supplied wire string (e.g. from `state` in the
         * `AccessRequest` JSON payload) into an [AccessRequestState].
         * Throws [IllegalArgumentException] if the value is not one of
         * the ten recognised states.
         */
        @JvmStatic
        fun fromWire(value: String): AccessRequestState =
            entries.firstOrNull { it.value == value }
                ?: throw IllegalArgumentException(
                    "unknown AccessRequestState wire value: $value",
                )
    }
}

/**
 * Coarse risk bucket for an [AccessRequest]. Values mirror the Go-side
 * `models.RequestRiskLow` / `RequestRiskMedium` / `RequestRiskHigh`
 * constants in `internal/models/access_request.go`. The server stores
 * risk as a string bucket; finer-grained numeric scoring is a Phase 4
 * AI-agent concern.
 *
 * Each constant carries the lowercase wire string the server emits
 * (`"low"` / `"medium"` / `"high"`); use [fromWire] to parse JSON.
 */
enum class AccessRequestRiskScore(val value: String) {
    LOW("low"),
    MEDIUM("medium"),
    HIGH("high");

    companion object {
        /**
         * Parse a server-supplied wire string into an
         * [AccessRequestRiskScore]. Throws [IllegalArgumentException]
         * if the value is not one of the three recognised buckets.
         */
        @JvmStatic
        fun fromWire(value: String): AccessRequestRiskScore =
            entries.firstOrNull { it.value == value }
                ?: throw IllegalArgumentException(
                    "unknown AccessRequestRiskScore wire value: $value",
                )
    }
}

/**
 * Persisted access request row. Mirrors the `access_requests` table
 * (`docs/architecture.md` §10). Returned by `POST /access/requests` and
 * `GET /access/requests`.
 */
data class AccessRequest(
    val id: String,
    val workspaceId: String,
    val requesterUserId: String,
    val targetUserId: String? = null,
    val connectorId: String,
    val resourceExternalId: String,
    val role: String? = null,
    val justification: String? = null,
    val state: AccessRequestState,
    val riskScore: AccessRequestRiskScore? = null,
    val riskFactors: List<String>? = null,
    val workflowId: String? = null,
    val createdAt: Instant,
    val updatedAt: Instant? = null,
)

/**
 * Active upstream grant. Mirrors `access_grants`. Returned by
 * `GET /access/grants`.
 */
data class AccessGrant(
    val id: String,
    val workspaceId: String,
    val userId: String,
    val connectorId: String,
    val resourceExternalId: String,
    val role: String? = null,
    val grantedAt: Instant,
    val expiresAt: Instant? = null,
    val lastUsedAt: Instant? = null,
    val revokedAt: Instant? = null,
)

/**
 * Plain-English explanation of a policy, produced server-side by the
 * `policy_recommendation` agent. Returned by `POST /access/explain`.
 */
data class PolicyExplanation(
    val policyId: String,
    val summary: String,
    val rationale: List<String> = emptyList(),
    val affectedResources: List<String> = emptyList(),
)

/**
 * Recommended resource for the calling user. Returned (as a list) by
 * `POST /access/suggest`.
 */
data class Suggestion(
    val id: String,
    val resourceExternalId: String,
    val displayName: String,
    val reason: String,
    val confidence: Double? = null,
)

/** Filter for [AccessSDKClient.listRequests]. */
data class AccessRequestListFilter(
    val state: AccessRequestState? = null,
    val requesterUserId: String? = null,
    val resourceExternalId: String? = null,
)

/** Filter for [AccessSDKClient.listGrants]. */
data class AccessGrantListFilter(
    val userId: String? = null,
    val connectorId: String? = null,
)

/**
 * Typed error surface for SDK consumers. Concrete clients should throw
 * subclasses of this sealed type so host applications can branch on them
 * in a type-safe way.
 */
sealed class AccessSDKException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** Network / transport failure (timeouts, DNS, TLS). */
    class Transport(message: String, cause: Throwable? = null) : AccessSDKException(message, cause)

    /**
     * Non-2xx HTTP response from `ztna-api`. [body] is the raw response
     * body if the server provided one (typically the canonical
     * `{"error": {...}}` envelope produced by `internal/handlers/errors.go`).
     */
    class Http(val statusCode: Int, val body: String?) :
        AccessSDKException("HTTP $statusCode${body?.let { ": $it" } ?: ""}")

    /** Response body could not be decoded into the expected data class. */
    class Decoding(message: String, cause: Throwable? = null) : AccessSDKException(message, cause)

    /** Caller-side invariant violation (e.g. empty `resource` string). */
    class InvalidInput(message: String) : AccessSDKException(message)

    /** The caller is not authenticated. */
    class Unauthenticated : AccessSDKException("unauthenticated")

    /** The host application has not yet been configured (base URL, token). */
    class NotConfigured : AccessSDKException("SDK not configured")
}

/**
 * Async REST surface for the ShieldNet 360 Access Platform.
 *
 * Methods are declared `suspend` so concrete implementations (e.g. an
 * `OkHttpAccessSDKClient`) can do their I/O on coroutine dispatchers
 * supplied by the host application. Errors are surfaced as
 * [AccessSDKException].
 */
interface AccessSDKClient {
    /**
     * Create a new access request.
     *
     * `POST /access/requests` — body `{ resource_external_id, role,
     * justification }`. Returns the persisted [AccessRequest] row.
     */
    suspend fun createRequest(
        resource: String,
        role: String? = null,
        justification: String? = null,
    ): AccessRequest

    /**
     * List access requests, optionally filtered.
     *
     * `GET /access/requests?state=…&requester=…&resource=…` — empty filter
     * returns the caller's own requests.
     */
    suspend fun listRequests(
        state: AccessRequestState? = null,
        requester: String? = null,
        resource: String? = null,
    ): List<AccessRequest>

    /**
     * Approve a pending request (subject to workflow rules).
     *
     * `POST /access/requests/:id/approve`.
     */
    suspend fun approveRequest(id: String): AccessRequest

    /**
     * Deny a pending request.
     *
     * `POST /access/requests/:id/deny` — body `{ reason }`.
     */
    suspend fun denyRequest(id: String, reason: String): AccessRequest

    /**
     * Requester cancels their own pending request.
     *
     * `POST /access/requests/:id/cancel`.
     */
    suspend fun cancelRequest(id: String): AccessRequest

    /**
     * List active upstream grants.
     *
     * `GET /access/grants?user_id=…&connector_id=…` — `userId` is honored
     * only for admins; non-admin callers always see their own grants.
     */
    suspend fun listGrants(
        userId: String? = null,
        connectorId: String? = null,
    ): List<AccessGrant>

    /**
     * Plain-English explanation of a policy.
     *
     * `POST /access/explain` — body `{ policy_id }`. The backend forwards
     * the request to the `policy_recommendation` A2A skill on
     * `access-ai-agent`. **REST only** — no on-device inference.
     */
    suspend fun explainPolicy(policyId: String): PolicyExplanation

    /**
     * Recommended resources for the calling user.
     *
     * `POST /access/suggest` — empty body. The backend computes
     * suggestions server-side (via `policy_recommendation` A2A skill).
     * **REST only** — no on-device inference.
     */
    suspend fun suggestResources(): List<Suggestion>
}
