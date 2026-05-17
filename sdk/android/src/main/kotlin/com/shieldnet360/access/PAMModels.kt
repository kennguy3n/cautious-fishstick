// PAMModels.kt — Kotlin data model types for the PAM extension of
// the ShieldNet 360 Access SDK (Android).
//
// Mirrors `sdk/ios/Sources/ShieldNetAccess/PAMModels.swift` so the
// Swift and Kotlin sides stay byte-for-byte compatible on the JSON
// wire format. See `docs/pam/architecture.md` §6 and
// `docs/pam/proposal.md` for the source-of-truth contracts.
//
// REST endpoints exercised by `PAMSDKClient`:
//
//   POST   /pam/leases/:id/approve   — approve a pending lease
//                                       (number-matching code optional)
//   POST   /pam/leases/:id/revoke    — deny / revoke a lease, with a
//                                       free-text reason
//   POST   /pam/secrets/:id/reveal   — reveal a vaulted secret after
//                                       a passkey (FIDO2 / WebAuthn)
//                                       step-up assertion
//
// Push notification payload shape (FCM data dict):
//
//   {
//     "type": "pam.approval.requested",
//     "lease_id": "lse_01HXYZ...",
//     "workspace_id": "ws_...",
//     "requester_user_id": "usr_...",
//     "asset_name": "prod-db-1",
//     "protocol": "postgres",
//     "criticality": "crown_jewel",
//     "risk_score": "high",
//     "risk_factors": ["unusual_time", "first_time_asset"],
//     "matched_code": "47",
//     "decoy_codes": ["12", "98"],
//     "justification": "incident IR-2025-04",
//     "expires_at": "2025-06-01T12:00:00Z"
//   }
//
// There is NO on-device inference in this SDK. The same rule the
// access surface enforces applies here.

package com.shieldnet360.access

import java.time.Instant

/**
 * Wire protocol negotiated for the PAM session this approval prompt
 * is gating. Mirrors the `pam.session.protocol` enum captured by
 * `internal/services/pam/session_service.go` on the server side.
 */
enum class PAMSessionProtocol(val wireValue: String) {
    SSH("ssh"),
    KUBERNETES("kubernetes"),
    POSTGRES("postgres"),
    MYSQL("mysql"),
    MARIADB("mariadb");

    companion object {
        /**
         * Parse a server-issued wire value. Throws
         * `AccessSDKException.Decoding` for unknown values so
         * callers can reject malformed payloads early.
         */
        @JvmStatic
        fun fromWire(value: String): PAMSessionProtocol =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown protocol: $value")
    }
}

/**
 * Coarse criticality bucket for the asset being accessed. Mirrors
 * `models.PAMAssetCriticality*` constants in
 * `internal/models/pam_asset.go`. `CROWN_JEWEL` is the highest tier
 * and always demands an approver.
 */
enum class PAMAssetCriticality(val wireValue: String) {
    LOW("low"),
    MEDIUM("medium"),
    HIGH("high"),
    CROWN_JEWEL("crown_jewel");

    companion object {
        @JvmStatic
        fun fromWire(value: String): PAMAssetCriticality =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown criticality: $value")
    }
}

/**
 * Risk bucket returned by the `pam_session_risk_assessment` A2A
 * skill (`cmd/access-ai-agent/skills/pam_session_risk.py`). Same
 * three-bucket grading the access surface uses.
 */
enum class PAMRiskScore(val wireValue: String) {
    LOW("low"),
    MEDIUM("medium"),
    HIGH("high");

    companion object {
        @JvmStatic
        fun fromWire(value: String): PAMRiskScore =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown risk_score: $value")
    }
}

/**
 * Push notification type discriminator. The mobile SDK only handles
 * `pam.approval.requested` today.
 */
enum class PAMNotificationType(val wireValue: String) {
    APPROVAL_REQUESTED("pam.approval.requested");

    companion object {
        @JvmStatic
        fun fromWire(value: String): PAMNotificationType =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.InvalidInput("unsupported push type: $value")
    }
}

/**
 * Parsed PAM approval push payload. Produced by
 * `PAMSDKClient.parseApprovalNotification(data)`.
 *
 * The `matchedCode` is the digit string the requester is staring at
 * on their device; the approver must select the same value out of
 * the union of `matchedCode ∪ decoyCodes`. The selection is sent
 * back to the server in the approve call so a stolen device that
 * taps the prompt without seeing the requester's screen has only a
 * 1-in-(N+1) chance of guessing correctly.
 */
data class PAMApprovalNotification(
    val type: PAMNotificationType,
    val leaseId: String,
    val workspaceId: String,
    val requesterUserId: String,
    val assetName: String,
    val protocol: PAMSessionProtocol,
    val criticality: PAMAssetCriticality,
    val riskScore: PAMRiskScore,
    val riskFactors: List<String>,
    val matchedCode: String,
    val decoyCodes: List<String>,
    val justification: String?,
    val expiresAt: Instant?,
) {
    /**
     * Returns the union of `matchedCode` and `decoyCodes` in a
     * stable, sorted order. Useful for laying out the
     * "Confirm-the-number" prompt without leaking which entry is
     * the real one. Sorts numerically when the codes parse as
     * integers; falls back to lexicographic order otherwise so the
     * layout stays deterministic for tests.
     */
    fun allCodes(): List<String> {
        val codes = decoyCodes.toMutableList()
        codes.add(matchedCode)
        val allNumeric = codes.all { it.toIntOrNull() != null }
        return if (allNumeric) {
            codes.sortedBy { it.toInt() }
        } else {
            codes.sorted()
        }
    }
}

/**
 * Lifecycle state of a `PAMLease`. Mirrors the Go-side constants
 * in `internal/models/pam_lease.go`.
 */
enum class PAMLeaseState(val wireValue: String) {
    REQUESTED("requested"),
    GRANTED("granted"),
    DENIED("denied"),
    EXPIRED("expired"),
    REVOKED("revoked");

    companion object {
        @JvmStatic
        fun fromWire(value: String): PAMLeaseState =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown lease state: $value")
    }
}

/**
 * Persisted lease row returned by `POST /pam/leases/:id/approve`
 * and `POST /pam/leases/:id/revoke`.
 */
data class PAMLease(
    val id: String,
    val workspaceId: String,
    val userId: String,
    val assetId: String,
    val accountId: String,
    val reason: String?,
    val state: PAMLeaseState,
    val approvedBy: String?,
    val grantedAt: Instant?,
    val expiresAt: Instant?,
    val revokedAt: Instant?,
    val createdAt: Instant,
)

/**
 * FIDO2 / WebAuthn assertion produced by the host application's
 * Credential Manager flow. The SDK treats the assertion as opaque
 * — the server-side `MFAVerifier` interprets it.
 *
 * `clientDataJson`, `authenticatorData`, `signature`, and
 * `userHandle` are the four fields a WebAuthn assertion always
 * surfaces; `credentialId` is the public-key credential identifier
 * the relying party stored at registration time. All five are
 * base64url-encoded strings on the wire so the JSON envelope stays
 * transport-safe.
 */
data class PassKeyAssertion(
    val credentialId: String,
    val clientDataJson: String,
    val authenticatorData: String,
    val signature: String,
    val userHandle: String? = null,
)

/**
 * Response payload from `POST /pam/secrets/:id/reveal`. The
 * `plaintext` is one-shot — clients must zero / overwrite the
 * string buffer as soon as it has been used. The server emits a
 * `pam.secret.revealed` Kafka event before returning so even a
 * successful reveal is auditable.
 */
data class PAMSecretRevealResponse(
    val secretId: String,
    val plaintext: String,
)

/**
 * Result of `PAMSDKClient.verifyMatchedCode`. The SDK does the
 * constant-time comparison in-process so a Yes/No outcome can be
 * surfaced to the UI before any network call is made.
 */
enum class NumberMatchOutcome {
    /** Selected code matched — the approve flow may continue. */
    MATCHED,

    /**
     * Selected code did not match — the SDK rejects the approve
     * flow client-side without round-tripping to the server.
     */
    MISMATCHED,
}
