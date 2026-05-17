// OkHttpPAMSDKClient.kt — production OkHttp-backed PAM SDK
// implementation (Android).
//
// Each `suspend` method builds a real `okhttp3.Request`, executes
// it on the IO dispatcher, and parses the response body using the
// minimal hand-rolled JSON utilities in this file. Same approach
// as `OkHttpAccessSDKClient.kt` — the SDK is deliberately
// library-free so host applications already shipping OkHttp don't
// need to pull in a JSON library choice from the SDK.
//
// REST endpoint mapping follows `PAMSDKClient.kt` (per
// `docs/pam/architecture.md`).

package com.shieldnet360.access

import java.io.IOException
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

private val PAM_JSON_MEDIA = "application/json".toMediaType()

/**
 * Production HTTP implementation of [PAMSDKClient].
 *
 * Construct once per app launch. `baseUrl` is the `ztna-api` root
 * (with or without trailing slash). `authTokenProvider` is invoked
 * before every request so token refresh stays the caller's
 * responsibility.
 *
 * The class deliberately keeps a transport implementation parallel
 * to `OkHttpAccessSDKClient` rather than reaching into its private
 * members — the small duplication (≈ 40 lines) lets the PAM
 * extension ship without breaking host apps that already pin a
 * specific version of the access client.
 */
class OkHttpPAMSDKClient(
    private val baseUrl: String,
    private val client: OkHttpClient,
    private val authTokenProvider: suspend () -> String,
) : PAMSDKClient {
    // -------------------- Push parsing + number matching --------------------

    override fun parseApprovalNotification(data: Map<String, String>): PAMApprovalNotification {
        if (data.isEmpty()) {
            throw AccessSDKException.InvalidInput("empty push payload")
        }
        val typeRaw = data["type"]
            ?: throw AccessSDKException.InvalidInput("push payload missing 'type'")
        val type = PAMNotificationType.fromWire(typeRaw)

        val leaseId = requireNonEmpty(data, "lease_id")
        val workspaceId = requireNonEmpty(data, "workspace_id")
        val requesterUserId = requireNonEmpty(data, "requester_user_id")
        val assetName = requireNonEmpty(data, "asset_name")
        val protocol = PAMSessionProtocol.fromWire(requireNonEmpty(data, "protocol"))
        val criticality = PAMAssetCriticality.fromWire(requireNonEmpty(data, "criticality"))
        val riskScore = PAMRiskScore.fromWire(requireNonEmpty(data, "risk_score"))
        val matchedCode = requireNonEmpty(data, "matched_code")

        val riskFactors = parseStringArray(data["risk_factors"], "risk_factors")
        val decoyCodes = parseStringArray(data["decoy_codes"], "decoy_codes")
        val justification = data["justification"]?.takeIf { it.isNotEmpty() }
        val expiresAt = data["expires_at"]?.takeIf { it.isNotEmpty() }?.let {
            try {
                Instant.parse(it)
            } catch (e: Exception) {
                throw AccessSDKException.Decoding("expires_at: ${e.message}", e)
            }
        }

        return PAMApprovalNotification(
            type = type,
            leaseId = leaseId,
            workspaceId = workspaceId,
            requesterUserId = requesterUserId,
            assetName = assetName,
            protocol = protocol,
            criticality = criticality,
            riskScore = riskScore,
            riskFactors = riskFactors,
            matchedCode = matchedCode,
            decoyCodes = decoyCodes,
            justification = justification,
            expiresAt = expiresAt,
        )
    }

    override fun verifyMatchedCode(
        selected: String,
        notification: PAMApprovalNotification,
    ): NumberMatchOutcome {
        // Constant-time comparison of the UTF-8 bytes so a timing
        // side-channel cannot leak which decoy the user tapped.
        val lhs = selected.toByteArray(Charsets.UTF_8)
        val rhs = notification.matchedCode.toByteArray(Charsets.UTF_8)
        if (lhs.size != rhs.size) {
            return NumberMatchOutcome.MISMATCHED
        }
        var diff = 0
        for (i in lhs.indices) {
            diff = diff or (lhs[i].toInt() xor rhs[i].toInt())
        }
        return if (diff == 0) NumberMatchOutcome.MATCHED else NumberMatchOutcome.MISMATCHED
    }

    // ------------------------------ Approval ------------------------------

    override suspend fun approveLease(
        notification: PAMApprovalNotification,
        approverUserId: String,
        durationMinutes: Int?,
        selectedCode: String,
    ): PAMLease {
        if (approverUserId.isEmpty()) {
            throw AccessSDKException.InvalidInput("approver_user_id is required")
        }
        if (selectedCode.isEmpty()) {
            throw AccessSDKException.InvalidInput("selected_code is required")
        }
        if (verifyMatchedCode(selectedCode, notification) != NumberMatchOutcome.MATCHED) {
            throw AccessSDKException.InvalidInput("selected_code does not match")
        }
        val body = JSONObject().apply {
            put("workspace_id", notification.workspaceId)
            put("approver_id", approverUserId)
            if (durationMinutes != null) {
                put("duration_minutes", durationMinutes)
            }
            put("matched_code", selectedCode)
        }
        val raw = post("/pam/leases/${notification.leaseId}/approve", body.toString())
        return parseLease(raw)
    }

    override suspend fun denyLease(
        notification: PAMApprovalNotification,
        reason: String,
    ): PAMLease {
        val body = JSONObject().apply {
            put("workspace_id", notification.workspaceId)
            put("reason", reason)
        }
        val raw = post("/pam/leases/${notification.leaseId}/revoke", body.toString())
        return parseLease(raw)
    }

    // ----------------------------- Passkey reveal -----------------------------

    override suspend fun revealSecret(
        secretId: String,
        workspaceId: String,
        userId: String,
        assertion: PassKeyAssertion,
    ): PAMSecretRevealResponse {
        if (secretId.isEmpty()) {
            throw AccessSDKException.InvalidInput("secret_id is required")
        }
        if (workspaceId.isEmpty()) {
            throw AccessSDKException.InvalidInput("workspace_id is required")
        }
        if (userId.isEmpty()) {
            throw AccessSDKException.InvalidInput("user_id is required")
        }
        val assertionJson = JSONObject().apply {
            put("credential_id", assertion.credentialId)
            put("client_data_json", assertion.clientDataJson)
            put("authenticator_data", assertion.authenticatorData)
            put("signature", assertion.signature)
            if (assertion.userHandle != null) {
                put("user_handle", assertion.userHandle)
            }
        }.toString()
        val body = JSONObject().apply {
            put("workspace_id", workspaceId)
            put("user_id", userId)
            put("mfa_assertion", assertionJson)
        }
        val raw = post("/pam/secrets/$secretId/reveal", body.toString())
        return parseRevealResponse(raw, secretId)
    }

    // ------------------------------ Transport ------------------------------

    private suspend fun post(path: String, body: String): String {
        val req = Request.Builder()
            .url(baseUrl.trimEnd('/') + path)
            .header("Accept", "application/json")
            .header("Authorization", "Bearer ${fetchToken()}")
            .post(body.toRequestBody(PAM_JSON_MEDIA))
            .build()
        return execute(req)
    }

    private suspend fun fetchToken(): String {
        return try {
            authTokenProvider()
        } catch (e: Throwable) {
            throw AccessSDKException.Unauthenticated()
        }
    }

    private suspend fun execute(req: Request): String = withContext(Dispatchers.IO) {
        val response = try {
            client.newCall(req).execute()
        } catch (e: IOException) {
            throw AccessSDKException.Transport(e.message ?: "transport failure", e)
        }
        response.use { res ->
            val raw = res.body?.string() ?: ""
            if (res.code == 401) throw AccessSDKException.Unauthenticated()
            if (res.code !in 200..299) {
                throw AccessSDKException.Http(res.code, raw.ifBlank { null })
            }
            if (raw.isBlank()) {
                throw AccessSDKException.Decoding("empty response body for ${req.url}")
            }
            raw
        }
    }

    // ------------------------------ Parsing ------------------------------

    private fun parseLease(json: String): PAMLease {
        val obj = try {
            JSONObject(json)
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("PAMLease: ${e.message}", e)
        }
        return PAMLease(
            id = obj.getString("id"),
            workspaceId = obj.getString("workspace_id"),
            userId = obj.getString("user_id"),
            assetId = obj.getString("asset_id"),
            accountId = obj.getString("account_id"),
            reason = obj.optStringOrNullPAM("reason"),
            state = PAMLeaseState.fromWire(obj.getString("state")),
            approvedBy = obj.optStringOrNullPAM("approved_by"),
            grantedAt = obj.optStringOrNullPAM("granted_at")?.let(Instant::parse),
            expiresAt = obj.optStringOrNullPAM("expires_at")?.let(Instant::parse),
            revokedAt = obj.optStringOrNullPAM("revoked_at")?.let(Instant::parse),
            createdAt = Instant.parse(obj.getString("created_at")),
        )
    }

    private fun parseRevealResponse(json: String, fallbackSecretId: String): PAMSecretRevealResponse {
        val obj = try {
            JSONObject(json)
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("PAMSecretRevealResponse: ${e.message}", e)
        }
        // The server includes `secret_id` in the response — fall
        // back to the request-side id only if the field is missing
        // so a callers-side typo doesn't silently mask a wire bug.
        val secretId = obj.optStringOrNullPAM("secret_id") ?: fallbackSecretId
        val plaintext = obj.getString("plaintext")
        return PAMSecretRevealResponse(secretId = secretId, plaintext = plaintext)
    }

    private fun parseStringArray(raw: String?, fieldName: String): List<String> {
        if (raw.isNullOrEmpty()) return emptyList()
        // FCM data dicts always send values as strings; the server
        // serialises arrays as JSON before stamping them into the
        // push payload, so we decode them back here.
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("$fieldName: not a JSON array", e)
        }
    }

    private fun requireNonEmpty(data: Map<String, String>, key: String): String {
        val v = data[key]
        if (v.isNullOrEmpty()) {
            throw AccessSDKException.InvalidInput("$key is required")
        }
        return v
    }

    private fun JSONObject.optStringOrNullPAM(key: String): String? =
        if (!has(key) || isNull(key)) null else optString(key, "").takeIf { it.isNotEmpty() }
}
