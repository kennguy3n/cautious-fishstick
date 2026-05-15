/*
 * OkHttpAccessSDKClient.kt — production OkHttp-backed Access SDK
 * implementation.
 *
 * Each `suspend` method builds a real `okhttp3.Request`, executes
 * it on the IO dispatcher, and parses the response body using the
 * minimal hand-rolled JSON utilities in this file. The SDK is
 * deliberately library-free — host applications already ship
 * OkHttp, and we don't want to force a kotlinx.serialization /
 * Moshi / Gson choice on consumers.
 *
 * REST endpoint mapping follows AccessSDKClient.kt (per
 * docs/overview.md §11.4).
 */
package com.shieldnet360.access

import java.io.IOException
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

private val JSON_MEDIA = "application/json".toMediaType()

/**
 * Production HTTP implementation of [AccessSDKClient].
 *
 * Construct once per app launch. `baseUrl` is the `ztna-api` root
 * (with or without trailing slash). `authTokenProvider` is invoked
 * before every request so token refresh stays the caller's
 * responsibility.
 */
class OkHttpAccessSDKClient(
    private val baseUrl: String,
    private val client: OkHttpClient,
    private val authTokenProvider: suspend () -> String,
) : AccessSDKClient {
    override suspend fun createRequest(
        resource: String,
        role: String?,
        justification: String?,
    ): AccessRequest {
        val body = JSONObject().apply {
            put("resource_external_id", resource)
            if (role != null) put("role", role)
            if (justification != null) put("justification", justification)
        }
        val json = post("/access/requests", body.toString())
        return parseAccessRequest(json)
    }

    override suspend fun listRequests(
        state: AccessRequestState?,
        requester: String?,
        resource: String?,
    ): List<AccessRequest> {
        val params = buildMap<String, String> {
            if (state != null) put("state", state.value)
            if (requester != null) put("requester", requester)
            if (resource != null) put("resource", resource)
        }
        val json = get("/access/requests", params)
        return parseAccessRequestArray(json)
    }

    override suspend fun approveRequest(id: String): AccessRequest {
        val json = post("/access/requests/$id/approve", "{}")
        return parseAccessRequest(json)
    }

    override suspend fun denyRequest(id: String, reason: String): AccessRequest {
        val body = JSONObject().put("reason", reason)
        val json = post("/access/requests/$id/deny", body.toString())
        return parseAccessRequest(json)
    }

    override suspend fun cancelRequest(id: String): AccessRequest {
        val json = post("/access/requests/$id/cancel", "{}")
        return parseAccessRequest(json)
    }

    override suspend fun listGrants(
        userId: String?,
        connectorId: String?,
    ): List<AccessGrant> {
        val params = buildMap<String, String> {
            if (userId != null) put("user_id", userId)
            if (connectorId != null) put("connector_id", connectorId)
        }
        val json = get("/access/grants", params)
        return parseAccessGrantArray(json)
    }

    override suspend fun explainPolicy(policyId: String): PolicyExplanation {
        val body = JSONObject().put("policy_id", policyId)
        val json = post("/access/explain", body.toString())
        return parsePolicyExplanation(json)
    }

    override suspend fun suggestResources(): List<Suggestion> {
        val json = post("/access/suggest", "{}", allowEmpty = true)
        return parseSuggestionArray(json)
    }

    // ----------------------------- Transport -----------------------------

    private suspend fun get(path: String, query: Map<String, String>): String {
        val url = (baseUrl.trimEnd('/') + path).toHttpUrlOrNull()
            ?: throw AccessSDKException.InvalidInput("invalid URL for path $path")
        val builder = url.newBuilder()
        for ((k, v) in query) builder.addQueryParameter(k, v)
        val req = Request.Builder()
            .url(builder.build())
            .header("Accept", "application/json")
            .header("Authorization", "Bearer ${fetchToken()}")
            .get()
            .build()
        return execute(req, allowEmpty = false)
    }

    private suspend fun post(
        path: String,
        body: String,
        allowEmpty: Boolean = false,
    ): String {
        val req = Request.Builder()
            .url(baseUrl.trimEnd('/') + path)
            .header("Accept", "application/json")
            .header("Authorization", "Bearer ${fetchToken()}")
            .post(body.toRequestBody(JSON_MEDIA))
            .build()
        return execute(req, allowEmpty)
    }

    private suspend fun fetchToken(): String {
        return try {
            authTokenProvider()
        } catch (e: Throwable) {
            throw AccessSDKException.Unauthenticated()
        }
    }

    private suspend fun execute(req: Request, allowEmpty: Boolean): String =
        withContext(Dispatchers.IO) {
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
                if (raw.isBlank() && !allowEmpty) {
                    throw AccessSDKException.Decoding("empty response body for ${req.url}")
                }
                raw
            }
        }

    // ----------------------------- Parsing -----------------------------

    private fun parseAccessRequest(json: String): AccessRequest {
        val obj = try {
            JSONObject(json)
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("AccessRequest: ${e.message}", e)
        }
        return obj.toAccessRequest()
    }

    private fun parseAccessRequestArray(json: String): List<AccessRequest> {
        val arr = try {
            if (json.isBlank()) JSONArray() else JSONArray(json)
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("AccessRequest[]: ${e.message}", e)
        }
        return (0 until arr.length()).map { arr.getJSONObject(it).toAccessRequest() }
    }

    private fun parseAccessGrantArray(json: String): List<AccessGrant> {
        val arr = try {
            if (json.isBlank()) JSONArray() else JSONArray(json)
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("AccessGrant[]: ${e.message}", e)
        }
        return (0 until arr.length()).map { arr.getJSONObject(it).toAccessGrant() }
    }

    private fun parsePolicyExplanation(json: String): PolicyExplanation {
        val obj = try {
            JSONObject(json)
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("PolicyExplanation: ${e.message}", e)
        }
        val rationale = obj.optJSONArray("rationale")?.let { arr ->
            (0 until arr.length()).map { arr.getString(it) }
        } ?: emptyList()
        val affected = obj.optJSONArray("affected_resources")?.let { arr ->
            (0 until arr.length()).map { arr.getString(it) }
        } ?: emptyList()
        return PolicyExplanation(
            policyId = obj.getString("policy_id"),
            summary = obj.optString("summary"),
            rationale = rationale,
            affectedResources = affected,
        )
    }

    private fun parseSuggestionArray(json: String): List<Suggestion> {
        if (json.isBlank()) return emptyList()
        val arr = try {
            JSONArray(json)
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("Suggestion[]: ${e.message}", e)
        }
        return (0 until arr.length()).map {
            val o = arr.getJSONObject(it)
            Suggestion(
                id = o.getString("id"),
                resourceExternalId = o.getString("resource_external_id"),
                displayName = o.optString("display_name"),
                reason = o.optString("reason"),
                confidence = if (o.has("confidence") && !o.isNull("confidence")) o.getDouble("confidence") else null,
            )
        }
    }

    private fun JSONObject.toAccessRequest(): AccessRequest {
        val riskFactors = optJSONArray("risk_factors")?.let { arr ->
            (0 until arr.length()).map { arr.getString(it) }
        }
        return AccessRequest(
            id = getString("id"),
            workspaceId = getString("workspace_id"),
            requesterUserId = getString("requester_user_id"),
            targetUserId = optStringOrNull("target_user_id"),
            connectorId = getString("connector_id"),
            resourceExternalId = getString("resource_external_id"),
            role = optStringOrNull("role"),
            justification = optStringOrNull("justification"),
            state = AccessRequestState.fromWire(getString("state")),
            riskScore = optStringOrNull("risk_score")?.let(AccessRequestRiskScore::fromWire),
            riskFactors = riskFactors,
            workflowId = optStringOrNull("workflow_id"),
            createdAt = Instant.parse(getString("created_at")),
            updatedAt = optStringOrNull("updated_at")?.let(Instant::parse),
        )
    }

    private fun JSONObject.toAccessGrant(): AccessGrant = AccessGrant(
        id = getString("id"),
        workspaceId = getString("workspace_id"),
        userId = getString("user_id"),
        connectorId = getString("connector_id"),
        resourceExternalId = getString("resource_external_id"),
        role = optStringOrNull("role"),
        grantedAt = Instant.parse(getString("granted_at")),
        expiresAt = optStringOrNull("expires_at")?.let(Instant::parse),
        lastUsedAt = optStringOrNull("last_used_at")?.let(Instant::parse),
        revokedAt = optStringOrNull("revoked_at")?.let(Instant::parse),
    )

    private fun JSONObject.optStringOrNull(key: String): String? =
        if (!has(key) || isNull(key)) null else optString(key, "").takeIf { it.isNotEmpty() }
}
