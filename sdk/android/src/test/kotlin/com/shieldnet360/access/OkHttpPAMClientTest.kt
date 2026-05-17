/*
 * OkHttpPAMClientTest.kt — real OkHttp tests for the PAM client
 * using MockWebServer.
 *
 * MockWebServer is a real HTTP server that OkHttp connects to over
 * TCP; it is NOT a mock of OkHttp itself. The SDK code path
 * (Request.Builder, RequestBody, client.newCall.execute, JSON
 * parsing) is fully real.
 *
 * Coverage parallels `URLSessionPAMClientTests.swift`:
 *   • approveLease → POST /pam/leases/:id/approve  (auth + body shape)
 *   • approveLease validates input client-side and short-circuits
 *     before hitting the wire on empty / mismatched code.
 *   • denyLease    → POST /pam/leases/:id/revoke
 *   • revealSecret → POST /pam/secrets/:id/reveal  (body carries
 *     workspace + user + nested mfa_assertion JSON)
 *   • 401 → AccessSDKException.Unauthenticated
 *   • 500 → AccessSDKException.Http(statusCode=500, …)
 *   • malformed JSON → AccessSDKException.Decoding
 */
package com.shieldnet360.access

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class OkHttpPAMClientTest {
    private lateinit var server: MockWebServer
    private lateinit var client: OkHttpPAMSDKClient

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
        client = OkHttpPAMSDKClient(
            baseUrl = server.url("/").toString().trimEnd('/'),
            client = OkHttpClient(),
            authTokenProvider = { "pam-token-xyz" },
        )
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    // ------------------------------- Helpers -------------------------------

    private fun notification(
        leaseId: String = "lse_01",
        matchedCode: String = "47",
    ): PAMApprovalNotification = PAMApprovalNotification(
        type = PAMNotificationType.APPROVAL_REQUESTED,
        leaseId = leaseId,
        workspaceId = "ws_1",
        requesterUserId = "usr_req",
        assetName = "prod-db-1",
        protocol = PAMSessionProtocol.POSTGRES,
        criticality = PAMAssetCriticality.CROWN_JEWEL,
        riskScore = PAMRiskScore.HIGH,
        riskFactors = listOf("unusual_time"),
        matchedCode = matchedCode,
        decoyCodes = listOf("12", "98"),
        justification = "incident IR-2025-04",
        expiresAt = null,
    )

    private val grantedLeaseJson = """
        {
            "id": "lse_01",
            "workspace_id": "ws_1",
            "user_id": "usr_req",
            "asset_id": "ast_1",
            "account_id": "acc_1",
            "reason": "incident IR-2025-04",
            "state": "granted",
            "approved_by": "usr_approver",
            "granted_at": "2025-06-01T11:00:00Z",
            "expires_at": "2025-06-01T13:00:00Z",
            "created_at": "2025-06-01T10:59:00Z"
        }
    """.trimIndent()

    private val revokedLeaseJson = """
        {
            "id": "lse_01",
            "workspace_id": "ws_1",
            "user_id": "usr_req",
            "asset_id": "ast_1",
            "account_id": "acc_1",
            "reason": "policy-violation",
            "state": "revoked",
            "revoked_at": "2025-06-01T11:00:00Z",
            "created_at": "2025-06-01T10:59:00Z"
        }
    """.trimIndent()

    // ------------------------------ approveLease ------------------------------

    @Test
    fun `approveLease posts auth header + matched_code body to approve endpoint`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(200).setBody(grantedLeaseJson))
        val lease = client.approveLease(
            notification = notification(),
            approverUserId = "usr_approver",
            durationMinutes = 120,
            selectedCode = "47",
        )
        assertEquals(PAMLeaseState.GRANTED, lease.state)
        assertEquals("usr_approver", lease.approvedBy)

        val recorded = server.takeRequest()
        assertEquals("/pam/leases/lse_01/approve", recorded.path)
        assertEquals("POST", recorded.method)
        assertEquals("Bearer pam-token-xyz", recorded.getHeader("Authorization"))
        assertTrue(
            recorded.getHeader("Content-Type")?.startsWith("application/json") == true,
            "missing JSON Content-Type",
        )
        val body = JSONObject(recorded.body.readUtf8())
        assertEquals("ws_1", body.getString("workspace_id"))
        assertEquals("usr_approver", body.getString("approver_id"))
        assertEquals(120, body.getInt("duration_minutes"))
        assertEquals("47", body.getString("matched_code"))
    }

    @Test
    fun `approveLease rejects empty approver without hitting the wire`() = runBlocking {
        // No enqueue — if we reach the wire, MockWebServer will hang
        // and the test eventually times out.
        assertFailsWith<AccessSDKException.InvalidInput> {
            client.approveLease(
                notification = notification(),
                approverUserId = "",
                durationMinutes = null,
                selectedCode = "47",
            )
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `approveLease rejects empty selectedCode without hitting the wire`() = runBlocking {
        assertFailsWith<AccessSDKException.InvalidInput> {
            client.approveLease(
                notification = notification(),
                approverUserId = "usr",
                durationMinutes = null,
                selectedCode = "",
            )
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `approveLease rejects mismatched selectedCode without hitting the wire`() = runBlocking {
        val err = assertFailsWith<AccessSDKException.InvalidInput> {
            client.approveLease(
                notification = notification(),
                approverUserId = "usr",
                durationMinutes = null,
                selectedCode = "12",
            )
        }
        assertTrue(err.message!!.contains("does not match"), err.message)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `approveLease omits duration_minutes when not provided`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(200).setBody(grantedLeaseJson))
        client.approveLease(
            notification = notification(),
            approverUserId = "usr_approver",
            durationMinutes = null,
            selectedCode = "47",
        )
        val recorded = server.takeRequest()
        val body = JSONObject(recorded.body.readUtf8())
        assertTrue(!body.has("duration_minutes"))
    }

    @Test
    fun `approveLease maps 401 to Unauthenticated`() {
        server.enqueue(MockResponse().setResponseCode(401))
        assertFailsWith<AccessSDKException.Unauthenticated> {
            runBlocking {
                client.approveLease(
                    notification = notification(),
                    approverUserId = "usr_approver",
                    durationMinutes = null,
                    selectedCode = "47",
                )
            }
        }
    }

    @Test
    fun `approveLease maps 500 to Http error with status code`() {
        server.enqueue(MockResponse().setResponseCode(500).setBody("internal"))
        val err = assertFailsWith<AccessSDKException.Http> {
            runBlocking {
                client.approveLease(
                    notification = notification(),
                    approverUserId = "usr_approver",
                    durationMinutes = null,
                    selectedCode = "47",
                )
            }
        }
        assertEquals(500, err.statusCode)
        assertTrue(err.message!!.contains("internal"))
    }

    @Test
    fun `approveLease maps malformed JSON to Decoding error`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("not-json"))
        assertFailsWith<AccessSDKException.Decoding> {
            runBlocking {
                client.approveLease(
                    notification = notification(),
                    approverUserId = "usr_approver",
                    durationMinutes = null,
                    selectedCode = "47",
                )
            }
        }
    }

    // ------------------------------- denyLease -------------------------------

    @Test
    fun `denyLease posts reason body to revoke endpoint`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(200).setBody(revokedLeaseJson))
        val lease = client.denyLease(notification(), "policy-violation")
        assertEquals(PAMLeaseState.REVOKED, lease.state)
        assertEquals("policy-violation", lease.reason)

        val recorded = server.takeRequest()
        assertEquals("/pam/leases/lse_01/revoke", recorded.path)
        assertEquals("POST", recorded.method)
        assertEquals("Bearer pam-token-xyz", recorded.getHeader("Authorization"))
        val body = JSONObject(recorded.body.readUtf8())
        assertEquals("ws_1", body.getString("workspace_id"))
        assertEquals("policy-violation", body.getString("reason"))
    }

    @Test
    fun `denyLease maps 401 to Unauthenticated`() {
        server.enqueue(MockResponse().setResponseCode(401))
        assertFailsWith<AccessSDKException.Unauthenticated> {
            runBlocking { client.denyLease(notification(), "reason") }
        }
    }

    // ------------------------------- revealSecret -------------------------------

    @Test
    fun `revealSecret posts workspace + user + assertion to reveal endpoint`() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("""{"secret_id":"sec_1","plaintext":"super-secret-value"}"""),
        )
        val assertion = PassKeyAssertion(
            credentialId = "cred_1",
            clientDataJson = "Y2RhdGE=",
            authenticatorData = "YXV0aGRhdGE=",
            signature = "c2lnbmF0dXJl",
            userHandle = "uh",
        )
        val response = client.revealSecret(
            secretId = "sec_1",
            workspaceId = "ws_1",
            userId = "usr_req",
            assertion = assertion,
        )
        assertEquals("sec_1", response.secretId)
        assertEquals("super-secret-value", response.plaintext)

        val recorded = server.takeRequest()
        assertEquals("/pam/secrets/sec_1/reveal", recorded.path)
        assertEquals("POST", recorded.method)
        assertEquals("Bearer pam-token-xyz", recorded.getHeader("Authorization"))

        val body = JSONObject(recorded.body.readUtf8())
        assertEquals("ws_1", body.getString("workspace_id"))
        assertEquals("usr_req", body.getString("user_id"))
        // mfa_assertion is a serialised JSON string carrying the
        // assertion fields — the server-side MFAVerifier unwraps
        // and verifies it. Decode it here and assert shape.
        val nested = JSONObject(body.getString("mfa_assertion"))
        assertEquals("cred_1", nested.getString("credential_id"))
        assertEquals("Y2RhdGE=", nested.getString("client_data_json"))
        assertEquals("YXV0aGRhdGE=", nested.getString("authenticator_data"))
        assertEquals("c2lnbmF0dXJl", nested.getString("signature"))
        assertEquals("uh", nested.getString("user_handle"))
    }

    @Test
    fun `revealSecret omits user_handle when not provided`() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("""{"secret_id":"sec_1","plaintext":"x"}"""),
        )
        client.revealSecret(
            secretId = "sec_1",
            workspaceId = "ws_1",
            userId = "usr_req",
            assertion = PassKeyAssertion(
                credentialId = "cred_1",
                clientDataJson = "cdata",
                authenticatorData = "adata",
                signature = "sig",
            ),
        )
        val nested = JSONObject(JSONObject(server.takeRequest().body.readUtf8()).getString("mfa_assertion"))
        assertTrue(!nested.has("user_handle"))
    }

    @Test
    fun `revealSecret rejects empty ids without hitting the wire`() = runBlocking {
        val assertion = PassKeyAssertion(
            credentialId = "cred_1",
            clientDataJson = "cdata",
            authenticatorData = "adata",
            signature = "sig",
        )
        for ((sid, wid, uid) in listOf(
            Triple("", "ws", "u"),
            Triple("s", "", "u"),
            Triple("s", "ws", ""),
        )) {
            assertFailsWith<AccessSDKException.InvalidInput> {
                client.revealSecret(sid, wid, uid, assertion)
            }
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `revealSecret maps 401 to Unauthenticated`() {
        server.enqueue(MockResponse().setResponseCode(401))
        assertFailsWith<AccessSDKException.Unauthenticated> {
            runBlocking {
                client.revealSecret(
                    secretId = "sec_1",
                    workspaceId = "ws_1",
                    userId = "usr_req",
                    assertion = PassKeyAssertion(
                        credentialId = "cred_1",
                        clientDataJson = "cdata",
                        authenticatorData = "adata",
                        signature = "sig",
                    ),
                )
            }
        }
    }
}
