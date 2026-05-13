/*
 * ContractTest.kt — compile-time conformance check.
 *
 * The SDK ships an interface only; concrete `OkHttp`-backed clients live
 * in the host application. This test asserts that the interface is
 * implementable: if a method signature changes in a breaking way, the
 * mock below stops compiling and the test target fails to build. There
 * are intentionally **no network round-trip tests** here.
 */
package com.shieldnet360.access

import java.time.Instant
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Stub conformance — exercises every method on the interface. */
private class MockAccessSDKClient : AccessSDKClient {
    override suspend fun createRequest(
        resource: String,
        role: String?,
        justification: String?,
    ): AccessRequest = AccessRequest(
        id = "req_test",
        workspaceId = "ws_test",
        requesterUserId = "user_test",
        connectorId = "conn_test",
        resourceExternalId = resource,
        role = role,
        justification = justification,
        state = AccessRequestState.REQUESTED,
        createdAt = Instant.EPOCH,
    )

    override suspend fun listRequests(
        state: AccessRequestState?,
        requester: String?,
        resource: String?,
    ): List<AccessRequest> = emptyList()

    override suspend fun approveRequest(id: String): AccessRequest = AccessRequest(
        id = id,
        workspaceId = "ws_test",
        requesterUserId = "user_test",
        connectorId = "conn_test",
        resourceExternalId = "res_test",
        state = AccessRequestState.APPROVED,
        createdAt = Instant.EPOCH,
    )

    override suspend fun denyRequest(id: String, reason: String): AccessRequest = AccessRequest(
        id = id,
        workspaceId = "ws_test",
        requesterUserId = "user_test",
        connectorId = "conn_test",
        resourceExternalId = "res_test",
        state = AccessRequestState.DENIED,
        createdAt = Instant.EPOCH,
    )

    override suspend fun cancelRequest(id: String): AccessRequest = AccessRequest(
        id = id,
        workspaceId = "ws_test",
        requesterUserId = "user_test",
        connectorId = "conn_test",
        resourceExternalId = "res_test",
        state = AccessRequestState.CANCELLED,
        createdAt = Instant.EPOCH,
    )

    override suspend fun listGrants(userId: String?, connectorId: String?): List<AccessGrant> = emptyList()

    override suspend fun explainPolicy(policyId: String): PolicyExplanation =
        PolicyExplanation(policyId = policyId, summary = "mock")

    override suspend fun suggestResources(): List<Suggestion> = emptyList()
}

class ContractTest {
    @Test
    fun `mock satisfies AccessSDKClient and can be exercised end-to-end`() = runBlocking {
        val client: AccessSDKClient = MockAccessSDKClient()

        val created = client.createRequest(
            resource = "res_test",
            role = "viewer",
            justification = "ci",
        )
        assertEquals(AccessRequestState.REQUESTED, created.state)
        assertEquals("res_test", created.resourceExternalId)
        assertEquals("conn_test", created.connectorId)

        val list = client.listRequests()
        assertTrue(list.isEmpty())

        val approved = client.approveRequest("req_1")
        assertEquals(AccessRequestState.APPROVED, approved.state)

        val denied = client.denyRequest("req_2", "policy-violation")
        assertEquals(AccessRequestState.DENIED, denied.state)

        val cancelled = client.cancelRequest("req_3")
        assertEquals(AccessRequestState.CANCELLED, cancelled.state)

        val grants = client.listGrants()
        assertTrue(grants.isEmpty())

        val explanation = client.explainPolicy("pol_1")
        assertEquals("pol_1", explanation.policyId)

        val suggestions = client.suggestResources()
        assertTrue(suggestions.isEmpty())
    }

    @Test
    fun `AccessSDKException carries structured status codes`() {
        val ex = AccessSDKException.Http(statusCode = 401, body = "{\"error\":{\"code\":\"unauthorized\"}}")
        assertEquals(401, ex.statusCode)
        assertTrue(ex.message!!.contains("HTTP 401"))
    }

    @Test
    fun `AccessRequestState maps to and from lowercase wire values`() {
        // Wire values match the Go-side constants in
        // internal/services/access/request_state_machine.go.
        assertEquals("requested", AccessRequestState.REQUESTED.value)
        assertEquals("provision_failed", AccessRequestState.PROVISION_FAILED.value)
        assertEquals("expired", AccessRequestState.EXPIRED.value)

        assertEquals(AccessRequestState.APPROVED, AccessRequestState.fromWire("approved"))
        assertEquals(AccessRequestState.PROVISION_FAILED, AccessRequestState.fromWire("provision_failed"))
        assertEquals(AccessRequestState.EXPIRED, AccessRequestState.fromWire("expired"))

        val unknown = try {
            AccessRequestState.fromWire("unknown_state")
            null
        } catch (e: IllegalArgumentException) {
            e
        }
        assertTrue(unknown != null, "fromWire must throw on unknown values")
    }

    @Test
    fun `AccessRequestRiskScore maps to and from lowercase wire values`() {
        // Wire values match the Go-side RequestRiskLow / Medium / High
        // constants in internal/models/access_request.go.
        assertEquals("low", AccessRequestRiskScore.LOW.value)
        assertEquals("medium", AccessRequestRiskScore.MEDIUM.value)
        assertEquals("high", AccessRequestRiskScore.HIGH.value)

        assertEquals(AccessRequestRiskScore.LOW, AccessRequestRiskScore.fromWire("low"))
        assertEquals(AccessRequestRiskScore.HIGH, AccessRequestRiskScore.fromWire("high"))
    }
}
