/*
 * OkHttpClientTest.kt — real OkHttp tests using MockWebServer.
 *
 * MockWebServer is a real HTTP server that OkHttp connects to over
 * TCP; it is NOT a mock of OkHttp itself. The SDK code path
 * (Request.Builder, RequestBody, client.newCall.execute, JSON
 * parsing) is fully real.
 */
package com.shieldnet360.access

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class OkHttpClientTest {
    private lateinit var server: MockWebServer
    private lateinit var client: OkHttpAccessSDKClient

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
        client = OkHttpAccessSDKClient(
            baseUrl = server.url("/").toString().trimEnd('/'),
            client = OkHttpClient(),
            authTokenProvider = { "test-token-xyz" },
        )
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `createRequest sends auth and parses response`() = runBlocking {
        server.enqueue(
            MockResponse().setResponseCode(201).setBody(
                """
                {
                    "id": "req_1",
                    "workspace_id": "ws_1",
                    "requester_user_id": "user_1",
                    "connector_id": "conn_1",
                    "resource_external_id": "projects/foo",
                    "state": "requested",
                    "created_at": "2025-01-30T12:00:00Z"
                }
                """.trimIndent(),
            ),
        )
        val out = client.createRequest("projects/foo", "viewer", "ci")
        assertEquals("req_1", out.id)
        assertEquals(AccessRequestState.REQUESTED, out.state)

        val recorded = server.takeRequest()
        assertEquals("/access/requests", recorded.path)
        assertEquals("POST", recorded.method)
        assertEquals("Bearer test-token-xyz", recorded.getHeader("Authorization"))
    }

    @Test
    fun `listRequests includes query parameters`() = runBlocking {
        server.enqueue(MockResponse().setBody("[]"))
        client.listRequests(state = AccessRequestState.REQUESTED, requester = "u1", resource = null)
        val rec = server.takeRequest()
        assertTrue(rec.path!!.startsWith("/access/requests?"))
        assertTrue(rec.path!!.contains("state=requested"))
        assertTrue(rec.path!!.contains("requester=u1"))
    }

    @Test
    fun `approveRequest hits correct path`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"id":"req_9","workspace_id":"ws","requester_user_id":"u","connector_id":"c","resource_external_id":"r","state":"approved","created_at":"2025-01-30T12:00:00Z"}""",
            ),
        )
        val out = client.approveRequest("req_9")
        assertEquals(AccessRequestState.APPROVED, out.state)
        val rec = server.takeRequest()
        assertEquals("/access/requests/req_9/approve", rec.path)
    }

    @Test
    fun `listGrants decodes array`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """[{"id":"g1","workspace_id":"ws","user_id":"u","connector_id":"c","resource_external_id":"r","granted_at":"2025-01-30T12:00:00Z"}]""",
            ),
        )
        val out = client.listGrants(userId = "u", connectorId = null)
        assertEquals(1, out.size)
        assertEquals("g1", out[0].id)
    }

    @Test
    fun `explainPolicy decodes response`() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"policy_id":"pol_1","summary":"plain English"}"""))
        val out = client.explainPolicy("pol_1")
        assertEquals("pol_1", out.policyId)
        assertEquals("plain English", out.summary)
    }

    @Test
    fun `suggestResources tolerates empty body`() = runBlocking {
        server.enqueue(MockResponse().setBody(""))
        val out = client.suggestResources()
        assertEquals(0, out.size)
    }

    @Test
    fun `401 maps to Unauthenticated`() {
        server.enqueue(MockResponse().setResponseCode(401))
        assertFailsWith<AccessSDKException.Unauthenticated> {
            runBlocking { client.cancelRequest("req_x") }
        }
    }

    @Test
    fun `500 maps to Http error`() {
        server.enqueue(MockResponse().setResponseCode(500).setBody("internal"))
        val err = assertFailsWith<AccessSDKException.Http> {
            runBlocking { client.cancelRequest("req_x") }
        }
        assertEquals(500, err.statusCode)
    }

    @Test
    fun `malformed JSON maps to Decoding error`() {
        server.enqueue(MockResponse().setBody("not-json"))
        assertFailsWith<AccessSDKException.Decoding> {
            runBlocking { client.approveRequest("req_x") }
        }
    }
}
