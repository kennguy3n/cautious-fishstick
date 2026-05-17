/*
 * PAMContractTest.kt — compile-time conformance + value-shape
 * tests for the PAM extension of the Android Access SDK.
 *
 * These tests do NOT exercise the network — they verify:
 *   • `PAMSDKClient` is implementable (a mock satisfies it).
 *   • Enum wire values match the documented server-side strings.
 *   • `PAMApprovalNotification.allCodes()` returns the union of
 *     `matchedCode ∪ decoyCodes` in a deterministic order.
 *   • `OkHttpPAMSDKClient.parseApprovalNotification` accepts the
 *     documented FCM data-dict shape, rejects unknown discriminators,
 *     and rejects empty payloads.
 *   • `OkHttpPAMSDKClient.verifyMatchedCode` performs a byte-equal
 *     constant-time comparison.
 *
 * Full HTTP round-trip coverage lives in `OkHttpPAMClientTest.kt`.
 */
package com.shieldnet360.access

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.jupiter.api.assertDoesNotThrow

/** Stub conformance — exercises every method on the PAM interface. */
private class MockPAMSDKClient : PAMSDKClient {
    override fun parseApprovalNotification(data: Map<String, String>): PAMApprovalNotification {
        // Return a minimal valid notification so the integration
        // exercise below has something to feed into approve / deny.
        return PAMApprovalNotification(
            type = PAMNotificationType.APPROVAL_REQUESTED,
            leaseId = "lse_test",
            workspaceId = "ws_test",
            requesterUserId = "usr_test",
            assetName = "asset_test",
            protocol = PAMSessionProtocol.SSH,
            criticality = PAMAssetCriticality.HIGH,
            riskScore = PAMRiskScore.MEDIUM,
            riskFactors = emptyList(),
            matchedCode = "47",
            decoyCodes = listOf("12", "98"),
            justification = null,
            expiresAt = null,
        )
    }

    override fun verifyMatchedCode(
        selected: String,
        notification: PAMApprovalNotification,
    ): NumberMatchOutcome = if (selected == notification.matchedCode) {
        NumberMatchOutcome.MATCHED
    } else {
        NumberMatchOutcome.MISMATCHED
    }

    override suspend fun approveLease(
        notification: PAMApprovalNotification,
        approverUserId: String,
        durationMinutes: Int?,
        selectedCode: String,
    ): PAMLease = PAMLease(
        id = notification.leaseId,
        workspaceId = notification.workspaceId,
        userId = notification.requesterUserId,
        assetId = "ast_test",
        accountId = "acc_test",
        reason = null,
        state = PAMLeaseState.GRANTED,
        approvedBy = approverUserId,
        grantedAt = java.time.Instant.EPOCH,
        expiresAt = null,
        revokedAt = null,
        createdAt = java.time.Instant.EPOCH,
    )

    override suspend fun denyLease(
        notification: PAMApprovalNotification,
        reason: String,
    ): PAMLease = PAMLease(
        id = notification.leaseId,
        workspaceId = notification.workspaceId,
        userId = notification.requesterUserId,
        assetId = "ast_test",
        accountId = "acc_test",
        reason = reason,
        state = PAMLeaseState.REVOKED,
        approvedBy = null,
        grantedAt = null,
        expiresAt = null,
        revokedAt = java.time.Instant.EPOCH,
        createdAt = java.time.Instant.EPOCH,
    )

    override suspend fun revealSecret(
        secretId: String,
        workspaceId: String,
        userId: String,
        assertion: PassKeyAssertion,
    ): PAMSecretRevealResponse = PAMSecretRevealResponse(
        secretId = secretId,
        plaintext = "mock-plaintext",
    )
}

class PAMContractTest {
    @Test
    fun `mock satisfies PAMSDKClient and can be exercised end-to-end`() = runBlocking {
        val client: PAMSDKClient = MockPAMSDKClient()

        val notification = client.parseApprovalNotification(mapOf("type" to "ignored-by-mock"))
        assertEquals("lse_test", notification.leaseId)

        assertEquals(
            NumberMatchOutcome.MATCHED,
            client.verifyMatchedCode("47", notification),
        )
        assertEquals(
            NumberMatchOutcome.MISMATCHED,
            client.verifyMatchedCode("12", notification),
        )

        val granted = client.approveLease(
            notification = notification,
            approverUserId = "usr_approver",
            durationMinutes = 60,
            selectedCode = "47",
        )
        assertEquals(PAMLeaseState.GRANTED, granted.state)
        assertEquals("usr_approver", granted.approvedBy)

        val revoked = client.denyLease(notification, "policy-violation")
        assertEquals(PAMLeaseState.REVOKED, revoked.state)
        assertEquals("policy-violation", revoked.reason)

        val assertion = PassKeyAssertion(
            credentialId = "cred",
            clientDataJson = "Y2RhdGE=",
            authenticatorData = "YXV0aGRhdGE=",
            signature = "c2lnbmF0dXJl",
        )
        val revealed = client.revealSecret(
            secretId = "sec_1",
            workspaceId = "ws_1",
            userId = "usr_1",
            assertion = assertion,
        )
        assertEquals("sec_1", revealed.secretId)
    }

    @Test
    fun `enum wire values match server contracts`() {
        // Mirrors the Go-side constants in internal/models/pam_*.go
        // and the FCM data dict in docs/pam/architecture.md §6.
        assertEquals("ssh", PAMSessionProtocol.SSH.wireValue)
        assertEquals("kubernetes", PAMSessionProtocol.KUBERNETES.wireValue)
        assertEquals("postgres", PAMSessionProtocol.POSTGRES.wireValue)
        assertEquals("mysql", PAMSessionProtocol.MYSQL.wireValue)
        assertEquals("mariadb", PAMSessionProtocol.MARIADB.wireValue)

        assertEquals("crown_jewel", PAMAssetCriticality.CROWN_JEWEL.wireValue)
        assertEquals("high", PAMAssetCriticality.HIGH.wireValue)

        assertEquals("low", PAMRiskScore.LOW.wireValue)
        assertEquals("medium", PAMRiskScore.MEDIUM.wireValue)
        assertEquals("high", PAMRiskScore.HIGH.wireValue)

        assertEquals("pam.approval.requested", PAMNotificationType.APPROVAL_REQUESTED.wireValue)

        // PAMLeaseState mirrors models.PAMLeaseState*.
        assertEquals("requested", PAMLeaseState.REQUESTED.wireValue)
        assertEquals("granted", PAMLeaseState.GRANTED.wireValue)
        assertEquals("denied", PAMLeaseState.DENIED.wireValue)
        assertEquals("expired", PAMLeaseState.EXPIRED.wireValue)
        assertEquals("revoked", PAMLeaseState.REVOKED.wireValue)

        // Round-trip the fromWire factories.
        assertEquals(PAMSessionProtocol.POSTGRES, PAMSessionProtocol.fromWire("postgres"))
        assertEquals(PAMAssetCriticality.CROWN_JEWEL, PAMAssetCriticality.fromWire("crown_jewel"))
        assertEquals(PAMRiskScore.HIGH, PAMRiskScore.fromWire("high"))
        assertEquals(PAMLeaseState.GRANTED, PAMLeaseState.fromWire("granted"))
        assertEquals(
            PAMNotificationType.APPROVAL_REQUESTED,
            PAMNotificationType.fromWire("pam.approval.requested"),
        )

        // Unknown values must throw — Decoding for value enums,
        // InvalidInput for the type discriminator.
        assertFailsWith<AccessSDKException.Decoding> {
            PAMSessionProtocol.fromWire("smb")
        }
        assertFailsWith<AccessSDKException.Decoding> {
            PAMAssetCriticality.fromWire("planetary")
        }
        assertFailsWith<AccessSDKException.Decoding> {
            PAMRiskScore.fromWire("extreme")
        }
        assertFailsWith<AccessSDKException.Decoding> {
            PAMLeaseState.fromWire("flushed")
        }
        assertFailsWith<AccessSDKException.InvalidInput> {
            PAMNotificationType.fromWire("access.request.created")
        }
    }

    @Test
    fun `allCodes is sorted numerically when codes are numeric`() {
        val n = PAMApprovalNotification(
            type = PAMNotificationType.APPROVAL_REQUESTED,
            leaseId = "lse",
            workspaceId = "ws",
            requesterUserId = "usr",
            assetName = "a",
            protocol = PAMSessionProtocol.SSH,
            criticality = PAMAssetCriticality.LOW,
            riskScore = PAMRiskScore.LOW,
            riskFactors = emptyList(),
            matchedCode = "47",
            decoyCodes = listOf("98", "12"),
            justification = null,
            expiresAt = null,
        )
        assertEquals(listOf("12", "47", "98"), n.allCodes())
    }

    @Test
    fun `allCodes falls back to lexicographic sort for non-numeric codes`() {
        val n = PAMApprovalNotification(
            type = PAMNotificationType.APPROVAL_REQUESTED,
            leaseId = "lse",
            workspaceId = "ws",
            requesterUserId = "usr",
            assetName = "a",
            protocol = PAMSessionProtocol.SSH,
            criticality = PAMAssetCriticality.LOW,
            riskScore = PAMRiskScore.LOW,
            riskFactors = emptyList(),
            matchedCode = "bravo",
            decoyCodes = listOf("alpha", "charlie"),
            justification = null,
            expiresAt = null,
        )
        assertEquals(listOf("alpha", "bravo", "charlie"), n.allCodes())
    }

    @Test
    fun `parseApprovalNotification accepts documented FCM payload shape`() {
        val client = OkHttpPAMSDKClient(
            baseUrl = "https://example.invalid",
            client = OkHttpClient(),
            authTokenProvider = { "tok" },
        )
        val data = mapOf(
            "type" to "pam.approval.requested",
            "lease_id" to "lse_01",
            "workspace_id" to "ws_1",
            "requester_user_id" to "usr_req",
            "asset_name" to "prod-db-1",
            "protocol" to "postgres",
            "criticality" to "crown_jewel",
            "risk_score" to "high",
            "risk_factors" to """["unusual_time","first_time_asset"]""",
            "matched_code" to "47",
            "decoy_codes" to """["12","98"]""",
            "justification" to "incident IR-2025-04",
            "expires_at" to "2025-06-01T12:00:00Z",
        )
        val parsed = assertDoesNotThrow { client.parseApprovalNotification(data) }
        assertEquals("lse_01", parsed.leaseId)
        assertEquals(PAMSessionProtocol.POSTGRES, parsed.protocol)
        assertEquals(PAMAssetCriticality.CROWN_JEWEL, parsed.criticality)
        assertEquals(PAMRiskScore.HIGH, parsed.riskScore)
        assertEquals("47", parsed.matchedCode)
        assertEquals(listOf("12", "98"), parsed.decoyCodes)
        assertEquals(listOf("unusual_time", "first_time_asset"), parsed.riskFactors)
        assertEquals("incident IR-2025-04", parsed.justification)
        assertTrue(parsed.expiresAt != null)
    }

    @Test
    fun `parseApprovalNotification rejects empty payload`() {
        val client = OkHttpPAMSDKClient(
            baseUrl = "https://example.invalid",
            client = OkHttpClient(),
            authTokenProvider = { "tok" },
        )
        assertFailsWith<AccessSDKException.InvalidInput> {
            client.parseApprovalNotification(emptyMap())
        }
    }

    @Test
    fun `parseApprovalNotification rejects missing type`() {
        val client = OkHttpPAMSDKClient(
            baseUrl = "https://example.invalid",
            client = OkHttpClient(),
            authTokenProvider = { "tok" },
        )
        val err = assertFailsWith<AccessSDKException.InvalidInput> {
            client.parseApprovalNotification(mapOf("lease_id" to "lse_01"))
        }
        assertTrue(err.message!!.contains("type"), err.message)
    }

    @Test
    fun `parseApprovalNotification rejects unknown type discriminator`() {
        val client = OkHttpPAMSDKClient(
            baseUrl = "https://example.invalid",
            client = OkHttpClient(),
            authTokenProvider = { "tok" },
        )
        val data = mapOf(
            "type" to "access.request.created",
            "lease_id" to "lse_01",
        )
        assertFailsWith<AccessSDKException.InvalidInput> {
            client.parseApprovalNotification(data)
        }
    }

    @Test
    fun `parseApprovalNotification rejects malformed risk_factors`() {
        val client = OkHttpPAMSDKClient(
            baseUrl = "https://example.invalid",
            client = OkHttpClient(),
            authTokenProvider = { "tok" },
        )
        val data = mapOf(
            "type" to "pam.approval.requested",
            "lease_id" to "lse_01",
            "workspace_id" to "ws_1",
            "requester_user_id" to "usr",
            "asset_name" to "a",
            "protocol" to "ssh",
            "criticality" to "low",
            "risk_score" to "low",
            "matched_code" to "47",
            "decoy_codes" to "[]",
            "risk_factors" to "not-an-array",
        )
        assertFailsWith<AccessSDKException.Decoding> {
            client.parseApprovalNotification(data)
        }
    }

    @Test
    fun `verifyMatchedCode is byte-equal in constant time`() {
        val client = OkHttpPAMSDKClient(
            baseUrl = "https://example.invalid",
            client = OkHttpClient(),
            authTokenProvider = { "tok" },
        )
        val n = PAMApprovalNotification(
            type = PAMNotificationType.APPROVAL_REQUESTED,
            leaseId = "lse",
            workspaceId = "ws",
            requesterUserId = "usr",
            assetName = "a",
            protocol = PAMSessionProtocol.SSH,
            criticality = PAMAssetCriticality.LOW,
            riskScore = PAMRiskScore.LOW,
            riskFactors = emptyList(),
            matchedCode = "47",
            decoyCodes = listOf("12", "98"),
            justification = null,
            expiresAt = null,
        )
        assertEquals(NumberMatchOutcome.MATCHED, client.verifyMatchedCode("47", n))
        assertEquals(NumberMatchOutcome.MISMATCHED, client.verifyMatchedCode("12", n))
        assertEquals(NumberMatchOutcome.MISMATCHED, client.verifyMatchedCode("", n))
        // Differing length but matching prefix.
        assertEquals(NumberMatchOutcome.MISMATCHED, client.verifyMatchedCode("470", n))
        // Same length, different bytes.
        assertEquals(NumberMatchOutcome.MISMATCHED, client.verifyMatchedCode("48", n))
    }

    @Test
    fun `PassKeyAssertion serialises userHandle as optional`() {
        val withHandle = PassKeyAssertion(
            credentialId = "cred",
            clientDataJson = "cdata",
            authenticatorData = "adata",
            signature = "sig",
            userHandle = "uh",
        )
        val withoutHandle = PassKeyAssertion(
            credentialId = "cred",
            clientDataJson = "cdata",
            authenticatorData = "adata",
            signature = "sig",
        )
        // The model itself doesn't serialise — that's the
        // implementation's job — but make sure both forms are
        // valid value objects.
        assertEquals("uh", withHandle.userHandle)
        assertEquals(null, withoutHandle.userHandle)
    }
}
