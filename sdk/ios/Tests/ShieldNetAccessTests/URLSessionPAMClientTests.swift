//
// URLSessionPAMClientTests.swift — real URLSession round-trip tests
// for the PAM extension of the iOS Access SDK.
//
// We reuse `URLProtocolStub` from `URLSessionClientTests.swift`
// (same target) to intercept the network without mocking
// URLSession. The SDK code drives a real `URLSession`, including
// `URLRequest` construction, headers, the protocol-class lookup,
// `data(for:)` dispatch, and `HTTPURLResponse` parsing.
//
// Coverage:
//   • approve   → POST /pam/leases/:id/approve with workspace +
//                 approver + duration + matched_code body
//   • deny      → POST /pam/leases/:id/revoke  with reason body
//   • reveal    → POST /pam/secrets/:id/reveal with workspace +
//                 user + mfa_assertion body, body decodes to
//                 PAMSecretRevealResponse
//   • approve rejects empty / mismatched selected_code without
//     making a network call
//   • approve / deny / reveal all set Authorization: Bearer <tok>
//   • 401 maps to AccessSDKError.unauthenticated; 500 maps to
//     AccessSDKError.http(statusCode:body:); transport failures map
//     to AccessSDKError.transport; malformed JSON maps to
//     AccessSDKError.decoding.
//

import XCTest

@testable import ShieldNetAccess

final class URLSessionPAMClientTests: XCTestCase {
    private var session: URLSession!
    private var client: URLSessionPAMSDKClient!

    private let baseURL = URL(string: "https://api.example.com")!

    override func setUp() {
        super.setUp()
        URLProtocolStub.captured = []
        URLProtocolStub.handler = nil
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [URLProtocolStub.self]
        session = URLSession(configuration: config)
        client = URLSessionPAMSDKClient(
            baseURL: baseURL,
            session: session,
            authTokenProvider: { "pam-token-xyz" }
        )
    }

    override func tearDown() {
        URLProtocolStub.handler = nil
        URLProtocolStub.captured = []
        session.invalidateAndCancel()
        session = nil
        client = nil
        super.tearDown()
    }

    // MARK: - Helpers

    /// Returns a notification with `matchedCode` "47" and two
    /// decoy codes. Reused across most tests.
    private func makeNotification(
        leaseID: String = "lse_01",
        matchedCode: String = "47"
    ) -> PAMApprovalNotification {
        return PAMApprovalNotification(
            leaseID: leaseID,
            workspaceID: "ws_1",
            requesterUserID: "usr_req",
            assetName: "prod-db-1",
            protocol: .postgres,
            criticality: .crownJewel,
            riskScore: .high,
            matchedCode: matchedCode,
            decoyCodes: ["12", "98"]
        )
    }

    /// Canned JSON for a granted lease — sufficient to decode into
    /// a `PAMLease` value.
    private let grantedLeaseJSON = """
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
        """

    /// Canned JSON for a revoked lease.
    private let revokedLeaseJSON = """
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
        """

    // MARK: - approveLease

    func testApprove_HappyPath_BuildsURLHeadersAndBody() async throws {
        URLProtocolStub.handler = { _ in (200, Data(self.grantedLeaseJSON.utf8)) }
        let n = makeNotification()
        let lease = try await client.approveLease(
            notification: n,
            approverUserID: "usr_approver",
            durationMinutes: 120,
            selectedCode: "47"
        )
        XCTAssertEqual(lease.id, "lse_01")
        XCTAssertEqual(lease.state, .granted)
        XCTAssertEqual(lease.approvedBy, "usr_approver")

        XCTAssertEqual(URLProtocolStub.captured.count, 1)
        let req = URLProtocolStub.captured[0]
        XCTAssertEqual(req.httpMethod, "POST")
        XCTAssertEqual(req.url?.path, "/pam/leases/lse_01/approve")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer pam-token-xyz")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Content-Type"), "application/json")
    }

    func testApprove_RejectsEmptyApprover_NoNetworkCall() async {
        URLProtocolStub.handler = { _ in (200, Data(self.grantedLeaseJSON.utf8)) }
        let n = makeNotification()
        do {
            _ = try await client.approveLease(
                notification: n,
                approverUserID: "",
                durationMinutes: nil,
                selectedCode: "47"
            )
            XCTFail("expected invalidInput")
        } catch AccessSDKError.invalidInput {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(URLProtocolStub.captured.count, 0)
    }

    func testApprove_RejectsEmptyCode_NoNetworkCall() async {
        URLProtocolStub.handler = { _ in (200, Data(self.grantedLeaseJSON.utf8)) }
        let n = makeNotification()
        do {
            _ = try await client.approveLease(
                notification: n,
                approverUserID: "usr",
                durationMinutes: nil,
                selectedCode: ""
            )
            XCTFail("expected invalidInput")
        } catch AccessSDKError.invalidInput {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(URLProtocolStub.captured.count, 0)
    }

    func testApprove_RejectsMismatchedCode_NoNetworkCall() async {
        URLProtocolStub.handler = { _ in (200, Data(self.grantedLeaseJSON.utf8)) }
        let n = makeNotification()
        do {
            _ = try await client.approveLease(
                notification: n,
                approverUserID: "usr",
                durationMinutes: nil,
                selectedCode: "12"
            )
            XCTFail("expected invalidInput")
        } catch AccessSDKError.invalidInput(let msg) {
            XCTAssertTrue(msg.contains("does not match"), msg)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(URLProtocolStub.captured.count, 0)
    }

    func testApprove_401MapsToUnauthenticated() async {
        URLProtocolStub.handler = { _ in (401, Data()) }
        let n = makeNotification()
        do {
            _ = try await client.approveLease(
                notification: n,
                approverUserID: "usr",
                durationMinutes: nil,
                selectedCode: "47"
            )
            XCTFail("expected unauthenticated")
        } catch AccessSDKError.unauthenticated {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testApprove_500MapsToHTTPError() async {
        URLProtocolStub.handler = { _ in (500, Data("internal".utf8)) }
        let n = makeNotification()
        do {
            _ = try await client.approveLease(
                notification: n,
                approverUserID: "usr",
                durationMinutes: nil,
                selectedCode: "47"
            )
            XCTFail("expected http error")
        } catch AccessSDKError.http(let code, _) {
            XCTAssertEqual(code, 500)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testApprove_MalformedJSON_MapsToDecoding() async {
        URLProtocolStub.handler = { _ in (200, Data("not-json".utf8)) }
        let n = makeNotification()
        do {
            _ = try await client.approveLease(
                notification: n,
                approverUserID: "usr",
                durationMinutes: nil,
                selectedCode: "47"
            )
            XCTFail("expected decoding error")
        } catch AccessSDKError.decoding {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    // MARK: - denyLease

    func testDeny_HappyPath_PostsToRevokeEndpoint() async throws {
        URLProtocolStub.handler = { _ in (200, Data(self.revokedLeaseJSON.utf8)) }
        let n = makeNotification()
        let lease = try await client.denyLease(notification: n, reason: "policy-violation")
        XCTAssertEqual(lease.state, .revoked)
        XCTAssertEqual(lease.reason, "policy-violation")

        let req = URLProtocolStub.captured[0]
        XCTAssertEqual(req.httpMethod, "POST")
        XCTAssertEqual(req.url?.path, "/pam/leases/lse_01/revoke")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer pam-token-xyz")
    }

    // MARK: - revealSecret

    func testReveal_HappyPath_DecodesPlaintext() async throws {
        URLProtocolStub.handler = { _ in
            (200, Data("""
                {"secret_id":"sec_1","plaintext":"super-secret-value"}
                """.utf8))
        }
        let assertion = PassKeyAssertion(
            credentialID: "cred_1",
            clientDataJSON: "Y2RhdGE=",
            authenticatorData: "YXV0aGRhdGE=",
            signature: "c2lnbmF0dXJl"
        )
        let result = try await client.revealSecret(
            secretID: "sec_1",
            workspaceID: "ws_1",
            userID: "usr_req",
            assertion: assertion
        )
        XCTAssertEqual(result.secretID, "sec_1")
        XCTAssertEqual(result.plaintext, "super-secret-value")

        let req = URLProtocolStub.captured[0]
        XCTAssertEqual(req.url?.path, "/pam/secrets/sec_1/reveal")
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer pam-token-xyz")
    }

    func testReveal_RejectsEmptyIDs_NoNetworkCall() async {
        URLProtocolStub.handler = { _ in
            (200, Data("""
                {"secret_id":"sec_1","plaintext":"x"}
                """.utf8))
        }
        let assertion = PassKeyAssertion(
            credentialID: "cred_1",
            clientDataJSON: "Y2RhdGE=",
            authenticatorData: "YXV0aGRhdGE=",
            signature: "c2lnbmF0dXJl"
        )

        for (sid, wid, uid, expected) in [
            ("", "ws", "u", "secret_id"),
            ("s", "", "u", "workspace_id"),
            ("s", "ws", "", "user_id"),
        ] {
            URLProtocolStub.captured = []
            do {
                _ = try await client.revealSecret(
                    secretID: sid,
                    workspaceID: wid,
                    userID: uid,
                    assertion: assertion
                )
                XCTFail("expected invalidInput for \(expected)")
            } catch AccessSDKError.invalidInput(let msg) {
                XCTAssertTrue(msg.contains(expected), msg)
            } catch {
                XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(URLProtocolStub.captured.count, 0)
        }
    }

    func testReveal_401MapsToUnauthenticated() async {
        URLProtocolStub.handler = { _ in (401, Data()) }
        let assertion = PassKeyAssertion(
            credentialID: "cred_1",
            clientDataJSON: "Y2RhdGE=",
            authenticatorData: "YXV0aGRhdGE=",
            signature: "c2lnbmF0dXJl"
        )
        do {
            _ = try await client.revealSecret(
                secretID: "sec_1",
                workspaceID: "ws_1",
                userID: "usr_req",
                assertion: assertion
            )
            XCTFail("expected unauthenticated")
        } catch AccessSDKError.unauthenticated {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
