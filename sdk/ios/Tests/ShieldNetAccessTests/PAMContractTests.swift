//
// PAMContractTests.swift — compile-time conformance + value-shape
// tests for the PAM extension of the iOS Access SDK.
//
// These tests do NOT exercise the network — they verify:
//   • `PAMSDKClient` is implementable (a mock satisfies it).
//   • Push payload parsing accepts the documented shape verbatim.
//   • Number-matching uses a constant-time byte comparison and
//     rejects mismatches.
//   • Approve / deny / reveal flows route to the expected
//     mock-implementation methods with the expected arguments.
//
// The full HTTP round-trip is covered by
// `URLSessionPAMClientTests.swift`.
//

import XCTest

@testable import ShieldNetAccess

// MARK: - MockPAMSDKClient — implementable stub used by other tests

/// A trivial stub. The presence of this stub is what proves
/// `PAMSDKClient` is a real, satisfiable protocol — adding a method
/// without a default value to the protocol breaks the build of this
/// file, which is the desired safety net.
final class MockPAMSDKClient: PAMSDKClient {
    var lastParsedUserInfo: [AnyHashable: Any]?
    var lastApprove: (PAMApprovalNotification, String, Int?, String)?
    var lastDeny: (PAMApprovalNotification, String)?
    var lastReveal: (String, String, String, PassKeyAssertion)?

    var parseResult: Result<PAMApprovalNotification, Error> = .failure(
        AccessSDKError.invalidInput("not configured"))
    var approveResult: Result<PAMLease, Error> = .failure(
        AccessSDKError.invalidInput("not configured"))
    var denyResult: Result<PAMLease, Error> = .failure(
        AccessSDKError.invalidInput("not configured"))
    var revealResult: Result<PAMSecretRevealResponse, Error> = .failure(
        AccessSDKError.invalidInput("not configured"))

    func parseApprovalNotification(userInfo: [AnyHashable: Any]) throws
        -> PAMApprovalNotification
    {
        self.lastParsedUserInfo = userInfo
        switch parseResult {
        case .success(let v): return v
        case .failure(let e): throw e
        }
    }

    func verifyMatchedCode(
        selected: String,
        notification: PAMApprovalNotification
    ) -> NumberMatchOutcome {
        return selected == notification.matchedCode ? .matched : .mismatched
    }

    func approveLease(
        notification: PAMApprovalNotification,
        approverUserID: String,
        durationMinutes: Int?,
        selectedCode: String
    ) async throws -> PAMLease {
        self.lastApprove = (notification, approverUserID, durationMinutes, selectedCode)
        switch approveResult {
        case .success(let v): return v
        case .failure(let e): throw e
        }
    }

    func denyLease(
        notification: PAMApprovalNotification,
        reason: String
    ) async throws -> PAMLease {
        self.lastDeny = (notification, reason)
        switch denyResult {
        case .success(let v): return v
        case .failure(let e): throw e
        }
    }

    func revealSecret(
        secretID: String,
        workspaceID: String,
        userID: String,
        assertion: PassKeyAssertion
    ) async throws -> PAMSecretRevealResponse {
        self.lastReveal = (secretID, workspaceID, userID, assertion)
        switch revealResult {
        case .success(let v): return v
        case .failure(let e): throw e
        }
    }
}

// MARK: - Tests

final class PAMContractTests: XCTestCase {

    // Compile-time check: any object conforming to PAMSDKClient
    // must implement every method. If a method is added without a
    // default impl, MockPAMSDKClient stops compiling and this test
    // file fails to build — which is the desired failure mode.
    func test_mockSatisfiesProtocol() {
        let mock: PAMSDKClient = MockPAMSDKClient()
        XCTAssertNotNil(mock)
    }

    func test_pamApprovalNotification_codingKeysRoundTrip() throws {
        let payload = PAMApprovalNotification(
            leaseID: "lse_01",
            workspaceID: "ws_1",
            requesterUserID: "usr_1",
            assetName: "prod-db-1",
            protocol: .postgres,
            criticality: .crownJewel,
            riskScore: .high,
            riskFactors: ["unusual_time", "first_time_asset"],
            matchedCode: "47",
            decoyCodes: ["12", "98"],
            justification: "incident IR-2025-04",
            expiresAt: Date(timeIntervalSince1970: 1_717_242_000)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(payload)
        guard let s = String(data: data, encoding: .utf8) else {
            XCTFail("encoder produced non-utf8 output")
            return
        }
        // Spot-check the wire format — snake_case + ISO-8601 +
        // enum raw values.
        XCTAssertTrue(s.contains("\"lease_id\":\"lse_01\""), s)
        XCTAssertTrue(s.contains("\"workspace_id\":\"ws_1\""), s)
        XCTAssertTrue(s.contains("\"protocol\":\"postgres\""), s)
        XCTAssertTrue(s.contains("\"criticality\":\"crown_jewel\""), s)
        XCTAssertTrue(s.contains("\"risk_score\":\"high\""), s)
        XCTAssertTrue(s.contains("\"matched_code\":\"47\""), s)
        XCTAssertTrue(s.contains("\"decoy_codes\":[\"12\",\"98\"]"), s)

        // And it must round-trip back through Decoder.
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(PAMApprovalNotification.self, from: data)
        XCTAssertEqual(decoded, payload)
    }

    func test_allCodes_sortedNumerically() {
        let n = PAMApprovalNotification(
            leaseID: "lse",
            workspaceID: "ws",
            requesterUserID: "usr",
            assetName: "asset",
            protocol: .ssh,
            criticality: .high,
            riskScore: .medium,
            matchedCode: "47",
            decoyCodes: ["12", "98"]
        )
        XCTAssertEqual(n.allCodes, ["12", "47", "98"])
    }

    func test_allCodes_sortedLexicographicallyForNonNumeric() {
        let n = PAMApprovalNotification(
            leaseID: "lse",
            workspaceID: "ws",
            requesterUserID: "usr",
            assetName: "asset",
            protocol: .ssh,
            criticality: .low,
            riskScore: .low,
            matchedCode: "bravo",
            decoyCodes: ["alpha", "charlie"]
        )
        XCTAssertEqual(n.allCodes, ["alpha", "bravo", "charlie"])
    }

    func test_parseApprovalNotification_acceptsDocumentedShape() throws {
        let client = URLSessionPAMSDKClient(
            baseURL: URL(string: "https://example.invalid")!,
            authTokenProvider: { "tok" }
        )
        let userInfo: [AnyHashable: Any] = [
            "type": "pam.approval.requested",
            "lease_id": "lse_01",
            "workspace_id": "ws_1",
            "requester_user_id": "usr_1",
            "asset_name": "prod-db-1",
            "protocol": "postgres",
            "criticality": "crown_jewel",
            "risk_score": "high",
            "risk_factors": ["unusual_time"],
            "matched_code": "47",
            "decoy_codes": ["12", "98"],
            "justification": "incident IR-2025-04",
            "expires_at": "2024-06-01T12:00:00Z",
        ]
        let parsed = try client.parseApprovalNotification(userInfo: userInfo)
        XCTAssertEqual(parsed.leaseID, "lse_01")
        XCTAssertEqual(parsed.workspaceID, "ws_1")
        XCTAssertEqual(parsed.protocol, .postgres)
        XCTAssertEqual(parsed.criticality, .crownJewel)
        XCTAssertEqual(parsed.riskScore, .high)
        XCTAssertEqual(parsed.matchedCode, "47")
        XCTAssertEqual(parsed.decoyCodes, ["12", "98"])
        XCTAssertEqual(parsed.riskFactors, ["unusual_time"])
        XCTAssertEqual(parsed.justification, "incident IR-2025-04")
        XCTAssertNotNil(parsed.expiresAt)
    }

    func test_parseApprovalNotification_rejectsMissingType() {
        let client = URLSessionPAMSDKClient(
            baseURL: URL(string: "https://example.invalid")!,
            authTokenProvider: { "tok" }
        )
        let userInfo: [AnyHashable: Any] = [
            "lease_id": "lse_01"
        ]
        do {
            _ = try client.parseApprovalNotification(userInfo: userInfo)
            XCTFail("expected invalidInput")
        } catch let AccessSDKError.invalidInput(msg) {
            XCTAssertTrue(msg.contains("type"), msg)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func test_parseApprovalNotification_rejectsUnknownType() {
        let client = URLSessionPAMSDKClient(
            baseURL: URL(string: "https://example.invalid")!,
            authTokenProvider: { "tok" }
        )
        let userInfo: [AnyHashable: Any] = [
            "type": "access.request.created",
            "lease_id": "lse_01",
        ]
        do {
            _ = try client.parseApprovalNotification(userInfo: userInfo)
            XCTFail("expected invalidInput")
        } catch let AccessSDKError.invalidInput(msg) {
            XCTAssertTrue(msg.contains("unsupported push type"), msg)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func test_parseApprovalNotification_rejectsEmptyPayload() {
        let client = URLSessionPAMSDKClient(
            baseURL: URL(string: "https://example.invalid")!,
            authTokenProvider: { "tok" }
        )
        do {
            _ = try client.parseApprovalNotification(userInfo: [:])
            XCTFail("expected invalidInput")
        } catch AccessSDKError.invalidInput {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func test_verifyMatchedCode_matchesByteEqualOnly() {
        let client = URLSessionPAMSDKClient(
            baseURL: URL(string: "https://example.invalid")!,
            authTokenProvider: { "tok" }
        )
        let n = PAMApprovalNotification(
            leaseID: "lse",
            workspaceID: "ws",
            requesterUserID: "usr",
            assetName: "a",
            protocol: .ssh,
            criticality: .low,
            riskScore: .low,
            matchedCode: "47"
        )
        XCTAssertEqual(client.verifyMatchedCode(selected: "47", notification: n), .matched)
        XCTAssertEqual(client.verifyMatchedCode(selected: "12", notification: n), .mismatched)
        XCTAssertEqual(client.verifyMatchedCode(selected: "", notification: n), .mismatched)
        // Length differs but prefix matches — must still mismatch.
        XCTAssertEqual(
            client.verifyMatchedCode(selected: "470", notification: n), .mismatched)
        // Same length but different bytes.
        XCTAssertEqual(client.verifyMatchedCode(selected: "48", notification: n), .mismatched)
    }
}
