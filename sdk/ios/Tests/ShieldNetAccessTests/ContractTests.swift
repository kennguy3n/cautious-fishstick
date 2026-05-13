//
// ContractTests.swift — compile-time conformance tests.
//
// The SDK ships a protocol only; concrete `URLSession`-backed clients live
// in the host application. These tests assert that the protocol's surface
// area is stable and implementable: if a method signature changes in a
// breaking way, the mock below stops compiling and the test target fails to
// build. There are intentionally **no network round-trip tests** here.
//

import XCTest
@testable import ShieldNetAccess

/// Stub conformance — exercises every method on the protocol so a breaking
/// signature change in `AccessSDKProtocol.swift` triggers a compile error.
private final class MockAccessSDKClient: AccessSDKClient {
    func createRequest(
        resource: String,
        role: String?,
        justification: String?
    ) async throws -> AccessRequest {
        AccessRequest(
            id: "req_test",
            workspaceID: "ws_test",
            requesterUserID: "user_test",
            connectorID: "conn_test",
            resourceExternalID: resource,
            role: role,
            justification: justification,
            state: .requested,
            createdAt: Date(timeIntervalSince1970: 0)
        )
    }

    func listRequests(
        state: AccessRequestState?,
        requester: String?,
        resource: String?
    ) async throws -> [AccessRequest] {
        []
    }

    func approveRequest(id: String) async throws -> AccessRequest {
        AccessRequest(
            id: id,
            workspaceID: "ws_test",
            requesterUserID: "user_test",
            connectorID: "conn_test",
            resourceExternalID: "res_test",
            state: .approved,
            createdAt: Date(timeIntervalSince1970: 0)
        )
    }

    func denyRequest(id: String, reason: String) async throws -> AccessRequest {
        AccessRequest(
            id: id,
            workspaceID: "ws_test",
            requesterUserID: "user_test",
            connectorID: "conn_test",
            resourceExternalID: "res_test",
            state: .denied,
            createdAt: Date(timeIntervalSince1970: 0)
        )
    }

    func cancelRequest(id: String) async throws -> AccessRequest {
        AccessRequest(
            id: id,
            workspaceID: "ws_test",
            requesterUserID: "user_test",
            connectorID: "conn_test",
            resourceExternalID: "res_test",
            state: .cancelled,
            createdAt: Date(timeIntervalSince1970: 0)
        )
    }

    func listGrants(userID: String?, connectorID: String?) async throws -> [AccessGrant] {
        []
    }

    func explainPolicy(policyID: String) async throws -> PolicyExplanation {
        PolicyExplanation(policyID: policyID, summary: "mock")
    }

    func suggestResources() async throws -> [Suggestion] {
        []
    }
}

final class ContractTests: XCTestCase {
    /// Verifies the mock conforms to the protocol and can be exercised
    /// end-to-end without crashing. This is intentionally a smoke test —
    /// the real value is the compile-time check on the mock.
    func testMockSatisfiesProtocol() async throws {
        let client: AccessSDKClient = MockAccessSDKClient()

        let created = try await client.createRequest(
            resource: "res_test",
            role: "viewer",
            justification: "ci"
        )
        XCTAssertEqual(created.state, .requested)
        XCTAssertEqual(created.resourceExternalID, "res_test")
        XCTAssertEqual(created.connectorID, "conn_test")

        let list = try await client.listRequests(state: nil, requester: nil, resource: nil)
        XCTAssertEqual(list.count, 0)

        let approved = try await client.approveRequest(id: "req_1")
        XCTAssertEqual(approved.state, .approved)

        let denied = try await client.denyRequest(id: "req_2", reason: "policy-violation")
        XCTAssertEqual(denied.state, .denied)

        let cancelled = try await client.cancelRequest(id: "req_3")
        XCTAssertEqual(cancelled.state, .cancelled)

        let grants = try await client.listGrants(userID: nil, connectorID: nil)
        XCTAssertEqual(grants.count, 0)

        let explanation = try await client.explainPolicy(policyID: "pol_1")
        XCTAssertEqual(explanation.policyID, "pol_1")

        let suggestions = try await client.suggestResources()
        XCTAssertEqual(suggestions.count, 0)
    }

    /// Sanity-check that `AccessSDKError` is a value type with stable cases.
    func testErrorCases() {
        XCTAssertEqual(AccessSDKError.unauthenticated, AccessSDKError.unauthenticated)
        XCTAssertNotEqual(
            AccessSDKError.http(statusCode: 401, body: nil),
            AccessSDKError.http(statusCode: 403, body: nil)
        )
    }
}
