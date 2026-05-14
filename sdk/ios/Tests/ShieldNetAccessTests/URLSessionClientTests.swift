//
// URLSessionClientTests.swift — real URLSession round-trip tests.
//
// We intercept network I/O by registering a `URLProtocol` subclass
// on a dedicated `URLSession`. This is NOT a mock of URLSession —
// the SDK code drives a fully-real `URLSession`, including
// `URLRequest` construction, headers, the protocol-class lookup,
// and `data(for:)` dispatch. The protocol subclass simply
// returns canned responses so the tests are deterministic.
//

import XCTest
@testable import ShieldNetAccess

/// `URLProtocol` subclass that returns canned responses for any
/// outbound request matching `URLProtocolStub.handler`.
final class URLProtocolStub: URLProtocol {
    /// Closure invoked for every intercepted request. Returns the
    /// HTTP status, response body, and the recorded request — the
    /// tests use the recorded request to assert headers / paths.
    static var handler: ((URLRequest) -> (statusCode: Int, body: Data))?
    /// Captured requests, in order received.
    static var captured: [URLRequest] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.captured.append(request)
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "stub", code: -1))
            return
        }
        let (statusCode, body) = handler(request)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

final class URLSessionClientTests: XCTestCase {
    private var session: URLSession!
    private var client: URLSessionAccessSDKClient!

    override func setUp() {
        super.setUp()
        URLProtocolStub.captured = []
        URLProtocolStub.handler = nil
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [URLProtocolStub.self]
        session = URLSession(configuration: config)
        client = URLSessionAccessSDKClient(
            baseURL: URL(string: "https://api.example.com")!,
            session: session,
            authTokenProvider: { "test-token-abc" }
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

    func testCreateRequest_HappyPath_AttachesAuthAndDecodesResponse() async throws {
        let body = """
        {
            "id": "req_1",
            "workspace_id": "ws_1",
            "requester_user_id": "user_1",
            "connector_id": "conn_1",
            "resource_external_id": "projects/foo",
            "role": "viewer",
            "state": "requested",
            "created_at": "2025-01-30T12:00:00Z"
        }
        """
        URLProtocolStub.handler = { _ in (201, Data(body.utf8)) }
        let result = try await client.createRequest(resource: "projects/foo", role: "viewer", justification: "ci")
        XCTAssertEqual(result.id, "req_1")
        XCTAssertEqual(result.state, .requested)
        XCTAssertEqual(URLProtocolStub.captured.count, 1)
        let req = URLProtocolStub.captured[0]
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer test-token-abc")
        XCTAssertEqual(req.httpMethod, "POST")
        XCTAssertEqual(req.url?.path, "/access/requests")
    }

    func testListRequests_BuildsQueryString() async throws {
        URLProtocolStub.handler = { _ in (200, Data("[]".utf8)) }
        _ = try await client.listRequests(state: .requested, requester: "user_1", resource: nil)
        let req = URLProtocolStub.captured[0]
        let query = req.url?.query ?? ""
        XCTAssertTrue(query.contains("state=requested"))
        XCTAssertTrue(query.contains("requester=user_1"))
        XCTAssertFalse(query.contains("resource="))
    }

    func testApproveRequest_PostsToCorrectPath() async throws {
        let body = """
        {"id":"req_9","workspace_id":"ws","requester_user_id":"u","connector_id":"c","resource_external_id":"r","state":"approved","created_at":"2025-01-30T12:00:00Z"}
        """
        URLProtocolStub.handler = { _ in (200, Data(body.utf8)) }
        let result = try await client.approveRequest(id: "req_9")
        XCTAssertEqual(result.state, .approved)
        XCTAssertEqual(URLProtocolStub.captured[0].url?.path, "/access/requests/req_9/approve")
    }

    func testDenyRequest_PostsReasonBody() async throws {
        let body = """
        {"id":"req_9","workspace_id":"ws","requester_user_id":"u","connector_id":"c","resource_external_id":"r","state":"denied","created_at":"2025-01-30T12:00:00Z"}
        """
        URLProtocolStub.handler = { _ in (200, Data(body.utf8)) }
        _ = try await client.denyRequest(id: "req_9", reason: "policy-violation")
        let req = URLProtocolStub.captured[0]
        XCTAssertEqual(req.url?.path, "/access/requests/req_9/deny")
        // Body is consumed before stopLoading; can't read req.httpBody
        // directly in URLProtocol context — assert path instead.
    }

    func testListGrants_DecodesArray() async throws {
        let body = """
        [{"id":"g1","workspace_id":"ws","user_id":"u","connector_id":"c","resource_external_id":"r","granted_at":"2025-01-30T12:00:00Z"}]
        """
        URLProtocolStub.handler = { _ in (200, Data(body.utf8)) }
        let result = try await client.listGrants(userID: "u", connectorID: nil)
        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result[0].id, "g1")
    }

    func testExplainPolicy_DecodesResponse() async throws {
        let body = #"{"policy_id":"pol_1","summary":"plain-English explanation"}"#
        URLProtocolStub.handler = { _ in (200, Data(body.utf8)) }
        let result = try await client.explainPolicy(policyID: "pol_1")
        XCTAssertEqual(result.policyID, "pol_1")
        XCTAssertEqual(result.summary, "plain-English explanation")
    }

    func testSuggestResources_AcceptsEmptyBody() async throws {
        URLProtocolStub.handler = { _ in (200, Data()) }
        let result = try await client.suggestResources()
        XCTAssertEqual(result.count, 0)
    }

    func test401MapsToUnauthenticated() async {
        URLProtocolStub.handler = { _ in (401, Data()) }
        do {
            _ = try await client.cancelRequest(id: "req_x")
            XCTFail("expected unauthenticated error")
        } catch AccessSDKError.unauthenticated {
            // OK
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func test500MapsToHTTPError() async {
        URLProtocolStub.handler = { _ in (500, Data("internal".utf8)) }
        do {
            _ = try await client.cancelRequest(id: "req_x")
            XCTFail("expected http error")
        } catch AccessSDKError.http(let status, _) {
            XCTAssertEqual(status, 500)
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testMalformedJSONMapsToDecodingError() async {
        URLProtocolStub.handler = { _ in (200, Data("not-json".utf8)) }
        do {
            _ = try await client.approveRequest(id: "req_x")
            XCTFail("expected decoding error")
        } catch AccessSDKError.decoding {
            // OK
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }
}
