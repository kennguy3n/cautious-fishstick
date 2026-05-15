//
// URLSessionAccessSDKClient.swift — production URLSession-backed
// implementation of `AccessSDKClient`.
//
// Each protocol method serialises its inputs to JSON, builds a real
// `URLRequest` against `ztna-api`, attaches a bearer token from the
// caller-supplied async provider, and decodes the response body
// using `JSONDecoder.convertFromSnakeCase`. Non-2xx responses are
// mapped to `AccessSDKError.http` / `AccessSDKError.unauthenticated`.
//
// This file deliberately depends only on `Foundation` — no Combine,
// no third-party HTTP libraries. Host applications can substitute
// their own `URLSession` (e.g. one with custom certificate pinning
// or background configuration) via the initializer.
//
// REST endpoint mapping is per `docs/overview.md` §11.4.
//

import Foundation

/// Production HTTP client conforming to `AccessSDKClient`.
///
/// Initialize once per app launch:
/// ```swift
/// let client = URLSessionAccessSDKClient(
///     baseURL: URL(string: "https://api.example.com")!,
///     authTokenProvider: { try await tokenStore.currentToken() }
/// )
/// ```
public final class URLSessionAccessSDKClient: AccessSDKClient, @unchecked Sendable {
    private let baseURL: URL
    private let session: URLSession
    private let authTokenProvider: @Sendable () async throws -> String

    /// Construct a client. `baseURL` is the `ztna-api` root (no
    /// trailing slash). `session` defaults to `URLSession.shared`
    /// but callers can override it for connection pooling / pinning.
    /// `authTokenProvider` returns a current bearer token; the
    /// client invokes it on every request so token refresh stays
    /// the caller's responsibility.
    public init(
        baseURL: URL,
        session: URLSession = .shared,
        authTokenProvider: @Sendable @escaping () async throws -> String
    ) {
        self.baseURL = baseURL
        self.session = session
        self.authTokenProvider = authTokenProvider
    }

    // MARK: - AccessSDKClient conformance

    public func createRequest(
        resource: String,
        role: String?,
        justification: String?
    ) async throws -> AccessRequest {
        struct Body: Encodable {
            let resourceExternalID: String
            let role: String?
            let justification: String?
            enum CodingKeys: String, CodingKey {
                case resourceExternalID = "resource_external_id"
                case role
                case justification
            }
        }
        return try await post(path: "/access/requests", body: Body(resourceExternalID: resource, role: role, justification: justification))
    }

    public func listRequests(
        state: AccessRequestState?,
        requester: String?,
        resource: String?
    ) async throws -> [AccessRequest] {
        var items: [URLQueryItem] = []
        if let state { items.append(URLQueryItem(name: "state", value: state.rawValue)) }
        if let requester { items.append(URLQueryItem(name: "requester", value: requester)) }
        if let resource { items.append(URLQueryItem(name: "resource", value: resource)) }
        return try await get(path: "/access/requests", query: items)
    }

    public func approveRequest(id: String) async throws -> AccessRequest {
        try await post(path: "/access/requests/\(id)/approve", body: EmptyBody())
    }

    public func denyRequest(id: String, reason: String) async throws -> AccessRequest {
        struct Body: Encodable { let reason: String }
        return try await post(path: "/access/requests/\(id)/deny", body: Body(reason: reason))
    }

    public func cancelRequest(id: String) async throws -> AccessRequest {
        try await post(path: "/access/requests/\(id)/cancel", body: EmptyBody())
    }

    public func listGrants(
        userID: String?,
        connectorID: String?
    ) async throws -> [AccessGrant] {
        var items: [URLQueryItem] = []
        if let userID { items.append(URLQueryItem(name: "user_id", value: userID)) }
        if let connectorID { items.append(URLQueryItem(name: "connector_id", value: connectorID)) }
        return try await get(path: "/access/grants", query: items)
    }

    public func explainPolicy(policyID: String) async throws -> PolicyExplanation {
        struct Body: Encodable {
            let policyID: String
            enum CodingKeys: String, CodingKey { case policyID = "policy_id" }
        }
        return try await post(path: "/access/explain", body: Body(policyID: policyID))
    }

    public func suggestResources() async throws -> [Suggestion] {
        // The server may legitimately return an empty body for the
        // "no suggestions" case; decode tolerates that.
        try await post(path: "/access/suggest", body: EmptyBody(), allowEmptyBody: true)
    }

    // MARK: - Transport primitives

    private struct EmptyBody: Encodable {}

    private func get<T: Decodable>(path: String, query: [URLQueryItem]) async throws -> T {
        var components = URLComponents(url: baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)
        if !query.isEmpty {
            components?.queryItems = query
        }
        guard let url = components?.url else {
            throw AccessSDKError.invalidInput("could not build URL for path \(path)")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        try await attachAuth(&request)
        return try await dispatch(request: request, allowEmptyBody: false)
    }

    private func post<T: Decodable, B: Encodable>(
        path: String,
        body: B,
        allowEmptyBody: Bool = false
    ) async throws -> T {
        let url = baseURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        try await attachAuth(&request)
        // The model types in `Models.swift` declare explicit
        // `CodingKeys` for every property, so we leave both encoder
        // and decoder using the default key strategy — the
        // `convertToSnakeCase` strategy would clash with the
        // explicit lowerCamelCase keys we define for nested
        // payload structs.
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        do {
            request.httpBody = try encoder.encode(body)
        } catch {
            throw AccessSDKError.invalidInput("encode body: \(error)")
        }
        return try await dispatch(request: request, allowEmptyBody: allowEmptyBody)
    }

    private func attachAuth(_ request: inout URLRequest) async throws {
        let token: String
        do {
            token = try await authTokenProvider()
        } catch {
            throw AccessSDKError.unauthenticated
        }
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
    }

    private func dispatch<T: Decodable>(request: URLRequest, allowEmptyBody: Bool) async throws -> T {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw AccessSDKError.transport(String(describing: error))
        }
        guard let http = response as? HTTPURLResponse else {
            throw AccessSDKError.transport("non-HTTP response")
        }
        if http.statusCode == 401 {
            throw AccessSDKError.unauthenticated
        }
        if !(200..<300).contains(http.statusCode) {
            let body = String(data: data, encoding: .utf8)
            throw AccessSDKError.http(statusCode: http.statusCode, body: body)
        }
        if data.isEmpty && allowEmptyBody {
            if let empty = (try? JSONDecoder().decode(T.self, from: Data("[]".utf8))) {
                return empty
            }
            if let empty = (try? JSONDecoder().decode(T.self, from: Data("{}".utf8))) {
                return empty
            }
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw AccessSDKError.decoding(String(describing: error))
        }
    }
}
