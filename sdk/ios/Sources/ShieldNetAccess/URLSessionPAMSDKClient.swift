//
// URLSessionPAMSDKClient.swift — production URLSession-backed
// implementation of `PAMSDKClient`.
//
// Each protocol method serialises its inputs to JSON, builds a real
// `URLRequest` against `ztna-api`, attaches a bearer token from the
// caller-supplied async provider, and decodes the response body
// using a per-call `JSONDecoder`. Errors are mapped to
// `AccessSDKError` — PAM does not introduce a new error type so
// host applications can reuse their existing access-error UI.
//
// The class deliberately keeps a transport implementation that is
// parallel to `URLSessionAccessSDKClient` rather than reaching into
// `URLSessionAccessSDKClient`'s private members. The duplication is
// small (≈ 50 lines) and means the PAM extension can ship without
// breaking host apps that already pin a specific version of the
// access client.
//

import Foundation

/// Production HTTP client conforming to `PAMSDKClient`.
public final class URLSessionPAMSDKClient: PAMSDKClient, @unchecked Sendable {
    private let baseURL: URL
    private let session: URLSession
    private let authTokenProvider: @Sendable () async throws -> String

    /// Construct a client. `baseURL` is the `ztna-api` root (no
    /// trailing slash). `session` defaults to `URLSession.shared`
    /// but callers can override it for connection pooling /
    /// pinning. `authTokenProvider` returns a current bearer token;
    /// the client invokes it on every request so token refresh
    /// stays the caller's responsibility.
    public init(
        baseURL: URL,
        session: URLSession = .shared,
        authTokenProvider: @Sendable @escaping () async throws -> String
    ) {
        self.baseURL = baseURL
        self.session = session
        self.authTokenProvider = authTokenProvider
    }

    // MARK: - PAMSDKClient — push parsing + number matching

    public func parseApprovalNotification(
        userInfo: [AnyHashable: Any]
    ) throws -> PAMApprovalNotification {
        // Re-wrap the userInfo dict so JSONSerialization can encode
        // it; APNS hands us `[AnyHashable: Any]` but the values are
        // already JSON-friendly types (String, Number, Array, Dict)
        // because the payload travelled across the APNS wire.
        let dict = userInfo.reduce(into: [String: Any]()) { acc, pair in
            if let key = pair.key as? String {
                acc[key] = pair.value
            }
        }
        guard !dict.isEmpty else {
            throw AccessSDKError.invalidInput("empty push payload")
        }
        // Reject payloads without the `type` discriminator so the
        // SDK never decodes an unrelated push (e.g. an access
        // notification) into the PAM shape.
        guard let typeValue = dict["type"] as? String else {
            throw AccessSDKError.invalidInput("push payload missing 'type'")
        }
        if PAMNotificationType(rawValue: typeValue) == nil {
            throw AccessSDKError.invalidInput("unsupported push type: \(typeValue)")
        }
        let data: Data
        do {
            data = try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
        } catch {
            throw AccessSDKError.invalidInput("could not re-serialise push payload: \(error)")
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(PAMApprovalNotification.self, from: data)
        } catch {
            throw AccessSDKError.decoding(String(describing: error))
        }
    }

    public func verifyMatchedCode(
        selected: String,
        notification: PAMApprovalNotification
    ) -> NumberMatchOutcome {
        // Constant-time comparison of the UTF-8 bytes so a timing
        // side-channel cannot leak which decoy the user tapped.
        let lhs = Array(selected.utf8)
        let rhs = Array(notification.matchedCode.utf8)
        if lhs.count != rhs.count {
            return .mismatched
        }
        var diff: UInt8 = 0
        for i in 0..<lhs.count {
            diff |= lhs[i] ^ rhs[i]
        }
        return diff == 0 ? .matched : .mismatched
    }

    // MARK: - PAMSDKClient — approval flow

    public func approveLease(
        notification: PAMApprovalNotification,
        approverUserID: String,
        durationMinutes: Int?,
        selectedCode: String
    ) async throws -> PAMLease {
        // Guard at the SDK layer — the server performs the same
        // check, but failing fast saves a round-trip and keeps the
        // UX honest. A caller that wants to defer verification
        // until the server can pass `notification.matchedCode`
        // through verbatim; the SDK still rejects empty input.
        if approverUserID.isEmpty {
            throw AccessSDKError.invalidInput("approver_user_id is required")
        }
        if selectedCode.isEmpty {
            throw AccessSDKError.invalidInput("selected_code is required")
        }
        if verifyMatchedCode(selected: selectedCode, notification: notification) != .matched {
            throw AccessSDKError.invalidInput("selected_code does not match")
        }
        struct Body: Encodable {
            let workspaceID: String
            let approverID: String
            let durationMinutes: Int?
            let matchedCode: String
            enum CodingKeys: String, CodingKey {
                case workspaceID = "workspace_id"
                case approverID = "approver_id"
                case durationMinutes = "duration_minutes"
                case matchedCode = "matched_code"
            }
        }
        return try await post(
            path: "/pam/leases/\(notification.leaseID)/approve",
            body: Body(
                workspaceID: notification.workspaceID,
                approverID: approverUserID,
                durationMinutes: durationMinutes,
                matchedCode: selectedCode
            )
        )
    }

    public func denyLease(
        notification: PAMApprovalNotification,
        reason: String
    ) async throws -> PAMLease {
        struct Body: Encodable {
            let workspaceID: String
            let reason: String
            enum CodingKeys: String, CodingKey {
                case workspaceID = "workspace_id"
                case reason
            }
        }
        return try await post(
            path: "/pam/leases/\(notification.leaseID)/revoke",
            body: Body(workspaceID: notification.workspaceID, reason: reason)
        )
    }

    // MARK: - PAMSDKClient — passkey reveal

    public func revealSecret(
        secretID: String,
        workspaceID: String,
        userID: String,
        assertion: PassKeyAssertion
    ) async throws -> PAMSecretRevealResponse {
        if secretID.isEmpty {
            throw AccessSDKError.invalidInput("secret_id is required")
        }
        if workspaceID.isEmpty {
            throw AccessSDKError.invalidInput("workspace_id is required")
        }
        if userID.isEmpty {
            throw AccessSDKError.invalidInput("user_id is required")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let assertionJSON: String
        do {
            let data = try encoder.encode(assertion)
            assertionJSON = String(decoding: data, as: UTF8.self)
        } catch {
            throw AccessSDKError.invalidInput("encode passkey assertion: \(error)")
        }
        struct Body: Encodable {
            let workspaceID: String
            let userID: String
            let mfaAssertion: String
            enum CodingKeys: String, CodingKey {
                case workspaceID = "workspace_id"
                case userID = "user_id"
                case mfaAssertion = "mfa_assertion"
            }
        }
        return try await post(
            path: "/pam/secrets/\(secretID)/reveal",
            body: Body(workspaceID: workspaceID, userID: userID, mfaAssertion: assertionJSON)
        )
    }

    // MARK: - Transport primitives (parallel to URLSessionAccessSDKClient)

    private func post<T: Decodable, B: Encodable>(path: String, body: B) async throws -> T {
        let url = baseURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        try await attachAuth(&request)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        do {
            request.httpBody = try encoder.encode(body)
        } catch {
            throw AccessSDKError.invalidInput("encode body: \(error)")
        }
        return try await dispatch(request: request)
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

    private func dispatch<T: Decodable>(request: URLRequest) async throws -> T {
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
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw AccessSDKError.decoding(String(describing: error))
        }
    }
}
