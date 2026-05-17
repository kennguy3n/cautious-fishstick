//
// PAMModels.swift — Swift data model types for the PAM extension of
// the ShieldNet 360 Access SDK.
//
// These types mirror the JSON payloads exchanged with `ztna-api` for the
// Privileged Access Management surface documented in
// `docs/pam/architecture.md` §6 and `docs/pam/proposal.md`. They are
// intentionally simple value types (`Codable` structs / enums) so they
// can be encoded / decoded by `URLSession`-based concrete clients in
// the host application.
//
// REST endpoints exercised by `PAMSDKClient`:
//
//   POST   /pam/leases/:id/approve   → approve a pending lease
//                                       (number-matching code optional)
//   POST   /pam/leases/:id/revoke    → deny / revoke a lease, with a
//                                       free-text reason
//   POST   /pam/secrets/:id/reveal   → reveal a vaulted secret after a
//                                       passkey (FIDO2 / WebAuthn) step-up
//                                       assertion
//
// There is NO on-device inference in this SDK — the same rule that
// governs the access surface applies here. Risk scores, criticality
// labels, and number-matching codes are all server-issued and arrive
// in the push notification payload.
//
// Push notification payload shape (APNS / FCM data dict):
//
//   {
//     "type": "pam.approval.requested",
//     "lease_id": "lse_01HXYZ...",
//     "workspace_id": "ws_...",
//     "requester_user_id": "usr_...",
//     "asset_name": "prod-db-1",
//     "protocol": "postgres",
//     "criticality": "crown_jewel",
//     "risk_score": "high",
//     "risk_factors": ["unusual_time", "first_time_asset"],
//     "matched_code": "47",
//     "decoy_codes": ["12", "98"],
//     "justification": "incident IR-2025-04",
//     "expires_at": "2025-06-01T12:00:00Z"
//   }
//

import Foundation

/// Wire protocol negotiated for the PAM session this approval prompt
/// is gating. Mirrors the `pam.session.protocol` enum captured by
/// `internal/services/pam/session_service.go`.
public enum PAMSessionProtocol: String, Codable, CaseIterable, Sendable {
    case ssh
    case kubernetes
    case postgres
    case mysql
    case mariadb
}

/// Coarse criticality bucket for the asset being accessed. Mirrors
/// `models.PAMAssetCriticality*` constants in
/// `internal/models/pam_asset.go`. `crownJewel` is the highest tier
/// and always demands an approver — server policy ignores
/// `autoApprove` for crown-jewel assets.
public enum PAMAssetCriticality: String, Codable, CaseIterable, Sendable {
    case low
    case medium
    case high
    case crownJewel = "crown_jewel"
}

/// Risk bucket returned by the `pam_session_risk_assessment` A2A
/// skill (`cmd/access-ai-agent/skills/pam_session_risk.py`). Same
/// three-bucket grading the access surface uses.
public enum PAMRiskScore: String, Codable, CaseIterable, Sendable {
    case low
    case medium
    case high
}

/// Push notification type discriminator. The mobile SDK only handles
/// `pam.approval.requested` today — the value is exposed verbatim so
/// host apps can filter by type before routing into the SDK parser.
public enum PAMNotificationType: String, Codable, Sendable {
    case approvalRequested = "pam.approval.requested"
}

/// Parsed PAM approval push payload.
///
/// Produced by `PAMSDKClient.parseApprovalNotification(userInfo:)`.
/// The `matchedCode` is the digit string the requester is staring at
/// on their device; the approver must select the same value out of
/// the union of `{matchedCode} ∪ decoyCodes`. The selection is sent
/// back to the server in the approve call so a stolen device that
/// taps the prompt without seeing the requester's screen has only a
/// 1-in-(N+1) chance of guessing correctly.
public struct PAMApprovalNotification: Codable, Sendable, Equatable {
    public let type: PAMNotificationType
    public let leaseID: String
    public let workspaceID: String
    public let requesterUserID: String
    public let assetName: String
    public let `protocol`: PAMSessionProtocol
    public let criticality: PAMAssetCriticality
    public let riskScore: PAMRiskScore
    public let riskFactors: [String]
    public let matchedCode: String
    public let decoyCodes: [String]
    public let justification: String?
    public let expiresAt: Date?

    public init(
        type: PAMNotificationType = .approvalRequested,
        leaseID: String,
        workspaceID: String,
        requesterUserID: String,
        assetName: String,
        protocol: PAMSessionProtocol,
        criticality: PAMAssetCriticality,
        riskScore: PAMRiskScore,
        riskFactors: [String] = [],
        matchedCode: String,
        decoyCodes: [String] = [],
        justification: String? = nil,
        expiresAt: Date? = nil
    ) {
        self.type = type
        self.leaseID = leaseID
        self.workspaceID = workspaceID
        self.requesterUserID = requesterUserID
        self.assetName = assetName
        self.`protocol` = `protocol`
        self.criticality = criticality
        self.riskScore = riskScore
        self.riskFactors = riskFactors
        self.matchedCode = matchedCode
        self.decoyCodes = decoyCodes
        self.justification = justification
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case type
        case leaseID = "lease_id"
        case workspaceID = "workspace_id"
        case requesterUserID = "requester_user_id"
        case assetName = "asset_name"
        case `protocol`
        case criticality
        case riskScore = "risk_score"
        case riskFactors = "risk_factors"
        case matchedCode = "matched_code"
        case decoyCodes = "decoy_codes"
        case justification
        case expiresAt = "expires_at"
    }

    /// Returns the union of `matchedCode` and `decoyCodes` in a
    /// stable, sorted order. Useful for laying out the
    /// "Confirm-the-number" prompt without leaking which entry is
    /// the real one.
    public var allCodes: [String] {
        var codes = decoyCodes
        codes.append(matchedCode)
        // Sort numerically when the codes parse as integers; fall
        // back to lexicographic order otherwise so the layout stays
        // deterministic for tests.
        return codes.sorted { lhs, rhs in
            if let li = Int(lhs), let ri = Int(rhs) {
                return li < ri
            }
            return lhs < rhs
        }
    }
}

/// Lifecycle state of a `PAMLease`. Mirrors the Go-side constants
/// in `internal/models/pam_lease.go`.
public enum PAMLeaseState: String, Codable, CaseIterable, Sendable {
    case requested
    case granted
    case denied
    case expired
    case revoked
}

/// Persisted lease row returned by `POST /pam/leases/:id/approve`
/// and `POST /pam/leases/:id/revoke`.
public struct PAMLease: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let workspaceID: String
    public let userID: String
    public let assetID: String
    public let accountID: String
    public let reason: String?
    public let state: PAMLeaseState
    public let approvedBy: String?
    public let grantedAt: Date?
    public let expiresAt: Date?
    public let revokedAt: Date?
    public let createdAt: Date

    public init(
        id: String,
        workspaceID: String,
        userID: String,
        assetID: String,
        accountID: String,
        reason: String? = nil,
        state: PAMLeaseState,
        approvedBy: String? = nil,
        grantedAt: Date? = nil,
        expiresAt: Date? = nil,
        revokedAt: Date? = nil,
        createdAt: Date
    ) {
        self.id = id
        self.workspaceID = workspaceID
        self.userID = userID
        self.assetID = assetID
        self.accountID = accountID
        self.reason = reason
        self.state = state
        self.approvedBy = approvedBy
        self.grantedAt = grantedAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey {
        case id
        case workspaceID = "workspace_id"
        case userID = "user_id"
        case assetID = "asset_id"
        case accountID = "account_id"
        case reason
        case state
        case approvedBy = "approved_by"
        case grantedAt = "granted_at"
        case expiresAt = "expires_at"
        case revokedAt = "revoked_at"
        case createdAt = "created_at"
    }
}

/// FIDO2 / WebAuthn assertion produced by the host application's
/// `ASAuthorizationController` flow. The SDK treats the assertion as
/// an opaque blob — the server-side `MFAVerifier` interprets it.
///
/// `clientDataJSON`, `authenticatorData`, `signature`, and
/// `userHandle` are the four fields a WebAuthn assertion always
/// surfaces; `credentialID` is the public-key credential identifier
/// the relying party stored at registration time. All five are
/// base64url-encoded strings on the wire so the JSON envelope stays
/// transport-safe.
public struct PassKeyAssertion: Codable, Sendable, Equatable {
    public let credentialID: String
    public let clientDataJSON: String
    public let authenticatorData: String
    public let signature: String
    public let userHandle: String?

    public init(
        credentialID: String,
        clientDataJSON: String,
        authenticatorData: String,
        signature: String,
        userHandle: String? = nil
    ) {
        self.credentialID = credentialID
        self.clientDataJSON = clientDataJSON
        self.authenticatorData = authenticatorData
        self.signature = signature
        self.userHandle = userHandle
    }

    enum CodingKeys: String, CodingKey {
        case credentialID = "credential_id"
        case clientDataJSON = "client_data_json"
        case authenticatorData = "authenticator_data"
        case signature
        case userHandle = "user_handle"
    }
}

/// Response payload from `POST /pam/secrets/:id/reveal`. The
/// `plaintext` is one-shot — clients must zero / overwrite the
/// string buffer as soon as it has been used. The server emits a
/// `pam.secret.revealed` Kafka event before returning so even a
/// successful reveal is auditable.
public struct PAMSecretRevealResponse: Codable, Sendable, Equatable {
    public let secretID: String
    public let plaintext: String

    public init(secretID: String, plaintext: String) {
        self.secretID = secretID
        self.plaintext = plaintext
    }

    enum CodingKeys: String, CodingKey {
        case secretID = "secret_id"
        case plaintext
    }
}

/// Result of `PAMSDKClient.verifyMatchedCode`. The SDK does the
/// constant-time comparison in-process so a Yes/No outcome can be
/// surfaced to the UI before any network call is made.
public enum NumberMatchOutcome: Sendable, Equatable {
    /// The user picked the same digit string the requester is
    /// looking at — the approve flow can continue.
    case matched
    /// The user picked one of the decoy codes — the SDK rejects the
    /// approve flow client-side without round-tripping to the
    /// server.
    case mismatched
}
