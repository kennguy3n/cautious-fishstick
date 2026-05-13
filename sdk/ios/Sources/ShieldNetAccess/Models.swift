//
// Models.swift — Swift data model types for the ShieldNet 360 Access SDK.
//
// These types mirror the JSON payloads exchanged with `ztna-api` per
// `docs/PROPOSAL.md` §11.4 (Shared REST API). They are intentionally simple
// value types (`Codable` structs) so they can be encoded / decoded by
// `URLSession`-based concrete clients in the host application.
//
// REST endpoints:
//   POST   /access/requests                    → create
//   GET    /access/requests                    → list (filter by state /
//                                                requester / resource)
//   POST   /access/requests/:id/approve        → approve
//   POST   /access/requests/:id/deny           → deny
//   POST   /access/requests/:id/cancel         → cancel
//   GET    /access/grants                      → list active grants
//   POST   /access/explain                     → policy explanation
//   POST   /access/suggest                     → resource suggestions
//
// There is NO on-device inference. No `import CoreML`, no `import MLX`, no
// bundled model files. Server-side AI calls are delegated to the
// `/access/explain` and `/access/suggest` endpoints which the backend
// forwards to `access-ai-agent` via A2A.
//

import Foundation

/// Lifecycle state of an `AccessRequest`. Values mirror the Go-side
/// `access.RequestState` constants in
/// `internal/services/access/request_state_machine.go`.
public enum AccessRequestState: String, Codable, CaseIterable, Sendable {
    case requested
    case approved
    case denied
    case cancelled
    case provisioning
    case provisioned
    case provisionFailed = "provision_failed"
    case active
    case revoked
    case expired
}

/// Coarse risk bucket for an `AccessRequest`. Values mirror the Go-side
/// `models.RequestRiskLow` / `RequestRiskMedium` / `RequestRiskHigh`
/// constants in `internal/models/access_request.go`. The server stores
/// risk as a string bucket; finer-grained numeric scoring is a Phase 4
/// AI-agent concern.
public enum AccessRequestRiskScore: String, Codable, CaseIterable, Sendable {
    case low
    case medium
    case high
}

/// Persisted access request row.
///
/// Mirrors `access_requests` (`docs/ARCHITECTURE.md` §10). Returned by
/// `POST /access/requests` and `GET /access/requests`.
public struct AccessRequest: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let workspaceID: String
    public let requesterUserID: String
    public let targetUserID: String?
    public let resourceExternalID: String
    public let role: String?
    public let justification: String?
    public let state: AccessRequestState
    public let riskScore: AccessRequestRiskScore?
    public let riskFactors: [String]?
    public let workflowID: String?
    public let createdAt: Date
    public let updatedAt: Date?

    public init(
        id: String,
        workspaceID: String,
        requesterUserID: String,
        targetUserID: String? = nil,
        resourceExternalID: String,
        role: String? = nil,
        justification: String? = nil,
        state: AccessRequestState,
        riskScore: AccessRequestRiskScore? = nil,
        riskFactors: [String]? = nil,
        workflowID: String? = nil,
        createdAt: Date,
        updatedAt: Date? = nil
    ) {
        self.id = id
        self.workspaceID = workspaceID
        self.requesterUserID = requesterUserID
        self.targetUserID = targetUserID
        self.resourceExternalID = resourceExternalID
        self.role = role
        self.justification = justification
        self.state = state
        self.riskScore = riskScore
        self.riskFactors = riskFactors
        self.workflowID = workflowID
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    enum CodingKeys: String, CodingKey {
        case id
        case workspaceID = "workspace_id"
        case requesterUserID = "requester_user_id"
        case targetUserID = "target_user_id"
        case resourceExternalID = "resource_external_id"
        case role
        case justification
        case state
        case riskScore = "risk_score"
        case riskFactors = "risk_factors"
        case workflowID = "workflow_id"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

/// Active upstream grant. Mirrors `access_grants`. Returned by
/// `GET /access/grants`.
public struct AccessGrant: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let workspaceID: String
    public let userID: String
    public let connectorID: String
    public let resourceExternalID: String
    public let role: String?
    public let grantedAt: Date
    public let expiresAt: Date?
    public let lastUsedAt: Date?
    public let revokedAt: Date?

    public init(
        id: String,
        workspaceID: String,
        userID: String,
        connectorID: String,
        resourceExternalID: String,
        role: String? = nil,
        grantedAt: Date,
        expiresAt: Date? = nil,
        lastUsedAt: Date? = nil,
        revokedAt: Date? = nil
    ) {
        self.id = id
        self.workspaceID = workspaceID
        self.userID = userID
        self.connectorID = connectorID
        self.resourceExternalID = resourceExternalID
        self.role = role
        self.grantedAt = grantedAt
        self.expiresAt = expiresAt
        self.lastUsedAt = lastUsedAt
        self.revokedAt = revokedAt
    }

    enum CodingKeys: String, CodingKey {
        case id
        case workspaceID = "workspace_id"
        case userID = "user_id"
        case connectorID = "connector_id"
        case resourceExternalID = "resource_external_id"
        case role
        case grantedAt = "granted_at"
        case expiresAt = "expires_at"
        case lastUsedAt = "last_used_at"
        case revokedAt = "revoked_at"
    }
}

/// Plain-English explanation of a policy, produced server-side by the
/// `policy_recommendation` agent and returned by `POST /access/explain`.
public struct PolicyExplanation: Codable, Sendable, Equatable {
    public let policyID: String
    public let summary: String
    public let rationale: [String]
    public let affectedResources: [String]

    public init(
        policyID: String,
        summary: String,
        rationale: [String] = [],
        affectedResources: [String] = []
    ) {
        self.policyID = policyID
        self.summary = summary
        self.rationale = rationale
        self.affectedResources = affectedResources
    }

    enum CodingKeys: String, CodingKey {
        case policyID = "policy_id"
        case summary
        case rationale
        case affectedResources = "affected_resources"
    }
}

/// Recommended resource for the calling user. Returned (as an array) by
/// `POST /access/suggest`.
public struct Suggestion: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let resourceExternalID: String
    public let displayName: String
    public let reason: String
    public let confidence: Double?

    public init(
        id: String,
        resourceExternalID: String,
        displayName: String,
        reason: String,
        confidence: Double? = nil
    ) {
        self.id = id
        self.resourceExternalID = resourceExternalID
        self.displayName = displayName
        self.reason = reason
        self.confidence = confidence
    }

    enum CodingKeys: String, CodingKey {
        case id
        case resourceExternalID = "resource_external_id"
        case displayName = "display_name"
        case reason
        case confidence
    }
}

/// Filter for `AccessSDKClient.listRequests`.
public struct AccessRequestListFilter: Sendable, Equatable {
    public let state: AccessRequestState?
    public let requesterUserID: String?
    public let resourceExternalID: String?

    public init(
        state: AccessRequestState? = nil,
        requesterUserID: String? = nil,
        resourceExternalID: String? = nil
    ) {
        self.state = state
        self.requesterUserID = requesterUserID
        self.resourceExternalID = resourceExternalID
    }
}

/// Filter for `AccessSDKClient.listGrants`.
public struct AccessGrantListFilter: Sendable, Equatable {
    public let userID: String?
    public let connectorID: String?

    public init(userID: String? = nil, connectorID: String? = nil) {
        self.userID = userID
        self.connectorID = connectorID
    }
}
