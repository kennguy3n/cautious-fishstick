package access

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// JMLService is the service layer for the Joiner / Mover / Leaver
// lifecycle per docs/PROPOSAL.md §5.4 and docs/ARCHITECTURE.md §7.
//
// JML automation is the Phase 6 feature that lets the access platform
// react to identity-store changes (typically via SCIM) without a
// human in the loop:
//
//   - Joiner: a new user appears in the workspace; default Teams are
//     assigned and the matching default access grants are pushed out
//     to every connector that owns a piece of the entitlement.
//   - Mover: an existing user's Team membership changes; the diff
//     drives a single atomic batch of revokes (for lost Teams) and
//     provisions (for gained Teams). PROPOSAL §5.4 calls this out as
//     "no partial-access window".
//   - Leaver: a user is deactivated; every active grant is revoked
//     synchronously and the user is removed from every Team.
//
// The service composes AccessRequestService and
// AccessProvisioningService — each Joiner/Mover-issued access grant
// goes through the same Phase 2 lifecycle (request → approved →
// provisioning → provisioned), so the audit trail and the FSM
// invariants stay intact. The only shortcut is that JML-issued
// requests are auto-approved (skip manual review) because the policy
// engine has already approved them implicitly by including them in
// the default grant set.
//
// Connector failures are bounded: a single grant that fails to
// provision (or revoke) does NOT abort the rest of the batch. The
// service returns a per-grant result list so the caller can surface
// partial failures to the operator.
type JMLService struct {
	db              *gorm.DB
	requestSvc      *AccessRequestService
	provisioningSvc *AccessProvisioningService
	// zitiClient is the optional Phase 6 OpenZiti hook. When set,
	// HandleLeaver calls DisableIdentity AFTER revoking every grant
	// and removing every team membership. nil means no OpenZiti
	// integration in this repo — the ZTNA business layer is
	// responsible for reconciling the identity state.
	zitiClient OpenZitiClient
	// ssoFedSvc is the optional Phase 11 hook into the Keycloak
	// federation surface. When set, the leaver flow flips the
	// Keycloak user to enabled=false and revokes every active SSO
	// session as the first kill-switch layer.
	ssoFedSvc *SSOFederationService
	// credLoader is the optional Phase 11 hook used to load the
	// (config, secrets) pair for each connector the user had
	// grants on. The leaver flow needs real credentials to call
	// SessionRevoker / SCIMProvisioner on the connector.
	credLoader *ConnectorCredentialsLoader
	// getConnectorFn lets tests inject a fake registry. Defaults
	// to access.GetAccessConnector.
	getConnectorFn func(provider string) (AccessConnector, error)
	// realmFor maps a workspace ID to its Keycloak realm. Defaults
	// to identity (the workspace ID is the realm name).
	realmFor func(workspaceID string) string
	// auditProducer is the optional Phase 11 hook into the
	// ShieldnetLogEvent audit pipeline. When set, HandleLeaver
	// publishes a LeaverKillSwitchEvent for each kill-switch layer
	// it fires. nil means dev / test mode — events are dropped
	// silently so binaries without a Kafka broker keep working.
	auditProducer AuditProducer
	now           func() time.Time
	newID         func() string
}

// NewJMLService returns a new service backed by db. db must not be
// nil. The caller passes the same AccessProvisioningService instance
// the rest of the application uses so connector resolution + state
// transitions share a single registry.
func NewJMLService(db *gorm.DB, provisioningSvc *AccessProvisioningService) *JMLService {
	if provisioningSvc == nil {
		// Construct a fresh provisioning service so nil-callers
		// (typically integration tests that wire only the request
		// + JML services) still compile. The service is unusable
		// for actual provisioning without a registered connector,
		// but that's the same constraint AccessProvisioningService
		// imposes on its own callers.
		provisioningSvc = NewAccessProvisioningService(db)
	}
	return &JMLService{
		db:              db,
		requestSvc:      provisioningSvc.requestSvc,
		provisioningSvc: provisioningSvc,
		getConnectorFn:  GetAccessConnector,
		realmFor:        func(workspaceID string) string { return workspaceID },
		now:             provisioningSvc.now,
		newID:           provisioningSvc.newID,
	}
}

// SetOpenZitiClient wires an OpenZitiClient onto the service.
// HandleLeaver calls DisableIdentity AFTER revoking every grant and
// removing every team membership. Passing nil restores the default
// "no OpenZiti integration in this repo" behaviour. Call this once
// at boot from cmd/ztna-api; it is NOT safe to call concurrently
// with HandleLeaver.
func (s *JMLService) SetOpenZitiClient(c OpenZitiClient) {
	s.zitiClient = c
}

// SetSSOFederationService wires the Phase 11 Keycloak federation
// hook. When set, HandleLeaver disables the Keycloak user and
// invalidates every active SSO session as the first kill-switch
// layer. Passing nil restores the default "no Keycloak
// integration" behaviour. Call this once at boot from cmd/ztna-api;
// it is NOT safe to call concurrently with HandleLeaver.
func (s *JMLService) SetSSOFederationService(svc *SSOFederationService) {
	s.ssoFedSvc = svc
}

// SetConnectorCredentialsLoader wires the Phase 11 credentials
// loader. The leaver flow needs decoded (config, secrets) pairs to
// call SessionRevoker / SCIMProvisioner on each connector the
// user had grants on. Without a loader the per-connector session
// revoke / SCIM deprovision layers are skipped with a log line.
func (s *JMLService) SetConnectorCredentialsLoader(l *ConnectorCredentialsLoader) {
	s.credLoader = l
}

// SetAuditProducer wires the Phase 11 audit producer onto the
// service. When set, HandleLeaver publishes a
// LeaverKillSwitchEvent for each kill-switch layer it fires (one
// per connector for the per-connector layers). Passing nil restores
// the default "no audit" behaviour. Call this once at boot from
// cmd/ztna-api; it is NOT safe to call concurrently with
// HandleLeaver.
func (s *JMLService) SetAuditProducer(p AuditProducer) {
	s.auditProducer = p
}

// emitLeaverEvent is the internal helper HandleLeaver calls to
// publish one kill-switch audit event. nil producer is a no-op;
// publish errors log but never block the kill switch.
func (s *JMLService) emitLeaverEvent(ctx context.Context, ev LeaverKillSwitchEvent) {
	if s.auditProducer == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		if s.now != nil {
			ev.Timestamp = s.now()
		} else {
			ev.Timestamp = time.Now().UTC()
		}
	}
	if err := publishLeaverEvent(ctx, s.auditProducer, ev); err != nil {
		log.Printf("access: leaver audit publish failed for layer %s: %v", ev.Layer, err)
	}
}

// SetKeycloakRealmResolver overrides the default workspace-id-is-
// realm-name mapping. Used by deployments where the Keycloak realm
// name diverges from the workspace ULID (e.g. a slug column).
func (s *JMLService) SetKeycloakRealmResolver(fn func(workspaceID string) string) {
	if fn == nil {
		s.realmFor = func(workspaceID string) string { return workspaceID }
		return
	}
	s.realmFor = fn
}

// JMLEventKind classifies a SCIM event into the JML lane the service
// will route it onto.
type JMLEventKind string

const (
	// JMLEventJoiner is a new-user event (SCIM POST /Users with
	// Active=true).
	JMLEventJoiner JMLEventKind = "joiner"
	// JMLEventMover is an attribute-or-group change on an existing
	// user (SCIM PATCH /Users/:id).
	JMLEventMover JMLEventKind = "mover"
	// JMLEventLeaver is a user deactivation (SCIM PATCH /Users/:id
	// with Active=false, or DELETE /Users/:id).
	JMLEventLeaver JMLEventKind = "leaver"
	// JMLEventUnknown is the fallback for events we cannot classify
	// (e.g. a no-op PATCH that touches no group / attribute).
	JMLEventUnknown JMLEventKind = "unknown"
)

// SCIMEvent is the minimal abstraction over a SCIM payload the JML
// service needs to classify the event. The handler layer maps SCIM
// JSON into this shape so the service does not couple to the SCIM
// schema directly.
type SCIMEvent struct {
	// Operation is "POST" / "PATCH" / "DELETE" — the inbound HTTP
	// verb that triggered the event.
	Operation string
	// Active is the post-event Active state of the user. nil means
	// "not present in the payload"; the classifier treats this as
	// "no change to active state".
	Active *bool
	// HasGroupChanges flags PATCH events that mutate group / team
	// membership. The classifier needs this because a PATCH that
	// only changes display name is NOT a Mover event.
	HasGroupChanges bool
	// HasAttributeChanges flags PATCH events that mutate user
	// attributes that drive Team-attribute matching (department,
	// title, location, ...). Same reasoning as HasGroupChanges.
	HasAttributeChanges bool
}

// ClassifyChange returns the JML lane for the supplied SCIM event.
// Classification is intentionally simple and deterministic so the
// service layer cannot accidentally route a mover into the joiner
// lane (or vice-versa).
//
// The rules (per PROPOSAL §5.4):
//
//   - POST with Active!=false   → joiner
//   - DELETE                    → leaver
//   - PATCH with Active=false   → leaver
//   - PATCH with group / attribute changes → mover
//   - any other PATCH           → unknown (no JML action)
func (s *JMLService) ClassifyChange(ev SCIMEvent) JMLEventKind {
	switch ev.Operation {
	case "POST":
		if ev.Active != nil && !*ev.Active {
			return JMLEventLeaver
		}
		return JMLEventJoiner
	case "DELETE":
		return JMLEventLeaver
	case "PATCH":
		if ev.Active != nil && !*ev.Active {
			return JMLEventLeaver
		}
		if ev.HasGroupChanges || ev.HasAttributeChanges {
			return JMLEventMover
		}
		return JMLEventUnknown
	}
	return JMLEventUnknown
}

// JMLAccessGrant describes a single grant the JML service should
// drive through the request → approved → provisioned lifecycle on
// behalf of a joiner / mover. Mirrors models.AccessGrant minus the
// fields the service is responsible for populating (ID, GrantedAt,
// state, audit timestamps).
type JMLAccessGrant struct {
	ConnectorID        string
	ResourceExternalID string
	Role               string
	ExpiresAt          *time.Time
}

// JoinerInput is the input contract for HandleJoiner. WorkspaceID,
// UserID and at least one of TeamIDs / DefaultGrants are required.
// Justification is the reason recorded in the access_request audit
// trail; defaults to "joiner: default access" when empty.
type JoinerInput struct {
	WorkspaceID   string
	UserID        string
	TeamIDs       []string
	DefaultGrants []JMLAccessGrant
	Justification string
}

// JMLGrantResult is one entry in the per-grant result list returned
// by HandleJoiner / HandleMover / HandleLeaver. RequestID is the
// access_requests row ID; GrantID is the access_grants row ID
// (populated only on successful provision / on Leaver lookup); Err is
// non-nil when the connector or DB write failed.
type JMLGrantResult struct {
	ConnectorID        string
	ResourceExternalID string
	Role               string
	RequestID          string
	GrantID            string
	Err                error
}

// JMLResult is the structured output of HandleJoiner / HandleMover /
// HandleLeaver. Provisioned / Revoked / Failed are the per-grant
// breakdown; the bool helpers let callers branch on a clean
// "everything succeeded" path without iterating.
type JMLResult struct {
	Provisioned []JMLGrantResult
	Revoked     []JMLGrantResult
	Failed      []JMLGrantResult
}

// AllOK reports whether every grant in the result completed without
// error. Callers use this to decide whether to surface a 200 vs 207
// to the SCIM provider.
func (r *JMLResult) AllOK() bool {
	return len(r.Failed) == 0
}

// HandleJoiner runs the joiner lane: assign Teams, create approved
// access_requests, fan-out provisioning. Per PROPOSAL §5.4 the
// joiner flow auto-approves every default grant — the policy engine
// has implicitly approved them by including them in the default set.
//
// Each grant is processed in its own DB transaction (request create
// + approve) followed by an out-of-transaction connector call (per
// AccessProvisioningService.Provision). A connector failure on grant
// N does NOT abort grants N+1..M; the failure is captured in the
// returned JMLResult.Failed list. The team-membership writes are
// performed first in a single batch transaction so a connector
// failure later in the call cannot leave a half-assigned membership
// graph.
//
// Caller responsibilities:
//   - Resolve TeamIDs from the user's attributes against the policy
//     graph. The service does NOT walk the policy table.
//   - Resolve DefaultGrants from the assigned Teams. The service is
//     a pure orchestrator over the (connector, resource, role)
//     tuples the caller hands in.
//   - Decrypt connector secrets before calling. JML never decrypts
//     secrets directly — connectors receive whatever the caller
//     hands the AccessProvisioningService.
func (s *JMLService) HandleJoiner(ctx context.Context, in JoinerInput) (*JMLResult, error) {
	if in.WorkspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.UserID == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrValidation)
	}
	if len(in.TeamIDs) == 0 && len(in.DefaultGrants) == 0 {
		return nil, fmt.Errorf("%w: at least one of team_ids or default_grants is required", ErrValidation)
	}

	if err := s.assignTeams(ctx, in.UserID, in.TeamIDs); err != nil {
		return nil, fmt.Errorf("access: assign joiner teams: %w", err)
	}

	justification := in.Justification
	if justification == "" {
		justification = "joiner: default access"
	}

	out := &JMLResult{}
	for _, g := range in.DefaultGrants {
		res := s.driveOneGrant(ctx, in.WorkspaceID, in.UserID, g, justification, "joiner: default access approved")
		if res.Err != nil {
			out.Failed = append(out.Failed, res)
			continue
		}
		out.Provisioned = append(out.Provisioned, res)
	}
	return out, nil
}

// MoverInput is the input contract for HandleMover. Old / New TeamIDs
// describe the Team membership before and after the SCIM event.
// Added / Removed grants are the (connector, resource, role) tuples
// the caller has resolved for the diff: AddedGrants is what the
// gained Teams entitle the user to; RemovedGrants is what the lost
// Teams used to entitle them to. The service does NOT compute the
// diff itself — that lives in the policy engine.
type MoverInput struct {
	WorkspaceID    string
	UserID         string
	OldTeamIDs     []string
	NewTeamIDs     []string
	AddedGrants    []JMLAccessGrant
	RemovedGrants  []JMLAccessGrant
	Justification  string
}

// HandleMover runs the mover lane: diff Team membership, atomically
// adjust team_members, then fan-out a single batch of revokes (for
// lost Teams) + provisions (for gained Teams). Per PROPOSAL §5.4
// "no partial-access window" — Team-membership writes happen in a
// single transaction so a connector-side failure cannot leave a
// half-moved user.
//
// A no-op mover (no membership changes, no grant changes) is a
// success: the service returns an empty JMLResult and does not
// touch the DB.
//
// Connector failures DO NOT roll back the team-membership writes —
// the diff is the source of truth, and a transient connector
// failure should not flip the user's logical Team membership back.
// The failed grant is captured in JMLResult.Failed; operators
// reconcile via the existing provision-retry path.
func (s *JMLService) HandleMover(ctx context.Context, in MoverInput) (*JMLResult, error) {
	if in.WorkspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.UserID == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrValidation)
	}

	added, removed := diffTeamIDs(in.OldTeamIDs, in.NewTeamIDs)
	if len(added) == 0 && len(removed) == 0 && len(in.AddedGrants) == 0 && len(in.RemovedGrants) == 0 {
		return &JMLResult{}, nil
	}

	if err := s.applyTeamDiff(ctx, in.UserID, added, removed); err != nil {
		return nil, fmt.Errorf("access: apply mover team diff: %w", err)
	}

	justification := in.Justification
	if justification == "" {
		justification = "mover: team membership change"
	}

	// Provision the gained-team grants BEFORE revoking the
	// lost-team grants. PROPOSAL §5.4 requires "no partial-access
	// window": when a Mover trades Team A access for Team B
	// access, the user must always retain access during the swap.
	// Doing the revokes first opens a window where the user has
	// neither old nor new access; doing the provisions first means
	// the user briefly has both, which is the safer over-shoot.
	// AccessProvisioningService is idempotent on
	// (user, connector, resource, role) so a re-run does not
	// double-grant.
	out := &JMLResult{}
	for _, g := range in.AddedGrants {
		res := s.driveOneGrant(ctx, in.WorkspaceID, in.UserID, g, justification, "mover: gained team access approved")
		if res.Err != nil {
			out.Failed = append(out.Failed, res)
			continue
		}
		out.Provisioned = append(out.Provisioned, res)
	}
	for _, g := range in.RemovedGrants {
		res := s.revokeOneGrantForUser(ctx, in.WorkspaceID, in.UserID, g)
		if res.Err != nil {
			out.Failed = append(out.Failed, res)
			continue
		}
		out.Revoked = append(out.Revoked, res)
	}
	return out, nil
}

// HandleLeaver runs the leaver lane: revoke every active grant for
// the user, drop them from every Team, and (Phase 6+) disable the
// OpenZiti identity. Per PROPOSAL §5.4 leaver is synchronous — the
// caller MUST observe every revocation completing before the
// upstream SCIM provider records the deactivation as final.
//
// A connector failure on grant N does NOT abort grants N+1..M; the
// failure is captured in the returned JMLResult.Failed list. The
// team-membership purge happens after the revoke loop so a
// connector failure does not strand the user as "removed from
// teams but still has live grants". Already-revoked grants are
// silently skipped (idempotent re-run).
//
// disableOpenZitiIdentity is a Phase 6 stub: the OpenZiti control-
// plane integration lives in the ZTNA business layer, not in this
// repo. The hook is logged so operators can wire it in later
// without changing the service contract.
func (s *JMLService) HandleLeaver(ctx context.Context, workspaceID, userID string) (*JMLResult, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if userID == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrValidation)
	}

	var grants []models.AccessGrant
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND user_id = ? AND revoked_at IS NULL", workspaceID, userID).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("access: list leaver active grants: %w", err)
	}

	// Snapshot the (connector_id → user_external_id) pivot BEFORE we
	// soft-delete team_members in removeUserFromAllTeams. The Phase
	// 11 kill switch needs these IDs to call SessionRevoker and
	// SCIMProvisioner on each connector the user existed on; once
	// the team_members rows are gone the pivot is lost.
	connectorExternalIDs, cerr := s.collectConnectorExternalIDs(ctx, workspaceID, userID)
	if cerr != nil {
		log.Printf("access: leaver %s: collect connector external ids: %v", userID, cerr)
		connectorExternalIDs = map[string]string{}
	}

	out := &JMLResult{}
	for i := range grants {
		g := &grants[i]
		res := JMLGrantResult{
			ConnectorID:        g.ConnectorID,
			ResourceExternalID: g.ResourceExternalID,
			Role:               g.Role,
			GrantID:            g.ID,
		}
		if err := s.provisioningSvc.Revoke(ctx, g, nil, nil); err != nil {
			if errors.Is(err, ErrAlreadyRevoked) {
				out.Revoked = append(out.Revoked, res)
				s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
					WorkspaceID: workspaceID, UserID: userID,
					Layer: LeaverLayerGrantRevoke, ConnectorID: g.ConnectorID,
					Status: LeaverStatusSuccess,
				})
				continue
			}
			res.Err = err
			out.Failed = append(out.Failed, res)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerGrantRevoke, ConnectorID: g.ConnectorID,
				Status: LeaverStatusFailed, Error: err.Error(),
			})
			continue
		}
		out.Revoked = append(out.Revoked, res)
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerGrantRevoke, ConnectorID: g.ConnectorID,
			Status: LeaverStatusSuccess,
		})
	}

	if err := s.removeUserFromAllTeams(ctx, userID); err != nil {
		// We've already revoked upstream grants by this point;
		// surfacing the team-membership cleanup failure as a hard
		// error would lose the revocation audit. Log and append
		// to Failed so the caller can see the partial state.
		log.Printf("access: leaver %s: remove from teams: %v", userID, err)
		out.Failed = append(out.Failed, JMLGrantResult{Err: err})
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerTeamRemove, Status: LeaverStatusFailed,
			Error: err.Error(),
		})
	} else {
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerTeamRemove, Status: LeaverStatusSuccess,
		})
	}

	// Phase 11 five-layer leaver kill switch — every step is
	// best-effort; a failure logs but does not block the next
	// layer. The order is intentional:
	//   1. grant revoke (above)            — pull upstream API access
	//   2. team membership removal (above) — drop ImpactResolver matches
	//   3. Keycloak user disable           — block new SSO sign-ins
	//   4. per-connector session revoke    — kill live SaaS sessions
	//   5. SCIM deprovision                — push terminal state to SaaS
	//   6. OpenZiti identity disable       — kill the dataplane tunnel
	s.disableKeycloakUser(ctx, workspaceID, userID)
	s.revokeSessionsAcrossConnectors(ctx, workspaceID, userID, connectorExternalIDs)
	s.scimDeprovisionAcrossConnectors(ctx, workspaceID, userID, connectorExternalIDs)
	s.disableOpenZitiIdentity(ctx, workspaceID, userID)
	return out, nil
}

// disableKeycloakUser flips the user to enabled=false in Keycloak
// and revokes every active refresh token. Best-effort: a Keycloak
// outage logs but does not block the rest of the kill switch.
func (s *JMLService) disableKeycloakUser(ctx context.Context, workspaceID, userID string) {
	if s.ssoFedSvc == nil {
		log.Printf("access: leaver %s in workspace %s: keycloak disable is stubbed (no sso federation service wired)", userID, workspaceID)
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerKeycloakDisable, Status: LeaverStatusSkipped,
		})
		return
	}
	realm := workspaceID
	if s.realmFor != nil {
		realm = s.realmFor(workspaceID)
	}
	if err := s.ssoFedSvc.DisableKeycloakUser(ctx, realm, userID); err != nil {
		if errors.Is(err, ErrSSOFederationDisabled) || errors.Is(err, ErrSSOFederationUnsupported) {
			log.Printf("access: leaver %s in workspace %s: keycloak disable skipped: %v", userID, workspaceID, err)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerKeycloakDisable, Status: LeaverStatusSkipped,
				Error: err.Error(),
			})
			return
		}
		log.Printf("access: leaver %s in workspace %s: keycloak DisableKeycloakUser failed: %v", userID, workspaceID, err)
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerKeycloakDisable, Status: LeaverStatusFailed,
			Error: err.Error(),
		})
		return
	}
	s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
		WorkspaceID: workspaceID, UserID: userID,
		Layer: LeaverLayerKeycloakDisable, Status: LeaverStatusSuccess,
	})
}

// revokeSessionsAcrossConnectors loads every connector the user
// has a team_members row on, and calls SessionRevoker on the
// connector when implemented. Best-effort: per-connector errors
// log but do not block the next connector or the next layer.
func (s *JMLService) revokeSessionsAcrossConnectors(ctx context.Context, workspaceID, userID string, members map[string]string) {
	if s.credLoader == nil || s.getConnectorFn == nil {
		log.Printf("access: leaver %s in workspace %s: session revoke skipped (no credentials loader wired)", userID, workspaceID)
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerSessionRevoke, Status: LeaverStatusSkipped,
		})
		return
	}
	for connectorID, externalID := range members {
		cfg, secrets, lerr := s.credLoader.LoadConnectorCredentials(ctx, connectorID)
		if lerr != nil {
			log.Printf("access: leaver %s connector %s: load credentials: %v", userID, connectorID, lerr)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSessionRevoke, ConnectorID: connectorID,
				Status: LeaverStatusFailed, Error: lerr.Error(),
			})
			continue
		}
		provider, perr := s.provisioningSvc.lookupProvider(ctx, connectorID)
		if perr != nil {
			log.Printf("access: leaver %s connector %s: lookup provider: %v", userID, connectorID, perr)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSessionRevoke, ConnectorID: connectorID,
				Status: LeaverStatusFailed, Error: perr.Error(),
			})
			continue
		}
		connector, cerr := s.getConnectorFn(provider)
		if cerr != nil {
			log.Printf("access: leaver %s connector %s: get connector %s: %v", userID, connectorID, provider, cerr)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSessionRevoke, ConnectorID: connectorID,
				Status: LeaverStatusFailed, Error: cerr.Error(),
			})
			continue
		}
		revoker, ok := connector.(SessionRevoker)
		if !ok {
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSessionRevoke, ConnectorID: connectorID,
				Status: LeaverStatusSkipped,
			})
			continue
		}
		if rerr := revoker.RevokeUserSessions(ctx, cfg, secrets, externalID); rerr != nil {
			log.Printf("access: leaver %s connector %s: RevokeUserSessions: %v", userID, connectorID, rerr)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSessionRevoke, ConnectorID: connectorID,
				Status: LeaverStatusFailed, Error: rerr.Error(),
			})
			continue
		}
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerSessionRevoke, ConnectorID: connectorID,
			Status: LeaverStatusSuccess,
		})
	}
}

// scimDeprovisionAcrossConnectors loads every connector the user
// has a team_members row on, and calls SCIMProvisioner.DeleteSCIMResource
// when implemented. Best-effort: per-connector errors log but do not
// block the next connector or the next layer.
func (s *JMLService) scimDeprovisionAcrossConnectors(ctx context.Context, workspaceID, userID string, members map[string]string) {
	if s.credLoader == nil || s.getConnectorFn == nil {
		log.Printf("access: leaver %s in workspace %s: scim deprovision skipped (no credentials loader wired)", userID, workspaceID)
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerSCIMDeprovision, Status: LeaverStatusSkipped,
		})
		return
	}
	for connectorID, externalID := range members {
		cfg, secrets, lerr := s.credLoader.LoadConnectorCredentials(ctx, connectorID)
		if lerr != nil {
			log.Printf("access: leaver %s connector %s: load credentials: %v", userID, connectorID, lerr)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSCIMDeprovision, ConnectorID: connectorID,
				Status: LeaverStatusFailed, Error: lerr.Error(),
			})
			continue
		}
		provider, perr := s.provisioningSvc.lookupProvider(ctx, connectorID)
		if perr != nil {
			log.Printf("access: leaver %s connector %s: lookup provider: %v", userID, connectorID, perr)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSCIMDeprovision, ConnectorID: connectorID,
				Status: LeaverStatusFailed, Error: perr.Error(),
			})
			continue
		}
		connector, cerr := s.getConnectorFn(provider)
		if cerr != nil {
			log.Printf("access: leaver %s connector %s: get connector %s: %v", userID, connectorID, provider, cerr)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSCIMDeprovision, ConnectorID: connectorID,
				Status: LeaverStatusFailed, Error: cerr.Error(),
			})
			continue
		}
		scim, ok := connector.(SCIMProvisioner)
		if !ok {
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSCIMDeprovision, ConnectorID: connectorID,
				Status: LeaverStatusSkipped,
			})
			continue
		}
		if derr := scim.DeleteSCIMResource(ctx, cfg, secrets, "User", externalID); derr != nil {
			log.Printf("access: leaver %s connector %s: DeleteSCIMResource: %v", userID, connectorID, derr)
			s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
				WorkspaceID: workspaceID, UserID: userID,
				Layer: LeaverLayerSCIMDeprovision, ConnectorID: connectorID,
				Status: LeaverStatusFailed, Error: derr.Error(),
			})
			continue
		}
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerSCIMDeprovision, ConnectorID: connectorID,
			Status: LeaverStatusSuccess,
		})
	}
}

// collectConnectorExternalIDs walks team_members for the supplied
// userID and returns a (connector_id → external_id) map. Rows with
// empty ConnectorID or ExternalID are skipped — the connector flow
// can't act on them. Soft-deleted rows are excluded by GORM's
// default scope.
func (s *JMLService) collectConnectorExternalIDs(ctx context.Context, workspaceID, userID string) (map[string]string, error) {
	_ = workspaceID // reserved for future workspace-scoped filtering
	var rows []models.TeamMember
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		if r.ConnectorID == "" || r.ExternalID == "" {
			continue
		}
		if _, ok := out[r.ConnectorID]; ok {
			continue // first writer wins; multiple team rows per (user, connector) collapse to one
		}
		out[r.ConnectorID] = r.ExternalID
	}
	return out, nil
}

// disableOpenZitiIdentity dispatches the OpenZiti DisableIdentity
// call when a Phase 6 OpenZitiClient is wired onto the service.
// Without a wired client the function logs and returns; the ZTNA
// business layer is responsible for the integration in that case.
//
// The call is best-effort: a DisableIdentity error logs but does not
// roll back the leaver. By the time we reach this branch every
// grant has already been revoked and team memberships dropped, so
// the source-of-truth state is "deactivated"; the OpenZiti control
// plane reconciles eventually.
func (s *JMLService) disableOpenZitiIdentity(ctx context.Context, workspaceID, userID string) {
	if s.zitiClient == nil {
		log.Printf("access: leaver %s in workspace %s: openziti identity disable is stubbed (no client wired)", userID, workspaceID)
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerOpenZitiDisable, Status: LeaverStatusSkipped,
		})
		return
	}
	if err := s.zitiClient.DisableIdentity(ctx, userID); err != nil {
		log.Printf("access: leaver %s in workspace %s: openziti DisableIdentity failed: %v", userID, workspaceID, err)
		s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
			WorkspaceID: workspaceID, UserID: userID,
			Layer: LeaverLayerOpenZitiDisable, Status: LeaverStatusFailed,
			Error: err.Error(),
		})
		return
	}
	s.emitLeaverEvent(ctx, LeaverKillSwitchEvent{
		WorkspaceID: workspaceID, UserID: userID,
		Layer: LeaverLayerOpenZitiDisable, Status: LeaverStatusSuccess,
	})
}

// driveOneGrant runs a single (connector, resource, role) tuple
// through the request → approved → provisioned lifecycle. The
// caller's justification / approval reason flow into the audit
// trail.
//
// Returns the per-grant JMLGrantResult. A non-nil Err means the
// connector or DB write failed; the request row may still exist
// (in approved or provision_failed state) so operators can retry.
func (s *JMLService) driveOneGrant(
	ctx context.Context,
	workspaceID, userID string,
	g JMLAccessGrant,
	justification, approvalReason string,
) JMLGrantResult {
	res := JMLGrantResult{
		ConnectorID:        g.ConnectorID,
		ResourceExternalID: g.ResourceExternalID,
		Role:               g.Role,
	}

	req, err := s.requestSvc.CreateRequest(ctx, CreateAccessRequestInput{
		WorkspaceID:        workspaceID,
		RequesterUserID:    userID,
		TargetUserID:       userID,
		ConnectorID:        g.ConnectorID,
		ResourceExternalID: g.ResourceExternalID,
		Role:               g.Role,
		Justification:      justification,
		ExpiresAt:          g.ExpiresAt,
	})
	if err != nil {
		res.Err = fmt.Errorf("create access_request: %w", err)
		return res
	}
	res.RequestID = req.ID

	if err := s.requestSvc.ApproveRequest(ctx, req.ID, "system:jml", approvalReason); err != nil {
		res.Err = fmt.Errorf("auto-approve access_request: %w", err)
		return res
	}

	// Reload so AccessProvisioningService.Provision sees the
	// up-to-date State column (request_service.go uses an
	// optimistic-lock UPDATE keyed on the prior State).
	var fresh models.AccessRequest
	if err := s.db.WithContext(ctx).Where("id = ?", req.ID).First(&fresh).Error; err != nil {
		res.Err = fmt.Errorf("reload approved access_request: %w", err)
		return res
	}

	if err := s.provisioningSvc.Provision(ctx, &fresh, nil, nil); err != nil {
		res.Err = fmt.Errorf("provision access_request: %w", err)
		return res
	}

	// Pull the access_grants row created inside Provision so the
	// caller can correlate with downstream audit / revoke flows.
	var grant models.AccessGrant
	if err := s.db.WithContext(ctx).
		Where("request_id = ?", req.ID).
		First(&grant).Error; err == nil {
		res.GrantID = grant.ID
	}
	return res
}

// revokeOneGrantForUser revokes the matching active grant for the
// supplied user. Returns a per-grant JMLGrantResult with Err set
// when no matching grant exists or the revoke fails.
//
// Matching is performed on (workspace, user, connector, resource,
// role); only the first matching active grant is revoked. JML
// callers should never have more than one active grant per tuple
// per user.
func (s *JMLService) revokeOneGrantForUser(
	ctx context.Context,
	workspaceID, userID string,
	g JMLAccessGrant,
) JMLGrantResult {
	res := JMLGrantResult{
		ConnectorID:        g.ConnectorID,
		ResourceExternalID: g.ResourceExternalID,
		Role:               g.Role,
	}

	var grant models.AccessGrant
	err := s.db.WithContext(ctx).
		Where(
			"workspace_id = ? AND user_id = ? AND connector_id = ? AND resource_external_id = ? AND role = ? AND revoked_at IS NULL",
			workspaceID, userID, g.ConnectorID, g.ResourceExternalID, g.Role,
		).
		First(&grant).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res.Err = fmt.Errorf("%w: no active grant for (user=%s, connector=%s, resource=%s, role=%s)", ErrGrantNotFound, userID, g.ConnectorID, g.ResourceExternalID, g.Role)
			return res
		}
		res.Err = fmt.Errorf("select active grant: %w", err)
		return res
	}
	res.GrantID = grant.ID

	if err := s.provisioningSvc.Revoke(ctx, &grant, nil, nil); err != nil {
		res.Err = fmt.Errorf("revoke active grant: %w", err)
		return res
	}
	return res
}

// assignTeams inserts team_members rows for the supplied user. The
// inserts are performed in a single transaction so a partial
// failure leaves no half-assigned membership graph.
//
// Re-running assignTeams with already-assigned teams is a no-op:
// the service silently skips rows where (team_id, user_id) already
// exists. We deliberately do NOT use ON CONFLICT here — SQLite +
// GORM do not portably express it, and the per-team round trip is
// cheap relative to the rest of the joiner flow.
func (s *JMLService) assignTeams(ctx context.Context, userID string, teamIDs []string) error {
	if len(teamIDs) == 0 {
		return nil
	}
	now := s.now()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, teamID := range teamIDs {
			var existing models.TeamMember
			err := tx.Where("team_id = ? AND user_id = ?", teamID, userID).First(&existing).Error
			if err == nil {
				continue
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("select team_member: %w", err)
			}
			row := &models.TeamMember{
				ID:        s.newID(),
				TeamID:    teamID,
				UserID:    userID,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := tx.Create(row).Error; err != nil {
				return fmt.Errorf("insert team_member (team=%s, user=%s): %w", teamID, userID, err)
			}
		}
		return nil
	})
}

// applyTeamDiff atomically inserts membership rows for the added
// teams and soft-deletes membership rows for the removed teams.
// The two halves run in a single transaction so the user's logical
// team membership is updated atomically (per PROPOSAL §5.4 "no
// partial-access window").
func (s *JMLService) applyTeamDiff(ctx context.Context, userID string, addedTeamIDs, removedTeamIDs []string) error {
	if len(addedTeamIDs) == 0 && len(removedTeamIDs) == 0 {
		return nil
	}
	now := s.now()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, teamID := range removedTeamIDs {
			if err := tx.Where("team_id = ? AND user_id = ?", teamID, userID).
				Delete(&models.TeamMember{}).Error; err != nil {
				return fmt.Errorf("remove team_member (team=%s, user=%s): %w", teamID, userID, err)
			}
		}
		for _, teamID := range addedTeamIDs {
			var existing models.TeamMember
			err := tx.Where("team_id = ? AND user_id = ?", teamID, userID).First(&existing).Error
			if err == nil {
				continue
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("select team_member: %w", err)
			}
			row := &models.TeamMember{
				ID:        s.newID(),
				TeamID:    teamID,
				UserID:    userID,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := tx.Create(row).Error; err != nil {
				return fmt.Errorf("insert team_member (team=%s, user=%s): %w", teamID, userID, err)
			}
		}
		return nil
	})
}

// removeUserFromAllTeams soft-deletes every team_members row for
// the supplied user. Used on Leaver to drop the user out of every
// Team in one shot.
func (s *JMLService) removeUserFromAllTeams(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&models.TeamMember{}).Error
}

// diffTeamIDs returns (added, removed) lists for the supplied old
// and new team IDs. The caller's slices are not mutated.
func diffTeamIDs(oldIDs, newIDs []string) (added, removed []string) {
	oldSet := make(map[string]struct{}, len(oldIDs))
	for _, id := range oldIDs {
		oldSet[id] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(newIDs))
	for _, id := range newIDs {
		newSet[id] = struct{}{}
	}
	for id := range newSet {
		if _, ok := oldSet[id]; !ok {
			added = append(added, id)
		}
	}
	for id := range oldSet {
		if _, ok := newSet[id]; !ok {
			removed = append(removed, id)
		}
	}
	return added, removed
}
