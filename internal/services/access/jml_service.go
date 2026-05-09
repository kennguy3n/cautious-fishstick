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
	now             func() time.Time
	newID           func() string
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
		now:             provisioningSvc.now,
		newID:           provisioningSvc.newID,
	}
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

	out := &JMLResult{}
	for _, g := range in.RemovedGrants {
		res := s.revokeOneGrantForUser(ctx, in.WorkspaceID, in.UserID, g)
		if res.Err != nil {
			out.Failed = append(out.Failed, res)
			continue
		}
		out.Revoked = append(out.Revoked, res)
	}
	for _, g := range in.AddedGrants {
		res := s.driveOneGrant(ctx, in.WorkspaceID, in.UserID, g, justification, "mover: gained team access approved")
		if res.Err != nil {
			out.Failed = append(out.Failed, res)
			continue
		}
		out.Provisioned = append(out.Provisioned, res)
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
				continue
			}
			res.Err = err
			out.Failed = append(out.Failed, res)
			continue
		}
		out.Revoked = append(out.Revoked, res)
	}

	if err := s.removeUserFromAllTeams(ctx, userID); err != nil {
		// We've already revoked upstream grants by this point;
		// surfacing the team-membership cleanup failure as a hard
		// error would lose the revocation audit. Log and append
		// to Failed so the caller can see the partial state.
		log.Printf("access: leaver %s: remove from teams: %v", userID, err)
		out.Failed = append(out.Failed, JMLGrantResult{Err: err})
	}

	s.disableOpenZitiIdentity(ctx, workspaceID, userID)
	return out, nil
}

// disableOpenZitiIdentity is a Phase 6 stub. The OpenZiti control-
// plane lives outside this repo; the hook is intentionally a no-op
// here so operators can swap in a real client without changing the
// service contract. Logged so the absence of the integration is
// visible in test / dev environments.
func (s *JMLService) disableOpenZitiIdentity(_ context.Context, workspaceID, userID string) {
	log.Printf("access: leaver %s in workspace %s: openziti identity disable is stubbed (Phase 6+)", userID, workspaceID)
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
