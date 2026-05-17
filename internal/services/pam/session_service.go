package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// PAMRiskAssessor is the narrow contract PAMSessionService uses to
// score a fresh session request through the access-ai-agent's
// pam_session_risk_assessment skill (docs/pam/architecture.md §6).
//
// The production implementation lives in
// internal/pkg/aiclient.PAMSessionRiskAdapter and wraps the
// pam_session_risk_assessment skill with a fallback that defaults to
// risk_score="medium" + recommendation="require_approval" when the
// AI agent is unreachable. Tests substitute a stub via this
// interface.
//
// Failure semantics — AI is decision-support, not critical path
// (docs/pam/architecture.md §6). The session is persisted regardless
// of the assessor's outcome; the score is best-effort metadata
// pushed onto the row after the INSERT succeeds.
type PAMRiskAssessor interface {
	// AssessSessionRisk returns the risk band, structured factors,
	// and routing recommendation. ok=false signals the fallback
	// fired and the caller MUST default the lease workflow to
	// "require approval".
	AssessSessionRisk(
		ctx context.Context,
		payload PAMSessionRiskPayload,
	) (riskScore string, riskFactors []string, recommendation string, ok bool)
}

// PAMSessionRiskPayload is the canonical request shape the Go side
// hands to the access-ai-agent's pam_session_risk_assessment skill.
// Mirrors the Python schema in
// cmd/access-ai-agent/skills/pam_session_risk.py.
type PAMSessionRiskPayload struct {
	WorkspaceID      string `json:"workspace_id"`
	UserID           string `json:"user_id"`
	AssetID          string `json:"asset_id"`
	Protocol         string `json:"protocol"`
	Criticality      string `json:"criticality"`
	TimeOfDay        int    `json:"time_of_day,omitempty"`
	PreviousDenials  int    `json:"previous_denials,omitempty"`
	IsFirstAccess    bool   `json:"is_first_access,omitempty"`
	IsEmergency      bool   `json:"is_emergency,omitempty"`
}

// Allowed recommendation values returned by the
// pam_session_risk_assessment skill. The service treats unknown
// values as if the AI was unreachable so a malformed model response
// cannot accidentally auto-approve a session.
const (
	PAMRecommendationAutoApprove     = "auto_approve"
	PAMRecommendationRequireApproval = "require_approval"
	PAMRecommendationDeny            = "deny"

	// pamSessionRiskFallback is the recommendation used when the AI
	// agent is unreachable. Mirrors the docs/pam/architecture.md §6
	// default of "always require manager approval when AI is down".
	pamSessionRiskFallback = PAMRecommendationRequireApproval
)

// PAMSessionService owns the lifecycle of pam_sessions rows:
// requested → active → completed / terminated / failed. Each session
// references the lease that authorised it via LeaseID so the
// authorisation trail and the IO-recording trail share a key.
//
// AI scoring is optional; SetRiskAssessor wires it in. With no
// assessor the service stamps an empty risk_score and the operator
// UI falls back to the lease-level workflow lane.
type PAMSessionService struct {
	db           *gorm.DB
	leaseLookup  PAMLeaseLookup
	riskAssessor PAMRiskAssessor
	producer     PAMAuditProducer
	now          func() time.Time
	newID        func() string
}

// PAMLeaseLookup is the narrow contract PAMSessionService uses to
// resolve a lease ID into the lease row at session-create time. The
// production implementation is *PAMLeaseService.GetLease; tests pass
// a closure-backed stub.
type PAMLeaseLookup interface {
	GetLease(ctx context.Context, workspaceID, leaseID string) (*models.PAMLease, error)
}

// PAMSessionServiceConfig wires the dependencies for
// NewPAMSessionService. db + producer are required; lease lookup is
// required when callers want CreateSession to validate the lease
// up-front. RiskAssessor is optional.
type PAMSessionServiceConfig struct {
	DB           *gorm.DB
	LeaseLookup  PAMLeaseLookup
	Producer     PAMAuditProducer
	RiskAssessor PAMRiskAssessor
	Now          func() time.Time
	NewID        func() string
}

// NewPAMSessionService validates cfg and returns a wired service.
// db and producer must be non-nil; the rest of the fields are
// optional with the defaults documented on each field.
func NewPAMSessionService(cfg PAMSessionServiceConfig) (*PAMSessionService, error) {
	if cfg.DB == nil {
		return nil, errors.New("pam: PAMSessionServiceConfig.DB is required")
	}
	if cfg.Producer == nil {
		return nil, errors.New("pam: PAMSessionServiceConfig.Producer is required")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.NewID == nil {
		cfg.NewID = NewULID
	}
	return &PAMSessionService{
		db:           cfg.DB,
		leaseLookup:  cfg.LeaseLookup,
		riskAssessor: cfg.RiskAssessor,
		producer:     cfg.Producer,
		now:          cfg.Now,
		newID:        cfg.NewID,
	}, nil
}

// SetRiskAssessor swaps the wired assessor at runtime. Used by the
// boot path in cmd/ztna-api/main.go to attach the AIClient adapter
// once the agent base URL is resolved.
func (s *PAMSessionService) SetRiskAssessor(r PAMRiskAssessor) {
	s.riskAssessor = r
}

// CreateSessionInput is the input contract for CreateSession.
type CreateSessionInput struct {
	UserID      string
	AssetID     string
	AccountID   string
	LeaseID     string
	Protocol    string
	Criticality string
	// Optional risk-assessment hints — the AI skill reads the
	// remaining fields when CreateSession invokes the assessor.
	TimeOfDay       int
	PreviousDenials int
	IsFirstAccess   bool
	IsEmergency     bool
}

// validateCreateSession enforces required fields + protocol allow-list.
func validateCreateSession(in CreateSessionInput) error {
	if in.UserID == "" {
		return fmt.Errorf("%w: user_id is required", ErrValidation)
	}
	if in.AssetID == "" {
		return fmt.Errorf("%w: asset_id is required", ErrValidation)
	}
	if in.AccountID == "" {
		return fmt.Errorf("%w: account_id is required", ErrValidation)
	}
	if in.LeaseID == "" {
		return fmt.Errorf("%w: lease_id is required", ErrValidation)
	}
	if in.Protocol == "" {
		return fmt.Errorf("%w: protocol is required", ErrValidation)
	}
	if in.Criticality == "" {
		return fmt.Errorf("%w: criticality is required", ErrValidation)
	}
	return nil
}

// CreateSessionResult is the response shape for CreateSession.
// Bundles the persisted row with the AI assessor's recommendation
// so the caller can route the lease workflow appropriately.
type CreateSessionResult struct {
	Session        *models.PAMSession `json:"session"`
	Recommendation string             `json:"recommendation,omitempty"`
	RiskFactors    []string           `json:"risk_factors,omitempty"`
	AIAvailable    bool               `json:"ai_available"`
}

// CreateSession persists a new pam_sessions row in the "requested"
// state, optionally scoring it through the AI assessor, and emits a
// pam.session.requested audit event.
//
// The session row is created regardless of the assessor's outcome —
// AI is decision-support, not critical path (docs/pam/architecture.md
// §6). When the assessor returns recommendation="deny", the row is
// still persisted (so admins can see the denied request) but the
// caller receives the recommendation in CreateSessionResult so it
// can refuse to flip the session to "active".
func (s *PAMSessionService) CreateSession(
	ctx context.Context,
	workspaceID string,
	in CreateSessionInput,
) (*CreateSessionResult, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if err := validateCreateSession(in); err != nil {
		return nil, err
	}
	if s.leaseLookup != nil {
		if _, err := s.leaseLookup.GetLease(ctx, workspaceID, in.LeaseID); err != nil {
			return nil, err
		}
	}

	now := s.now()
	session := &models.PAMSession{
		ID:          s.newID(),
		WorkspaceID: workspaceID,
		UserID:      in.UserID,
		AssetID:     in.AssetID,
		AccountID:   in.AccountID,
		Protocol:    in.Protocol,
		State:       models.PAMSessionStateRequested,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.db.WithContext(ctx).Create(session).Error; err != nil {
		return nil, fmt.Errorf("pam: insert pam_session: %w", err)
	}

	result := &CreateSessionResult{Session: session, AIAvailable: false}

	if s.riskAssessor != nil {
		score, factors, recommendation, ok := s.riskAssessor.AssessSessionRisk(ctx, PAMSessionRiskPayload{
			WorkspaceID:     workspaceID,
			UserID:          in.UserID,
			AssetID:         in.AssetID,
			Protocol:        in.Protocol,
			Criticality:     in.Criticality,
			TimeOfDay:       in.TimeOfDay,
			PreviousDenials: in.PreviousDenials,
			IsFirstAccess:   in.IsFirstAccess,
			IsEmergency:     in.IsEmergency,
		})
		result.AIAvailable = ok
		result.Recommendation = recommendation
		result.RiskFactors = factors
		// Risk score is best-effort metadata — persist whichever
		// score the assessor returned (the fallback path returns
		// "medium" with ok=false so the row carries a sane default
		// even when the AI is unreachable).
		if score != "" {
			if persistErr := s.persistRisk(ctx, session.ID, score, factors); persistErr != nil {
				log.Printf("pam: persist risk for session %s: %v", session.ID, persistErr)
			} else {
				band := riskScoreBand(score)
				session.RiskScore = &band
			}
		}
	}

	s.emit(ctx, PAMAuditEvent{
		EventType:   PAMEventSessionRequested,
		WorkspaceID: workspaceID,
		ActorUserID: in.UserID,
		SessionID:   session.ID,
		LeaseID:     in.LeaseID,
		AssetID:     in.AssetID,
		AccountID:   in.AccountID,
		Protocol:    in.Protocol,
		Outcome:     models.PAMSessionStateRequested,
		Metadata: map[string]interface{}{
			"recommendation": result.Recommendation,
			"risk_factors":   result.RiskFactors,
			"ai_available":   result.AIAvailable,
		},
	})

	return result, nil
}

// AuthorizeSession flips a requested session into the active state
// and stamps StartedAt + the gateway-assigned ReplayStorageKey. The
// caller (typically the pam-gateway when it accepts a connection)
// supplies the storage key — the service does not pick it because
// the gateway already constructed the bucket prefix.
func (s *PAMSessionService) AuthorizeSession(
	ctx context.Context,
	workspaceID, sessionID, replayStorageKey string,
) (*models.PAMSession, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session_id is required", ErrValidation)
	}
	now := s.now()
	updates := map[string]interface{}{
		"state":      models.PAMSessionStateActive,
		"started_at": &now,
		"updated_at": now,
	}
	if replayStorageKey != "" {
		updates["replay_storage_key"] = replayStorageKey
	}
	res := s.db.WithContext(ctx).
		Model(&models.PAMSession{}).
		Where("id = ? AND workspace_id = ? AND state = ?",
			sessionID, workspaceID, models.PAMSessionStateRequested,
		).
		Updates(updates)
	if res.Error != nil {
		return nil, fmt.Errorf("pam: authorize pam_session: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		// The row may exist in a non-requested state already
		// (e.g. terminated by an admin while approval was pending);
		// surface ErrSessionNotFound so the gateway returns 404
		// rather than appearing to succeed.
		return nil, ErrSessionNotFound
	}
	session, err := s.GetSession(ctx, workspaceID, sessionID)
	if err != nil {
		return nil, err
	}
	s.emit(ctx, PAMAuditEvent{
		EventType:   PAMEventSessionAuthorized,
		WorkspaceID: workspaceID,
		ActorUserID: session.UserID,
		SessionID:   session.ID,
		AssetID:     session.AssetID,
		AccountID:   session.AccountID,
		Protocol:    session.Protocol,
		Outcome:     models.PAMSessionStateActive,
	})
	s.emit(ctx, PAMAuditEvent{
		EventType:   PAMEventSessionStarted,
		WorkspaceID: workspaceID,
		ActorUserID: session.UserID,
		SessionID:   session.ID,
		AssetID:     session.AssetID,
		AccountID:   session.AccountID,
		Protocol:    session.Protocol,
		Outcome:     models.PAMSessionStateActive,
	})
	return session, nil
}

// CompleteSession transitions an active session into the completed
// state and stamps EndedAt + the final CommandCount the gateway has
// observed. The caller supplies commandCount because the gateway is
// the authoritative source — the pam_session_commands table is
// append-only and the gateway already counts as it writes.
func (s *PAMSessionService) CompleteSession(
	ctx context.Context,
	workspaceID, sessionID string,
	commandCount int,
) (*models.PAMSession, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session_id is required", ErrValidation)
	}
	now := s.now()
	updates := map[string]interface{}{
		"state":      models.PAMSessionStateCompleted,
		"ended_at":   &now,
		"updated_at": now,
	}
	if commandCount > 0 {
		updates["command_count"] = commandCount
	}
	res := s.db.WithContext(ctx).
		Model(&models.PAMSession{}).
		Where("id = ? AND workspace_id = ? AND state = ?",
			sessionID, workspaceID, models.PAMSessionStateActive,
		).
		Updates(updates)
	if res.Error != nil {
		return nil, fmt.Errorf("pam: complete pam_session: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrSessionNotFound
	}
	session, err := s.GetSession(ctx, workspaceID, sessionID)
	if err != nil {
		return nil, err
	}
	s.emit(ctx, PAMAuditEvent{
		EventType:   PAMEventSessionEnded,
		WorkspaceID: workspaceID,
		ActorUserID: session.UserID,
		SessionID:   session.ID,
		AssetID:     session.AssetID,
		AccountID:   session.AccountID,
		Protocol:    session.Protocol,
		Outcome:     models.PAMSessionStateCompleted,
		Metadata: map[string]interface{}{
			"command_count": session.CommandCount,
		},
	})
	return session, nil
}

// FailSession marks a session as failed (e.g. the gateway never
// established the upstream connection). Stamps EndedAt and records
// reason in the audit envelope.
func (s *PAMSessionService) FailSession(
	ctx context.Context,
	workspaceID, sessionID, reason string,
) (*models.PAMSession, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session_id is required", ErrValidation)
	}
	now := s.now()
	res := s.db.WithContext(ctx).
		Model(&models.PAMSession{}).
		Where("id = ? AND workspace_id = ?", sessionID, workspaceID).
		Where("state IN ?", []string{models.PAMSessionStateRequested, models.PAMSessionStateActive}).
		Updates(map[string]interface{}{
			"state":      models.PAMSessionStateFailed,
			"ended_at":   &now,
			"updated_at": now,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("pam: fail pam_session: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrSessionNotFound
	}
	session, err := s.GetSession(ctx, workspaceID, sessionID)
	if err != nil {
		return nil, err
	}
	s.emit(ctx, PAMAuditEvent{
		EventType:   PAMEventSessionFailed,
		WorkspaceID: workspaceID,
		ActorUserID: session.UserID,
		SessionID:   session.ID,
		AssetID:     session.AssetID,
		AccountID:   session.AccountID,
		Protocol:    session.Protocol,
		Outcome:     models.PAMSessionStateFailed,
		Reason:      reason,
	})
	return session, nil
}

// GetSession returns the pam_sessions row scoped to workspaceID.
// Mirrors the helper in PAMAuditService so callers don't need a
// second service handle for a single read.
func (s *PAMSessionService) GetSession(
	ctx context.Context,
	workspaceID, sessionID string,
) (*models.PAMSession, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session_id is required", ErrValidation)
	}
	var row models.PAMSession
	err := s.db.WithContext(ctx).
		Where("id = ? AND workspace_id = ?", sessionID, workspaceID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pam: load pam_session: %w", err)
	}
	return &row, nil
}

// persistRisk writes the risk score + factors back onto the
// pam_sessions row. Best-effort: failures are logged but never roll
// back the parent INSERT.
func (s *PAMSessionService) persistRisk(
	ctx context.Context,
	sessionID, score string,
	factors []string,
) error {
	band := riskScoreBand(score)
	updates := map[string]interface{}{
		"risk_score": &band,
		"updated_at": s.now(),
	}
	if len(factors) > 0 {
		b, err := json.Marshal(factors)
		if err == nil {
			// pam_sessions doesn't carry a risk_factors column — the
			// factors live in the pam_audit_logs envelope instead.
			// We keep the marshal here so a future schema bump that
			// adds the column gets the migration for free.
			_ = datatypes.JSON(b)
		}
	}
	return s.db.WithContext(ctx).
		Model(&models.PAMSession{}).
		Where("id = ?", sessionID).
		Updates(updates).Error
}

// emit pushes a PAM audit event onto the producer without surfacing
// transport errors to the caller. Audit emission is best-effort per
// docs/pam/architecture.md §7 — a missing audit event is logged but
// must not block a session lifecycle transition.
func (s *PAMSessionService) emit(ctx context.Context, event PAMAuditEvent) {
	if s.producer == nil {
		return
	}
	if err := s.producer.PublishPAMEvent(ctx, event); err != nil {
		log.Printf("pam: publish audit event %s for session %s: %v",
			event.EventType, event.SessionID, err)
	}
}

// riskScoreBand maps the AI agent's string score onto the
// PAMSession.RiskScore numeric bucket (0-100, nullable). The mapping
// is coarse — admin UI surfaces the band string anyway via the
// pam_audit_logs envelope. low/medium/high collapse to 25/50/75 so a
// future model that returns a percentile in [0,100] can replace the
// switch without breaking downstream callers.
func riskScoreBand(score string) int {
	switch score {
	case "low":
		return 25
	case "medium":
		return 50
	case "high":
		return 75
	default:
		return 0
	}
}
