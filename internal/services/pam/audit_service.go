// Package pam — audit service (Milestone 7 Tasks 15+17).
//
// PAMAuditService is the read+write facade the HTTP handlers and
// gateway control plane use to land the PAM evidence trail in three
// places at once:
//
//  1. Immutable Kafka stream of lifecycle events via a wrapped
//     PAMAuditProducer.
//  2. Command-row reads from pam_session_commands so the
//     /pam/sessions/:id/commands endpoint can render the typed
//     timeline (input + output hash + risk flag).
//  3. Replay-blob retrieval via a ReplaySignedURLer plugin so the
//     /pam/sessions/:id/replay endpoint returns a short-lived
//     pre-signed S3 GET URL operators can hand to forensics tooling
//     without leaking the underlying bucket name.
//
// The service is small + composable on purpose: the gateway calls
// RecordEvent directly when sessions transition state; the admin
// UI calls GetSessionReplay / GetCommandTimeline / ExportEvidence
// when an operator opens a session detail view.
package pam

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ErrSessionNotFound is the sentinel returned by lookups against
// pam_sessions when the supplied ID does not match a row. The
// handler layer translates this to HTTP 404.
var ErrSessionNotFound = errors.New("pam: session not found")

// ErrReplayUnavailable is returned by GetSessionReplay when the
// matching pam_sessions row exists but has no replay storage key
// (e.g. the gateway never accepted the session, or the row was
// inserted by a non-gateway code path). Handler maps to HTTP 409
// so operators can distinguish "session does not exist" from
// "session exists but has no replay yet".
var ErrReplayUnavailable = errors.New("pam: replay blob unavailable")

// ReplaySignedURLer is the contract PAMAuditService uses to mint
// short-lived pre-signed S3 GET URLs for session replay blobs. The
// production implementation lives in cmd/ztna-api and wraps
// aws-sdk-go-v2's s3.PresignClient; tests substitute a stub.
//
// The interface intentionally hides the bucket name and the SDK so
// PAMAuditService does not pull AWS into its test surface.
type ReplaySignedURLer interface {
	// PresignGet returns a pre-signed S3 GET URL for the supplied
	// object key, valid for ttl. An empty key MUST yield a non-nil
	// error so call sites do not silently mint URLs that resolve
	// to the bucket root.
	PresignGet(ctx context.Context, objectKey string, ttl time.Duration) (string, error)
}

// PAMAuditServiceConfig wires the three dependencies the service
// needs: a *gorm.DB for the command-table reads, a PAMAuditProducer
// for the event stream, and an optional ReplaySignedURLer for
// replay URL minting. Nil ReplaySignedURLer is fine — GetSessionReplay
// then returns ErrReplayUnavailable for every session.
type PAMAuditServiceConfig struct {
	DB              *gorm.DB
	Producer        PAMAuditProducer
	Replayer        ReplaySignedURLer
	ReplayURLExpiry time.Duration
	Now             func() time.Time
}

// PAMAuditService owns the read+write paths for PAM audit. It is
// safe for concurrent use: the underlying *gorm.DB is, the
// PAMAuditProducer implementations contract that they are, and the
// service itself stores no mutable state beyond cfg.
type PAMAuditService struct {
	cfg PAMAuditServiceConfig
}

// NewPAMAuditService validates cfg and returns the service. db is
// required because every method reads from the sessions / commands
// tables; producer is required because the gateway depends on
// RecordEvent never silently dropping events.
func NewPAMAuditService(cfg PAMAuditServiceConfig) (*PAMAuditService, error) {
	if cfg.DB == nil {
		return nil, errors.New("pam: PAMAuditServiceConfig.DB is required")
	}
	if cfg.Producer == nil {
		return nil, errors.New("pam: PAMAuditServiceConfig.Producer is required")
	}
	if cfg.ReplayURLExpiry <= 0 {
		// 15m default, matches docs/pam/architecture.md §6.
		cfg.ReplayURLExpiry = 15 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &PAMAuditService{cfg: cfg}, nil
}

// RecordEvent stamps EmittedAt (if unset) and publishes the event
// onto the wrapped PAMAuditProducer. A failure here is reported up
// to the caller because dropping a lifecycle event silently would
// leave the audit trail with holes — the caller (typically the
// gateway or the lease service) is expected to log the error and
// optionally retry, but never to swallow it.
func (s *PAMAuditService) RecordEvent(ctx context.Context, event PAMAuditEvent) error {
	if s == nil {
		return errors.New("pam: nil audit service")
	}
	if event.EventType == "" {
		return errors.New("pam: event_type is required")
	}
	if event.EmittedAt.IsZero() {
		event.EmittedAt = s.cfg.Now().UTC()
	}
	return s.cfg.Producer.PublishPAMEvent(ctx, event)
}

// GetSessionReplay loads the pam_sessions row scoped to workspaceID
// + sessionID, mints a pre-signed GET URL for its replay blob, and
// returns the URL alongside the session row so the handler can
// render replay metadata (started/ended timestamps, command count,
// replay storage key, expiry).
//
// Returns ErrSessionNotFound when the row is missing,
// ErrReplayUnavailable when the row exists but has no replay
// storage key, and any underlying error from the signing client
// otherwise. The replay key itself is NOT echoed back in the
// success path — only the signed URL — so the bucket name stays
// internal to the gateway / signer pair.
func (s *PAMAuditService) GetSessionReplay(ctx context.Context, workspaceID, sessionID string) (*SessionReplay, error) {
	session, err := s.loadSession(ctx, workspaceID, sessionID)
	if err != nil {
		return nil, err
	}
	if session.ReplayStorageKey == "" {
		return nil, fmt.Errorf("%w: session %s", ErrReplayUnavailable, sessionID)
	}
	if s.cfg.Replayer == nil {
		return nil, fmt.Errorf("%w: no replayer wired", ErrReplayUnavailable)
	}
	url, err := s.cfg.Replayer.PresignGet(ctx, session.ReplayStorageKey, s.cfg.ReplayURLExpiry)
	if err != nil {
		return nil, fmt.Errorf("pam: presign replay url session=%s: %w", sessionID, err)
	}
	expires := s.cfg.Now().UTC().Add(s.cfg.ReplayURLExpiry)
	return &SessionReplay{
		SessionID:   session.ID,
		WorkspaceID: session.WorkspaceID,
		SignedURL:   url,
		ExpiresAt:   expires,
		StartedAt:   session.StartedAt,
		EndedAt:     session.EndedAt,
		Protocol:    session.Protocol,
		AssetID:     session.AssetID,
		AccountID:   session.AccountID,
		Commands:    session.CommandCount,
	}, nil
}

// GetCommandTimeline returns every pam_session_commands row for
// sessionID, ordered by Sequence ascending. The caller (the
// handler) is expected to slice / paginate; PAM sessions rarely
// exceed a few hundred commands so we serve the full timeline.
func (s *PAMAuditService) GetCommandTimeline(ctx context.Context, workspaceID, sessionID string) ([]models.PAMSessionCommand, error) {
	if _, err := s.loadSession(ctx, workspaceID, sessionID); err != nil {
		return nil, err
	}
	var rows []models.PAMSessionCommand
	if err := s.cfg.DB.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Order("sequence ASC").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("pam: list pam_session_commands session=%s: %w", sessionID, err)
	}
	return rows, nil
}

// EvidencePack is the bundle ExportEvidence assembles for an
// operator who needs to hand a session over to forensics / audit
// review. It deliberately bundles every artefact in one call so the
// caller does not have to issue three round-trips just to render a
// session detail page.
//
// SignedReplayURL is empty when the underlying session has no
// replay blob — the rest of the pack (session row + commands) is
// still useful in that case. The signed URL expires per
// PAMAuditServiceConfig.ReplayURLExpiry.
type EvidencePack struct {
	Session         models.PAMSession          `json:"session"`
	Commands        []models.PAMSessionCommand `json:"commands"`
	SignedReplayURL string                     `json:"signed_replay_url,omitempty"`
	ReplayExpiresAt *time.Time                 `json:"replay_expires_at,omitempty"`
	ExportedAt      time.Time                  `json:"exported_at"`
}

// ExportEvidence loads the session row, fetches the command
// timeline, mints a pre-signed replay URL (best-effort — a
// missing replay key downgrades to empty URL + nil expiry rather
// than failing the whole export), and returns the assembled pack.
func (s *PAMAuditService) ExportEvidence(ctx context.Context, workspaceID, sessionID string) (*EvidencePack, error) {
	session, err := s.loadSession(ctx, workspaceID, sessionID)
	if err != nil {
		return nil, err
	}
	var rows []models.PAMSessionCommand
	if err := s.cfg.DB.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Order("sequence ASC").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("pam: list pam_session_commands session=%s: %w", sessionID, err)
	}
	// Defensive sort — the DB ORDER BY should already cover this
	// but a future query rewrite that relies on an index hint
	// could drop the guarantee. Keeping the sort explicit costs
	// O(n log n) on a few hundred rows and removes a class of
	// "commands appeared out of order" bugs from forensics.
	sort.Slice(rows, func(i, j int) bool { return rows[i].Sequence < rows[j].Sequence })

	pack := &EvidencePack{
		Session:    *session,
		Commands:   rows,
		ExportedAt: s.cfg.Now().UTC(),
	}
	if session.ReplayStorageKey != "" && s.cfg.Replayer != nil {
		url, err := s.cfg.Replayer.PresignGet(ctx, session.ReplayStorageKey, s.cfg.ReplayURLExpiry)
		if err == nil {
			expires := s.cfg.Now().UTC().Add(s.cfg.ReplayURLExpiry)
			pack.SignedReplayURL = url
			pack.ReplayExpiresAt = &expires
		}
	}
	return pack, nil
}

// loadSession reads pam_sessions scoped to workspaceID + id and
// translates gorm.ErrRecordNotFound to ErrSessionNotFound so the
// handler can return 404.
func (s *PAMAuditService) loadSession(ctx context.Context, workspaceID, sessionID string) (*models.PAMSession, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session_id is required", ErrValidation)
	}
	var session models.PAMSession
	if err := s.cfg.DB.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, sessionID).
		First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, sessionID)
		}
		return nil, fmt.Errorf("pam: get pam_session %s: %w", sessionID, err)
	}
	return &session, nil
}

// SessionReplay is the response shape GetSessionReplay returns to
// the handler layer. Fields are echoed straight through to JSON so
// the admin UI can render the replay metadata without a second
// round-trip to /pam/sessions/:id.
type SessionReplay struct {
	SessionID   string     `json:"session_id"`
	WorkspaceID string     `json:"workspace_id"`
	SignedURL   string     `json:"signed_url"`
	ExpiresAt   time.Time  `json:"expires_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`
	Protocol    string     `json:"protocol"`
	AssetID     string     `json:"asset_id"`
	AccountID   string     `json:"account_id"`
	Commands    int        `json:"command_count"`
}

// ListSessionsFilters narrows ListSessions without growing the
// method signature each release.
type ListSessionsFilters struct {
	UserID  string
	AssetID string
	State   string
	Limit   int
	Offset  int
}

// ListSessions returns the pam_sessions rows scoped to workspaceID
// matching filters, ordered by CreatedAt desc. Used by the
// /pam/sessions GET handler. Optional filters narrow on
// UserID / AssetID / State.
func (s *PAMAuditService) ListSessions(ctx context.Context, workspaceID string, filters ListSessionsFilters) ([]models.PAMSession, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	tx := s.cfg.DB.WithContext(ctx).Where("workspace_id = ?", workspaceID)
	if filters.UserID != "" {
		tx = tx.Where("user_id = ?", filters.UserID)
	}
	if filters.AssetID != "" {
		tx = tx.Where("asset_id = ?", filters.AssetID)
	}
	if filters.State != "" {
		tx = tx.Where("state = ?", filters.State)
	}
	if filters.Limit > 0 {
		tx = tx.Limit(filters.Limit)
	}
	if filters.Offset > 0 {
		tx = tx.Offset(filters.Offset)
	}
	var out []models.PAMSession
	if err := tx.Order("created_at desc").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("pam: list pam_sessions: %w", err)
	}
	return out, nil
}

// GetSession loads a single pam_sessions row scoped to workspaceID.
func (s *PAMAuditService) GetSession(ctx context.Context, workspaceID, sessionID string) (*models.PAMSession, error) {
	return s.loadSession(ctx, workspaceID, sessionID)
}

// TerminateSession force-terminates an active session. The session
// row is flipped to PAMSessionStateTerminated with EndedAt stamped;
// downstream consumers of the pam.session.terminated event are
// responsible for actually tearing down the gateway connection
// (the gateway subscribes to its own audit topic via the control
// plane in a follow-up milestone — for now an admin UI "terminate"
// action stamps the row and emits the event so the gateway can pick
// it up on its next health-tick).
//
// reason is the operator-supplied justification echoed onto the
// audit envelope. actorUserID is the admin who pressed the button.
func (s *PAMAuditService) TerminateSession(ctx context.Context, workspaceID, sessionID, actorUserID, reason string) (*models.PAMSession, error) {
	session, err := s.loadSession(ctx, workspaceID, sessionID)
	if err != nil {
		return nil, err
	}
	switch session.State {
	case models.PAMSessionStateCompleted,
		models.PAMSessionStateTerminated,
		models.PAMSessionStateFailed:
		// Already terminal — return the row as-is so the handler
		// can render the current state without erroring.
		return session, nil
	}
	now := s.cfg.Now().UTC()
	if err := s.cfg.DB.WithContext(ctx).
		Model(&models.PAMSession{}).
		Where("workspace_id = ? AND id = ?", workspaceID, sessionID).
		Updates(map[string]interface{}{
			"state":      models.PAMSessionStateTerminated,
			"ended_at":   now,
			"updated_at": now,
		}).Error; err != nil {
		return nil, fmt.Errorf("pam: terminate pam_session: %w", err)
	}
	session.State = models.PAMSessionStateTerminated
	session.EndedAt = &now
	session.UpdatedAt = now

	// Best-effort audit emit — a failed publish must not roll back
	// the state flip because the row is the source of truth.
	if err := s.RecordEvent(ctx, PAMAuditEvent{
		EventType:   PAMEventSessionTerminated,
		WorkspaceID: workspaceID,
		ActorUserID: actorUserID,
		SessionID:   sessionID,
		AssetID:     session.AssetID,
		AccountID:   session.AccountID,
		Protocol:    session.Protocol,
		Outcome:     "terminated",
		Reason:      reason,
		EmittedAt:   now,
	}); err != nil {
		// Don't return — see comment above. The handler logs.
		return session, fmt.Errorf("pam: state flipped to terminated but audit emit failed: %w", err)
	}
	return session, nil
}
