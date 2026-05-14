// Package access — Phase 11 grant-expiry audit trail.
//
// GrantExpiryEvent is the structured audit envelope emitted by the
// GrantExpiryEnforcer cron after auto-revoking an expired grant or
// surfacing a soon-to-expire warning. The event is serialised onto
// the same ShieldnetLogEvent v1 envelope the rest of the audit
// pipeline uses (see audit_producer.go) so downstream SIEM / SOAR
// pipelines can consume it without a new schema.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// GrantExpiryAction enumerates the actions the grant-expiry
// enforcer audits. Keep the slug stable across releases —
// downstream dashboards pivot on these values.
type GrantExpiryAction string

const (
	// GrantExpiryActionRevoked marks a grant that the enforcer
	// auto-revoked because expires_at has elapsed.
	GrantExpiryActionRevoked GrantExpiryAction = "auto_revoked"
	// GrantExpiryActionWarned marks a grant the enforcer surfaced
	// in the look-ahead warning sweep.
	GrantExpiryActionWarned GrantExpiryAction = "warned"
)

// GrantExpiryEvent is the canonical audit envelope for the
// grant-expiry enforcer. Status mirrors the kill-switch shape:
// "success" for happy-path emit, "failed" when the revoke or
// notification failed.
type GrantExpiryEvent struct {
	WorkspaceID string            `json:"workspace_id"`
	UserID      string            `json:"user_id"`
	GrantID     string            `json:"grant_id"`
	ConnectorID string            `json:"connector_id,omitempty"`
	ResourceID  string            `json:"resource_id,omitempty"`
	Action      GrantExpiryAction `json:"action"`
	Status      string            `json:"status"`
	Error       string            `json:"error,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// MarshalJSON ensures the timestamp is serialised in UTC RFC3339
// regardless of the local timezone. Downstream consumers depend on
// the Z suffix.
func (e GrantExpiryEvent) MarshalJSON() ([]byte, error) {
	type alias GrantExpiryEvent
	out := alias(e)
	out.Timestamp = e.Timestamp.UTC()
	if !e.ExpiresAt.IsZero() {
		out.ExpiresAt = e.ExpiresAt.UTC()
	}
	return json.Marshal(out)
}

// toAuditLogEntry maps onto the canonical AuditLogEntry shape so
// the existing AuditProducer pipeline can publish it unmodified.
func (e GrantExpiryEvent) toAuditLogEntry() *AuditLogEntry {
	raw := map[string]interface{}{
		"workspace_id": e.WorkspaceID,
		"grant_id":     e.GrantID,
		"action":       string(e.Action),
		"status":       e.Status,
	}
	if e.ConnectorID != "" {
		raw["connector_id"] = e.ConnectorID
	}
	if e.ResourceID != "" {
		raw["resource_id"] = e.ResourceID
	}
	if e.Error != "" {
		raw["error"] = e.Error
	}
	if !e.ExpiresAt.IsZero() {
		raw["expires_at"] = e.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return &AuditLogEntry{
		EventID:          fmt.Sprintf("grant-expiry-%s-%s-%d", e.GrantID, e.Action, e.Timestamp.UnixNano()),
		EventType:        "access.grant.expiry",
		Action:           string(e.Action),
		Timestamp:        e.Timestamp,
		TargetExternalID: e.UserID,
		TargetType:       "user",
		Outcome:          e.Status,
		RawData:          raw,
	}
}

// errGrantExpiryEventInvalid is the sentinel returned by
// validation; callers (in tests) can errors.Is() against it
// without depending on the literal error string.
var errGrantExpiryEventInvalid = errors.New("access: grant expiry event is invalid")

// ErrGrantExpiryEventInvalid is the exported sentinel.
var ErrGrantExpiryEventInvalid = errGrantExpiryEventInvalid

func (e GrantExpiryEvent) validate() error {
	if e.GrantID == "" {
		return fmt.Errorf("%w: grant_id is required", errGrantExpiryEventInvalid)
	}
	if e.Action == "" {
		return fmt.Errorf("%w: action is required", errGrantExpiryEventInvalid)
	}
	if e.Status == "" {
		return fmt.Errorf("%w: status is required", errGrantExpiryEventInvalid)
	}
	return nil
}

// PublishGrantExpiryEvent serialises one GrantExpiryEvent to the
// wired AuditProducer. nil producer is a no-op so dev / test
// binaries continue to work without Kafka.
func PublishGrantExpiryEvent(ctx context.Context, producer AuditProducer, ev GrantExpiryEvent) error {
	if producer == nil {
		return nil
	}
	if err := ev.validate(); err != nil {
		return err
	}
	connectorID := ev.ConnectorID
	if connectorID == "" {
		connectorID = "shieldnet360-access"
	}
	return producer.PublishAccessAuditLogs(ctx, connectorID, []*AuditLogEntry{ev.toAuditLogEntry()})
}
