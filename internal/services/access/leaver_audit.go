// Package access — Phase 11 leaver kill-switch audit trail.
//
// LeaverKillSwitchEvent is the structured audit envelope emitted by
// HandleLeaver after each kill-switch layer fires. The event is
// serialised onto the same ShieldnetLogEvent v1 envelope the rest
// of the audit pipeline already uses (see audit_producer.go) so
// downstream SIEM/SOAR pipelines can consume it without a new
// schema.
//
// Layers (mirroring the comment block in HandleLeaver):
//
//   1. LeaverLayerGrantRevoke      — pull upstream API access
//   2. LeaverLayerTeamRemove       — drop ImpactResolver matches
//   3. LeaverLayerKeycloakDisable  — block new SSO sign-ins
//   4. LeaverLayerSessionRevoke    — kill live SaaS sessions per connector
//   5. LeaverLayerSCIMDeprovision  — push terminal state to SaaS
//   6. LeaverLayerOpenZitiDisable  — kill the dataplane tunnel
//
// Status:
//
//   - LeaverStatusSuccess — layer executed successfully.
//   - LeaverStatusFailed  — layer attempted but the connector / hook returned an error.
//   - LeaverStatusSkipped — layer was not wired (e.g. no Keycloak hook in dev).
//
// Every event carries WorkspaceID + UserID so audit consumers can
// stitch a leaver across layers. ConnectorID is set for the
// per-connector layers (session-revoke, scim-deprovision); empty
// for the workspace-level layers.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// LeaverLayer enumerates the kill-switch stages HandleLeaver runs.
// Keep the slug stable across releases — downstream SIEM dashboards
// pivot on these values.
type LeaverLayer string

const (
	LeaverLayerGrantRevoke      LeaverLayer = "grant_revoke"
	LeaverLayerTeamRemove       LeaverLayer = "team_remove"
	LeaverLayerKeycloakDisable  LeaverLayer = "keycloak_disable"
	LeaverLayerSessionRevoke    LeaverLayer = "session_revoke"
	LeaverLayerSCIMDeprovision  LeaverLayer = "scim_deprovision"
	LeaverLayerOpenZitiDisable  LeaverLayer = "openziti_disable"
)

// LeaverStatus enumerates the per-layer outcome.
type LeaverStatus string

const (
	LeaverStatusSuccess LeaverStatus = "success"
	LeaverStatusFailed  LeaverStatus = "failed"
	LeaverStatusSkipped LeaverStatus = "skipped"
)

// LeaverKillSwitchEvent is the structured audit envelope HandleLeaver
// emits after each kill-switch layer. Serialise via the standard
// AuditProducer path; see emitLeaverEvent.
type LeaverKillSwitchEvent struct {
	WorkspaceID string       `json:"workspace_id"`
	UserID      string       `json:"user_id"`
	Layer       LeaverLayer  `json:"layer"`
	ConnectorID string       `json:"connector_id,omitempty"`
	Status      LeaverStatus `json:"status"`
	Error       string       `json:"error,omitempty"`
	Timestamp   time.Time    `json:"timestamp"`
}

// toAuditLogEntry maps the LeaverKillSwitchEvent onto the canonical
// AuditLogEntry shape so the existing AuditProducer pipeline can
// publish it unmodified.
func (e LeaverKillSwitchEvent) toAuditLogEntry() *AuditLogEntry {
	raw := map[string]interface{}{
		"workspace_id": e.WorkspaceID,
		"layer":        string(e.Layer),
		"status":       string(e.Status),
	}
	if e.ConnectorID != "" {
		raw["connector_id"] = e.ConnectorID
	}
	if e.Error != "" {
		raw["error"] = e.Error
	}
	return &AuditLogEntry{
		EventID:          fmt.Sprintf("leaver-%s-%s-%d", e.UserID, e.Layer, e.Timestamp.UnixNano()),
		EventType:        "access.leaver.kill_switch",
		Action:           string(e.Layer),
		Timestamp:        e.Timestamp,
		TargetExternalID: e.UserID,
		TargetType:       "user",
		Outcome:          string(e.Status),
		RawData:          raw,
	}
}

// MarshalJSON ensures the timestamp is serialised in UTC RFC3339
// regardless of the local timezone. Downstream consumers depend on
// the Z suffix.
func (e LeaverKillSwitchEvent) MarshalJSON() ([]byte, error) {
	type alias LeaverKillSwitchEvent
	out := alias(e)
	out.Timestamp = e.Timestamp.UTC()
	return json.Marshal(out)
}

// errLeaverEventInvalid is the sentinel returned by validation;
// callers (in tests) can errors.Is() against it without depending
// on the literal error string.
var errLeaverEventInvalid = errors.New("access: leaver kill-switch event is invalid")

// ErrLeaverEventInvalid is the exported sentinel.
var ErrLeaverEventInvalid = errLeaverEventInvalid

// validate returns a non-nil error when the event is missing a
// required field. Used by the SetAuditProducer wire-up tests.
func (e LeaverKillSwitchEvent) validate() error {
	if e.UserID == "" {
		return fmt.Errorf("%w: user_id is required", errLeaverEventInvalid)
	}
	if e.WorkspaceID == "" {
		return fmt.Errorf("%w: workspace_id is required", errLeaverEventInvalid)
	}
	if e.Layer == "" {
		return fmt.Errorf("%w: layer is required", errLeaverEventInvalid)
	}
	if e.Status == "" {
		return fmt.Errorf("%w: status is required", errLeaverEventInvalid)
	}
	return nil
}

// publishLeaverEvent serialises one LeaverKillSwitchEvent to the
// wired AuditProducer. nil producer is a no-op so dev / test
// binaries continue to work without Kafka.
func publishLeaverEvent(ctx context.Context, producer AuditProducer, ev LeaverKillSwitchEvent) error {
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
