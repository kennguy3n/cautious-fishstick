// Package pam — PAM audit producer (Milestone 7 Task 16).
//
// PAMAuditProducer publishes the immutable PAM lifecycle event stream
// (pam.session.*, pam.secret.*, pam.lease.*) onto the same Kafka
// substrate that the access-audit pipeline uses (see
// internal/services/access/audit_producer.go). The envelope reuses
// access.ShieldnetLogEvent so downstream OCSF normalisers do not need
// a second schema — only the new event_type strings and the Tags
// map distinguish PAM events from access events.
//
// A NoOpPAMAuditProducer is provided for dev / test wiring that
// runs without a Kafka broker so call sites can still observe
// "what would have been published" via counters.
package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// PAM event-type strings. These are the values written into
// PAMAuditEvent.EventType + the Kafka header `event_type`, and they
// match docs/pam/architecture.md §7 verbatim. Downstream consumers
// route on this string so any rename here must update the docs and
// every consumer in lockstep.
const (
	// session lifecycle
	PAMEventSessionRequested  = "pam.session.requested"
	PAMEventSessionAuthorized = "pam.session.authorized"
	PAMEventSessionStarted    = "pam.session.started"
	PAMEventSessionEnded      = "pam.session.ended"
	PAMEventSessionTerminated = "pam.session.terminated"
	PAMEventSessionFailed     = "pam.session.failed"
	PAMEventSessionCommand    = "pam.session.command"

	// secret lifecycle
	PAMEventSecretVaulted   = "pam.secret.vaulted"
	PAMEventSecretRevealed  = "pam.secret.revealed"
	PAMEventSecretRotated   = "pam.secret.rotated"
	PAMEventSecretRevoked   = "pam.secret.revoked"
	PAMEventSecretRevealErr = "pam.secret.reveal_denied"

	// lease lifecycle
	PAMEventLeaseRequested = "pam.lease.requested"
	PAMEventLeaseApproved  = "pam.lease.approved"
	PAMEventLeaseRevoked   = "pam.lease.revoked"
	PAMEventLeaseExpired   = "pam.lease.expired"
)

// pamAuditTopicDefault is the Kafka topic PAMAuditProducer publishes
// onto when the caller does not supply an override. The dedicated
// topic lets downstream consumers subscribe to PAM events without
// filtering the access-audit firehose by event_type.
const pamAuditTopicDefault = "pam_audit_logs"

// pamAuditSource is the value baked into every emitted envelope's
// Source field so downstream observers can tell PAM-originated
// events apart from access-platform events even after the headers
// are stripped.
const pamAuditSource = "shieldnet360-pam"

// PAMAuditEvent is the per-event payload PAMAuditProducer wraps in a
// ShieldnetLogEvent envelope before publishing. Most fields are
// optional — the producer drops empty fields from the marshalled
// JSON via omitempty so callers can populate just the slice that
// matters for their event type. Fields mirror docs/pam/architecture.md
// §7; keep the JSON tags stable across versions because consumers key
// off them.
type PAMAuditEvent struct {
	EventType   string    `json:"event_type"`
	WorkspaceID string    `json:"workspace_id"`
	ActorUserID string    `json:"actor_user_id,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	LeaseID     string    `json:"lease_id,omitempty"`
	AssetID     string    `json:"asset_id,omitempty"`
	AccountID   string    `json:"account_id,omitempty"`
	SecretID    string    `json:"secret_id,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	// Outcome is "success", "denied", "failed", or "expired" so
	// consumers can compute success / denial rates without parsing
	// the human-readable Reason.
	Outcome string `json:"outcome,omitempty"`
	// Reason is the free-text justification or error message
	// surfaced to humans (admin UI, audit search). Avoid embedding
	// secrets here — the audit topic may end up in shared evidence
	// exports.
	Reason string `json:"reason,omitempty"`
	// Metadata is a free-form map for event-specific context that
	// does not justify a top-level field (e.g. command_sequence,
	// command_input_truncated, risk_score, command_count_on_close).
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// EmittedAt is the wall-clock time the event source observed
	// the underlying change. If left zero PAMAuditProducer fills
	// it with the publish time.
	EmittedAt time.Time `json:"emitted_at"`
}

// PAMAuditProducer is the contract every PAM service-layer call
// site depends on to emit lifecycle events. Implementations MUST be
// safe for concurrent use because gateway request goroutines, cron
// sweeps, and HTTP handlers may publish simultaneously.
type PAMAuditProducer interface {
	PublishPAMEvent(ctx context.Context, event PAMAuditEvent) error
	PublishPAMEvents(ctx context.Context, events []PAMAuditEvent) error
	Close() error
}

// KafkaPAMAuditProducer wraps an access.KafkaWriter so the PAM
// module emits onto the same Kafka substrate the access-platform
// audit pipeline uses. The producer is a thin envelope adapter +
// header set; the heavy lifting (batching, retry, broker failover)
// lives in the wrapped writer.
type KafkaPAMAuditProducer struct {
	writer access.KafkaWriter
	topic  string
	source string
	now    func() time.Time
}

// NewKafkaPAMAuditProducer returns a producer that publishes onto
// topic via writer. An empty topic defaults to pamAuditTopicDefault
// so cmd/ztna-api wiring stays one line.
func NewKafkaPAMAuditProducer(writer access.KafkaWriter, topic string) *KafkaPAMAuditProducer {
	if topic == "" {
		topic = pamAuditTopicDefault
	}
	return &KafkaPAMAuditProducer{
		writer: writer,
		topic:  topic,
		source: pamAuditSource,
		now:    time.Now,
	}
}

// PublishPAMEvent is the single-event convenience over
// PublishPAMEvents.
func (p *KafkaPAMAuditProducer) PublishPAMEvent(ctx context.Context, event PAMAuditEvent) error {
	return p.PublishPAMEvents(ctx, []PAMAuditEvent{event})
}

// PublishPAMEvents marshals each event into a ShieldnetLogEvent v1
// envelope and writes the batch as one Kafka call. EmittedAt is
// stamped per event (caller-supplied values win); the workspace ID
// is the message key so per-tenant partitions stay ordered.
func (p *KafkaPAMAuditProducer) PublishPAMEvents(ctx context.Context, events []PAMAuditEvent) error {
	if p == nil || p.writer == nil {
		return errors.New("pam: kafka audit producer not initialised")
	}
	if len(events) == 0 {
		return nil
	}
	msgs := make([]access.KafkaMessage, 0, len(events))
	for i := range events {
		ev := events[i]
		if ev.EventType == "" {
			return fmt.Errorf("pam: event_type is required (index %d)", i)
		}
		if ev.EmittedAt.IsZero() {
			ev.EmittedAt = p.now().UTC()
		}
		env := access.ShieldnetLogEvent{
			SchemaVersion: access.ShieldnetLogEventVersion,
			Source:        p.source,
			ConnectorID:   ev.WorkspaceID,
			EmittedAt:     ev.EmittedAt,
			Event:         nil,
			Tags: map[string]string{
				"event_type":   ev.EventType,
				"workspace_id": ev.WorkspaceID,
			},
		}
		// We do NOT reuse access.AuditLogEntry as the envelope's
		// inner Event because the PAM event shape is materially
		// different (no upstream connector, no per-resource grant
		// row). Marshalling the PAMAuditEvent on its own and
		// hand-rolling the outer envelope avoids dragging the
		// access types into PAM consumers.
		body, err := marshalPAMEnvelope(env, ev)
		if err != nil {
			return fmt.Errorf("pam: encode pam audit envelope: %w", err)
		}
		msgs = append(msgs, access.KafkaMessage{
			Topic: p.topic,
			Key:   []byte(ev.WorkspaceID),
			Value: body,
			Headers: map[string]string{
				"schema_version": access.ShieldnetLogEventVersion,
				"event_type":     ev.EventType,
				"workspace_id":   ev.WorkspaceID,
				"source":         p.source,
			},
		})
	}
	if len(msgs) == 0 {
		return nil
	}
	return p.writer.WriteMessages(ctx, msgs...)
}

// Close shuts down the underlying KafkaWriter.
func (p *KafkaPAMAuditProducer) Close() error {
	if p == nil || p.writer == nil {
		return nil
	}
	return p.writer.Close()
}

// marshalPAMEnvelope renders the ShieldnetLogEvent envelope with the
// PAMAuditEvent as its inner event, side-stepping the
// access.AuditLogEntry typed field on ShieldnetLogEvent. The
// canonical schema documented in docs/pam/architecture.md §7
// matches this layout.
func marshalPAMEnvelope(env access.ShieldnetLogEvent, ev PAMAuditEvent) ([]byte, error) {
	out := struct {
		SchemaVersion string            `json:"schema_version"`
		Source        string            `json:"source"`
		ConnectorID   string            `json:"connector_id"`
		EmittedAt     time.Time         `json:"emitted_at"`
		Event         PAMAuditEvent     `json:"event"`
		Tags          map[string]string `json:"tags,omitempty"`
	}{
		SchemaVersion: env.SchemaVersion,
		Source:        env.Source,
		ConnectorID:   env.ConnectorID,
		EmittedAt:     env.EmittedAt,
		Event:         ev,
		Tags:          env.Tags,
	}
	return json.Marshal(out)
}

// NoOpPAMAuditProducer is the dev / test stand-in. Each call records
// the inbound batch + per-event counters so call sites can still
// assert the producer would have emitted N events. Safe for
// concurrent use.
type NoOpPAMAuditProducer struct {
	mu      sync.Mutex
	batches int
	events  []PAMAuditEvent
}

// PublishPAMEvent records the single event.
func (n *NoOpPAMAuditProducer) PublishPAMEvent(_ context.Context, ev PAMAuditEvent) error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	n.batches++
	n.events = append(n.events, ev)
	n.mu.Unlock()
	return nil
}

// PublishPAMEvents records the batch.
func (n *NoOpPAMAuditProducer) PublishPAMEvents(_ context.Context, events []PAMAuditEvent) error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	n.batches++
	n.events = append(n.events, events...)
	n.mu.Unlock()
	return nil
}

// Close is a no-op for NoOpPAMAuditProducer.
func (n *NoOpPAMAuditProducer) Close() error { return nil }

// BatchesPublished returns the number of PublishPAMEvent* calls
// observed. Useful for tests.
func (n *NoOpPAMAuditProducer) BatchesPublished() int {
	if n == nil {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.batches
}

// Events returns a defensive copy of every event observed since
// construction. Useful for tests that need to assert the field
// content of emitted events.
func (n *NoOpPAMAuditProducer) Events() []PAMAuditEvent {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]PAMAuditEvent, len(n.events))
	copy(out, n.events)
	return out
}

// Compile-time interface assertions.
var (
	_ PAMAuditProducer = (*KafkaPAMAuditProducer)(nil)
	_ PAMAuditProducer = (*NoOpPAMAuditProducer)(nil)
)
