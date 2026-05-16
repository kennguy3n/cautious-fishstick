// Package access — audit log producer (Task 16).
//
// AuditProducer is the abstract sink the access-audit worker (Task 17)
// publishes batched AuditLogEntry records into. The production
// implementation wraps a Kafka writer and emits ShieldnetLogEvent v1
// envelopes onto the topic configured by ACCESS_AUDIT_LOG_TOPIC (see
// internal/config/access.go and docs/architecture.md).
//
// A NoOpAuditProducer is provided for dev/test environments that run
// without a Kafka broker — it counts published entries so callers can
// still assert that the audit job *would* have emitted N records.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ShieldnetLogEventVersion is the schema version embedded in every
// ShieldnetLogEvent envelope produced by the audit pipeline.
const ShieldnetLogEventVersion = "v1"

// AuditProducer is the contract the access-audit job (Task 17) uses
// to publish batched audit entries downstream. Implementations MUST
// be safe for concurrent use because the worker may publish from
// multiple connector goroutines.
type AuditProducer interface {
	PublishAccessAuditLogs(ctx context.Context, connectorID string, entries []*AuditLogEntry) error
	Close() error
}

// ShieldnetLogEvent is the v1 envelope the audit producer wraps
// around each AuditLogEntry. Fields mirror docs/architecture.md — keep
// them in lockstep with the schema or downstream consumers will
// break.
type ShieldnetLogEvent struct {
	SchemaVersion string                 `json:"schema_version"`
	Source        string                 `json:"source"`
	ConnectorID   string                 `json:"connector_id"`
	EmittedAt     time.Time              `json:"emitted_at"`
	Event         *AuditLogEntry         `json:"event"`
	// Tags is a free-form map for downstream routing/tagging.
	Tags map[string]string `json:"tags,omitempty"`
}

// KafkaWriter is the minimal contract that KafkaAuditProducer
// depends on. The interface is small so tests can substitute a
// channel-backed fake and production binaries can plug in a real
// Kafka client (e.g. segmentio/kafka-go's *kafka.Writer) without
// dragging the dependency through this package.
type KafkaWriter interface {
	WriteMessages(ctx context.Context, msgs ...KafkaMessage) error
	Close() error
}

// KafkaMessage is the dependency-free message shape KafkaAuditProducer
// hands to KafkaWriter. Real Kafka writers should convert this to
// their native message struct in a thin adapter.
type KafkaMessage struct {
	Topic   string
	Key     []byte
	Value   []byte
	Headers map[string]string
}

// KafkaAuditProducer publishes ShieldnetLogEvent envelopes onto a
// Kafka topic. Connector ID is the message key so per-connector
// partitions remain ordered.
type KafkaAuditProducer struct {
	writer KafkaWriter
	topic  string
	source string
}

// NewKafkaAuditProducer constructs a KafkaAuditProducer.
func NewKafkaAuditProducer(writer KafkaWriter, topic string) *KafkaAuditProducer {
	if topic == "" {
		topic = "access_audit_logs"
	}
	return &KafkaAuditProducer{writer: writer, topic: topic, source: "shieldnet360-access"}
}

// PublishAccessAuditLogs serialises each entry to a ShieldnetLogEvent
// envelope and writes them as a single Kafka batch. An empty batch
// is a no-op (we don't poke the broker).
func (p *KafkaAuditProducer) PublishAccessAuditLogs(ctx context.Context, connectorID string, entries []*AuditLogEntry) error {
	if p == nil || p.writer == nil {
		return errors.New("access: kafka audit producer not initialised")
	}
	if len(entries) == 0 {
		return nil
	}
	msgs := make([]KafkaMessage, 0, len(entries))
	now := time.Now().UTC()
	for _, e := range entries {
		if e == nil {
			continue
		}
		env := ShieldnetLogEvent{
			SchemaVersion: ShieldnetLogEventVersion,
			Source:        p.source,
			ConnectorID:   connectorID,
			EmittedAt:     now,
			Event:         e,
		}
		raw, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("access: encode shieldnet log event: %w", err)
		}
		msgs = append(msgs, KafkaMessage{
			Topic: p.topic,
			Key:   []byte(connectorID),
			Value: raw,
			Headers: map[string]string{
				"schema_version": ShieldnetLogEventVersion,
				"connector_id":   connectorID,
			},
		})
	}
	if len(msgs) == 0 {
		return nil
	}
	return p.writer.WriteMessages(ctx, msgs...)
}

// Close shuts down the underlying writer.
func (p *KafkaAuditProducer) Close() error {
	if p == nil || p.writer == nil {
		return nil
	}
	return p.writer.Close()
}

// NoOpAuditProducer is the dev/test stand-in. PublishAccessAuditLogs
// records the inbound batches but never reaches the network, so
// binaries without Kafka stay healthy.
type NoOpAuditProducer struct {
	mu      sync.Mutex
	batches int
	entries int
}

// PublishAccessAuditLogs records the batch and entry counters.
func (n *NoOpAuditProducer) PublishAccessAuditLogs(_ context.Context, _ string, entries []*AuditLogEntry) error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	n.batches++
	n.entries += len(entries)
	n.mu.Unlock()
	return nil
}

// Close is a no-op for the NoOpAuditProducer.
func (n *NoOpAuditProducer) Close() error { return nil }

// BatchesPublished returns the number of PublishAccessAuditLogs calls
// observed. Useful for tests.
func (n *NoOpAuditProducer) BatchesPublished() int {
	if n == nil {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.batches
}

// EntriesPublished returns the total number of audit log entries
// observed across every PublishAccessAuditLogs call. Useful for tests.
func (n *NoOpAuditProducer) EntriesPublished() int {
	if n == nil {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.entries
}

// Compile-time interface assertions.
var (
	_ AuditProducer = (*KafkaAuditProducer)(nil)
	_ AuditProducer = (*NoOpAuditProducer)(nil)
)
