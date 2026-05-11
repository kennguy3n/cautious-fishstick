package access

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type fakeKafkaWriter struct {
	msgs       []KafkaMessage
	writeErr   error
	closed     bool
}

func (f *fakeKafkaWriter) WriteMessages(_ context.Context, msgs ...KafkaMessage) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.msgs = append(f.msgs, msgs...)
	return nil
}

func (f *fakeKafkaWriter) Close() error {
	f.closed = true
	return nil
}

func TestKafkaAuditProducer_PublishesEnvelopes(t *testing.T) {
	w := &fakeKafkaWriter{}
	p := NewKafkaAuditProducer(w, "access_audit_logs")
	entries := []*AuditLogEntry{
		{EventID: "e1", EventType: "signIn", Timestamp: time.Unix(1704110400, 0).UTC(), ActorEmail: "alice@corp.example"},
		{EventID: "e2", EventType: "signIn", Timestamp: time.Unix(1704114000, 0).UTC(), ActorEmail: "bob@corp.example"},
	}
	if err := p.PublishAccessAuditLogs(context.Background(), "conn-1", entries); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(w.msgs) != 2 {
		t.Fatalf("messages = %d", len(w.msgs))
	}
	if w.msgs[0].Topic != "access_audit_logs" {
		t.Errorf("topic = %s", w.msgs[0].Topic)
	}
	if string(w.msgs[0].Key) != "conn-1" {
		t.Errorf("key = %s", string(w.msgs[0].Key))
	}
	var env ShieldnetLogEvent
	if err := json.Unmarshal(w.msgs[0].Value, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.SchemaVersion != ShieldnetLogEventVersion {
		t.Errorf("schema = %s", env.SchemaVersion)
	}
	if env.ConnectorID != "conn-1" {
		t.Errorf("connector = %s", env.ConnectorID)
	}
	if env.Event == nil || env.Event.EventID != "e1" {
		t.Errorf("event = %+v", env.Event)
	}
}

func TestKafkaAuditProducer_EmptyBatchSkipsWriter(t *testing.T) {
	w := &fakeKafkaWriter{}
	p := NewKafkaAuditProducer(w, "")
	if err := p.PublishAccessAuditLogs(context.Background(), "conn-1", nil); err != nil {
		t.Fatalf("Publish nil: %v", err)
	}
	if len(w.msgs) != 0 {
		t.Errorf("messages = %d", len(w.msgs))
	}
}

func TestKafkaAuditProducer_PropagatesWriteError(t *testing.T) {
	want := errors.New("kafka unavailable")
	w := &fakeKafkaWriter{writeErr: want}
	p := NewKafkaAuditProducer(w, "")
	err := p.PublishAccessAuditLogs(context.Background(), "conn-1",
		[]*AuditLogEntry{{EventID: "e1"}})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestKafkaAuditProducer_DefaultsTopic(t *testing.T) {
	w := &fakeKafkaWriter{}
	p := NewKafkaAuditProducer(w, "")
	if p.topic != "access_audit_logs" {
		t.Errorf("topic = %s", p.topic)
	}
}

func TestNoOpAuditProducer_Records(t *testing.T) {
	n := &NoOpAuditProducer{}
	if err := n.PublishAccessAuditLogs(context.Background(), "c", []*AuditLogEntry{{EventID: "e1"}, {EventID: "e2"}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := n.PublishAccessAuditLogs(context.Background(), "c", []*AuditLogEntry{{EventID: "e3"}}); err != nil {
		t.Fatalf("Publish 2: %v", err)
	}
	if got := n.BatchesPublished(); got != 2 {
		t.Errorf("batches = %d", got)
	}
	if got := n.EntriesPublished(); got != 3 {
		t.Errorf("entries = %d", got)
	}
}
