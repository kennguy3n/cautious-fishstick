package access

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// droppingRiskAssessor implements RiskAssessor and, as a side
// effect, drops the access_requests table the moment
// AssessRequestRisk is called. The initial CreateRequest INSERT
// has already committed by then; the follow-up risk_score UPDATE
// is what we want to fail.
//
// This drives the "UPDATE failed" branch in CreateRequest without
// reaching for a custom GORM dialect or a fault-injecting driver.
type droppingRiskAssessor struct {
	db      *gorm.DB
	score   string
	factors []string
}

func (d *droppingRiskAssessor) AssessRequestRisk(_ context.Context, _ interface{}) (string, []string, bool) {
	// SQLite's Migrator.DropTable is synchronous; once we return,
	// the request_service.go follow-up UPDATE will hit a non-
	// existent table and surface an error. CreateRequest must log
	// + swallow it.
	_ = d.db.Migrator().DropTable((&models.AccessRequest{}).TableName())
	return d.score, d.factors, true
}

// captureLogs swaps log.Default()'s output for a buffer and
// restores it on test cleanup. Returns the buffer the test can
// inspect after the call under test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	prevFlags := log.Flags()
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prev)
		log.SetFlags(prevFlags)
	})
	return buf
}

// TestCreateRequest_RiskPersistFailureLogsAndReturnsNilError asserts
// the contract from docs/architecture.md: a failure to persist the AI risk
// score must NOT fail the access request. The service logs the
// failure (so operators have a signal) and returns the in-memory
// request unchanged with a nil error. The DB row stays without
// risk_score until a future enrichment pass.
func TestCreateRequest_RiskPersistFailureLogsAndReturnsNilError(t *testing.T) {
	db := newTestDB(t)
	svc := NewAccessRequestService(db)
	svc.SetRiskAssessor(&droppingRiskAssessor{
		db:      db,
		score:   models.RequestRiskHigh,
		factors: []string{"sensitive_resource"},
	})

	buf := captureLogs(t)

	got, err := svc.CreateRequest(context.Background(), validInput())
	if err != nil {
		t.Fatalf("CreateRequest returned err = %v; want nil (per docs/architecture.md AI is decision-support)", err)
	}
	if got == nil {
		t.Fatal("CreateRequest returned nil request without error")
	}
	if got.RiskScore != models.RequestRiskHigh {
		t.Errorf("returned RiskScore = %q; want %q (in-memory copy must reflect score)", got.RiskScore, models.RequestRiskHigh)
	}

	logged := buf.String()
	if !strings.Contains(logged, "failed to persist risk_score") {
		t.Errorf("log output = %q; want substring \"failed to persist risk_score\"", logged)
	}
	if !strings.Contains(logged, got.ID) {
		t.Errorf("log output = %q; want it to include request ID %q", logged, got.ID)
	}
}
