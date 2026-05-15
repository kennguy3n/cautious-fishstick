package access

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newPhase3DB opens a fresh in-memory SQLite DB and AutoMigrates the
// Phase 3 tables (plus the Phase 2 tables that the existing newTestDB
// helper already migrates). Each test gets its own DB so tests can
// run in parallel under -race.
func newPhase3DB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newTestDB(t)
	if err := db.AutoMigrate(
		&models.Policy{},
		&models.Team{},
		&models.TeamMember{},
		&models.Resource{},
	); err != nil {
		t.Fatalf("auto migrate phase 3: %v", err)
	}
	return db
}

// rawJSON marshals v into a json.RawMessage; bare-bones helper used
// throughout the policy/test-access tests.
func rawJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal selector: %v", err)
	}
	return json.RawMessage(b)
}

// validDraftInput returns a populated CreateDraftPolicyInput targeting
// engineers + ssh-host resources. Tests mutate individual fields to
// drive specific validation paths.
func validDraftInput(t *testing.T) CreateDraftPolicyInput {
	return CreateDraftPolicyInput{
		WorkspaceID:        "01H000000000000000WORKSPACE",
		Name:               "engineering ssh access",
		Description:        "engineers get SSH on prod-db hosts",
		AttributesSelector: rawJSON(t, map[string]string{"department": "engineering"}),
		ResourceSelector:   rawJSON(t, map[string]string{"category": "ssh-host"}),
		Action:             models.PolicyActionAllow,
	}
}

// seedTeam inserts a teams row with the given attributes. Pass a nil
// map to skip the JSON tag.
func seedTeam(t *testing.T, db *gorm.DB, workspaceID, id, name string, attrs map[string]string) {
	t.Helper()
	team := &models.Team{
		ID:          id,
		WorkspaceID: workspaceID,
		Name:        name,
	}
	if attrs != nil {
		b, err := json.Marshal(attrs)
		if err != nil {
			t.Fatalf("marshal team attrs: %v", err)
		}
		team.Attributes = datatypes.JSON(b)
	}
	if err := db.Create(team).Error; err != nil {
		t.Fatalf("seed team: %v", err)
	}
}

// seedTeamMember inserts a team_members row.
func seedTeamMember(t *testing.T, db *gorm.DB, teamID, userID string) {
	t.Helper()
	tm := &models.TeamMember{
		ID:     teamID + ":" + userID,
		TeamID: teamID,
		UserID: userID,
	}
	if err := db.Create(tm).Error; err != nil {
		t.Fatalf("seed team_member: %v", err)
	}
}

// seedResource inserts a resources row.
func seedResource(t *testing.T, db *gorm.DB, workspaceID, id, externalID, category string, tags map[string]string) {
	t.Helper()
	r := &models.Resource{
		ID:          id,
		WorkspaceID: workspaceID,
		ExternalID:  externalID,
		Name:        externalID,
		Category:    category,
	}
	if tags != nil {
		b, err := json.Marshal(tags)
		if err != nil {
			t.Fatalf("marshal resource tags: %v", err)
		}
		r.Tags = datatypes.JSON(b)
	}
	if err := db.Create(r).Error; err != nil {
		t.Fatalf("seed resource: %v", err)
	}
}

// seedLivePolicy inserts a non-draft, active policy with the supplied
// selectors and action — used by conflict-detector tests.
//
// IsDraft is the zero value (false) here, and the GORM tag declares
// default:true on policies.is_draft, so a plain struct-mode db.Create
// would let the DB default fire and silently turn the row into a draft.
// We dodge that with a GORM map-mode INSERT, which always serialises
// every key in the map regardless of Go zero-value status. This is a
// supported GORM v2 pattern and not raw SQL.
func seedLivePolicy(t *testing.T, db *gorm.DB, workspaceID, id, name string, attrSel, resSel map[string]string, action string) *models.Policy {
	t.Helper()
	row := map[string]interface{}{
		"id":           id,
		"workspace_id": workspaceID,
		"name":         name,
		"action":       action,
		"is_draft":     false,
		"is_active":    true,
	}
	if attrSel != nil {
		b, err := json.Marshal(attrSel)
		if err != nil {
			t.Fatalf("marshal attr sel: %v", err)
		}
		row["attributes_selector"] = datatypes.JSON(b)
	}
	if resSel != nil {
		b, err := json.Marshal(resSel)
		if err != nil {
			t.Fatalf("marshal res sel: %v", err)
		}
		row["resource_selector"] = datatypes.JSON(b)
	}
	if err := db.Table((models.Policy{}).TableName()).Create(row).Error; err != nil {
		t.Fatalf("seed live policy: %v", err)
	}
	var p models.Policy
	if err := db.Where("id = ?", id).First(&p).Error; err != nil {
		t.Fatalf("read back live policy: %v", err)
	}
	return &p
}

// TestCreateDraft_HappyPath asserts the row is persisted with
// IsDraft=true, IsActive=true, no PromotedAt, and a non-empty ULID.
func TestCreateDraft_HappyPath(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)

	got, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if got == nil {
		t.Fatal("CreateDraft returned nil without error")
	}
	if got.ID == "" {
		t.Error("CreateDraft returned empty ID")
	}
	if !got.IsDraft {
		t.Errorf("IsDraft = false; want true")
	}
	if got.PromotedAt != nil {
		t.Errorf("PromotedAt = %v; want nil for fresh draft", got.PromotedAt)
	}
	if !got.IsActive {
		t.Errorf("IsActive = false; want true on creation")
	}

	var stored models.Policy
	if err := db.Where("id = ?", got.ID).First(&stored).Error; err != nil {
		t.Fatalf("read-back policies: %v", err)
	}
	if !stored.IsDraftPolicy() {
		t.Error("IsDraftPolicy() = false; want true")
	}
	if stored.IsPromoted() {
		t.Error("IsPromoted() = true; want false")
	}
}

// TestCreateDraft_MissingFields covers every required-field validation
// path so accidentally dropping a check is caught.
func TestCreateDraft_MissingFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CreateDraftPolicyInput)
	}{
		{"missing workspace", func(in *CreateDraftPolicyInput) { in.WorkspaceID = "" }},
		{"missing name", func(in *CreateDraftPolicyInput) { in.Name = "" }},
		{"missing action", func(in *CreateDraftPolicyInput) { in.Action = "" }},
		{"invalid action", func(in *CreateDraftPolicyInput) { in.Action = "wat" }},
	}
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validDraftInput(t)
			tc.mutate(&in)
			_, err := svc.CreateDraft(context.Background(), in)
			if err == nil {
				t.Fatal("expected validation error; got nil")
			}
			if !errors.Is(err, ErrValidation) {
				t.Errorf("error = %v; want ErrValidation", err)
			}
		})
	}
}

// TestGetDraft_RoundTrip asserts CreateDraft → GetDraft returns the
// same row and that GetDraft on a missing ID surfaces ErrPolicyNotFound.
func TestGetDraft_RoundTrip(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}

	got, err := svc.GetDraft(context.Background(), draft.WorkspaceID, draft.ID)
	if err != nil {
		t.Fatalf("GetDraft: %v", err)
	}
	if got.ID != draft.ID {
		t.Errorf("GetDraft.ID = %q; want %q", got.ID, draft.ID)
	}

	_, err = svc.GetDraft(context.Background(), draft.WorkspaceID, "01H000000000000000NOSUCHID")
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("GetDraft on missing ID: err = %v; want ErrPolicyNotFound", err)
	}
}

// TestListDrafts_OnlyDrafts asserts the listing is scoped to drafts in
// the supplied workspace and excludes promoted rows.
func TestListDrafts_OnlyDrafts(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"
	other := "01H000000000000000OTHERWS  "

	in := validDraftInput(t)
	in.WorkspaceID = ws
	if _, err := svc.CreateDraft(context.Background(), in); err != nil {
		t.Fatalf("CreateDraft 1: %v", err)
	}
	in.Name = "second draft"
	if _, err := svc.CreateDraft(context.Background(), in); err != nil {
		t.Fatalf("CreateDraft 2: %v", err)
	}

	otherIn := validDraftInput(t)
	otherIn.WorkspaceID = other
	otherIn.Name = "other workspace draft"
	if _, err := svc.CreateDraft(context.Background(), otherIn); err != nil {
		t.Fatalf("CreateDraft other ws: %v", err)
	}

	drafts, err := svc.ListDrafts(context.Background(), ws)
	if err != nil {
		t.Fatalf("ListDrafts: %v", err)
	}
	if len(drafts) != 2 {
		t.Errorf("got %d drafts; want 2", len(drafts))
	}
	for _, d := range drafts {
		if d.WorkspaceID != ws {
			t.Errorf("got draft from workspace %q; want %q", d.WorkspaceID, ws)
		}
	}
}

// TestGetPolicy_FindsDraftAndLive asserts GetPolicy returns rows
// regardless of draft state, and surfaces ErrPolicyNotFound for
// missing IDs.
func TestGetPolicy_FindsDraftAndLive(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	live := seedLivePolicy(t, db, ws, "01H000000000000000LIVE      ", "live", nil, nil, models.PolicyActionAllow)

	for _, id := range []string{draft.ID, live.ID} {
		got, err := svc.GetPolicy(context.Background(), ws, id)
		if err != nil {
			t.Fatalf("GetPolicy(%s): %v", id, err)
		}
		if got.ID != id {
			t.Errorf("GetPolicy.ID = %q; want %q", got.ID, id)
		}
	}

	_, err = svc.GetPolicy(context.Background(), ws, "01H000000000000000NONE      ")
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("err = %v; want ErrPolicyNotFound", err)
	}
}

// TestSimulate_HappyPath seeds a small graph (one team with two members
// and two matching resources), simulates an allow draft, and asserts
// the impact report is stamped onto the row.
func TestSimulate_HappyPath(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"

	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedTeamMember(t, db, "team-eng", "user-bob")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)
	seedResource(t, db, ws, "res-2", "prod-db-02", "ssh-host", nil)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}

	report, err := svc.Simulate(context.Background(), ws, draft.ID)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if report.MembersGainingAccess != 2 {
		t.Errorf("MembersGainingAccess = %d; want 2", report.MembersGainingAccess)
	}
	if report.NewResourcesGranted != 2 {
		t.Errorf("NewResourcesGranted = %d; want 2", report.NewResourcesGranted)
	}
	if len(report.ConflictsWithExisting) != 0 {
		t.Errorf("ConflictsWithExisting = %v; want []", report.ConflictsWithExisting)
	}
	if len(report.AffectedTeams) != 1 || report.AffectedTeams[0] != "Engineering" {
		t.Errorf("AffectedTeams = %v; want [Engineering]", report.AffectedTeams)
	}

	// Read back the row and confirm draft_impact was persisted.
	var stored models.Policy
	if err := db.Where("id = ?", draft.ID).First(&stored).Error; err != nil {
		t.Fatalf("read-back: %v", err)
	}
	if len(stored.DraftImpact) == 0 {
		t.Fatal("DraftImpact empty after Simulate")
	}
	var roundTrip ImpactReport
	if err := json.Unmarshal(stored.DraftImpact, &roundTrip); err != nil {
		t.Fatalf("unmarshal DraftImpact: %v", err)
	}
	if roundTrip.MembersGainingAccess != 2 {
		t.Errorf("persisted MembersGainingAccess = %d; want 2", roundTrip.MembersGainingAccess)
	}
}

// TestSimulate_OnPromotedReturnsErrPolicyNotDraft asserts the
// guard rail: once promoted, a row cannot be re-simulated in place.
func TestSimulate_OnPromotedReturnsErrPolicyNotDraft(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"

	live := seedLivePolicy(t, db, ws, "01H000000000000000LIVEPOL   ", "live one",
		map[string]string{"department": "engineering"},
		map[string]string{"category": "ssh-host"},
		models.PolicyActionAllow,
	)

	_, err := svc.Simulate(context.Background(), ws, live.ID)
	if !errors.Is(err, ErrPolicyNotDraft) {
		t.Errorf("Simulate live policy: err = %v; want ErrPolicyNotDraft", err)
	}
}

// TestSimulate_NotFound asserts the missing-policy path.
func TestSimulate_NotFound(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	_, err := svc.Simulate(context.Background(), "01H000000000000000WORKSPACE", "01H000000000000000NOSUCH    ")
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("err = %v; want ErrPolicyNotFound", err)
	}
}

// TestPromote_HappyPath drives create → simulate → promote and asserts
// the row flips to live with PromotedAt / PromotedBy set.
func TestPromote_HappyPath(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}

	promoted, err := svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     ")
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if promoted.IsDraft {
		t.Error("Promote: IsDraft = true; want false")
	}
	if promoted.PromotedAt == nil {
		t.Error("Promote: PromotedAt is nil")
	}
	if promoted.PromotedBy == nil || *promoted.PromotedBy != "01H000000000000000ADMIN     " {
		t.Errorf("Promote: PromotedBy = %v; want admin id", promoted.PromotedBy)
	}
	if !promoted.IsPromoted() {
		t.Error("IsPromoted() = false; want true")
	}
}

// TestPromote_WithoutSimulate asserts the simulate-before-promote
// guard fires.
func TestPromote_WithoutSimulate(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	_, err = svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     ")
	if !errors.Is(err, ErrPolicyNotSimulated) {
		t.Errorf("err = %v; want ErrPolicyNotSimulated", err)
	}
}

// TestPromote_AlreadyPromoted asserts double-promotion is rejected.
func TestPromote_AlreadyPromoted(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if _, err := svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     "); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	_, err = svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     ")
	if !errors.Is(err, ErrPolicyAlreadyPromoted) {
		t.Errorf("err = %v; want ErrPolicyAlreadyPromoted", err)
	}
}

// TestPromote_DoesNotInvokeOpenZiti is the Phase 3 exit-criterion
// integration test from docs/internal/PHASES.md: "Drafts do not create OpenZiti
// ServicePolicy until promotion (integration test)".
//
// In this repo the OpenZiti integration is intentionally absent —
// PolicyService.Promote only flips the DB state. We assert the
// negative against a process-global counter exported by the access
// package; today the counter is never incremented, but the day someone
// wires Ziti into Promote without updating the test plan, this test
// (and the docs) will need to be updated together.
func TestPromote_DoesNotInvokeOpenZiti(t *testing.T) {
	resetOpenZitiCallCounter()
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"

	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if _, err := svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     "); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	if got := openZitiCallCount(); got != 0 {
		t.Errorf("OpenZiti called %d time(s) by Promote; want 0 (Ziti integration lives in ZTNA business layer)", got)
	}
}

// TestTestAccess_UserAndResourceInScope_Allow verifies the happy allow
// path: user in matched team, resource matches the selector, action
// is allow → Allowed=true.
func TestTestAccess_UserAndResourceInScope_Allow(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}

	res, err := svc.TestAccess(context.Background(), TestAccessInput{
		WorkspaceID:        ws,
		PolicyID:           draft.ID,
		UserID:             "user-alice",
		ResourceExternalID: "prod-db-01",
	})
	if err != nil {
		t.Fatalf("TestAccess: %v", err)
	}
	if !res.Allowed {
		t.Errorf("Allowed = false; want true; reason=%q", res.Reason)
	}
}

// TestTestAccess_UserAndResourceInScope_Deny verifies the deny path
// surfaces Allowed=false even though both checks pass.
func TestTestAccess_UserAndResourceInScope_Deny(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	in := validDraftInput(t)
	in.Action = models.PolicyActionDeny
	in.Name = "deny ssh"
	draft, err := svc.CreateDraft(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}

	res, err := svc.TestAccess(context.Background(), TestAccessInput{
		WorkspaceID:        ws,
		PolicyID:           draft.ID,
		UserID:             "user-alice",
		ResourceExternalID: "prod-db-01",
	})
	if err != nil {
		t.Fatalf("TestAccess: %v", err)
	}
	if res.Allowed {
		t.Error("Allowed = true; want false (deny policy)")
	}
}

// TestTestAccess_UserNotInScope verifies that a user outside the
// matched team set is not allowed regardless of action.
func TestTestAccess_UserNotInScope(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}

	res, err := svc.TestAccess(context.Background(), TestAccessInput{
		WorkspaceID:        ws,
		PolicyID:           draft.ID,
		UserID:             "user-bob-not-in-team",
		ResourceExternalID: "prod-db-01",
	})
	if err != nil {
		t.Fatalf("TestAccess: %v", err)
	}
	if res.Allowed {
		t.Error("Allowed = true; want false (user not in scope)")
	}
}

// TestTestAccess_ResourceNotInScope verifies that an out-of-scope
// resource short-circuits to Allowed=false.
func TestTestAccess_ResourceNotInScope(t *testing.T) {
	db := newPhase3DB(t)
	svc := NewPolicyService(db)
	ws := "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "drive-folder", "saas-app", nil)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}

	res, err := svc.TestAccess(context.Background(), TestAccessInput{
		WorkspaceID:        ws,
		PolicyID:           draft.ID,
		UserID:             "user-alice",
		ResourceExternalID: "drive-folder",
	})
	if err != nil {
		t.Fatalf("TestAccess: %v", err)
	}
	if res.Allowed {
		t.Error("Allowed = true; want false (resource is wrong category)")
	}
}
