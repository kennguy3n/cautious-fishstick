package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// stubResolver records the resolver calls made by the SCIM handler
// and returns canned values so tests drive the JML service happy /
// error paths without seeding the policy + connector graph.
type stubResolver struct {
	JoinerIn  access.JoinerInput
	MoverIn   access.MoverInput
	LeaverID  string
	JoinerErr error
	MoverErr  error
	LeaverErr error

	JoinerCalls int
	MoverCalls  int
	LeaverCalls int
}

func (s *stubResolver) ResolveJoiner(_ context.Context, _ string, _ SCIMUserPayload) (access.JoinerInput, error) {
	s.JoinerCalls++
	if s.JoinerErr != nil {
		return access.JoinerInput{}, s.JoinerErr
	}
	return s.JoinerIn, nil
}

func (s *stubResolver) ResolveMover(_ context.Context, _, _ string, _ SCIMUserPayload) (access.MoverInput, error) {
	s.MoverCalls++
	if s.MoverErr != nil {
		return access.MoverInput{}, s.MoverErr
	}
	return s.MoverIn, nil
}

func (s *stubResolver) ResolveLeaver(_ context.Context, _, externalID string) (string, error) {
	s.LeaverCalls++
	if s.LeaverErr != nil {
		return "", s.LeaverErr
	}
	if s.LeaverID == "" {
		return "user-" + externalID, nil
	}
	return s.LeaverID, nil
}

// scimRouterStack returns a Router pre-wired with a JML service
// backed by a fresh in-memory DB plus the supplied resolver. The
// returned *gorm.DB lets the test seed connectors / pre-existing
// grants the resolver will reference.
func scimRouterStack(t *testing.T, resolver SCIMUserResolver) (*gin.Engine, *gorm.DB) {
	t.Helper()
	db := newTestDB(t)
	provSvc := access.NewAccessProvisioningService(db)
	jml := access.NewJMLService(db, provSvc)
	deps := Dependencies{
		JMLService:   jml,
		SCIMResolver: resolver,
	}
	return Router(deps), db
}

// seedSCIMConnector inserts an access_connectors row at id pointing
// to provider.
func seedSCIMConnector(t *testing.T, db *gorm.DB, id, provider string) *models.AccessConnector {
	t.Helper()
	conn := &models.AccessConnector{
		ID:            id,
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      provider,
		ConnectorType: "test",
		Status:        models.StatusConnected,
	}
	if err := db.Create(conn).Error; err != nil {
		t.Fatalf("seed access_connector: %v", err)
	}
	return conn
}

// TestSCIMHandler_PostJoinerHappyPath asserts a SCIM POST /Users
// with a valid payload runs the joiner lane and returns 200.
func TestSCIMHandler_PostJoinerHappyPath(t *testing.T) {
	const provider = "mock_scim_post_joiner"
	resolver := &stubResolver{}
	router, db := scimRouterStack(t, resolver)
	conn := seedSCIMConnector(t, db, "01H00000000000000SCIMCONN001", provider)

	mock := &access.MockAccessConnector{}
	access.SwapConnector(t, provider, mock)

	resolver.JoinerIn = access.JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000SCIMUSR001",
		DefaultGrants: []access.JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/x", Role: "viewer"},
		},
	}

	tru := true
	body := SCIMUserPayload{
		Schemas:    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ExternalID: "ext-001",
		UserName:   "alice@example.com",
		Active:     &tru,
		Name:       &SCIMNamePayload{GivenName: "Alice", FamilyName: "Doe"},
		Emails:     []SCIMEmailPayload{{Value: "alice@example.com", Primary: true}},
	}

	w := doJSON(t, router, http.MethodPost, "/scim/Users?workspace_id=01H000000000000000WORKSPACE", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	if resolver.JoinerCalls != 1 {
		t.Errorf("ResolveJoiner calls = %d; want 1", resolver.JoinerCalls)
	}
	if mock.ProvisionAccessCalls != 1 {
		t.Errorf("ProvisionAccess calls = %d; want 1", mock.ProvisionAccessCalls)
	}
}

// TestSCIMHandler_PostMalformedPayload asserts an unparseable JSON
// body surfaces 400 without invoking the resolver.
func TestSCIMHandler_PostMalformedPayload(t *testing.T) {
	resolver := &stubResolver{}
	router, _ := scimRouterStack(t, resolver)

	req := httptest.NewRequest(http.MethodPost, "/scim/Users?workspace_id=ws",
		bytes.NewReader([]byte(`{not json`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
	if resolver.JoinerCalls != 0 {
		t.Errorf("ResolveJoiner calls = %d; want 0 on malformed body", resolver.JoinerCalls)
	}
}

// TestSCIMHandler_PostMissingWorkspace asserts a POST without a
// resolvable workspace surfaces 400.
func TestSCIMHandler_PostMissingWorkspace(t *testing.T) {
	resolver := &stubResolver{}
	router, _ := scimRouterStack(t, resolver)

	body := SCIMUserPayload{ExternalID: "ext-002"}
	w := doJSON(t, router, http.MethodPost, "/scim/Users", body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

// TestSCIMHandler_PatchMover asserts a PATCH with group changes
// runs the mover lane and dispatches the resolver-supplied
// MoverInput to the JML service.
func TestSCIMHandler_PatchMover(t *testing.T) {
	const provider = "mock_scim_patch_mover"
	resolver := &stubResolver{}
	router, db := scimRouterStack(t, resolver)
	conn := seedSCIMConnector(t, db, "01H00000000000000SCIMCONN002", provider)

	mock := &access.MockAccessConnector{}
	access.SwapConnector(t, provider, mock)

	body := SCIMUserPayload{
		Schemas:    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []SCIMPatchOperation{{Op: "add", Path: "groups", Value: []string{"new-team"}}},
	}
	resolver.MoverIn = access.MoverInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000SCIMUSR002",
		AddedGrants: []access.JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/y", Role: "viewer"},
		},
	}

	w := doJSON(t, router, http.MethodPatch, "/scim/Users/ext-002?workspace_id=01H000000000000000WORKSPACE", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	if resolver.MoverCalls != 1 {
		t.Errorf("ResolveMover calls = %d; want 1", resolver.MoverCalls)
	}
	if mock.ProvisionAccessCalls != 1 {
		t.Errorf("ProvisionAccess calls = %d; want 1", mock.ProvisionAccessCalls)
	}
}

// TestSCIMHandler_PatchUnknownUserReturns404 asserts a PATCH
// against an unknown externalID returns 404 (per RFC 7644 §3.6).
func TestSCIMHandler_PatchUnknownUserReturns404(t *testing.T) {
	resolver := &stubResolver{
		MoverErr: fmt.Errorf("%w: ext-missing", ErrSCIMUserNotFound),
	}
	router, _ := scimRouterStack(t, resolver)

	body := SCIMUserPayload{
		Operations: []SCIMPatchOperation{{Op: "replace", Path: "name.givenName", Value: "Bob"}},
	}
	w := doJSON(t, router, http.MethodPatch, "/scim/Users/missing?workspace_id=ws", body)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// TestSCIMHandler_PatchActiveFalseRoutesLeaver asserts a PATCH
// with active=false routes through the leaver lane (revoking all
// active grants) rather than the mover lane.
func TestSCIMHandler_PatchActiveFalseRoutesLeaver(t *testing.T) {
	resolver := &stubResolver{LeaverID: "01H00000000000000SCIMUSR003"}
	router, _ := scimRouterStack(t, resolver)

	fal := false
	body := SCIMUserPayload{Active: &fal}
	w := doJSON(t, router, http.MethodPatch, "/scim/Users/ext-003?workspace_id=ws", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	if resolver.LeaverCalls != 1 {
		t.Errorf("ResolveLeaver calls = %d; want 1", resolver.LeaverCalls)
	}
	if resolver.MoverCalls != 0 {
		t.Errorf("ResolveMover calls = %d; want 0 (active=false must skip mover)", resolver.MoverCalls)
	}
}

// TestSCIMHandler_PatchEmptyIsBadRequest asserts a PATCH with no
// JML-relevant changes surfaces 400.
func TestSCIMHandler_PatchEmptyIsBadRequest(t *testing.T) {
	resolver := &stubResolver{}
	router, _ := scimRouterStack(t, resolver)

	body := SCIMUserPayload{}
	w := doJSON(t, router, http.MethodPatch, "/scim/Users/ext-004?workspace_id=ws", body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (PATCH must include changes)", w.Code)
	}
}

// TestSCIMHandler_DeleteUnknownReturns404 asserts that DELETE
// against an unknown externalID returns 404.
func TestSCIMHandler_DeleteUnknownReturns404(t *testing.T) {
	resolver := &stubResolver{LeaverErr: fmt.Errorf("%w: ghost", ErrSCIMUserNotFound)}
	router, _ := scimRouterStack(t, resolver)

	w := doJSON(t, router, http.MethodDelete, "/scim/Users/ghost?workspace_id=ws", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// TestSCIMHandler_DeleteHappyPath asserts a DELETE with a
// resolvable user runs the leaver lane and returns 200 (no active
// grants → no-op).
func TestSCIMHandler_DeleteHappyPath(t *testing.T) {
	resolver := &stubResolver{LeaverID: "01H00000000000000SCIMUSR005"}
	router, _ := scimRouterStack(t, resolver)

	w := doJSON(t, router, http.MethodDelete, "/scim/Users/ext-005?workspace_id=ws", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s); want 200", w.Code, w.Body.String())
	}
	if resolver.LeaverCalls != 1 {
		t.Errorf("ResolveLeaver calls = %d; want 1", resolver.LeaverCalls)
	}
}

// TestSCIMHandler_ResolverErrorIs500 asserts that a resolver
// returning a non-sentinel error surfaces as 500.
func TestSCIMHandler_ResolverErrorIs500(t *testing.T) {
	resolver := &stubResolver{JoinerErr: errors.New("policy lookup boom")}
	router, _ := scimRouterStack(t, resolver)

	body := SCIMUserPayload{ExternalID: "ext-006"}
	w := doJSON(t, router, http.MethodPost, "/scim/Users?workspace_id=ws", body)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}

// _ = io.EOF keeps the import alive when the file doesn't otherwise
// need it; the malformed-payload test reads via bytes.NewReader.
var _ = io.EOF
