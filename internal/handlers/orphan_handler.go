package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// OrphanReconcilerReader is the read/write contract the handler
// needs from the OrphanReconciler service. Production wires the
// concrete *access.OrphanReconciler; tests wire a fake.
type OrphanReconcilerReader interface {
	ListOrphans(ctx context.Context, workspaceID, status string) ([]models.AccessOrphanAccount, error)
	ReconcileWorkspace(ctx context.Context, workspaceID string) ([]models.AccessOrphanAccount, error)
	ReconcileWorkspaceDryRun(ctx context.Context, workspaceID string) ([]models.AccessOrphanAccount, error)
	RevokeOrphan(ctx context.Context, orphanID string) error
	DismissOrphan(ctx context.Context, orphanID string) error
	AcknowledgeOrphan(ctx context.Context, orphanID string) error
}

// OrphanHandler exposes the Phase 11 "unused app accounts" surface
// area per docs/PROPOSAL.md §13.4. The user-facing vocabulary used
// in JSON responses is the SN360 term ("unused app account") rather
// than the engineering term ("orphan account").
type OrphanHandler struct {
	svc OrphanReconcilerReader
}

// NewOrphanHandler returns a handler bound to svc. svc must not be nil.
func NewOrphanHandler(svc OrphanReconcilerReader) *OrphanHandler {
	return &OrphanHandler{svc: svc}
}

// Register wires the handler's routes onto r.
func (h *OrphanHandler) Register(r *gin.Engine) {
	if h == nil || h.svc == nil {
		return
	}
	r.GET("/access/orphans", h.List)
	r.POST("/access/orphans/reconcile", h.Reconcile)
	r.POST("/access/orphans/:id/revoke", h.Revoke)
	r.POST("/access/orphans/:id/dismiss", h.Dismiss)
	r.POST("/access/orphans/:id/acknowledge", h.Acknowledge)
}

// unusedAccountView is the JSON shape returned to the operator UI.
// The field names use the SN360 vocabulary while preserving the
// underlying engineering identifiers so the UI can wire revoke /
// dismiss buttons directly.
type unusedAccountView struct {
	ID                   string `json:"id"`
	WorkspaceID          string `json:"workspace_id"`
	ConnectorID          string `json:"connector_id"`
	AppUserID            string `json:"app_user_id"`
	Email                string `json:"email,omitempty"`
	DisplayName          string `json:"display_name,omitempty"`
	Status               string `json:"status"`
	DetectedAt           string `json:"detected_at"`
	ResolvedAt           string `json:"resolved_at,omitempty"`
}

func newUnusedAccountView(row models.AccessOrphanAccount) unusedAccountView {
	view := unusedAccountView{
		ID:          row.ID,
		WorkspaceID: row.WorkspaceID,
		ConnectorID: row.ConnectorID,
		AppUserID:   row.UserExternalID,
		Email:       row.Email,
		DisplayName: row.DisplayName,
		Status:      row.Status,
		DetectedAt:  row.DetectedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	if row.ResolvedAt != nil {
		view.ResolvedAt = row.ResolvedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return view
}

// List handles GET /access/orphans. Filters by workspace_id (required)
// and optionally by status.
func (h *OrphanHandler) List(c *gin.Context) {
	wsPtr := GetPtrStringQuery(c, "workspace_id")
	if wsPtr == nil || *wsPtr == "" {
		writeError(c, http.StatusBadRequest, errors.New("workspace_id query parameter is required"))
		return
	}
	statusPtr := GetPtrStringQuery(c, "status")
	status := ""
	if statusPtr != nil {
		status = *statusPtr
	}
	rows, err := h.svc.ListOrphans(c.Request.Context(), *wsPtr, status)
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	out := make([]unusedAccountView, 0, len(rows))
	for _, r := range rows {
		out = append(out, newUnusedAccountView(r))
	}
	c.JSON(http.StatusOK, gin.H{"unused_app_accounts": out})
}

// Reconcile handles POST /access/orphans/reconcile. Triggers an
// on-demand reconciliation for the supplied workspace. When the
// optional "dry_run" body field is true, the handler returns the
// detected unused app accounts without persisting them — useful
// for operators who want to review what a sweep would record
// before kicking off a full run.
func (h *OrphanHandler) Reconcile(c *gin.Context) {
	var body struct {
		WorkspaceID string `json:"workspace_id"`
		DryRun      bool   `json:"dry_run"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.WorkspaceID == "" {
		writeError(c, http.StatusBadRequest, errors.New("workspace_id is required"))
		return
	}
	var (
		rows []models.AccessOrphanAccount
		err  error
	)
	if body.DryRun {
		rows, err = h.svc.ReconcileWorkspaceDryRun(c.Request.Context(), body.WorkspaceID)
	} else {
		rows, err = h.svc.ReconcileWorkspace(c.Request.Context(), body.WorkspaceID)
	}
	if err != nil {
		writeError(c, http.StatusInternalServerError, err)
		return
	}
	out := make([]unusedAccountView, 0, len(rows))
	for _, r := range rows {
		out = append(out, newUnusedAccountView(r))
	}
	c.JSON(http.StatusOK, gin.H{
		"unused_app_accounts": out,
		"dry_run":             body.DryRun,
	})
}

// Revoke handles POST /access/orphans/:id/revoke.
func (h *OrphanHandler) Revoke(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		writeError(c, http.StatusBadRequest, errors.New("id path parameter is required"))
		return
	}
	if err := h.svc.RevokeOrphan(c.Request.Context(), id); err != nil {
		h.writeMutationError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "status": models.OrphanStatusAutoRevoked})
}

// Dismiss handles POST /access/orphans/:id/dismiss.
func (h *OrphanHandler) Dismiss(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		writeError(c, http.StatusBadRequest, errors.New("id path parameter is required"))
		return
	}
	if err := h.svc.DismissOrphan(c.Request.Context(), id); err != nil {
		h.writeMutationError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "status": models.OrphanStatusDismissed})
}

// Acknowledge handles POST /access/orphans/:id/acknowledge.
func (h *OrphanHandler) Acknowledge(c *gin.Context) {
	id := GetStringParam(c, "id")
	if id == "" {
		writeError(c, http.StatusBadRequest, errors.New("id path parameter is required"))
		return
	}
	if err := h.svc.AcknowledgeOrphan(c.Request.Context(), id); err != nil {
		h.writeMutationError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "status": models.OrphanStatusAcknowledged})
}

func (h *OrphanHandler) writeMutationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		writeError(c, http.StatusNotFound, err)
	case errors.Is(err, access.ErrValidation):
		writeError(c, http.StatusBadRequest, err)
	default:
		writeError(c, http.StatusInternalServerError, err)
	}
}
