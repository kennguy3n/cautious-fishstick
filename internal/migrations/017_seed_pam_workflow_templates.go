package migrations

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Seeded PAM template names. Stable across migrations — call sites
// resolve the template by name when cloning it into a real
// workspace, so renaming any of these is a data migration.
const (
	WorkflowTemplatePAMSessionLowRisk   = "pam_session_low_risk"
	WorkflowTemplatePAMSessionStandard  = "pam_session_standard"
	WorkflowTemplatePAMSessionCritical  = "pam_session_critical"
	defaultPAMWorkflowTemplateWorkspace = "00000000000000000000000000"
)

// Migration017SeedPAMWorkflowTemplates inserts the three PAM
// approval-flow templates so PAMLeaseService boots with usable
// defaults instead of an empty access_workflows table. The
// templates use the same JSON schema as
// 008_seed_workflow_templates (timeout_hours, escalation_target,
// levels[]) so the existing WorkflowService dispatcher handles
// them without a code change.
//
// Routing rule (consumed by the lease service in a follow-up
// milestone, not enforced here):
//   - low-risk + low-criticality asset → low_risk template (auto)
//   - everything else                  → standard template
//   - high / critical asset            → critical template
//
// Idempotent: each row is upserted by (workspace_id, name). Re-
// running the migration leaves operator customisations intact.
func Migration017SeedPAMWorkflowTemplates(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	templates, err := DefaultPAMWorkflowTemplates()
	if err != nil {
		return fmt.Errorf("migrations: build default pam workflow templates: %w", err)
	}
	for i := range templates {
		t := templates[i]
		var existing models.AccessWorkflow
		err := db.Where("workspace_id = ? AND name = ?", t.WorkspaceID, t.Name).
			First(&existing).Error
		if err == nil {
			continue
		}
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("migrations: probe pam workflow template %q: %w", t.Name, err)
		}
		t.CreatedAt = time.Now().UTC()
		t.UpdatedAt = t.CreatedAt
		if err := db.Create(&t).Error; err != nil {
			return fmt.Errorf("migrations: seed pam workflow template %q: %w", t.Name, err)
		}
	}
	return nil
}

// DefaultPAMWorkflowTemplates returns the three PAM templates as a
// slice of AccessWorkflow rows ready for INSERT. Exposed so
// service-layer code (and tests) can reuse the canonical
// definitions without duplicating the JSON literals.
func DefaultPAMWorkflowTemplates() ([]models.AccessWorkflow, error) {
	type def struct {
		id    string
		name  string
		steps []models.WorkflowStepDefinition
	}
	defs := []def{
		{
			id:   "01TPL0000000000PAMSESLOW00",
			name: WorkflowTemplatePAMSessionLowRisk,
			steps: []models.WorkflowStepDefinition{
				{Type: models.WorkflowStepAutoApprove},
			},
		},
		{
			id:   "01TPL000000000PAMSESSTD000",
			name: WorkflowTemplatePAMSessionStandard,
			steps: []models.WorkflowStepDefinition{
				{
					Type:             models.WorkflowStepManagerApproval,
					TimeoutHours:     4,
					EscalationTarget: "admin",
				},
			},
		},
		{
			id:   "01TPL0000000PAMSESCRIT0000",
			name: WorkflowTemplatePAMSessionCritical,
			steps: []models.WorkflowStepDefinition{
				{
					Type:             models.WorkflowStepSecurityReview,
					TimeoutHours:     2,
					EscalationTarget: "admin",
				},
				{
					Type:             models.WorkflowStepManagerApproval,
					TimeoutHours:     2,
					EscalationTarget: "admin",
				},
			},
		},
	}
	out := make([]models.AccessWorkflow, 0, len(defs))
	for _, d := range defs {
		raw, err := json.Marshal(d.steps)
		if err != nil {
			return nil, fmt.Errorf("marshal steps for %q: %w", d.name, err)
		}
		out = append(out, models.AccessWorkflow{
			ID:          d.id,
			WorkspaceID: defaultPAMWorkflowTemplateWorkspace,
			Name:        d.name,
			Steps:       datatypes.JSON(raw),
			IsActive:    true,
		})
	}
	return out, nil
}

// migration017 is appended to All() in 001_create_access_connectors.go.
var migration017 = Migration{
	ID:   "017",
	Name: "seed_pam_workflow_templates",
	Up:   Migration017SeedPAMWorkflowTemplates,
}
