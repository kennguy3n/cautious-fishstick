package migrations

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Seeded template names. Stable across migrations — operators query
// by name to find a default template, so renaming any of these is a
// data migration.
const (
	WorkflowTemplateNewHireOnboarding  = "new_hire_onboarding"
	WorkflowTemplateContractorOnboard  = "contractor_onboarding"
	WorkflowTemplateRoleChange         = "role_change"
	WorkflowTemplateProjectAccess      = "project_access"
	defaultWorkflowTemplateWorkspaceID = "00000000000000000000000000"
)

// Migration008SeedWorkflowTemplates inserts the four Phase 8 default
// access_workflows rows so cmd/access-workflow-engine boots with
// usable templates instead of an empty table.
//
// Templates use the Phase 8 JSON schema (timeout_hours,
// escalation_target, levels[]). They are scoped to a sentinel
// "default-template" workspace ID so a real workspace cannot match
// them by accident; WorkflowService callers explicitly resolve a
// template-by-name when they need to clone one into their workspace.
//
// The migration is idempotent: each row is upserted by (workspace_id,
// name). Re-running the migration leaves existing customisations
// (operator-tweaked steps) intact unless a future migration
// explicitly overwrites the row.
func Migration008SeedWorkflowTemplates(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	templates, err := DefaultWorkflowTemplates()
	if err != nil {
		return fmt.Errorf("migrations: build default workflow templates: %w", err)
	}
	for i := range templates {
		t := templates[i]
		var existing models.AccessWorkflow
		err := db.Where("workspace_id = ? AND name = ?", t.WorkspaceID, t.Name).
			First(&existing).Error
		if err == nil {
			// Already seeded — leave operator customisations alone.
			continue
		}
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("migrations: probe workflow template %q: %w", t.Name, err)
		}
		t.CreatedAt = time.Now().UTC()
		t.UpdatedAt = t.CreatedAt
		if err := db.Create(&t).Error; err != nil {
			return fmt.Errorf("migrations: seed workflow template %q: %w", t.Name, err)
		}
	}
	return nil
}

// DefaultWorkflowTemplates returns the four Phase 8 templates as a
// slice of AccessWorkflow rows ready for INSERT. Exposed as a public
// helper so service-layer code (and tests) can reuse the same canonical
// definitions without duplicating the JSON literals.
func DefaultWorkflowTemplates() ([]models.AccessWorkflow, error) {
	type def struct {
		id    string
		name  string
		steps []models.WorkflowStepDefinition
	}
	defs := []def{
		{
			id:   "01TPL00000000000000NEWHIRE",
			name: WorkflowTemplateNewHireOnboarding,
			steps: []models.WorkflowStepDefinition{
				{Type: models.WorkflowStepAutoApprove},
			},
		},
		{
			id:   "01TPL000000000000CONTRACTR",
			name: WorkflowTemplateContractorOnboard,
			steps: []models.WorkflowStepDefinition{
				{
					Type:             models.WorkflowStepManagerApproval,
					TimeoutHours:     24,
					EscalationTarget: models.WorkflowStepSecurityReview,
				},
				{
					Type:             models.WorkflowStepSecurityReview,
					TimeoutHours:     48,
					EscalationTarget: "admin",
				},
			},
		},
		{
			id:   "01TPL00000000000ROLECHANGE",
			name: WorkflowTemplateRoleChange,
			steps: []models.WorkflowStepDefinition{
				{
					Type:             models.WorkflowStepManagerApproval,
					TimeoutHours:     24,
					EscalationTarget: "admin",
				},
			},
		},
		{
			id:   "01TPL000000000000PROJACCS",
			name: WorkflowTemplateProjectAccess,
			steps: []models.WorkflowStepDefinition{
				{
					Type:             models.WorkflowStepManagerApproval,
					TimeoutHours:     48,
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
			WorkspaceID: defaultWorkflowTemplateWorkspaceID,
			Name:        d.name,
			Steps:       datatypes.JSON(raw),
			IsActive:    true,
		})
	}
	return out, nil
}

// migration008 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration008 = Migration{
	ID:   "008",
	Name: "seed_workflow_templates",
	Up:   Migration008SeedWorkflowTemplates,
}
