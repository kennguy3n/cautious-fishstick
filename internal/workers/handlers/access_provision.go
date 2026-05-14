package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// provisionAccessPayload is the worker-specific payload shape for
// an access_jobs row of job_type = provision_access. Mirrors the
// AccessGrant shape per docs/PROPOSAL §5.4.
type provisionAccessPayload struct {
	UserExternalID     string                 `json:"user_external_id"`
	ResourceExternalID string                 `json:"resource_external_id"`
	Role               string                 `json:"role"`
	Scope              map[string]interface{} `json:"scope,omitempty"`
}

// AccessProvision is the worker handler for provision_access jobs.
// It decodes the payload into an access.AccessGrant and calls
// AccessConnector.ProvisionAccess. Re-running the same job is
// expected to be idempotent at the connector layer (the
// AccessConnector contract requires it).
func AccessProvision(ctx context.Context, jc JobContext, jobID string) error {
	return runJob(ctx, jc, jobID, func(ctx context.Context, conn access.AccessConnector, job *models.AccessJob, cfg, secrets map[string]interface{}) error {
		payload := []byte(job.Payload)
		if len(payload) == 0 {
			return fmt.Errorf("handlers: provision_access: payload is required")
		}
		var pl provisionAccessPayload
		if err := json.Unmarshal(payload, &pl); err != nil {
			return fmt.Errorf("handlers: provision_access: decode payload: %w", err)
		}
		grant := access.AccessGrant{
			UserExternalID:     pl.UserExternalID,
			ResourceExternalID: pl.ResourceExternalID,
			Role:               pl.Role,
			Scope:              pl.Scope,
		}
		return conn.ProvisionAccess(ctx, cfg, secrets, grant)
	})
}
