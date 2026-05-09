package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// listEntitlementsPayload is the worker-specific payload shape for
// an access_jobs row of job_type = list_entitlements.
type listEntitlementsPayload struct {
	UserExternalID string `json:"user_external_id"`
}

// AccessListEntitlements is the worker handler for
// list_entitlements jobs. It calls AccessConnector.ListEntitlements
// with the user_external_id from the payload and discards the
// returned entitlements — the Phase 6 scaffold defers entitlement
// persistence to a future phase.
func AccessListEntitlements(ctx context.Context, jc JobContext, jobID string) error {
	return runJob(ctx, jc, jobID, func(ctx context.Context, conn access.AccessConnector, cfg, secrets map[string]interface{}, payload []byte) error {
		if len(payload) == 0 {
			return fmt.Errorf("handlers: list_entitlements: payload is required")
		}
		var pl listEntitlementsPayload
		if err := json.Unmarshal(payload, &pl); err != nil {
			return fmt.Errorf("handlers: list_entitlements: decode payload: %w", err)
		}
		if pl.UserExternalID == "" {
			return fmt.Errorf("handlers: list_entitlements: user_external_id is required")
		}
		// Phase 6 scaffold: discard the entitlements. A future
		// phase persists them into the grants table / entitlement
		// cache.
		_, err := conn.ListEntitlements(ctx, cfg, secrets, pl.UserExternalID)
		return err
	})
}
