package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
	"math/rand"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// listEntitlementsPayload is the worker-specific payload shape for
// an access_jobs row of job_type = list_entitlements.
type listEntitlementsPayload struct {
	UserExternalID string `json:"user_external_id"`
}

// AccessListEntitlements is the worker handler for
// list_entitlements jobs. It calls AccessConnector.ListEntitlements
// and persists the returned slice into access_grant_entitlements,
// replacing the existing snapshot for the (connector_id,
// user_external_id) pair atomically.
//
// Lifecycle:
//
//  1. Call ListEntitlements (real connector network I/O).
//  2. Open a real transaction.
//  3. Soft-delete the previous snapshot for (connector_id,
//     user_external_id).
//  4. Insert one fresh row per returned Entitlement.
//
// Re-running the job is safe — the (connector_id, user_external_id,
// resource_external_id, role) unique index guarantees no duplicates
// because step 3 wipes the previous batch.
func AccessListEntitlements(ctx context.Context, jc JobContext, jobID string) error {
	return runJob(ctx, jc, jobID, func(ctx context.Context, conn access.AccessConnector, job *models.AccessJob, cfg, secrets map[string]interface{}) error {
		payload := []byte(job.Payload)
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
		entitlements, err := conn.ListEntitlements(ctx, cfg, secrets, pl.UserExternalID)
		if err != nil {
			return err
		}
		now := jc.Now()
		// Replace snapshot atomically.
		return jc.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Hard-delete the previous snapshot — re-running a
			// list_entitlements job represents a fresh read, and
			// the unique index on (connector_id, user_external_id,
			// resource_external_id, role) would otherwise reject
			// the inserts below.
			if err := tx.Unscoped().
				Where("connector_id = ? AND user_external_id = ?", job.ConnectorID, pl.UserExternalID).
				Delete(&models.AccessGrantEntitlement{}).Error; err != nil {
				return fmt.Errorf("handlers: purge previous entitlements: %w", err)
			}
			for _, ent := range entitlements {
				row := &models.AccessGrantEntitlement{
					ID:                 newEntitlementID(),
					ConnectorID:        job.ConnectorID,
					UserExternalID:     pl.UserExternalID,
					ResourceExternalID: ent.ResourceExternalID,
					Role:               ent.Role,
					Source:             ent.Source,
					LastUsedAt:         ent.LastUsedAt,
					RiskScore:          ent.RiskScore,
					CreatedAt:          now,
					UpdatedAt:          now,
				}
				if err := tx.Create(row).Error; err != nil {
					return fmt.Errorf("handlers: insert entitlement: %w", err)
				}
			}
			return nil
		})
	})
}

// newEntitlementID generates a 26-char Crockford-base32 ULID for
// inserts into access_grant_entitlements. The handler must not
// depend on the services/access newULID symbol (cyclic import); we
// keep a private duplicate here.
var entitlementRng = rand.New(rand.NewSource(time.Now().UnixNano()))

func newEntitlementID() string {
	return ulid.MustNew(ulid.Now(), entitlementRng).String()
}
