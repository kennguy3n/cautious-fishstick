package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// AccessGrantQueryService is the read-only counterpart to
// AccessProvisioningService. It exists so the GET /access/grants
// handler can list active entitlements without opening up the
// full provisioning surface (and the connector registry it pulls
// in transitively).
type AccessGrantQueryService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAccessGrantQueryService returns a service backed by db. db
// must not be nil. The now hook is overridable for tests so we can
// pin the expiry filter timestamp.
func NewAccessGrantQueryService(db *gorm.DB) *AccessGrantQueryService {
	return &AccessGrantQueryService{
		db:  db,
		now: time.Now,
	}
}

// GrantQuery is the input contract for ListActiveGrants. UserID and
// ConnectorID are wildcard filters; nil means "no filter on this
// dimension". At least one MUST be set so the handler never
// surfaces an unbounded list.
type GrantQuery struct {
	UserID      *string
	ConnectorID *string
}

// ListActiveGrants returns grants whose RevokedAt is nil and whose
// ExpiresAt is either nil or in the future. Workspace-scoping is
// implicit through the supplied filters: a UserID identifies a
// user inside one workspace, and a ConnectorID identifies a
// connector inside one workspace, so filtering by either is enough
// for tenant isolation.
func (s *AccessGrantQueryService) ListActiveGrants(ctx context.Context, q GrantQuery) ([]models.AccessGrant, error) {
	if q.UserID == nil && q.ConnectorID == nil {
		return nil, fmt.Errorf("%w: at least one of user_id or connector_id is required", ErrValidation)
	}
	now := s.now()
	tx := s.db.WithContext(ctx).
		Where("revoked_at IS NULL").
		Where("(expires_at IS NULL OR expires_at > ?)", now)
	if q.UserID != nil {
		tx = tx.Where("user_id = ?", *q.UserID)
	}
	if q.ConnectorID != nil {
		tx = tx.Where("connector_id = ?", *q.ConnectorID)
	}
	var out []models.AccessGrant
	if err := tx.Order("granted_at desc").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("access: list access_grants: %w", err)
	}
	return out, nil
}

// GetGrant loads a single grant by ULID and returns it. Returns
// ErrGrantNotFound (wrapped) when the row does not exist or has been
// soft-deleted. Used by GET /access/grants/:id/entitlements to look
// up the (connector_id, user_id) the entitlements lookup is scoped
// to.
func (s *AccessGrantQueryService) GetGrant(ctx context.Context, grantID string) (*models.AccessGrant, error) {
	if grantID == "" {
		return nil, fmt.Errorf("%w: grant id is required", ErrValidation)
	}
	var grant models.AccessGrant
	if err := s.db.WithContext(ctx).Where("id = ?", grantID).First(&grant).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrGrantNotFound, grantID)
		}
		return nil, fmt.Errorf("access: get access_grant: %w", err)
	}
	return &grant, nil
}
