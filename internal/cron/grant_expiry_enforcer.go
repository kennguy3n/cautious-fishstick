package cron

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// GrantRevoker is the narrow contract GrantExpiryEnforcer uses to
// revoke an expired access_grants row. The production
// implementation is *access.AccessProvisioningService; tests
// substitute a stub that captures every call.
type GrantRevoker interface {
	Revoke(ctx context.Context, grant *models.AccessGrant, config, secrets map[string]interface{}) error
}

// ConnectorCredentialsLoader is the narrow contract
// GrantExpiryEnforcer uses to fetch the decrypted (config, secrets)
// pair for the connector a grant points at. The production
// implementation is *access.ConnectorCredentialsLoader, which reads
// the access_connectors row and decrypts the credentials blob via
// the org CredentialEncryptor. Tests substitute a transparent stub
// that returns the seed config/secrets straight from memory.
//
// Passing real credentials through to GrantRevoker.Revoke is what
// makes upstream revocation actually work — the previous design
// passed nil and silently failed against every real connector,
// leaving every expired grant in a "expires_at past, revoked_at
// nil" state that the next tick would re-attempt against the same
// nil credentials forever.
type ConnectorCredentialsLoader interface {
	LoadConnectorCredentials(ctx context.Context, connectorID string) (config map[string]interface{}, secrets map[string]interface{}, err error)
}

// GrantExpiryEnforcer is the Phase 6 background cron job that
// scans access_grants for rows whose expires_at has passed and
// revokes each one through the supplied GrantRevoker. Runs on the
// same external ticker pattern as IdentitySyncScheduler.
//
// Real-world behaviour: the revoker pushes the revoke out to the
// upstream provider via the AccessConnector contract before
// updating the DB. The enforcer is therefore best-effort — a
// connector failure leaves the grant in an "expires_at past,
// revoked_at nil" state, which the next tick retries. Credentials
// are loaded per-connector via the supplied
// ConnectorCredentialsLoader so the revoke call hits the upstream
// provider with the real per-org config + secrets.
type GrantExpiryEnforcer struct {
	db        *gorm.DB
	revoker   GrantRevoker
	loader    ConnectorCredentialsLoader
	batchSize int
	now       func() time.Time
}

// NewGrantExpiryEnforcer returns an enforcer bound to db that
// revokes grants via revoker. revoker and loader must not be nil;
// batchSize caps the number of grants processed per tick (zero /
// negative falls back to 100 — sized to keep a single tick under
// the SLA budget at the SN360 connector scale).
//
// loader is consulted once per distinct connector_id encountered
// in the batch; the resulting (config, secrets) pair is then
// passed to every Revoke call for that connector. This avoids the
// previous nil-credentials bug where every real connector failed
// the upstream revoke and the next tick repeated the same failing
// call indefinitely.
func NewGrantExpiryEnforcer(db *gorm.DB, revoker GrantRevoker, loader ConnectorCredentialsLoader, batchSize int) *GrantExpiryEnforcer {
	if batchSize <= 0 {
		batchSize = 100
	}
	return &GrantExpiryEnforcer{
		db:        db,
		revoker:   revoker,
		loader:    loader,
		batchSize: batchSize,
		now:       time.Now,
	}
}

// SetClock overrides time.Now. Tests use this to pin expiry
// comparisons to a deterministic timestamp.
func (e *GrantExpiryEnforcer) SetClock(now func() time.Time) {
	if now != nil {
		e.now = now
	}
}

// Run scans the access_grants table for unrevoked rows with
// expires_at <= now and calls revoker.Revoke on each with the
// decrypted credentials of the corresponding connector. Returns
// the count of grants successfully revoked. A non-nil err carries
// the last per-grant error so callers can log it; individual
// failures do NOT abort the loop.
//
// Per-connector credential loading is cached within a single Run
// so a batch of N grants from the same connector triggers exactly
// one loader call. A loader error for a connector skips every
// grant pointing at that connector (the error is captured as
// lastErr so callers can surface it) — the next tick will retry.
func (e *GrantExpiryEnforcer) Run(ctx context.Context) (int, error) {
	if e.db == nil {
		return 0, errors.New("cron: grant_expiry_enforcer missing db")
	}
	if e.revoker == nil {
		return 0, errors.New("cron: grant_expiry_enforcer missing revoker")
	}
	if e.loader == nil {
		return 0, errors.New("cron: grant_expiry_enforcer missing credentials loader")
	}
	now := e.now()

	var grants []models.AccessGrant
	if err := e.db.WithContext(ctx).
		Where("revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?", now).
		Limit(e.batchSize).
		Find(&grants).Error; err != nil {
		return 0, fmt.Errorf("cron: list expired grants: %w", err)
	}

	type credCacheEntry struct {
		cfg     map[string]interface{}
		secrets map[string]interface{}
		err     error
	}
	credCache := map[string]credCacheEntry{}

	var (
		revoked int
		lastErr error
	)
	for i := range grants {
		grant := &grants[i]
		entry, ok := credCache[grant.ConnectorID]
		if !ok {
			cfg, secrets, err := e.loader.LoadConnectorCredentials(ctx, grant.ConnectorID)
			entry = credCacheEntry{cfg: cfg, secrets: secrets, err: err}
			credCache[grant.ConnectorID] = entry
		}
		if entry.err != nil {
			lastErr = fmt.Errorf("cron: load credentials for connector %s: %w", grant.ConnectorID, entry.err)
			continue
		}
		if err := e.revoker.Revoke(ctx, grant, entry.cfg, entry.secrets); err != nil {
			// Treat ErrAlreadyRevoked as idempotent success.
			if errors.Is(err, access.ErrAlreadyRevoked) {
				continue
			}
			lastErr = fmt.Errorf("cron: revoke grant %s: %w", grant.ID, err)
			continue
		}
		revoked++
	}
	return revoked, lastErr
}
