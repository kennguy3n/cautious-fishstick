package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ConnectorCredentialsLoader reads an access_connectors row by ID
// and returns the decoded config map plus the decrypted secrets
// map. Background jobs (GrantExpiryEnforcer) and lifecycle services
// (ConnectorManagementService.Disconnect) both need real
// (config, secrets) pairs to drive upstream connector calls; this
// helper centralises the decode-and-decrypt path so neither caller
// has to know about the credentials column layout.
//
// The loader binds the connector ULID as AAD and looks up the org
// DEK by KeyVersion, matching the encryption side in
// encryptSecretsMap. ErrConnectorRowNotFound is surfaced when no
// row matches; ErrValidation is surfaced when the encryptor is nil.
//
// Production wires the AES-GCM encryptor; tests wire
// PassthroughEncryptor{}. The same code path runs in both cases.
type ConnectorCredentialsLoader struct {
	db        *gorm.DB
	encryptor CredentialEncryptor
}

// NewConnectorCredentialsLoader returns a loader bound to db and
// encryptor. Both are required; nil arguments surface as
// ErrValidation from LoadConnectorCredentials.
func NewConnectorCredentialsLoader(db *gorm.DB, encryptor CredentialEncryptor) *ConnectorCredentialsLoader {
	return &ConnectorCredentialsLoader{db: db, encryptor: encryptor}
}

// LoadConnectorCredentials loads the access_connectors row by ID
// and returns the decoded (config, secrets) pair. Returns
// ErrConnectorRowNotFound when no row exists, ErrValidation when
// the loader was not fully configured, and a wrapped error when
// the JSON / decryption step fails.
func (l *ConnectorCredentialsLoader) LoadConnectorCredentials(ctx context.Context, connectorID string) (map[string]interface{}, map[string]interface{}, error) {
	if l == nil || l.db == nil {
		return nil, nil, fmt.Errorf("%w: credentials loader missing db", ErrValidation)
	}
	if l.encryptor == nil {
		return nil, nil, fmt.Errorf("%w: credentials loader missing encryptor", ErrValidation)
	}
	if connectorID == "" {
		return nil, nil, fmt.Errorf("%w: connector_id is required", ErrValidation)
	}
	var conn models.AccessConnector
	if err := l.db.WithContext(ctx).Where("id = ?", connectorID).First(&conn).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, fmt.Errorf("%w: %s", ErrConnectorRowNotFound, connectorID)
		}
		return nil, nil, fmt.Errorf("access: load connector for credentials: %w", err)
	}
	return decodeConnectorCredentials(&conn, l.encryptor)
}

// decodeConnectorCredentials is the shared decode+decrypt routine
// used by ConnectorCredentialsLoader and ConnectorManagementService.
// It does NOT load the row — callers pass it in so they can reuse a
// row they have already loaded for other purposes (Disconnect loads
// it to soft-delete; the loader loads it fresh per call).
func decodeConnectorCredentials(conn *models.AccessConnector, encryptor CredentialEncryptor) (map[string]interface{}, map[string]interface{}, error) {
	if conn == nil {
		return nil, nil, fmt.Errorf("%w: connector row is required", ErrValidation)
	}
	if encryptor == nil {
		return nil, nil, fmt.Errorf("%w: encryptor is required", ErrValidation)
	}
	cfg := map[string]interface{}{}
	if len(conn.Config) > 0 {
		if err := json.Unmarshal(conn.Config, &cfg); err != nil {
			return nil, nil, fmt.Errorf("access: decode connector config %s: %w", conn.ID, err)
		}
	}
	secrets := map[string]interface{}{}
	if conn.Credentials != "" {
		keyVersion := fmt.Sprintf("%d", conn.KeyVersion)
		pt, err := encryptor.Decrypt([]byte(conn.Credentials), []byte(conn.ID), keyVersion)
		if err != nil {
			return nil, nil, fmt.Errorf("access: decrypt credentials for %s: %w", conn.ID, err)
		}
		if err := json.Unmarshal(pt, &secrets); err != nil {
			return nil, nil, fmt.Errorf("access: decode credentials for %s: %w", conn.ID, err)
		}
	}
	return cfg, secrets, nil
}
