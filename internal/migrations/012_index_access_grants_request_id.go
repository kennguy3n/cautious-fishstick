package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// Migration012IndexAccessGrantsRequestID materialises the index on
// access_grants.request_id declared on the AccessGrant model.
//
// The column has always been part of the table (see Migration002),
// but the index was added later when /access/requests/:id GetRequest
// started fetching the originating grant by request_id. Without an
// index that lookup is a full table scan on a table that grows once
// per provisioned grant.
//
// AutoMigrate on AccessGrant is idempotent — on a fresh DB it creates
// the table with the index; on an existing DB at migration 011 it
// issues CREATE INDEX (no row rewrite). No FOREIGN KEY constraints
// (per docs/internal/PHASES.md cross-cutting criteria).
func Migration012IndexAccessGrantsRequestID(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: db is nil")
	}
	if err := db.AutoMigrate(&models.AccessGrant{}); err != nil {
		return fmt.Errorf("migrations: auto migrate access_grants request_id index: %w", err)
	}
	return nil
}

// migration012 is appended to All() in 001_create_access_connectors.go
// so the runner sees migrations in declaration order.
var migration012 = Migration{
	ID:   "012",
	Name: "index_access_grants_request_id",
	Up:   Migration012IndexAccessGrantsRequestID,
}
