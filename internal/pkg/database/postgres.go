// Package database holds shared DB-connection helpers for the access
// platform binaries. cmd/ztna-api, cmd/access-connector-worker and
// cmd/access-workflow-engine all open the same Postgres pool against
// the ACCESS_DATABASE_URL DSN docker-compose supplies; centralising
// the open + pool-tuning here keeps the binaries from drifting on
// pool size / connection lifetime.
package database

import (
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/migrations"
)

// PoolConfig captures the connection-pool knobs OpenPostgres applies
// to the underlying *sql.DB. Zero values fall back to DefaultPool().
type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// DefaultPool returns the pool settings the access binaries use when
// no override is supplied. The numbers are sized for the
// docker-compose dev stack — production deployments are expected to
// override via the Helm chart once load profiling lands.
func DefaultPool() PoolConfig {
	return PoolConfig{
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}
}

// OpenPostgres opens a gorm.DB against dsn with the access-platform
// pool defaults applied. dsn must be a libpq-style URL (the same
// format docker-compose hands the binaries in ACCESS_DATABASE_URL).
//
// The returned DB has the connection pool already configured; callers
// can hand it straight to RunMigrations and the service constructors
// without further setup.
func OpenPostgres(dsn string) (*gorm.DB, error) {
	return OpenPostgresWithPool(dsn, DefaultPool())
}

// OpenPostgresWithPool is the explicit-pool variant of OpenPostgres.
// Tests that want to assert against a single-connection pool wire
// their own PoolConfig through this entry-point.
func OpenPostgresWithPool(dsn string, pool PoolConfig) (*gorm.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("database: dsn is required")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("database: open postgres: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("database: pool handle: %w", err)
	}
	if pool.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(pool.MaxOpenConns)
	}
	if pool.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(pool.MaxIdleConns)
	}
	if pool.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(pool.ConnMaxLifetime)
	}
	if pool.ConnMaxIdleTime > 0 {
		sqlDB.SetConnMaxIdleTime(pool.ConnMaxIdleTime)
	}
	return db, nil
}

// RunMigrations applies every entry returned by migrations.All() in
// order. Each migration is idempotent (AutoMigrate-backed); a partial
// failure aborts the loop and surfaces the failing migration's ID so
// operators can diagnose without grepping the log for goroutine
// numbers.
func RunMigrations(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("database: db is nil")
	}
	for _, m := range migrations.All() {
		if m.Up == nil {
			return fmt.Errorf("database: migration %s has nil Up func", m.ID)
		}
		if err := m.Up(db); err != nil {
			return fmt.Errorf("database: migration %s (%s): %w", m.ID, m.Name, err)
		}
	}
	return nil
}
