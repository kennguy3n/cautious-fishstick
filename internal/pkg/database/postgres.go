// Package database holds shared DB-connection helpers for the access
// platform binaries. cmd/ztna-api, cmd/access-connector-worker and
// cmd/access-workflow-engine all open the same Postgres pool against
// the ACCESS_DATABASE_URL DSN docker-compose supplies; centralising
// the open + pool-tuning here keeps the binaries from drifting on
// pool size / connection lifetime.
package database

import (
	"context"
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

// migrationAdvisoryLockKey is the fixed pg_advisory_lock key the
// access-platform binaries use to serialise migration runs across
// processes. docker-compose brings ztna-api, access-connector-worker
// and access-workflow-engine up against the same Postgres at the
// same time; without a cross-process lock they race on GORM's
// CREATE TYPE / CREATE TABLE catalog writes and exactly one of them
// crashes with SQLSTATE 23505 (duplicate key on
// pg_type_typname_nsp_index). The key is an arbitrary 64-bit
// constant — it just has to be the same in every binary.
const migrationAdvisoryLockKey int64 = 0x6163636573735f6d // "access_m"

// RunMigrations applies every entry returned by migrations.All() in
// order. Each migration is idempotent (AutoMigrate-backed); a
// partial failure aborts the loop and surfaces the failing
// migration's ID so operators can diagnose without grepping the log
// for goroutine numbers.
//
// When the underlying driver is Postgres, RunMigrations wraps the
// loop in a session-scoped pg_advisory_lock so concurrent invocations
// from the three access binaries serialise instead of racing on
// catalog writes. Non-Postgres dialects (SQLite in CI / dev) skip
// the lock since they're single-writer by definition.
func RunMigrations(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("database: db is nil")
	}
	release, err := acquireMigrationLock(db)
	if err != nil {
		return err
	}
	defer release()
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

// acquireMigrationLock takes a session-scoped pg_advisory_lock on a
// fixed key so concurrent migration runs from sibling binaries
// serialise. Returns a release func that callers must defer; on
// non-Postgres dialects the func is a no-op.
//
// Single-connection-pool guard: callers that configure
// PoolConfig.MaxOpenConns <= 1 (test pools, mostly) cannot reserve
// a dedicated *sql.Conn for the advisory lock without starving the
// subsequent migration DDL of any connection at all — the lock
// would hold the only slot and AutoMigrate would block forever
// trying to borrow a second. A single-writer pool is already
// serialised by definition (there is no concurrent migration
// runner to race with) so the lock is unnecessary anyway; we skip
// the advisory-lock path entirely in that configuration.
func acquireMigrationLock(db *gorm.DB) (func(), error) {
	if db.Dialector == nil || db.Dialector.Name() != "postgres" {
		return func() {}, nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("database: pool handle for advisory lock: %w", err)
	}
	if maxOpen := sqlDB.Stats().MaxOpenConnections; maxOpen > 0 && maxOpen <= 1 {
		// Single-writer pool — see godoc above. Returning a
		// no-op release is safe because RunMigrations defers
		// release() unconditionally.
		return func() {}, nil
	}
	// A single dedicated *sql.Conn so the lock and the unlock land
	// on the same backend session — pg_advisory_unlock is a no-op
	// from a different connection.
	conn, err := sqlDB.Conn(context.Background())
	if err != nil {
		return nil, fmt.Errorf("database: reserve conn for advisory lock: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), "SELECT pg_advisory_lock($1)", migrationAdvisoryLockKey); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("database: pg_advisory_lock: %w", err)
	}
	release := func() {
		// Best-effort — we hand the conn back to the pool either
		// way so a misbehaving Postgres can't leak the dedicated
		// conn for the rest of the binary's lifetime.
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", migrationAdvisoryLockKey)
		_ = conn.Close()
	}
	return release, nil
}
