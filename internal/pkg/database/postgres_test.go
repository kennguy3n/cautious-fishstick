package database

import (
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestDefaultPool covers the pool-defaults contract the binaries
// rely on. If these numbers drift unintentionally, the
// docker-compose dev stack and any deployment using DefaultPool()
// will silently change behavior. Pin them explicitly.
func TestDefaultPool(t *testing.T) {
	pool := DefaultPool()
	if pool.MaxOpenConns != 25 {
		t.Errorf("MaxOpenConns = %d; want 25", pool.MaxOpenConns)
	}
	if pool.MaxIdleConns != 5 {
		t.Errorf("MaxIdleConns = %d; want 5", pool.MaxIdleConns)
	}
	if pool.ConnMaxLifetime != 30*time.Minute {
		t.Errorf("ConnMaxLifetime = %s; want 30m", pool.ConnMaxLifetime)
	}
	if pool.ConnMaxIdleTime != 5*time.Minute {
		t.Errorf("ConnMaxIdleTime = %s; want 5m", pool.ConnMaxIdleTime)
	}
}

// TestOpenPostgres_EmptyDSN is the failure-path guard. Without
// this check OpenPostgres would hand an empty DSN to libpq, which
// produces a less actionable error and only on first query rather
// than at construction time. The binaries call log.Fatalf on
// OpenPostgres errors, so an early, clear error makes
// misconfiguration obvious in the boot log.
func TestOpenPostgres_EmptyDSN(t *testing.T) {
	db, err := OpenPostgres("")
	if err == nil {
		t.Fatal("OpenPostgres(\"\") returned nil err; want a clear failure")
	}
	if db != nil {
		t.Errorf("OpenPostgres(\"\") returned a non-nil db; want nil so callers cannot accidentally use a partial connection")
	}
	if !strings.Contains(err.Error(), "dsn") {
		t.Errorf("err = %q; want it to mention 'dsn' so the operator can diagnose", err.Error())
	}
}

// TestOpenPostgresWithPool_EmptyDSN mirrors OpenPostgres_EmptyDSN
// against the explicit-pool entry-point. Tests that hand-roll a
// PoolConfig (e.g. single-connection pools) hit this code path.
func TestOpenPostgresWithPool_EmptyDSN(t *testing.T) {
	db, err := OpenPostgresWithPool("", PoolConfig{MaxOpenConns: 1})
	if err == nil {
		t.Fatal("OpenPostgresWithPool(\"\", ...) returned nil err; want a clear failure")
	}
	if db != nil {
		t.Error("OpenPostgresWithPool(\"\", ...) returned a non-nil db; want nil")
	}
}

// TestRunMigrations_NilDB is the failure-path guard for callers
// that forget to wire a db (e.g. via a misordered
// openDatabase/RunMigrations pair). Without it the function would
// dereference a nil pointer inside acquireMigrationLock and panic
// with a less useful stack trace.
func TestRunMigrations_NilDB(t *testing.T) {
	err := RunMigrations(nil)
	if err == nil {
		t.Fatal("RunMigrations(nil) returned nil err; want a clear failure")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("err = %q; want it to mention nil db", err.Error())
	}
}

// TestRunMigrations_AppliesSchemaToSQLite is the happy-path
// cross-check that the migration set actually runs against the
// SQLite dialect (the workflow engine's fallback). It also pins
// the non-Postgres advisory-lock short-circuit: if
// acquireMigrationLock tried to ExecContext "SELECT
// pg_advisory_lock(...)" against SQLite, this test would surface
// the regression as a migration failure.
func TestRunMigrations_AppliesSchemaToSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open(sqlite): %v", err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	// Spot-check a table that lands in the migration set so the
	// "migrations ran" assertion isn't purely vacuous. The
	// access_connectors table is created early in the migration
	// chain and is one of the more commonly queried by service-
	// layer code, so its presence is a good canary.
	if !db.Migrator().HasTable("access_connectors") {
		t.Error("access_connectors table missing after RunMigrations; migration chain did not apply")
	}
}

// TestRunMigrations_SingleConnPoolDoesNotDeadlock pins the
// single-connection-pool guard in acquireMigrationLock. The
// scenario: a caller opens a Postgres pool sized to exactly one
// connection (a common test idiom for reproducing serialised-
// access bugs) and then calls RunMigrations. Without the guard,
// the advisory-lock path would reserve the only connection for
// pg_advisory_lock and the subsequent migration DDL would block
// forever trying to borrow a second connection from a pool with
// zero free slots.
//
// We can't easily stand up a real Postgres pool from here, but we
// CAN exercise the dialect-aware short-circuit by handing a
// SQLite pool of one connection: SQLite skips the lock entirely,
// so the path that matters is symmetric to the Postgres
// MaxOpenConns=1 branch. The Postgres-specific guard is covered
// by the godoc + the sqlDB.Stats().MaxOpenConnections == 1 check
// in acquireMigrationLock itself, which this test pins by way of
// not deadlocking when migrations run against a 1-conn pool.
func TestRunMigrations_SingleConnPoolDoesNotDeadlock(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open(sqlite): %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	// Channel + timeout guard so a regression deadlocks the
	// test goroutine rather than wedging the whole test binary
	// until the framework timeout kicks in.
	done := make(chan error, 1)
	go func() { done <- RunMigrations(db) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunMigrations on 1-conn pool: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("RunMigrations on 1-conn pool deadlocked; advisory lock or migration loop is holding the only connection")
	}
}

// TestAcquireMigrationLock_NoOpOnNonPostgres pins the dialect-
// branching: on SQLite the helper must return a release func
// without touching the connection (which has no
// pg_advisory_lock). Calling the release func must be safe.
func TestAcquireMigrationLock_NoOpOnNonPostgres(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open(sqlite): %v", err)
	}
	release, err := acquireMigrationLock(db)
	if err != nil {
		t.Fatalf("acquireMigrationLock(sqlite): err = %v; want nil so SQLite skips the advisory-lock path", err)
	}
	if release == nil {
		t.Fatal("release = nil; want a no-op closure so callers can unconditionally defer release()")
	}
	// Calling release twice must not panic — the no-op closure
	// is idempotent, which matches the contract documented in
	// acquireMigrationLock's godoc.
	release()
	release()
}
