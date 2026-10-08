package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationLockID serialises concurrent `tavian migrate` runs (arbitrary
// constant, pg_advisory_lock key space is per database).
const migrationLockID int64 = 0x746176696e

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil {
			return nil, fmt.Errorf("migration %q: name must start with <number>_", e.Name())
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("migration %q: versions must be consecutive from 1", m.name)
		}
	}
	return out, nil
}

// Migrate applies pending migrations, each in its own transaction, and returns
// the versions it applied. It is safe to run concurrently.
func (s *Store) Migrate(ctx context.Context) ([]int, error) {
	all, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return nil, fmt.Errorf("migrate: lock: %w", err)
	}
	defer func() {
		// Background context: the lock must be released even if ctx is done.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)
	}()
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    integer PRIMARY KEY,
		name       text        NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	current, err := schemaVersion(ctx, conn.QueryRow)
	if err != nil {
		return nil, err
	}
	if current > len(all) {
		return nil, fmt.Errorf("migrate: database schema is at version %d, newer than this binary (%d)", current, len(all))
	}
	var applied []int
	for _, m := range all[current:] {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, fmt.Errorf("migrate %s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("migrate %s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("migrate %s: %w", m.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, fmt.Errorf("migrate %s: %w", m.name, err)
		}
		applied = append(applied, m.version)
	}
	return applied, nil
}

// CheckSchema fails unless the database is exactly at the version this binary
// expects, so that `serve` never runs against a schema it does not understand.
func (s *Store) CheckSchema(ctx context.Context) error {
	all, err := loadMigrations()
	if err != nil {
		return err
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return fmt.Errorf("check schema: %w", err)
	}
	current := 0
	if exists {
		if current, err = schemaVersion(ctx, s.pool.QueryRow); err != nil {
			return err
		}
	}
	switch {
	case current < len(all):
		return fmt.Errorf("database schema is at version %d, this binary needs %d: run `tavian migrate`", current, len(all))
	case current > len(all):
		return fmt.Errorf("database schema is at version %d, newer than this binary (%d): upgrade tavian", current, len(all))
	}
	return nil
}

func schemaVersion(ctx context.Context, queryRow func(context.Context, string, ...any) pgx.Row) (int, error) {
	var v int
	if err := queryRow(ctx, `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return v, nil
}
