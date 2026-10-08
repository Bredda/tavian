package store

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests need a PostgreSQL they may wipe. Point TAVIAN_TEST_DATABASE_URL
// at a throwaway database, e.g.
//
//	docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=tavian postgres:17-alpine
//	TAVIAN_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/tavian go test ./internal/store
//
// CI runs them against a service container.
func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("TAVIAN_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TAVIAN_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestMigrateAndCheckSchema(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.CheckSchema(ctx); err == nil || !strings.Contains(err.Error(), "tavian migrate") {
		t.Fatalf("CheckSchema on an empty database = %v, want a hint to run migrate", err)
	}
	applied, err := s.Migrate(ctx)
	if err != nil || len(applied) == 0 {
		t.Fatalf("Migrate = %v, %v", applied, err)
	}
	if err := s.CheckSchema(ctx); err != nil {
		t.Errorf("CheckSchema after migrate: %v", err)
	}
	again, err := s.Migrate(ctx)
	if err != nil || len(again) != 0 {
		t.Errorf("second Migrate = %v, %v; want nothing to apply", again, err)
	}
}

func TestMigrateConcurrently(t *testing.T) {
	s := testStore(t)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Migrate(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Migrate: %v", err)
		}
	}
}

func TestSchemaNewerThanBinaryIsRefused(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES (9999, 'future')`); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSchema(ctx); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("CheckSchema = %v", err)
	}
}

func TestInsertOutboxIsIdempotent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	rows := []OutboxRow{
		{EventID: "e1", Kind: "usage", OccurredAt: now, Payload: []byte(`{"n":1}`)},
		{EventID: "e2", Kind: "usage", OccurredAt: now, Payload: []byte(`{"n":2}`)},
	}
	if err := s.InsertOutbox(ctx, rows); err != nil {
		t.Fatal(err)
	}
	// A replay of the same events, plus one new, must not duplicate or fail.
	rows = append(rows, OutboxRow{EventID: "e3", Kind: "usage", OccurredAt: now, Payload: []byte(`{"n":3}`)})
	if err := s.InsertOutbox(ctx, rows); err != nil {
		t.Fatal(err)
	}
	var n int
	var n1 int
	if err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE payload->>'n' = '1') FROM outbox`).Scan(&n, &n1); err != nil {
		t.Fatal(err)
	}
	if n != 3 || n1 != 1 {
		t.Errorf("rows = %d (n=1: %d), want 3 and 1", n, n1)
	}
	if err := s.InsertOutbox(ctx, nil); err != nil {
		t.Errorf("empty insert: %v", err)
	}
}

func TestSaveRevision(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	r := Revision{ID: "abc123", Profile: "air-gapped", YAML: []byte("profile: air-gapped\n"), Version: "v0.1.0"}
	for range 2 {
		if err := s.SaveRevision(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	var yaml string
	if err := s.pool.QueryRow(ctx, `SELECT config_yaml FROM config_revisions WHERE revision = 'abc123'`).Scan(&yaml); err != nil {
		t.Fatal(err)
	}
	if yaml != "profile: air-gapped\n" {
		t.Errorf("yaml = %q", yaml)
	}
}

func TestOpenDoesNotLeakThePassword(t *testing.T) {
	_, err := Open(context.Background(), "postgres://user:s3cret@127.0.0.1:1/db?sslmode=bogus")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error leaks the password: %v", err)
	}
}
