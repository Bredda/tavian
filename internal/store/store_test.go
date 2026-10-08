package store

import (
	"context"
	"errors"
	"net"
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
	s, err := Open(ctx, url, (&net.Dialer{}).DialContext)
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
	_, err := Open(context.Background(), "postgres://user:s3cret@127.0.0.1:1/db?sslmode=bogus", (&net.Dialer{}).DialContext)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error leaks the password: %v", err)
	}
}

func TestOpenConnectsOnlyThroughTheGivenDialer(t *testing.T) {
	url := os.Getenv("TAVIAN_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TAVIAN_TEST_DATABASE_URL not set")
	}
	var dialed []string
	real := &net.Dialer{}
	s, err := Open(context.Background(), url, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return real.DialContext(ctx, network, addr)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(dialed) == 0 {
		t.Error("the connection did not go through the dial function")
	}
	want, err := Endpoints(url)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range dialed {
		// pgx must hand the guard the configured name, not an IP it resolved itself.
		if addr != want[0] && !strings.EqualFold(addr, want[0]) {
			t.Errorf("dialed %q, want the configured endpoint %q", addr, want[0])
		}
	}
}

func TestOpenRefusedByTheDialerFails(t *testing.T) {
	refuse := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("egress: refused") }
	_, err := Open(context.Background(), "postgres://u:p@db.example:5432/x", refuse)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("err = %v", err)
	}
	if _, err := Open(context.Background(), "postgres://u:p@db.example/x", nil); err == nil {
		t.Error("a nil dial function must be refused")
	}
}

func TestEndpoints(t *testing.T) {
	for url, want := range map[string]string{
		"postgres://u:p@DB.Example:6543/x":                 "db.example:6543",
		"postgres://u:p@db.internal/x":                     "db.internal:5432",
		"postgres://u:p@a.internal:5432,b.internal:5433/x": "a.internal:5432,b.internal:5433",
		"host=db.internal port=5434 user=u dbname=x":       "db.internal:5434",
		"postgres://u:p@[2001:db8::1]:5432/x":              "[2001:db8::1]:5432",
	} {
		got, err := Endpoints(url)
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("Endpoints(%q) = %v, %v; want %s", url, got, err, want)
		}
	}
	for _, url := range []string{
		"postgres:///x?host=/var/run/postgresql",
		"host=/var/run/postgresql dbname=x",
		"not a url at all %%",
	} {
		if got, err := Endpoints(url); err == nil {
			t.Errorf("Endpoints(%q) = %v, want an error", url, got)
		} else if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("error leaks the URL: %v", err)
		}
	}
}

func TestRevisionsKeepTheirPolicyFiles(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRevision(ctx, Revision{ID: "without", Profile: "air-gapped", YAML: []byte("a: 1\n"), Version: "v"}); err != nil {
		t.Fatal(err)
	}
	policies := []byte(`[{"name":"finance.yaml","yaml":"kind: Policy\n"}]`)
	if err := s.SaveRevision(ctx, Revision{ID: "with", Profile: "air-gapped", YAML: []byte("a: 2\n"), Version: "v", Policies: policies}); err != nil {
		t.Fatal(err)
	}
	var n int
	var name, body string
	if err := s.pool.QueryRow(ctx, `SELECT jsonb_array_length(policies) FROM config_revisions WHERE revision = 'without'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a revision without policies: %d, %v", n, err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT policies->0->>'name', policies->0->>'yaml' FROM config_revisions WHERE revision = 'with'`).Scan(&name, &body); err != nil {
		t.Fatal(err)
	}
	if name != "finance.yaml" || body != "kind: Policy\n" {
		t.Errorf("stored policy = %q %q", name, body)
	}
}
