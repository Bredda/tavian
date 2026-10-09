// Package storetest gives tests a migrated PostgreSQL schema of their own.
//
// Point TAVIAN_TEST_DATABASE_URL at a throwaway database, e.g.
//
//	docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=tavian postgres:17-alpine
//	TAVIAN_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/tavian go test ./...
//
// Without it the tests that call New are skipped. Each test works in a schema
// created for it and dropped afterwards, so packages can run in parallel.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bredda/tavian/internal/store"
)

// New returns a Store on a fresh, migrated schema, and the connection URL that
// leads to it. It skips the test when no test database is configured.
func New(t *testing.T) (*store.Store, string) {
	t.Helper()
	base := os.Getenv("TAVIAN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TAVIAN_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "t_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	st, err := store.Open(ctx, u.String(), (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return st, u.String()
}
