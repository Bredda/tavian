package store_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/store/storetest"
)

func TestAuditorRoleSQL(t *testing.T) {
	sql, err := store.AuditorRoleSQL("tavian_auditor", "tavian", "public")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`CREATE ROLE "tavian_auditor" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`,
		`ALTER ROLE "tavian_auditor" SET default_transaction_read_only = on;`,
		`GRANT CONNECT ON DATABASE "tavian" TO "tavian_auditor";`,
		`GRANT USAGE ON SCHEMA "public" TO "tavian_auditor";`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("the script lacks %s:\n%s", want, sql)
		}
	}
	for _, tbl := range store.AuditorTables {
		if !strings.Contains(sql, `"public"."`+tbl+`"`) {
			t.Errorf("%s is not granted", tbl)
		}
	}
	for _, tbl := range store.ReservedTables {
		if strings.Contains(sql, `."`+tbl+`"`) {
			t.Errorf("%s is granted, it is reserved", tbl)
		}
	}
	// nothing but SELECT is ever granted, and nothing on all tables
	for _, bad := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE", "ALL PRIVILEGES", "ALL TABLES", "WITH GRANT OPTION", "SUPERUSER;"} {
		if strings.Contains(strings.ReplaceAll(sql, "NOSUPERUSER", ""), bad) && bad != "SUPERUSER;" {
			t.Errorf("the script says %q", bad)
		}
	}
	// what cannot be an identifier is refused, quotes and injections included
	for _, args := range [][3]string{
		{"", "tavian", "public"}, {"Tavian", "tavian", "public"}, {`a"; DROP TABLE outbox; --`, "tavian", "public"},
		{"a", "db-name", "public"}, {"a", "tavian", "pub lic"}, {"a", "tavian", strings.Repeat("a", 64)}, {"1a", "tavian", "public"},
	} {
		if _, err := store.AuditorRoleSQL(args[0], args[1], args[2]); err == nil {
			t.Errorf("%q was accepted", args)
		}
	}
}

// Every table of the schema is either for the auditor or reserved: whoever
// adds a table decides who may read it.
func TestEveryTableIsForTheAuditorOrReserved(t *testing.T) {
	st, url := storetest.New(t)
	_ = url
	rs, err := st.Pool().Query(context.Background(), `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var have []string
	for rs.Next() {
		var n string
		if err := rs.Scan(&n); err != nil {
			t.Fatal(err)
		}
		have = append(have, n)
	}
	for _, n := range have {
		if !slices.Contains(store.AuditorTables, n) && !slices.Contains(store.ReservedTables, n) {
			t.Errorf("table %s is in neither store.AuditorTables nor store.ReservedTables: decide who may read it", n)
		}
	}
	for _, n := range append(slices.Clone(store.AuditorTables), store.ReservedTables...) {
		if !slices.Contains(have, n) {
			t.Errorf("%s is listed but there is no such table", n)
		}
	}
	for _, n := range store.AuditorTables {
		if slices.Contains(store.ReservedTables, n) {
			t.Errorf("%s is both for the auditor and reserved", n)
		}
	}
}

func TestTheAuditorRoleReadsAndCannotChangeAnything(t *testing.T) {
	st, url := storetest.New(t)
	ctx := context.Background()
	// something to read and to try to destroy
	if err := st.RecordAdminChange(ctx, change(1)); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, storetest.AuditorURL(t, url))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("the role cannot connect: %v", err)
	}
	for _, tbl := range store.AuditorTables {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&n); err != nil {
			t.Errorf("reading %s: %v", tbl, err)
		}
	}
	var changes int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM admin_changes`).Scan(&changes); err != nil || changes != 1 {
		t.Errorf("admin_changes: %d %v", changes, err)
	}
	for _, tbl := range store.ReservedTables {
		if _, err := pool.Exec(ctx, `SELECT 1 FROM `+tbl); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("reading the reserved table %s: %v", tbl, err)
		}
	}
	// nothing can be written, not even after asking for a read-write session
	if _, err := pool.Exec(ctx, `SET default_transaction_read_only = off`); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO outbox (event_id, kind, occurred_at, payload) VALUES ('x', 'decision', now(), '{}')`,
		`INSERT INTO admin_changes (event_id, occurred_at, actor, action, outcome) VALUES ('x', now(), 'a', 'b', 'applied')`,
		`UPDATE outbox SET payload = '{}'`,
		`UPDATE audit_chain SET entry_hash = prev_hash`,
		`UPDATE config_active SET revision = 'x'`,
		`DELETE FROM audit_seals`,
		`DELETE FROM admin_changes`,
		`TRUNCATE outbox`,
		`TRUNCATE audit_chain, audit_seals`,
		`CREATE TABLE evil (x int)`,
		`DROP TABLE outbox`,
		`ALTER TABLE outbox ADD COLUMN y int`,
		`DROP TABLE audit_chain CASCADE`,
		`CREATE ROLE evil SUPERUSER`,
	} {
		if _, err := pool.Exec(ctx, stmt); err == nil {
			t.Errorf("the auditor role could run: %s", stmt)
		}
	}
	// asking for more is not an error in PostgreSQL, it just grants nothing
	_, _ = pool.Exec(ctx, `GRANT ALL ON outbox TO PUBLIC`)
	_, _ = pool.Exec(ctx, `GRANT ALL ON outbox TO CURRENT_USER`)
	if _, err := pool.Exec(ctx, `INSERT INTO outbox (event_id, kind, occurred_at, payload) VALUES ('y', 'decision', now(), '{}')`); err == nil {
		t.Error("the role gave itself the right to write")
	}
	var after int
	if err := st.Pool().QueryRow(ctx, `SELECT (SELECT count(*) FROM admin_changes) + (SELECT count(*) FROM outbox)`).Scan(&after); err != nil || after != 2 {
		t.Errorf("rows after the attempts: %d (%v), want 2", after, err)
	}
}
