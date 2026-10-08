package meter

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bredda/tavian/internal/spool"
	"github.com/bredda/tavian/internal/store"
)

// Needs a PostgreSQL that may be wiped: see internal/store/store_test.go.
func TestEventsOfEveryKindReachPostgresDirectlyAndThroughTheSpool(t *testing.T) {
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
	st, err := store.Open(ctx, url, (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	sp, err := spool.Open(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	s := &OutboxSink{Store: st, Spool: sp, Log: slog.New(slog.DiscardHandler)}

	now := time.Now().UTC().Truncate(time.Millisecond)
	// direct
	if err := s.Emit(ctx, decisionLike{DecisionID: "d-direct", At_: now, Note: "direct"}); err != nil {
		t.Fatal(err)
	}
	// through the spool, as during an outage
	s.down.Store(true)
	if err := s.Emit(ctx, decisionLike{DecisionID: "d-spooled", At_: now, Note: "spooled"}); err != nil {
		t.Fatal(err)
	}
	u := event("u-spooled")
	u.DecisionID = "d-spooled"
	if err := s.Emit(ctx, u); err != nil {
		t.Fatal(err)
	}
	s.flush(ctx)
	if s.Spool.Size() != 0 {
		t.Fatalf("spool not drained: %d bytes", s.Spool.Size())
	}

	rows, err := pool.Query(ctx, `SELECT event_id, kind, payload->>'note', payload->>'decision_id' FROM outbox ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type row struct{ id, kind, note, decision string }
	var got []row
	for rows.Next() {
		var r row
		var note, decision *string
		if err := rows.Scan(&r.id, &r.kind, &note, &decision); err != nil {
			t.Fatal(err)
		}
		if note != nil {
			r.note = *note
		}
		if decision != nil {
			r.decision = *decision
		}
		got = append(got, r)
	}
	want := []row{
		{"d-direct", "decision", "direct", "d-direct"},
		{"d-spooled", "decision", "spooled", "d-spooled"},
		{"u-spooled", "usage", "", "d-spooled"},
	}
	if len(got) != len(want) {
		t.Fatalf("rows = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
