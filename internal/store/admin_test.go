package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/store/storetest"
)

func change(i int) store.AdminChange {
	return store.AdminChange{
		EventID: fmt.Sprintf("evt-%02d", i), OccurredAt: time.Date(2026, 10, 10, 12, i, 0, 0, time.UTC),
		Actor: "ops-alice", Action: "config.reload", Target: fmt.Sprintf("rev-%d", i), Outcome: store.OutcomeApplied,
		RequestID: "req-12345678", RemoteAddr: "10.0.0.7", Detail: json.RawMessage(`{"previous":"rev-0"}`),
	}
}

func TestRecordAdminChangeWritesTheRowAndTheOutboxEventTogether(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	if err := st.RecordAdminChange(ctx, change(1)); err != nil {
		t.Fatal(err)
	}
	var kind, payload string
	if err := st.Pool().QueryRow(ctx, `SELECT kind, payload::text FROM outbox WHERE event_id = 'evt-01'`).Scan(&kind, &payload); err != nil {
		t.Fatal(err)
	}
	if kind != "admin_change" {
		t.Errorf("kind = %q", kind)
	}
	var p store.AdminChange
	if err := json.Unmarshal([]byte(payload), &p); err != nil || p.Actor != "ops-alice" || p.Target != "rev-1" || p.RemoteAddr != "10.0.0.7" || p.RequestID != "req-12345678" {
		t.Errorf("payload = %s (%v)", payload, err)
	}

	// the same event twice changes nothing
	if err := st.RecordAdminChange(ctx, change(1)); err != nil {
		t.Fatal(err)
	}
	var rows, events int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM admin_changes`).Scan(&rows)
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE kind = 'admin_change'`).Scan(&events)
	if rows != 1 || events != 1 {
		t.Errorf("rows = %d, outbox events = %d, want 1 and 1", rows, events)
	}
}

func TestRecordAdminChangeIsAllOrNothing(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	// An outbox row that cannot be written (kind is NOT NULL: an event id too
	// long for nothing, so use a constraint we control) must not leave the
	// admin_changes row behind. Make the outbox insert fail by dropping the table.
	if _, err := st.Pool().Exec(ctx, `ALTER TABLE outbox RENAME TO outbox_gone`); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAdminChange(ctx, change(1)); err == nil {
		t.Fatal("recording succeeded without an outbox")
	}
	var n int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM admin_changes`).Scan(&n)
	if n != 0 {
		t.Errorf("%d admin_changes rows were left behind by a failed record", n)
	}
}

func TestListAdminChangesPagesNewestFirst(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		if err := st.RecordAdminChange(ctx, change(i)); err != nil {
			t.Fatal(err)
		}
	}
	first, next, err := st.ListAdminChanges(ctx, 2, 0)
	if err != nil || len(first) != 2 || next == 0 || first[0].EventID != "evt-05" || first[1].EventID != "evt-04" {
		t.Fatalf("first page = %+v next=%d err=%v", first, next, err)
	}
	second, next, err := st.ListAdminChanges(ctx, 2, next)
	if err != nil || len(second) != 2 || next == 0 || second[0].EventID != "evt-03" {
		t.Fatalf("second page = %+v next=%d err=%v", second, next, err)
	}
	last, next, err := st.ListAdminChanges(ctx, 2, next)
	if err != nil || len(last) != 1 || next != 0 || last[0].EventID != "evt-01" {
		t.Fatalf("last page = %+v next=%d err=%v", last, next, err)
	}
	if string(last[0].Detail) == "" || !strings.Contains(string(last[0].Detail), "rev-0") || last[0].Outcome != store.OutcomeApplied || last[0].RemoteAddr != "10.0.0.7" {
		t.Errorf("fields lost: %+v", last[0])
	}
	empty := change(9)
	empty.EventID, empty.Detail = "evt-empty", nil
	if err := st.RecordAdminChange(ctx, empty); err != nil {
		t.Fatal(err)
	}
	got, _, _ := st.ListAdminChanges(ctx, 1, 0)
	if string(got[0].Detail) != "{}" {
		t.Errorf("a change without detail has detail %q", got[0].Detail)
	}
}

func TestListAdminChangesBoundsTheLimit(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		if err := st.RecordAdminChange(ctx, change(i)); err != nil {
			t.Fatal(err)
		}
	}
	if all, next, err := st.ListAdminChanges(ctx, 100000, 0); err != nil || len(all) != 8 || next != 0 {
		t.Errorf("a large limit: %d rows next=%d (%v), want all 8", len(all), next, err)
	}
	if one, _, err := st.ListAdminChanges(ctx, 0, 0); err != nil || len(one) != 1 {
		t.Errorf("a zero limit: %d rows (%v), want 1", len(one), err)
	}
}
