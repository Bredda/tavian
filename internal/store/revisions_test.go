package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/store/storetest"
)

func activation(id, base, file string, i int) store.Activation {
	c := change(i)
	c.EventID, c.Target = "act-"+id+"-"+fmt.Sprint(i), id
	return store.Activation{
		Revision: store.Revision{ID: id, Profile: "standard", YAML: []byte("profile: standard\n# " + id), Version: "test", Policies: []byte(`[{"name":"a.yaml","yaml":"YQ=="}]`)},
		Base:     base, FileRevision: file, Change: c,
	}
}

func count(t *testing.T, st *store.Store, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := st.Pool().QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestActivateMovesThePointerAndRecordsTheChange(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	if _, ok, err := st.ActiveRevision(ctx); err != nil || ok {
		t.Fatalf("a fresh database has an active revision: %v %v", ok, err)
	}
	if err := st.Activate(ctx, activation("aaa", "", "aaa", 1)); err != nil {
		t.Fatal(err)
	}
	a, ok, err := st.ActiveRevision(ctx)
	if err != nil || !ok || a.Revision != "aaa" || a.ActivatedBy != "ops-alice" || a.FileRevision != "aaa" || !a.ActivatedAt.Equal(change(1).OccurredAt) {
		t.Fatalf("active = %+v %v %v", a, ok, err)
	}
	// from the API: the file revision is left alone
	if err := st.Activate(ctx, activation("bbb", "aaa", "", 2)); err != nil {
		t.Fatal(err)
	}
	if a, _, _ = st.ActiveRevision(ctx); a.Revision != "bbb" || a.FileRevision != "aaa" {
		t.Errorf("after an API change: %+v", a)
	}
	// from the file again
	if err := st.Activate(ctx, activation("ccc", "bbb", "ccc", 3)); err != nil {
		t.Fatal(err)
	}
	if a, _, _ = st.ActiveRevision(ctx); a.Revision != "ccc" || a.FileRevision != "ccc" {
		t.Errorf("after a change from the file: %+v", a)
	}
	// the same revision again (nothing changed) is allowed and recorded
	if err := st.Activate(ctx, activation("ccc", "ccc", "ccc", 4)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, st, `SELECT count(*) FROM admin_changes`); n != 4 {
		t.Errorf("admin_changes = %d, want 4", n)
	}
	if n := count(t, st, `SELECT count(*) FROM outbox WHERE kind = 'admin_change'`); n != 4 {
		t.Errorf("outbox events = %d, want 4", n)
	}
	if n := count(t, st, `SELECT count(*) FROM config_revisions`); n != 3 {
		t.Errorf("revisions = %d, want 3 (one repeated)", n)
	}
}

func TestActivateRefusesAWrongBaseAndWritesNothing(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	if err := st.Activate(ctx, activation("aaa", "", "aaa", 1)); err != nil {
		t.Fatal(err)
	}
	for name, base := range map[string]string{"stale": "zzz", "none given": ""} {
		err := st.Activate(ctx, activation("bbb", base, "", 2))
		if !errors.Is(err, store.ErrConflict) {
			t.Errorf("%s base: err = %v, want a conflict", name, err)
		}
	}
	if a, _, _ := st.ActiveRevision(ctx); a.Revision != "aaa" {
		t.Errorf("the pointer moved to %q", a.Revision)
	}
	if n := count(t, st, `SELECT count(*) FROM config_revisions WHERE revision = 'bbb'`); n != 0 {
		t.Error("the revision of a refused change was kept")
	}
	if n := count(t, st, `SELECT count(*) FROM admin_changes`); n != 1 {
		t.Errorf("admin_changes = %d, a refused activation must leave no record of its own", n)
	}
	// and a base is required once something is active
	if err := st.Activate(ctx, activation("aaa", "", "aaa", 3)); !errors.Is(err, store.ErrConflict) {
		t.Errorf("re-bootstrapping over an active revision: %v", err)
	}
}

func TestActivateIsAllOrNothing(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	if _, err := st.Pool().Exec(ctx, `ALTER TABLE outbox RENAME TO outbox_gone`); err != nil {
		t.Fatal(err)
	}
	if err := st.Activate(ctx, activation("aaa", "", "aaa", 1)); err == nil {
		t.Fatal("activation succeeded without an outbox")
	}
	if n := count(t, st, `SELECT count(*) FROM config_active`) + count(t, st, `SELECT count(*) FROM config_revisions`) + count(t, st, `SELECT count(*) FROM admin_changes`); n != 0 {
		t.Errorf("%d rows were left behind by a failed activation", n)
	}
}

func TestGetAndListRevisions(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	if _, err := st.GetRevision(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing revision: %v", err)
	}
	base := ""
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		if err := st.Activate(ctx, activation(id, base, "", i+1)); err != nil {
			t.Fatal(err)
		}
		base = id
	}
	r, err := st.GetRevision(ctx, "r2")
	if err != nil || r.ID != "r2" || r.Profile != "standard" || r.Version != "test" || string(r.YAML) != "profile: standard\n# r2" ||
		len(r.Policies) == 0 || r.FirstLoadedAt.IsZero() || r.Seq == 0 {
		t.Fatalf("revision = %+v (%v)", r, err)
	}
	first, next, err := st.ListRevisions(ctx, 2, 0)
	if err != nil || len(first) != 2 || next == 0 || first[0].ID != "r5" || first[1].ID != "r4" {
		t.Fatalf("first page = %+v next=%d (%v)", first, next, err)
	}
	if len(first[0].YAML) != 0 {
		t.Error("a listing carries the content of the revisions")
	}
	second, next, _ := st.ListRevisions(ctx, 2, next)
	last, next, _ := st.ListRevisions(ctx, 2, next)
	if len(second) != 2 || second[0].ID != "r3" || len(last) != 1 || last[0].ID != "r1" || next != 0 {
		t.Errorf("pages: %+v / %+v next=%d", second, last, next)
	}
	if all, _, _ := st.ListRevisions(ctx, 100000, 0); len(all) != 5 {
		t.Errorf("a large limit returned %d", len(all))
	}
	if one, _, _ := st.ListRevisions(ctx, 0, 0); len(one) != 1 {
		t.Errorf("a zero limit returned %d", len(one))
	}
}

func TestListRevisionsHonoursALargeLimit(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	base := ""
	for i := 1; i <= 8; i++ {
		id := fmt.Sprintf("v%d", i)
		if err := st.Activate(ctx, activation(id, base, "", i)); err != nil {
			t.Fatal(err)
		}
		base = id
	}
	if all, next, err := st.ListRevisions(ctx, 100000, 0); err != nil || len(all) != 8 || next != 0 {
		t.Errorf("a large limit returned %d (next %d, %v), want all 8", len(all), next, err)
	}
}
