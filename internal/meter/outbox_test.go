package meter

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/spool"
	"github.com/bredda/tavian/internal/store"
)

// fakeStore is an outbox that can be switched off, like a database outage.
type fakeStore struct {
	mu   sync.Mutex
	down bool
	rows map[string]store.OutboxRow
	n    int // successful InsertOutbox calls
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]store.OutboxRow{}} }

func (f *fakeStore) setDown(d bool) { f.mu.Lock(); f.down = d; f.mu.Unlock() }

func (f *fakeStore) InsertOutbox(_ context.Context, rows []store.OutboxRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("connection refused")
	}
	f.n++
	for _, r := range rows {
		f.rows[r.EventID] = r // idempotent, like ON CONFLICT DO NOTHING
	}
	return nil
}

func (f *fakeStore) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.rows) }

func newSink(t *testing.T, maxSpool int64) (*OutboxSink, *fakeStore) {
	t.Helper()
	sp, err := spool.Open(t.TempDir(), maxSpool)
	if err != nil {
		t.Fatal(err)
	}
	fs := newFakeStore()
	return &OutboxSink{Store: fs, Spool: sp, Log: slog.New(slog.DiscardHandler)}, fs
}

func event(id string) UsageEvent {
	return UsageEvent{EventID: id, RequestID: "r-" + id, Time: time.Now().UTC(), Model: "m", InputTokens: 3}
}

func TestEmitWritesToTheDatabase(t *testing.T) {
	s, fs := newSink(t, 1<<20)
	if err := s.Emit(context.Background(), event("e1")); err != nil {
		t.Fatal(err)
	}
	if fs.count() != 1 || s.Spool.Size() != 0 {
		t.Errorf("rows=%d spool=%d", fs.count(), s.Spool.Size())
	}
	row := fs.rows["e1"]
	if row.Kind != KindUsage || len(row.Payload) == 0 {
		t.Errorf("row = %+v", row)
	}
}

func TestOutageSpoolsThenReplays(t *testing.T) {
	s, fs := newSink(t, 1<<20)
	fs.setDown(true)
	for _, id := range []string{"e1", "e2", "e3"} {
		if err := s.Emit(context.Background(), event(id)); err != nil {
			t.Fatalf("emit during outage: %v", err)
		}
	}
	if s.Up() || fs.count() != 0 || s.Spool.Size() == 0 {
		t.Fatalf("up=%v rows=%d spool=%d", s.Up(), fs.count(), s.Spool.Size())
	}

	// Still down: replay fails and keeps everything.
	s.flush(context.Background())
	if s.Spool.Size() == 0 {
		t.Fatal("spool emptied while the database was down")
	}

	fs.setDown(false)
	s.flush(context.Background())
	if fs.count() != 3 || s.Spool.Size() != 0 || !s.Up() {
		t.Errorf("rows=%d spool=%d up=%v", fs.count(), s.Spool.Size(), s.Up())
	}
}

func TestEventsDuringReplayAreNotLost(t *testing.T) {
	s, fs := newSink(t, 1<<20)
	fs.setDown(true)
	_ = s.Emit(context.Background(), event("e1"))
	fs.setDown(false)
	// Database is back but the spool is not drained yet: the new event queues
	// behind the old one instead of overtaking it.
	_ = s.Emit(context.Background(), event("e2"))
	if fs.count() != 0 {
		t.Fatalf("rows = %d, want events kept in order in the spool", fs.count())
	}
	s.flush(context.Background())
	if fs.count() != 2 {
		t.Errorf("rows = %d, want 2", fs.count())
	}
}

func TestFullSpoolFailsClosed(t *testing.T) {
	s, fs := newSink(t, 1500)
	fs.setDown(true)
	if err := s.Admit(); err != nil {
		t.Fatalf("admit with an empty spool: %v", err)
	}
	var failed error
	for i := range 20 {
		if err := s.Emit(context.Background(), event(string(rune('a'+i)))); err != nil {
			failed = err
			break
		}
	}
	if !errors.Is(failed, ErrAuditUnavailable) {
		t.Fatalf("emit err = %v, want ErrAuditUnavailable", failed)
	}
	if err := s.Admit(); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("admit = %v, want ErrAuditUnavailable once the spool is full", err)
	}
	// Recovery reopens admission.
	fs.setDown(false)
	s.flush(context.Background())
	if err := s.Admit(); err != nil {
		t.Errorf("admit after recovery: %v", err)
	}
}

func TestAdmitIsOpenWhileDatabaseIsUp(t *testing.T) {
	s, _ := newSink(t, 100) // tiny spool, but never used
	if err := s.Admit(); err != nil {
		t.Errorf("admit = %v", err)
	}
}

func TestUnreadableSpoolRecordDoesNotBlockTheQueue(t *testing.T) {
	s, fs := newSink(t, 1<<20)
	_ = s.Spool.Append([]byte(`{"event_id":"e1"`)) // torn write
	_ = s.Spool.Append([]byte(`{"event_id":"e2","time":"2026-01-01T00:00:00Z"}`))
	s.flush(context.Background())
	if _, ok := fs.rows["e2"]; !ok || fs.count() != 1 {
		t.Errorf("rows = %v", fs.rows)
	}
	if s.Spool.Size() != 0 {
		t.Errorf("spool = %d", s.Spool.Size())
	}
}

func TestRunReplaysInBackground(t *testing.T) {
	s, fs := newSink(t, 1<<20)
	s.FlushEvery = 10 * time.Millisecond
	fs.setDown(true)
	_ = s.Emit(context.Background(), event("e1"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	fs.setDown(false)
	deadline := time.Now().Add(2 * time.Second)
	for fs.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if fs.count() != 1 {
		t.Errorf("rows = %d, want 1", fs.count())
	}
}
