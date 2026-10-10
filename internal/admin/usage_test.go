package admin

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/store"
)

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type fakeFlusher struct {
	mu    sync.Mutex
	got   [][]store.TokenUse
	fails int
}

func (f *fakeFlusher) AddTokenUse(_ context.Context, uses []store.TokenUse) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return errors.New("database down")
	}
	f.got = append(f.got, append([]store.TokenUse(nil), uses...))
	return nil
}

func (f *fakeFlusher) writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func TestUsesCountsInMemoryAndDrains(t *testing.T) {
	u := NewUses()
	u.Touch("b", t0, "10.0.0.2")
	u.Touch("a", t0.Add(time.Second), "10.0.0.1")
	u.Touch("a", t0.Add(3*time.Second), "10.0.0.3")
	u.Touch("a", t0.Add(2*time.Second), "10.0.0.9") // late: counted, but not the last
	p := u.Pending()
	if p["a"].Uses != 3 || !p["a"].LastUsedAt.Equal(t0.Add(3*time.Second)) || p["a"].LastRemote != "10.0.0.3" || p["b"].Uses != 1 {
		t.Errorf("pending = %+v", p)
	}
	if len(u.Pending()) != 2 {
		t.Error("looking at what is pending took it")
	}
	d := u.Drain()
	if len(d) != 2 || d[0].TokenID != "a" || d[1].TokenID != "b" {
		t.Errorf("drain = %+v, want a then b", d)
	}
	if len(u.Drain()) != 0 || len(u.Pending()) != 0 {
		t.Error("nothing was left, yet something came back")
	}
}

func TestUsesFlushKeepsWhatCouldNotBeWritten(t *testing.T) {
	u := NewUses()
	f := &fakeFlusher{fails: 1}
	u.Touch("a", t0, "10.0.0.1")
	u.Touch("a", t0.Add(time.Second), "10.0.0.2")
	if err := u.Flush(context.Background(), f); err == nil {
		t.Fatal("a failed write was not reported")
	}
	// calls made meanwhile are added to what is kept
	u.Touch("a", t0.Add(2*time.Second), "10.0.0.3")
	u.Touch("b", t0.Add(time.Second), "10.0.0.4")
	if err := u.Flush(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if f.writes() != 1 {
		t.Fatalf("writes = %d", f.writes())
	}
	got := map[string]store.TokenUse{}
	for _, x := range f.got[0] {
		got[x.TokenID] = x
	}
	if got["a"].Uses != 3 || got["a"].LastRemote != "10.0.0.3" || !got["a"].LastUsedAt.Equal(t0.Add(2*time.Second)) || got["b"].Uses != 1 {
		t.Errorf("written = %+v", got)
	}
	// nothing to write: no write
	if err := u.Flush(context.Background(), f); err != nil || f.writes() != 1 {
		t.Errorf("an empty flush wrote: %v %d", err, f.writes())
	}
	// restoring an older use does not turn the last one back
	u.Touch("c", t0.Add(time.Hour), "new")
	u.Restore([]store.TokenUse{{TokenID: "c", Uses: 2, LastUsedAt: t0, LastRemote: "old"}})
	if p := u.Pending()["c"]; p.Uses != 3 || p.LastRemote != "new" {
		t.Errorf("restored = %+v", p)
	}
}

func TestUsesRunWritesAtTheIntervalAndOnceMoreAtTheEnd(t *testing.T) {
	u := NewUses()
	f := &fakeFlusher{}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		u.Run(ctx, f, 20*time.Millisecond, slog.New(slog.DiscardHandler))
		close(done)
	}()
	u.Touch("a", t0, "10.0.0.1")
	deadline := time.Now().Add(5 * time.Second)
	for f.writes() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("nothing was written at the interval")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// one more use, then shut down before the next tick: it is not lost
	time.Sleep(60 * time.Millisecond)
	before := f.writes()
	u.Touch("late", t0, "10.0.0.2")
	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	found := false
	for _, w := range f.got[before:] {
		for _, x := range w {
			found = found || x.TokenID == "late"
		}
	}
	if !found {
		t.Error("the use made just before the end was lost")
	}
}

func TestUsesRunSurvivesAFailingDatabase(t *testing.T) {
	var logs strings.Builder
	u := NewUses()
	f := &fakeFlusher{fails: 3}
	u.Touch("a", t0, "10.0.0.1")
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		u.Run(ctx, f, 10*time.Millisecond, slog.New(slog.NewTextHandler(&logs, nil)))
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for f.writes() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the use was never written once the database came back")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	<-done
	if f.got[0][0].Uses != 1 {
		t.Errorf("written = %+v", f.got[0])
	}
	if n := strings.Count(logs.String(), "failed"); n != 1 || !strings.Contains(logs.String(), "written again") {
		t.Errorf("a failing database is said once, and its recovery too:\n%s", logs.String())
	}
}

func TestUsesAreSafeToCountFromManyCalls(t *testing.T) {
	u := NewUses()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				u.Touch("a", t0.Add(time.Duration(i)*time.Millisecond), "r")
				if i%100 == 0 {
					u.Restore(u.Drain())
				}
			}
		}()
	}
	wg.Wait()
	if n := u.Pending()["a"].Uses; n != 8*500 {
		t.Errorf("counted %d, want %d", n, 8*500)
	}
}
