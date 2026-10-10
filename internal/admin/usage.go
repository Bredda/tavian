package admin

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/bredda/tavian/internal/store"
)

// Uses counts the use of the administration tokens in memory. Calling Touch
// costs a lock and no I/O: what has accumulated is written to the database in
// one statement every few seconds by Run, never once per request.
type Uses struct {
	mu      sync.Mutex
	pending map[string]*store.TokenUse
}

// NewUses returns an empty counter.
func NewUses() *Uses { return &Uses{pending: map[string]*store.TokenUse{}} }

// Touch notes that the token used the API at now, from remote.
func (u *Uses) Touch(id string, now time.Time, remote string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	e := u.pending[id]
	if e == nil {
		e = &store.TokenUse{TokenID: id}
		u.pending[id] = e
	}
	e.Uses++
	if !now.Before(e.LastUsedAt) {
		e.LastUsedAt, e.LastRemote = now, remote
	}
}

// Drain returns what has accumulated since the last time and starts again from
// nothing.
func (u *Uses) Drain() []store.TokenUse {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]store.TokenUse, 0, len(u.pending))
	for _, e := range u.pending {
		out = append(out, *e)
	}
	clear(u.pending)
	sort.Slice(out, func(i, j int) bool { return out[i].TokenID < out[j].TokenID })
	return out
}

// Restore puts back what Drain returned and could not be written.
func (u *Uses) Restore(items []store.TokenUse) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, it := range items {
		e := u.pending[it.TokenID]
		if e == nil {
			c := it
			u.pending[it.TokenID] = &c
			continue
		}
		e.Uses += it.Uses
		if it.LastUsedAt.After(e.LastUsedAt) {
			e.LastUsedAt, e.LastRemote = it.LastUsedAt, it.LastRemote
		}
	}
}

// Pending is what has not been written yet, without taking it.
func (u *Uses) Pending() map[string]store.TokenUse {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make(map[string]store.TokenUse, len(u.pending))
	for id, e := range u.pending {
		out[id] = *e
	}
	return out
}

// Flusher writes the use of the tokens.
type Flusher interface {
	AddTokenUse(ctx context.Context, uses []store.TokenUse) error
}

// Flush writes what has accumulated; if that fails it is kept for the next
// time.
func (u *Uses) Flush(ctx context.Context, to Flusher) error {
	items := u.Drain()
	if len(items) == 0 {
		return nil
	}
	if err := to.AddTokenUse(ctx, items); err != nil {
		u.Restore(items)
		return err
	}
	return nil
}

// Run flushes every interval until ctx is done, then once more so that
// nothing is lost at a clean shutdown.
func (u *Uses) Run(ctx context.Context, to Flusher, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	failing := false
	flush := func(c context.Context) {
		fctx, cancel := context.WithTimeout(c, 10*time.Second)
		defer cancel()
		switch err := u.Flush(fctx, to); {
		case err != nil && !failing:
			failing = true
			log.Error("writing the use of the admin tokens failed, trying again at the next interval", "error", err)
		case err == nil && failing:
			failing = false
			log.Info("the use of the admin tokens is written again")
		}
	}
	for {
		select {
		case <-ctx.Done():
			flush(context.Background())
			return
		case <-t.C:
			flush(ctx)
		}
	}
}
