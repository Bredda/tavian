package quota

import (
	"sync"
	"time"
)

// maxCoalesced bounds the memory of a Coalescer. Past it a refusal is always
// recorded: losing an audit record is worse than writing one more.
const maxCoalesced = 10000

type coalesceKey struct {
	scope  Scope
	dim    Dimension
	caller string
}

type coalesceEntry struct {
	at         time.Time
	suppressed int64
}

// Coalescer keeps a caller who hammers a limit from filling the audit trail:
// refusals are counted in metrics one by one, but recorded at most once per
// second for each caller and limit, with the number it stands for. Without it
// a single client over its rpm would write a record per request until the
// spool is full, and the gateway would then refuse everyone (ADR-0005).
type Coalescer struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[coalesceKey]*coalesceEntry
}

// NewCoalescer returns a Coalescer; now may be nil (time.Now).
func NewCoalescer(now func() time.Time) *Coalescer {
	if now == nil {
		now = time.Now
	}
	return &Coalescer{now: now, entries: map[coalesceKey]*coalesceEntry{}}
}

// Allow says whether this refusal is to be recorded. When it is, suppressed is
// the number of refusals since the last record that were not (best effort:
// they are lost if the caller stops for good, the metric stays exact).
func (c *Coalescer) Allow(scope Scope, dim Dimension, caller string) (record bool, suppressed int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	k := coalesceKey{scope, dim, caller}
	e := c.entries[k]
	if e == nil {
		if len(c.entries) >= maxCoalesced {
			c.sweep(now)
		}
		if len(c.entries) >= maxCoalesced {
			return true, 0
		}
		c.entries[k] = &coalesceEntry{at: now}
		return true, 0
	}
	if now.Sub(e.at) >= time.Second {
		suppressed = e.suppressed
		e.at, e.suppressed = now, 0
		return true, suppressed
	}
	e.suppressed++
	return false, 0
}

// sweep forgets callers who were last refused more than a second ago.
func (c *Coalescer) sweep(now time.Time) {
	for k, e := range c.entries {
		if now.Sub(e.at) >= time.Second {
			delete(c.entries, k)
		}
	}
}
