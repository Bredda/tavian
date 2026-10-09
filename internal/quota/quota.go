package quota

import (
	"sort"
	"sync"
	"time"
)

// Dimension is what a quota counts.
type Dimension string

const (
	RPM          Dimension = "rpm"            // requests in the last minute
	Concurrency  Dimension = "concurrency"    // requests being served
	TPM          Dimension = "tpm"            // tokens in the last minute
	TokensPerDay Dimension = "tokens_per_day" //nolint:gosec // a quota name, not a credential: tokens since midnight UTC
	BudgetEUR    Dimension = "budget_eur"     // money since the 1st of the month, UTC; limits are in micro-euros
)

// Amount is what a request asks for or used, in the units of the dimensions
// that count it: tokens for tpm and tokens_per_day, micro-euros for
// budget_eur.
type Amount struct{ Tokens, MicroEUR int64 }

// Tokens is an Amount of tokens only.
func Tokens(n int64) Amount { return Amount{Tokens: n} }

func (a Amount) of(d Dimension) int64 {
	if d == BudgetEUR {
		return a.MicroEUR
	}
	return a.Tokens
}

// Valid reports whether d is a dimension this version enforces.
func (d Dimension) Valid() bool {
	switch d {
	case RPM, Concurrency, TPM, TokensPerDay, BudgetEUR:
		return true
	}
	return false
}

// Window is the canonical spelling of the window of d in policy files: empty
// for a dimension without one.
func (d Dimension) Window() string {
	switch d {
	case RPM, TPM:
		return "1m"
	case TokensPerDay:
		return "1d"
	case BudgetEUR:
		return "month"
	}
	return ""
}

// atAdmission reports whether d is checked before the request is read (cheap
// counters), as opposed to reserved once the backend is known.
func (d Dimension) atAdmission() bool { return d == RPM || d == Concurrency }

// Scope says whose counter a limit applies to. It is comparable, so it keys
// the counters directly: their number is bounded by the configuration.
type Scope struct {
	Organization bool
	Team         string
	Application  string
}

// Kind names the scope for messages and metrics: organization, team,
// application or team_application.
func (s Scope) Kind() string {
	switch {
	case s.Organization:
		return "organization"
	case s.Team != "" && s.Application != "":
		return "team_application"
	case s.Team != "":
		return "team"
	}
	return "application"
}

// Matches reports whether usage by this team and application falls under the
// scope.
func (s Scope) Matches(team, application string) bool {
	if s.Organization {
		return true
	}
	return (s.Team == "" || s.Team == team) && (s.Application == "" || s.Application == application)
}

// Limit is one quota as a policy sets it.
type Limit struct {
	// Policy names the policy that sets the limit.
	Policy    string
	Scope     Scope
	Dimension Dimension
	Max       int64
	// Soft limits are counted and reported but never refuse. Shadow ones come
	// from a policy in shadow mode and behave the same way.
	Soft, Shadow bool
}

// Effect is what exceeding the limit does: refused, soft or shadow.
func (l Limit) Effect() string {
	switch {
	case l.Shadow:
		return "shadow"
	case l.Soft:
		return "soft"
	}
	return "refused"
}

func (l Limit) enforced() bool { return !l.Soft && !l.Shadow }

// Check is a limit that a request would exceed.
type Check struct {
	Limit Limit
	// Used is the count before the request, Requested what it asks for.
	Used, Requested int64
	// Never says that no amount of waiting helps: the request alone is more
	// than the limit.
	Never bool
	// Retry is how long until the request would fit; zero when it cannot be
	// told (Never) or does not apply.
	Retry time.Duration
}

// Result is the outcome of an admission or a reservation.
type Result struct {
	// Exceeded lists every limit the request would exceed, enforced or not.
	Exceeded []Check
	// Refused is true when an enforced limit is among them; nothing was
	// counted then.
	Refused bool
}

// Primary is the enforced check that explains a refusal: one that can never be
// met if there is one, else the one that takes longest to clear. Nil when the
// request was not refused.
func (r Result) Primary() *Check {
	var best *Check
	for i := range r.Exceeded {
		c := &r.Exceeded[i]
		if !c.Limit.enforced() {
			continue
		}
		if best == nil || (c.Never && !best.Never) || (c.Never == best.Never && c.Retry > best.Retry) {
			best = c
		}
	}
	return best
}

type counterKey struct {
	scope Scope
	dim   Dimension
}

const buckets = 60

// counter holds the state of one scope and dimension: a minute in one-second
// buckets, a day total, or the requests in flight.
type counter struct {
	sec [buckets]int64 // the second a bucket holds
	amt [buckets]int64
	day int64 // days since the epoch, UTC
	use int64 // used that day
	run int64 // in flight

	month int64 // calendar month, UTC (see monthOf)
	spent int64 // micro-euros that month
}

// monthOf numbers the calendar months, UTC.
func monthOf(t time.Time) int64 {
	t = t.UTC()
	return int64(t.Year())*12 + int64(t.Month()) - 1
}

func (c *counter) thisMonth(m int64) int64 {
	if c.month != m {
		c.month, c.spent = m, 0
	}
	return c.spent
}

func (c *counter) minute(now int64) int64 {
	var sum int64
	for i := range c.sec {
		if c.sec[i] > now-buckets && c.sec[i] <= now {
			sum += c.amt[i]
		}
	}
	return sum
}

func (c *counter) addMinute(now, n int64) {
	i := now % buckets
	if c.sec[i] != now {
		c.sec[i], c.amt[i] = now, 0
	}
	c.amt[i] = max(0, c.amt[i]+n)
}

func (c *counter) today(day int64) int64 {
	if c.day != day {
		c.day, c.use = day, 0
	}
	return c.use
}

// wait is how long until n of the minute's tokens have left the window.
func (c *counter) wait(now, n int64) time.Duration {
	type held struct{ sec, amt int64 }
	var live []held
	for i := range c.sec {
		if c.sec[i] > now-buckets && c.sec[i] <= now && c.amt[i] > 0 {
			live = append(live, held{c.sec[i], c.amt[i]})
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].sec < live[j].sec })
	var freed int64
	for _, h := range live {
		freed += h.amt
		if freed >= n {
			return time.Duration(max(1, h.sec+buckets-now)) * time.Second
		}
	}
	return 0
}

// Store counts in memory. The zero value is not usable; call NewStore.
type Store struct {
	mu       sync.Mutex
	now      func() time.Time
	counters map[counterKey]*counter
}

// NewStore returns an empty Store. now may be nil (time.Now); tests pass a
// fake clock.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, counters: map[counterKey]*counter{}}
}

func (s *Store) get(k counterKey) *counter {
	c := s.counters[k]
	if c == nil {
		c = &counter{}
		s.counters[k] = c
	}
	return c
}

// untilMidnight is the time left in the UTC day of t.
func untilMidnight(t time.Time) time.Duration {
	t = t.UTC()
	next := time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.UTC)
	return next.Sub(t)
}

// untilNextMonth is the time left in the UTC month of t.
func untilNextMonth(t time.Time) time.Duration {
	t = t.UTC()
	return time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC).Sub(t)
}

// check tests one limit against its counter for a request asking for n.
func (s *Store) check(l Limit, n int64, now time.Time) (Check, bool) {
	c := s.get(counterKey{l.Scope, l.Dimension})
	chk := Check{Limit: l, Requested: n}
	switch l.Dimension {
	case RPM, TPM:
		chk.Used = c.minute(now.Unix())
	case Concurrency:
		chk.Used = c.run
	case TokensPerDay:
		chk.Used = c.today(now.Unix() / 86400)
	case BudgetEUR:
		chk.Used = c.thisMonth(monthOf(now))
	}
	if chk.Used+n <= l.Max {
		return chk, false
	}
	if n > l.Max {
		chk.Never = true
		return chk, true
	}
	switch l.Dimension {
	case RPM, TPM:
		chk.Retry = c.wait(now.Unix(), chk.Used+n-l.Max)
	case Concurrency:
		chk.Retry = time.Second
	case TokensPerDay:
		chk.Retry = untilMidnight(now)
	case BudgetEUR:
		chk.Retry = untilNextMonth(now)
	}
	return chk, true
}

// SeedTokensPerDay sets the tokens already used today under scope, after a
// restart. A counter that exists is left alone (it has been counting since
// before): the call reports whether it set one.
func (s *Store) SeedTokensPerDay(scope Scope, tokens int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := counterKey{scope, TokensPerDay}
	if _, ok := s.counters[k]; ok {
		return false
	}
	c := s.get(k)
	c.day, c.use = s.now().Unix()/86400, max(0, tokens)
	return true
}

// SeedBudget is SeedTokensPerDay for the month's spending, in micro-euros.
func (s *Store) SeedBudget(scope Scope, microEUR int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := counterKey{scope, BudgetEUR}
	if _, ok := s.counters[k]; ok {
		return false
	}
	c := s.get(k)
	c.month, c.spent = monthOf(s.now()), max(0, microEUR)
	return true
}

// Slot is an admitted request: it holds a unit of concurrency until Release.
// A nil Slot is valid and does nothing.
type Slot struct {
	s    *Store
	keys []counterKey
	done bool
}

// Release gives the concurrency back. Calling it twice is harmless.
func (sl *Slot) Release() {
	if sl == nil {
		return
	}
	sl.s.mu.Lock()
	defer sl.s.mu.Unlock()
	if sl.done {
		return
	}
	sl.done = true
	for _, k := range sl.keys {
		c := sl.s.get(k)
		c.run = max(0, c.run-1)
	}
}

// Admit applies the limits that are checked before the request is read: rpm
// and concurrency. It counts the request against all of them or, when an
// enforced one is exceeded, against none (a refused request does not extend
// its own penalty). The Slot must be released when the request ends.
func (s *Store) Admit(limits []Limit) (*Slot, Result) {
	var mine []Limit
	for _, l := range limits {
		if l.Dimension.atAdmission() {
			mine = append(mine, l)
		}
	}
	if len(mine) == 0 {
		return nil, Result{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var res Result
	for _, l := range mine {
		if chk, over := s.check(l, 1, now); over {
			res.Exceeded = append(res.Exceeded, chk)
			res.Refused = res.Refused || l.enforced()
		}
	}
	if res.Refused {
		return nil, res
	}
	slot := &Slot{s: s}
	done := map[counterKey]bool{}
	for _, l := range mine {
		k := counterKey{l.Scope, l.Dimension}
		if done[k] { // two policies limiting the same counter count once
			continue
		}
		done[k] = true
		c := s.get(k)
		if l.Dimension == RPM {
			c.addMinute(now.Unix(), 1)
		} else {
			c.run++
			slot.keys = append(slot.keys, k)
		}
	}
	return slot, res
}

type held struct {
	key counterKey
	sec int64 // the second (or day) the reservation was counted in
	n   int64
}

// Reservation is tokens and money set aside for a request, to be settled with
// what it really used. A nil Reservation is valid and does nothing.
type Reservation struct {
	s      *Store
	amount Amount
	held   []held
	done   bool
}

// Tokens is the amount of tokens reserved.
func (r *Reservation) Tokens() int64 {
	if r == nil {
		return 0
	}
	return r.amount.Tokens
}

// MicroEUR is the money reserved.
func (r *Reservation) MicroEUR() int64 {
	if r == nil {
		return 0
	}
	return r.amount.MicroEUR
}

// Reserve applies the limits on tokens and money (tpm, tokens per day, budget)
// for a request that may use up to a. Like Admit it counts all of them or none.
func (s *Store) Reserve(limits []Limit, a Amount) (*Reservation, Result) {
	var mine []Limit
	for _, l := range limits {
		if !l.Dimension.atAdmission() {
			mine = append(mine, l)
		}
	}
	if len(mine) == 0 {
		return nil, Result{}
	}
	a = Amount{Tokens: max(0, a.Tokens), MicroEUR: max(0, a.MicroEUR)}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var res Result
	for _, l := range mine {
		if chk, over := s.check(l, a.of(l.Dimension), now); over {
			res.Exceeded = append(res.Exceeded, chk)
			res.Refused = res.Refused || l.enforced()
		}
	}
	if res.Refused {
		return nil, res
	}
	r := &Reservation{s: s, amount: a}
	done := map[counterKey]bool{}
	for _, l := range mine {
		k := counterKey{l.Scope, l.Dimension}
		if done[k] {
			continue
		}
		done[k] = true
		c := s.get(k)
		n := a.of(l.Dimension)
		switch l.Dimension {
		case TPM:
			c.addMinute(now.Unix(), n)
			r.held = append(r.held, held{k, now.Unix(), n})
		case BudgetEUR:
			m := monthOf(now)
			c.thisMonth(m)
			c.spent += n
			r.held = append(r.held, held{k, m, n})
		default:
			day := now.Unix() / 86400
			c.today(day)
			c.use += n
			r.held = append(r.held, held{k, day, n})
		}
	}
	return r, res
}

// Settle replaces the reservation with what was really used. It may push a
// counter past its limit: what has been produced is owed, and the next
// requests are refused until the window clears. Only the first call counts, so
// a retry or a crash path cannot count twice.
func (r *Reservation) Settle(actual Amount) {
	if r == nil {
		return
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if r.done {
		return
	}
	r.done = true
	now := r.s.now()
	for _, h := range r.held {
		c := r.s.get(h.key)
		used := max(0, actual.of(h.key.dim))
		switch h.key.dim {
		case TPM:
			if h.sec > now.Unix()-buckets && c.sec[h.sec%buckets] == h.sec {
				c.addMinute(h.sec, used-h.n)
			} else { // the reservation left the window: what was used counts now
				c.addMinute(now.Unix(), used)
			}
		case BudgetEUR:
			c.thisMonth(monthOf(now))
			if h.sec == monthOf(now) {
				c.spent = max(0, c.spent+used-h.n)
			} else { // the month changed since the reservation: what was used counts now
				c.spent += used
			}
		default:
			day := now.Unix() / 86400
			c.today(day)
			if h.sec == day {
				c.use = max(0, c.use+used-h.n)
			} else { // the day changed since the reservation: what was used counts now
				c.use += used
			}
		}
	}
}

// Estimate is the tokens to reserve for a request: its size, conservatively
// (a token is rarely fewer than three bytes, even for CJK text), plus the most
// the answer may be.
func Estimate(requestBytes int, maxOutput int64) int64 {
	const ceiling = 1 << 40 // a client-supplied max_tokens must not overflow the sum
	return int64(requestBytes)/3 + 1 + min(max(0, maxOutput), ceiling)
}
