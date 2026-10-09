package chain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/outbox"
	"github.com/bredda/tavian/internal/store"
	"github.com/bredda/tavian/internal/store/storetest"
)

// These tests need a PostgreSQL: see internal/store/storetest.

type env struct {
	t      *testing.T
	st     *store.Store
	runner *outbox.Runner
	sealer *Sealer
	pub    ed25519.PublicKey
	now    atomic.Int64 // unix nanoseconds of the sealer's clock
}

func newEnv(t *testing.T, withKey bool) *env {
	t.Helper()
	st, _ := storetest.New(t)
	e := &env{t: t, st: st}
	e.now.Store(time.Now().UnixNano())
	e.sealer = &Sealer{SealEveryEvents: 5, SealEvery: time.Hour, Now: func() time.Time { return time.Unix(0, e.now.Load()).UTC() }}
	if withKey {
		path := filepath.Join(t.TempDir(), "k")
		pub, err := GenerateKeyFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if e.sealer.Signer, err = LoadSigner(path); err != nil {
			t.Fatal(err)
		}
		e.pub = pub
	}
	e.runner = &outbox.Runner{Pool: st.Pool(), Log: slog.New(slog.DiscardHandler), BatchSize: 100}
	e.runner.Add(e.sealer)
	if err := e.runner.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) advance(d time.Duration) { e.now.Add(int64(d)) }

func (e *env) decisions(n int, prefix string) []string {
	e.t.Helper()
	var rows []store.OutboxRow
	var ids []string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%s-%d", prefix, i)
		ids = append(ids, id)
		payload, _ := json.Marshal(map[string]any{"decision_id": id, "outcome": "served", "n": i, "label": "internal"})
		rows = append(rows, store.OutboxRow{EventID: id, Kind: "decision", OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Payload: payload})
	}
	if err := e.st.InsertOutbox(context.Background(), rows); err != nil {
		e.t.Fatal(err)
	}
	return ids
}

// chained runs the sealer until the chain holds n entries.
func (e *env) chained(n int64) {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		cy, _ := e.runner.Step(context.Background(), e.sealer)
		if cy.Err != nil {
			e.t.Fatal(cy.Err)
		}
		var have int64
		if err := e.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_chain`).Scan(&have); err != nil {
			e.t.Fatal(err)
		}
		if have >= n && cy.Pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("chain has %d entries, want %d", have, n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (e *env) verify(opt Options) *Report {
	e.t.Helper()
	if e.pub != nil && opt.PublicKeys == nil {
		opt.PublicKeys = []ed25519.PublicKey{e.pub}
	}
	rep, err := Verify(context.Background(), e.st.Pool(), opt)
	if err != nil {
		e.t.Fatal(err)
	}
	return rep
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.st.Pool().Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatal(err)
	}
}

// twoSeals chains 12 records with a seal over entries 1 to 7 and one over 8 to 12.
func (e *env) twoSeals() {
	e.t.Helper()
	e.decisions(7, "d")
	e.chained(7)
	more := make([]string, 0, 5)
	for i := 7; i < 12; i++ {
		more = append(more, fmt.Sprintf("d-%d", i))
	}
	var rows []store.OutboxRow
	for _, id := range more {
		payload, _ := json.Marshal(map[string]any{"decision_id": id, "outcome": "served", "label": "internal"})
		rows = append(rows, store.OutboxRow{EventID: id, Kind: "decision", OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Payload: payload})
	}
	if err := e.st.InsertOutbox(context.Background(), rows); err != nil {
		e.t.Fatal(err)
	}
	e.chained(12)
}

func problems(r *Report) string {
	var out []string
	for _, p := range r.Problems {
		out = append(out, p.String())
	}
	return strings.Join(out, "; ")
}

func TestTheChainLinksEveryDecisionRecord(t *testing.T) {
	e := newEnv(t, false)
	ids := e.decisions(10, "d")
	e.chained(10)

	rs, err := e.st.Pool().Query(context.Background(), `SELECT position, event_id, prev_hash, entry_hash FROM audit_chain ORDER BY position`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	prev := Genesis()
	seen := map[string]bool{}
	var n int64
	for rs.Next() {
		var (
			pos      int64
			id       string
			ph, hash []byte
		)
		if err := rs.Scan(&pos, &id, &ph, &hash); err != nil {
			t.Fatal(err)
		}
		n++
		if pos != n || !bytes.Equal(ph, prev) {
			t.Fatalf("entry %d: position/link wrong", pos)
		}
		prev = hash
		seen[id] = true
	}
	for _, id := range ids {
		if !seen[id] {
			t.Errorf("%s is not in the chain", id)
		}
	}
	if rep := e.verify(Options{}); !rep.OK() || rep.Entries != 10 {
		t.Fatalf("a fresh chain does not verify: %s (%d entries)", problems(rep), rep.Entries)
	}
}

func TestOnlyDecisionRecordsAreChained(t *testing.T) {
	e := newEnv(t, false)
	if err := e.st.InsertOutbox(context.Background(), []store.OutboxRow{
		{EventID: "u1", Kind: "usage", OccurredAt: time.Now(), Payload: []byte(`{"event_id":"u1"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	e.decisions(2, "d")
	e.chained(2)
	var n int
	_ = e.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_chain WHERE event_id = 'u1'`).Scan(&n)
	if n != 0 {
		t.Fatal("a usage event was chained")
	}
}

func TestTheChainContinuesAcrossBatchesAndRestarts(t *testing.T) {
	e := newEnv(t, false)
	e.decisions(6, "a")
	e.chained(6)
	// a new sealer, as after a restart
	again := &Sealer{}
	e.runner = &outbox.Runner{Pool: e.st.Pool(), Log: slog.New(slog.DiscardHandler), BatchSize: 4}
	e.runner.Add(again)
	e.sealer = again
	e.decisions(5, "b")
	e.chained(11)
	if rep := e.verify(Options{}); !rep.OK() || rep.Entries != 11 {
		t.Fatalf("%s (%d entries)", problems(rep), rep.Entries)
	}
}

func TestADecisionRecordIsChainedOnce(t *testing.T) {
	e := newEnv(t, false)
	e.decisions(3, "d")
	e.chained(3)
	e.exec(`UPDATE outbox_consumers SET last_xid = 0, last_seq = 0`) // the cursor is lost
	e.chained(3)
	var n int
	_ = e.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_chain`).Scan(&n)
	if n != 3 {
		t.Fatalf("%d entries after the sealer re-read the outbox, want 3", n)
	}
	if rep := e.verify(Options{}); !rep.OK() {
		t.Fatal(problems(rep))
	}
}

// Writers commit in any order, and the chain still holds every record exactly
// once, whichever order they come in.
func TestConcurrentWritersAndASealerLoseNothing(t *testing.T) {
	e := newEnv(t, true)
	e.sealer.SealEveryEvents = 7
	ctx, cancel := context.WithCancel(context.Background())
	e.runner.PollEvery = 2 * time.Millisecond
	done := make(chan struct{})
	go func() { e.runner.Run(ctx); close(done) }()

	const writers, each = 6, 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				e.decisions(1, fmt.Sprintf("w%d-%d", w, i))
				if i%5 == 0 { // a multi-row transaction, like a spool replay
					e.decisions(3, fmt.Sprintf("batch%d-%d", w, i))
				}
			}
		}()
	}
	wg.Wait()
	var total int64
	if err := e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE kind = 'decision'`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		var have int64
		_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_chain`).Scan(&have)
		if have == total {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("chain has %d of %d records", have, total)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	rep := e.verify(Options{})
	if !rep.OK() || rep.Entries != total {
		t.Fatalf("%s (%d of %d entries)", problems(rep), rep.Entries, total)
	}
}

func TestSealsAreMadeWhenDue(t *testing.T) {
	e := newEnv(t, true)
	e.decisions(4, "a")
	e.chained(4)
	if rep := e.verify(Options{}); rep.Seals != 0 || rep.Unsealed != 4 {
		t.Fatalf("a seal was made too early: %+v", rep)
	}
	e.decisions(3, "b") // 7 unsealed >= 5
	e.chained(7)
	rep := e.verify(Options{})
	if rep.Seals != 1 || rep.Unsealed != 0 || !rep.SignaturesChecked || !rep.OK() {
		t.Fatalf("after the threshold: %+v %s", rep, problems(rep))
	}
	// time: one record, an hour later
	e.decisions(1, "c")
	e.chained(8)
	if e.verify(Options{}).Seals != 1 {
		t.Fatal("sealed a single new entry at once")
	}
	e.advance(61 * time.Minute)
	e.chained(8)
	if rep := e.verify(Options{}); rep.Seals != 2 || rep.Unsealed != 0 {
		t.Fatalf("the old unsealed entry was not sealed: %+v", rep)
	}
	if st := e.sealer.Stats(); st.Entries != 8 || st.Unsealed != 0 || st.LastSeal.IsZero() {
		t.Fatalf("stats = %+v", st)
	}
	seals, _ := Seals(context.Background(), e.st.Pool())
	if seals[0].FirstPosition != 1 || seals[0].LastPosition != 7 || seals[1].FirstPosition != 8 || seals[1].LastPosition != 8 {
		t.Fatalf("seals do not tile the chain: %+v", seals)
	}
}

func TestWithoutAKeyThereAreNoSealsAndTheReportSaysSo(t *testing.T) {
	e := newEnv(t, false)
	e.decisions(12, "a")
	e.chained(12)
	rep := e.verify(Options{})
	if rep.Seals != 0 || !rep.OK() || len(rep.Warnings) < 2 {
		t.Fatalf("%+v", rep)
	}
	joined := strings.Join(rep.Warnings, "|")
	if !strings.Contains(joined, "no seals") || !strings.Contains(joined, "signatures were not checked") {
		t.Errorf("warnings = %v", rep.Warnings)
	}
}

// Everything an administrator with write access to the database could try.
func TestVerifyFindsTampering(t *testing.T) {
	for name, tc := range map[string]struct {
		tamper func(e *env)
		want   string // part of a problem
	}{
		"payload edited": {
			func(e *env) {
				e.exec(`UPDATE outbox SET payload = jsonb_set(payload, '{outcome}', '"refused"') WHERE event_id = 'd-3'`)
			},
			"does not match its hash",
		},
		"payload removed": {
			func(e *env) { e.exec(`DELETE FROM outbox WHERE event_id = 'd-3'`) },
			"no longer in the outbox",
		},
		"outbox time edited": {
			func(e *env) {
				e.exec(`UPDATE outbox SET occurred_at = occurred_at + interval '1 hour' WHERE event_id = 'd-3'`)
			},
			"time of the outbox row differs",
		},
		"entry hash edited": {
			func(e *env) { e.exec(`UPDATE audit_chain SET entry_hash = content_hash WHERE position = 4`) },
			"entry was altered",
		},
		"content hash edited": {
			func(e *env) { e.exec(`UPDATE audit_chain SET content_hash = prev_hash WHERE position = 4`) },
			"entry was altered",
		},
		"entry removed from the middle": {
			func(e *env) { e.exec(`DELETE FROM audit_chain WHERE position = 4`) },
			"entries are missing",
		},
		"entries removed from the end": {
			func(e *env) { e.exec(`DELETE FROM audit_chain WHERE position > 8`) },
			"entries were removed",
		},
		"entries swapped": {
			func(e *env) {
				e.exec(`UPDATE audit_chain SET position = 0 WHERE position = 4`)
				e.exec(`UPDATE audit_chain SET position = 4 WHERE position = 5`)
				e.exec(`UPDATE audit_chain SET position = 5 WHERE position = 0`)
			},
			"does not link",
		},
		"record not chained": {
			func(e *env) {
				e.exec(`INSERT INTO outbox (event_id, kind, occurred_at, payload, xid) VALUES ('sneaky', 'decision', now(), '{}', '1')`)
			},
			"is not in the chain",
		},
		"seal removed": {
			func(e *env) { e.exec(`DELETE FROM audit_seals WHERE id = 1`) },
			"numbered",
		},
		"seal edited": {
			func(e *env) {
				e.exec(`UPDATE audit_seals SET last_entry_hash = decode(repeat('00', 32), 'hex') WHERE id = 1`)
			},
			"signature does not verify",
		},
		"chain rewritten without the key": {
			// the attacker recomputes the whole chain after changing a record,
			// but cannot sign: the seal no longer matches
			func(e *env) { rewriteChainFrom(e, 3) },
			"rewritten",
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, true)
			e.twoSeals()
			if rep := e.verify(Options{}); !rep.OK() || rep.Seals != 2 {
				t.Fatalf("setup: %s (%d seals)", problems(rep), rep.Seals)
			}
			tc.tamper(e)
			rep := e.verify(Options{})
			if rep.OK() {
				t.Fatal("tampering went unnoticed")
			}
			if !strings.Contains(problems(rep), tc.want) {
				t.Fatalf("problems = %s, want one mentioning %q", problems(rep), tc.want)
			}
		})
	}
}

// rewriteChainFrom changes the record at position pos and recomputes every
// hash after it, as someone who cannot sign but can compute would.
func rewriteChainFrom(e *env, pos int64) {
	e.t.Helper()
	ctx := context.Background()
	e.exec(`UPDATE outbox SET payload = jsonb_set(payload, '{outcome}', '"refused"') WHERE event_id = (SELECT event_id FROM audit_chain WHERE position = $1)`, pos)
	rs, err := e.st.Pool().Query(ctx, `SELECT c.position, c.event_id, c.occurred_at, o.payload::text FROM audit_chain c JOIN outbox o USING (event_id) WHERE c.position >= $1 ORDER BY c.position`, pos)
	if err != nil {
		e.t.Fatal(err)
	}
	type row struct {
		pos     int64
		id      string
		at      time.Time
		payload string
	}
	var all []row
	for rs.Next() {
		var r row
		if err := rs.Scan(&r.pos, &r.id, &r.at, &r.payload); err != nil {
			e.t.Fatal(err)
		}
		all = append(all, r)
	}
	rs.Close()
	var prev []byte
	if err := e.st.Pool().QueryRow(ctx, `SELECT entry_hash FROM audit_chain WHERE position = $1`, pos-1).Scan(&prev); err != nil {
		e.t.Fatal(err)
	}
	for _, r := range all {
		content, _ := ContentHash([]byte(r.payload))
		hash := EntryHash(r.pos, prev, r.id, r.at, content)
		e.exec(`UPDATE audit_chain SET content_hash = $2, prev_hash = $3, entry_hash = $4 WHERE position = $1`, r.pos, content, prev, hash)
		prev = hash
	}
}

func TestAnchorsDetectWhatTheDatabaseAloneCannot(t *testing.T) {
	e := newEnv(t, true)
	e.twoSeals()
	anchors, err := Seals(context.Background(), e.st.Pool())
	if err != nil || len(anchors) != 2 {
		t.Fatalf("%v %d", err, len(anchors))
	}
	if rep := e.verify(Options{Anchors: anchors}); !rep.OK() {
		t.Fatal(problems(rep))
	}

	// the newest seal and its entries are removed together: the database is
	// consistent with itself, only the anchor knows
	e.exec(`DELETE FROM audit_seals WHERE id = 2`)
	e.exec(`DELETE FROM audit_chain WHERE position > 7`)
	e.exec(`DELETE FROM outbox WHERE event_id IN ('d-7','d-8','d-9','d-10','d-11')`)
	if rep := e.verify(Options{}); !rep.OK() {
		t.Fatalf("setup: the truncated database should look consistent on its own: %s", problems(rep))
	}
	rep := e.verify(Options{Anchors: anchors})
	if rep.OK() || !strings.Contains(problems(rep), "gone from it") {
		t.Fatalf("truncation went unnoticed: %s", problems(rep))
	}
}

func TestAnchorsDetectAChangedSeal(t *testing.T) {
	e := newEnv(t, true)
	e.decisions(6, "d")
	e.chained(6)
	anchors, _ := Seals(context.Background(), e.st.Pool())
	forged := anchors[0]
	forged.Signature = append([]byte{0}, forged.Signature[1:]...)
	rep := e.verify(Options{Anchors: []Seal{forged}})
	if rep.OK() {
		t.Fatal("a forged anchor was accepted")
	}
}

func TestSignaturesNeedTheRightKey(t *testing.T) {
	e := newEnv(t, true)
	e.decisions(6, "d")
	e.chained(6)
	other, _, _ := ed25519.GenerateKey(nil)
	rep := e.verify(Options{PublicKeys: []ed25519.PublicKey{other}})
	if rep.OK() || !strings.Contains(problems(rep), "which was not given") {
		t.Fatalf("a seal verified with another key: %s", problems(rep))
	}
	// the old key and the new one may both be given after a rotation
	if rep := e.verify(Options{PublicKeys: []ed25519.PublicKey{other, e.pub}}); !rep.OK() {
		t.Fatal(problems(rep))
	}
}

func TestVerifyFromASeal(t *testing.T) {
	e := newEnv(t, true)
	e.twoSeals()
	// entries before the seal are not looked at: damage there is outside the walk
	e.exec(`UPDATE audit_chain SET entry_hash = content_hash WHERE position = 2`)
	if rep := e.verify(Options{}); rep.OK() {
		t.Fatal("setup: the damage should show from the start")
	}
	rep := e.verify(Options{FromSeal: 1})
	if !rep.OK() || rep.Entries != 5 {
		t.Fatalf("from seal 1: %s (%d entries)", problems(rep), rep.Entries)
	}
	e.exec(`UPDATE audit_chain SET entry_hash = content_hash WHERE position = 9`)
	if e.verify(Options{FromSeal: 1}).OK() {
		t.Fatal("damage after the seal went unnoticed")
	}
	if _, err := Verify(context.Background(), e.st.Pool(), Options{FromSeal: 1}); err == nil {
		t.Error("starting from a seal without a key was allowed")
	}
	if _, err := Verify(context.Background(), e.st.Pool(), Options{FromSeal: 9, PublicKeys: []ed25519.PublicKey{e.pub}}); err == nil {
		t.Error("starting from a seal that does not exist was allowed")
	}
}

func TestPrunedRecordsAreAcceptedOnlyWhenAsked(t *testing.T) {
	e := newEnv(t, true)
	e.twoSeals()
	e.exec(`DELETE FROM outbox WHERE event_id IN ('d-0','d-1','d-2')`) // sealed entries
	if e.verify(Options{}).OK() {
		t.Fatal("missing records are a problem by default")
	}
	rep := e.verify(Options{AllowPruned: true})
	if !rep.OK() || rep.Pruned != 3 {
		t.Fatalf("%s (%d pruned)", problems(rep), rep.Pruned)
	}
	e.decisions(1, "late") // unsealed
	e.chained(13)
	e.exec(`DELETE FROM outbox WHERE event_id = 'late-0'`)
	if e.verify(Options{AllowPruned: true}).OK() {
		t.Fatal("a missing record not covered by a seal was accepted")
	}
}

func TestPendingRecordsAreNotAProblem(t *testing.T) {
	e := newEnv(t, false)
	e.decisions(3, "a")
	e.chained(3)
	e.decisions(2, "b") // not chained yet
	var final int
	for i := 0; i < 500 && final < 5; i++ {
		_ = e.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE xid < pg_snapshot_xmin(pg_current_snapshot())`).Scan(&final)
		time.Sleep(2 * time.Millisecond)
	}
	rep := e.verify(Options{})
	if !rep.OK() || rep.Pending != 2 {
		t.Fatalf("%s (pending %d)", problems(rep), rep.Pending)
	}
}

// A seal changed in the database is caught by its exported copy even when no
// key is at hand to check signatures.
func TestAnchorsDetectASealChangedInTheDatabase(t *testing.T) {
	e := newEnv(t, true)
	e.decisions(6, "d")
	e.chained(6)
	anchors, _ := Seals(context.Background(), e.st.Pool())
	e.exec(`UPDATE audit_seals SET sealed_at = sealed_at + interval '1 day' WHERE id = 1`)
	rep, err := Verify(context.Background(), e.st.Pool(), Options{Anchors: anchors}) // no keys
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || !strings.Contains(problems(rep), "differs from the copy") {
		t.Fatalf("problems = %s", problems(rep))
	}
}
