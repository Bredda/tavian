package chain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options say what Verify checks against.
type Options struct {
	// PublicKeys verify the signatures of seals; a seal is checked against the
	// key with its key id. Without any, signatures are not checked and the
	// report says so.
	PublicKeys []ed25519.PublicKey
	// Anchors are seals kept outside the database. Each must still be there,
	// unchanged.
	Anchors []Seal
	// FromSeal starts the walk after the seal with this id (checked with its
	// signature), instead of from the first entry. 0 means from the start.
	FromSeal int64
	// AllowPruned accepts entries whose record is no longer in the outbox when
	// a signed seal covers them. By default a missing record is a problem: the
	// outbox is not pruned yet.
	AllowPruned bool
}

// Problem is something the verification found wrong.
type Problem struct {
	// Position is the chain position concerned, 0 if none.
	Position int64
	EventID  string
	What     string
}

func (p Problem) String() string {
	switch {
	case p.Position > 0 && p.EventID != "":
		return fmt.Sprintf("entry %d (event %s): %s", p.Position, p.EventID, p.What)
	case p.Position > 0:
		return fmt.Sprintf("entry %d: %s", p.Position, p.What)
	}
	return p.What
}

// Report is the outcome of Verify.
type Report struct {
	// Entries is how many chain entries were walked, and Seals how many seals
	// exist.
	Entries, Seals int64
	// SignaturesChecked is true when seals were checked against a public key.
	SignaturesChecked bool
	// Unsealed counts entries after the last seal: not covered by a signature.
	Unsealed int64
	// Pending counts decision records the sealer has not chained yet (normal
	// for the last few seconds).
	Pending int64
	// Pruned counts entries whose record is gone from the outbox, accepted
	// under AllowPruned.
	Pruned   int64
	Problems []Problem
	Warnings []string
}

// OK reports whether nothing was found wrong.
func (r *Report) OK() bool { return len(r.Problems) == 0 }

const (
	pageSize    = 1000
	maxProblems = 50
)

func (r *Report) problem(pos int64, id, format string, args ...any) {
	if len(r.Problems) == maxProblems {
		r.Warnings = append(r.Warnings, fmt.Sprintf("more than %d problems: the report stops here", maxProblems))
	}
	if len(r.Problems) >= maxProblems {
		return
	}
	r.Problems = append(r.Problems, Problem{Position: pos, EventID: id, What: fmt.Sprintf(format, args...)})
}

// Seals reads every seal, in order.
func Seals(ctx context.Context, pool *pgxpool.Pool) ([]Seal, error) {
	rs, err := pool.Query(ctx, `SELECT id, first_position, last_position, last_entry_hash, sealed_at, key_id, signature FROM audit_seals ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("read seals: %w", err)
	}
	defer rs.Close()
	var out []Seal
	for rs.Next() {
		var s Seal
		if err := rs.Scan(&s.ID, &s.FirstPosition, &s.LastPosition, &s.LastEntryHash, &s.SealedAt, &s.KeyID, &s.Signature); err != nil {
			return nil, fmt.Errorf("read seals: %w", err)
		}
		s.SealedAt = s.SealedAt.UTC()
		out = append(out, s)
	}
	return out, rs.Err()
}

// Verify checks the chain, the records it covers, the seals and the anchors.
// It only reads. An error means the check itself could not run; what it found
// is in the Report.
func Verify(ctx context.Context, pool *pgxpool.Pool, opt Options) (*Report, error) {
	rep := &Report{}
	seals, err := Seals(ctx, pool)
	if err != nil {
		return nil, err
	}
	rep.Seals = int64(len(seals))
	byKey := map[string]ed25519.PublicKey{}
	for _, k := range opt.PublicKeys {
		byKey[KeyID(k)] = k
	}
	rep.SignaturesChecked = len(byKey) > 0

	signed := checkSeals(rep, seals, byKey)

	start, prev := int64(1), Genesis()
	if opt.FromSeal > 0 {
		var from *Seal
		for i := range seals {
			if seals[i].ID == opt.FromSeal {
				from = &seals[i]
			}
		}
		switch {
		case from == nil:
			return nil, fmt.Errorf("there is no seal %d", opt.FromSeal)
		case !rep.SignaturesChecked:
			return nil, errors.New("starting from a seal needs the public key: the seal is the trust anchor")
		case !signed[from.ID]:
			return nil, fmt.Errorf("seal %d does not verify: it cannot be a starting point", from.ID)
		}
		start, prev = from.LastPosition+1, from.LastEntryHash
	}

	lastSealed := int64(0)
	sealAt := map[int64]Seal{}
	for _, s := range seals {
		if s.LastPosition > lastSealed {
			lastSealed = s.LastPosition
		}
		sealAt[s.LastPosition] = s
	}
	if err := walk(ctx, pool, rep, opt, start, prev, lastSealed, sealAt); err != nil {
		return nil, err
	}
	if err := completeness(ctx, pool, rep); err != nil {
		return nil, err
	}
	if err := checkRetention(ctx, pool, rep, opt); err != nil {
		return nil, err
	}
	checkAnchors(rep, opt, seals, byKey)
	if !rep.SignaturesChecked {
		rep.Warnings = append(rep.Warnings, "seal signatures were not checked (no public key given): the chain is checked against itself only")
	}
	if len(seals) == 0 {
		rep.Warnings = append(rep.Warnings, "there are no seals yet: nothing anchors the chain (seals need audit.signing_key_file and are made every audit.seal_every_events entries or audit.seal_every)")
	}
	return rep, nil
}

// checkSeals checks the numbering of seals and, with keys, their signatures.
// It returns the ids of the seals whose signature verified.
func checkSeals(rep *Report, seals []Seal, keys map[string]ed25519.PublicKey) map[int64]bool {
	signed := map[int64]bool{}
	for i, s := range seals {
		wantID, wantFirst := int64(1), int64(1)
		if i > 0 {
			wantID, wantFirst = seals[i-1].ID+1, seals[i-1].LastPosition+1
		}
		if s.ID != wantID {
			rep.problem(0, "", "seals are numbered %d then %d: a seal is missing", wantID-1, s.ID)
		}
		if s.FirstPosition != wantFirst || s.LastPosition < s.FirstPosition {
			rep.problem(0, "", "seal %d covers entries %d to %d, expected it to start at %d", s.ID, s.FirstPosition, s.LastPosition, wantFirst)
		}
		if len(keys) == 0 {
			continue
		}
		pub, ok := keys[s.KeyID]
		if !ok {
			rep.problem(0, "", "seal %d is signed with key %s, which was not given", s.ID, s.KeyID)
			continue
		}
		if err := VerifySeal(pub, s); err != nil {
			rep.problem(0, "", "seal %d: %v", s.ID, err)
			continue
		}
		signed[s.ID] = true
	}
	return signed
}

func walk(ctx context.Context, pool *pgxpool.Pool, rep *Report, opt Options, start int64, prev []byte, lastSealed int64, sealAt map[int64]Seal) error {
	next := start
	after := start - 1
	var lastPos int64
	for {
		rs, err := pool.Query(ctx, `
SELECT c.position, c.event_id, c.occurred_at, c.content_hash, c.prev_hash, c.entry_hash,
       o.kind, o.occurred_at, o.payload::text
FROM audit_chain c LEFT JOIN outbox o ON o.event_id = c.event_id
WHERE c.position > $1 ORDER BY c.position LIMIT $2`, after, pageSize)
		if err != nil {
			return fmt.Errorf("read chain: %w", err)
		}
		n := 0
		for rs.Next() {
			n++
			var (
				pos                  int64
				id                   string
				at                   time.Time
				content, prevH, hash []byte
				kind                 *string
				oat                  *time.Time
				payload              *string
			)
			if err := rs.Scan(&pos, &id, &at, &content, &prevH, &hash, &kind, &oat, &payload); err != nil {
				rs.Close()
				return fmt.Errorf("read chain: %w", err)
			}
			after, lastPos = pos, pos
			rep.Entries++
			if pos != next {
				rep.problem(pos, id, "expected entry %d: %d entries are missing before it", next, pos-next)
			}
			next = pos + 1
			if !bytes.Equal(prevH, prev) {
				rep.problem(pos, id, "does not link to the entry before it")
			}
			if want := EntryHash(pos, prevH, id, at, content); !bytes.Equal(want, hash) {
				rep.problem(pos, id, "the entry hash does not match its content: the entry was altered")
			}
			// continue from what is stored, so that one break is reported once
			prev = hash

			if s, ok := sealAt[pos]; ok && !bytes.Equal(s.LastEntryHash, hash) {
				rep.problem(pos, id, "seal %d says this entry's hash is different: the chain was rewritten", s.ID)
			}

			switch payload {
			case nil:
				if opt.AllowPruned && pos <= lastSealed {
					rep.Pruned++
				} else {
					rep.problem(pos, id, "the record is no longer in the outbox")
				}
			default:
				if got, err := ContentHash([]byte(*payload)); err != nil || !bytes.Equal(got, content) {
					rep.problem(pos, id, "the record in the outbox does not match its hash: it was altered")
				}
				if *kind != KindDecision {
					rep.problem(pos, id, "the outbox row is of kind %q, not a decision record", *kind)
				}
				if oat != nil && oat.UnixMicro() != at.UnixMicro() {
					rep.problem(pos, id, "the time of the outbox row differs from the chained one")
				}
			}
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return fmt.Errorf("read chain: %w", err)
		}
		if n < pageSize {
			break
		}
	}
	// the chain must reach every seal
	for pos, s := range sealAt {
		if pos > lastPos && pos >= start {
			rep.problem(pos, "", "seal %d covers entries up to %d, but the chain stops at %d: entries were removed", s.ID, pos, lastPos)
		}
	}
	if lastSealed > 0 {
		rep.Unsealed = max(0, lastPos-lastSealed)
	} else {
		rep.Unsealed = lastPos
	}
	return nil
}

// completeness looks for decision records that should be in the chain and are
// not: the sealer's cursor is past them.
func completeness(ctx context.Context, pool *pgxpool.Pool, rep *Report) error {
	rs, err := pool.Query(ctx, `
SELECT o.event_id FROM outbox o, outbox_consumers k
WHERE k.name = $1 AND o.kind = $2 AND (o.xid, o.seq) <= (k.last_xid::text::xid8, k.last_seq)
  AND NOT EXISTS (SELECT 1 FROM audit_chain c WHERE c.event_id = o.event_id)
ORDER BY o.xid, o.seq LIMIT $3`, ConsumerName, KindDecision, maxProblems)
	if err != nil {
		return fmt.Errorf("check completeness: %w", err)
	}
	for rs.Next() {
		var id string
		if err := rs.Scan(&id); err != nil {
			rs.Close()
			return fmt.Errorf("check completeness: %w", err)
		}
		rep.problem(0, id, "decision record is not in the chain although the sealer passed it")
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return fmt.Errorf("check completeness: %w", err)
	}
	var n int64
	err = pool.QueryRow(ctx, `
SELECT count(*) FROM outbox o
WHERE o.kind = $2 AND NOT EXISTS (SELECT 1 FROM audit_chain c WHERE c.event_id = o.event_id)
  AND NOT EXISTS (SELECT 1 FROM outbox_consumers k WHERE k.name = $1 AND (o.xid, o.seq) <= (k.last_xid::text::xid8, k.last_seq))`,
		ConsumerName, KindDecision).Scan(&n)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("check completeness: %w", err)
	}
	rep.Pending = n
	return nil
}

// checkRetention compares the records missing from the outbox with what the
// retention log says was removed: a record that is missing without being
// accounted for was removed some other way.
func checkRetention(ctx context.Context, pool *pgxpool.Pool, rep *Report, opt Options) error {
	var logged int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(sum(rows), 0)::bigint FROM outbox_prunes WHERE kind = $1`, KindDecision).Scan(&logged); err != nil {
		return fmt.Errorf("read retention log: %w", err)
	}
	switch {
	case !opt.AllowPruned:
		if logged > 0 {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("retention has removed %d decision records from the outbox: give -allow-pruned to accept the ones a signed seal covers", logged))
		}
	case opt.FromSeal > 0:
		rep.Warnings = append(rep.Warnings, "the retention log was not compared with the missing records: the walk started at a seal")
	case rep.Pruned > logged:
		rep.problem(0, "", "%d records are missing from the outbox but the retention log accounts for %d: the others were removed some other way", rep.Pruned, logged)
	case rep.Pruned < logged:
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("the retention log says %d records were removed but only %d are missing", logged, rep.Pruned))
	}
	return nil
}

func checkAnchors(rep *Report, opt Options, seals []Seal, keys map[string]ed25519.PublicKey) {
	byID := map[int64]Seal{}
	for _, s := range seals {
		byID[s.ID] = s
	}
	for _, a := range opt.Anchors {
		if pub, ok := keys[a.KeyID]; ok {
			if err := VerifySeal(pub, a); err != nil {
				rep.problem(0, "", "anchored seal %d: %v", a.ID, err)
			}
		}
		s, ok := byID[a.ID]
		switch {
		case !ok:
			rep.problem(0, "", "seal %d was anchored outside the database and is gone from it: the end of the chain was removed", a.ID)
		case !s.Equal(a):
			rep.problem(0, "", "seal %d differs from the copy anchored outside the database", a.ID)
		}
	}
}
