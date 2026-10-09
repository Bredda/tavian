package chain

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bredda/tavian/internal/outbox"
)

// ConsumerName is the name of the sealer's cursor in outbox_consumers.
const ConsumerName = "audit-chain"

// KindDecision is the outbox kind that is chained.
const KindDecision = "decision"

// Defaults for the zero values of Sealer's fields.
const (
	DefaultSealEveryEvents = 1000
	DefaultSealEvery       = 5 * time.Minute
)

// Sealer is the outbox consumer that chains decision records and, when it has
// a Signer, seals the chain.
type Sealer struct {
	// Signer signs seals. Without one the chain is still built, but nothing
	// anchors it: whoever can write to the database could rewrite all of it.
	Signer *Signer
	// SealEveryEvents and SealEvery say when a seal is due: when that many
	// entries are unsealed, or the oldest unsealed entry is that old.
	SealEveryEvents int64
	SealEvery       time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	entries  atomic.Int64
	unsealed atomic.Int64
	lastSeal atomic.Int64 // unix seconds of the last seal, 0 if none
}

// Stats are the sealer's progress, for metrics.
type Stats struct {
	Entries  int64 // length of the chain
	Unsealed int64 // entries after the last seal
	// LastSeal is the time of the last seal; zero if none was made.
	LastSeal time.Time
}

// Stats returns what the sealer knew after its last turn.
func (s *Sealer) Stats() Stats {
	st := Stats{Entries: s.entries.Load(), Unsealed: s.unsealed.Load()}
	if t := s.lastSeal.Load(); t != 0 {
		st.LastSeal = time.Unix(t, 0)
	}
	return st
}

func (s *Sealer) Name() string    { return ConsumerName }
func (s *Sealer) Kinds() []string { return []string{KindDecision} }

func (s *Sealer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type head struct {
	position int64
	hash     []byte
}

// Handle chains a batch of decision records and seals when a seal is due.
func (s *Sealer) Handle(ctx context.Context, tx pgx.Tx, batch []outbox.Row) error {
	h, err := loadHead(ctx, tx)
	if err != nil {
		return err
	}
	if len(batch) > 0 {
		if h, err = s.chain(ctx, tx, h, batch); err != nil {
			return err
		}
	}
	if err := s.sealIfDue(ctx, tx, h); err != nil {
		return err
	}
	s.entries.Store(h.position)
	return nil
}

func loadHead(ctx context.Context, tx pgx.Tx) (head, error) {
	h := head{hash: Genesis()}
	err := tx.QueryRow(ctx, `SELECT position, entry_hash FROM audit_chain ORDER BY position DESC LIMIT 1`).Scan(&h.position, &h.hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return h, fmt.Errorf("read chain head: %w", err)
	}
	return h, nil
}

func (s *Sealer) chain(ctx context.Context, tx pgx.Tx, h head, batch []outbox.Row) (head, error) {
	// A record already in the chain (a cursor that was reset) is not chained
	// twice.
	ids := make([]string, len(batch))
	for i, r := range batch {
		ids[i] = r.EventID
	}
	known := map[string]bool{}
	rs, err := tx.Query(ctx, `SELECT event_id FROM audit_chain WHERE event_id = ANY($1)`, ids)
	if err != nil {
		return h, fmt.Errorf("check chain: %w", err)
	}
	for rs.Next() {
		var id string
		if err := rs.Scan(&id); err != nil {
			rs.Close()
			return h, fmt.Errorf("check chain: %w", err)
		}
		known[id] = true
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return h, fmt.Errorf("check chain: %w", err)
	}

	b := &pgx.Batch{}
	for _, r := range batch {
		if known[r.EventID] {
			continue
		}
		content, err := ContentHash(r.Payload)
		if err != nil {
			return h, fmt.Errorf("event %s: %w", r.EventID, err)
		}
		pos := h.position + 1
		entry := EntryHash(pos, h.hash, r.EventID, r.OccurredAt, content)
		b.Queue(`INSERT INTO audit_chain (position, event_id, occurred_at, content_hash, prev_hash, entry_hash) VALUES ($1, $2, $3, $4, $5, $6)`,
			pos, r.EventID, r.OccurredAt, content, h.hash, entry)
		h = head{position: pos, hash: entry}
	}
	if b.Len() == 0 {
		return h, nil
	}
	res := tx.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := res.Exec(); err != nil {
			_ = res.Close()
			return h, fmt.Errorf("chain insert: %w", err)
		}
	}
	if err := res.Close(); err != nil {
		return h, fmt.Errorf("chain insert: %w", err)
	}
	return h, nil
}

func (s *Sealer) sealIfDue(ctx context.Context, tx pgx.Tx, h head) error {
	if s.Signer == nil {
		return nil
	}
	var last Seal
	err := tx.QueryRow(ctx, `SELECT id, last_position, sealed_at FROM audit_seals ORDER BY id DESC LIMIT 1`).Scan(&last.ID, &last.LastPosition, &last.SealedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read last seal: %w", err)
	}
	if !last.SealedAt.IsZero() {
		s.lastSeal.Store(last.SealedAt.Unix())
	}
	unsealed := h.position - last.LastPosition
	s.unsealed.Store(unsealed)
	if unsealed <= 0 {
		return nil
	}
	every, every2 := s.SealEveryEvents, s.SealEvery
	if every <= 0 {
		every = DefaultSealEveryEvents
	}
	if every2 <= 0 {
		every2 = DefaultSealEvery
	}
	due := unsealed >= every
	if !due {
		var oldest time.Time
		if err := tx.QueryRow(ctx, `SELECT chained_at FROM audit_chain WHERE position = $1`, last.LastPosition+1).Scan(&oldest); err != nil {
			return fmt.Errorf("read oldest unsealed entry: %w", err)
		}
		due = s.now().Sub(oldest) >= every2
	}
	if !due {
		return nil
	}
	seal := Seal{
		ID: last.ID + 1, FirstPosition: last.LastPosition + 1, LastPosition: h.position,
		LastEntryHash: h.hash, SealedAt: s.now().UTC().Truncate(time.Microsecond),
	}
	s.Signer.Sign(&seal)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_seals (id, first_position, last_position, last_entry_hash, sealed_at, key_id, signature) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		seal.ID, seal.FirstPosition, seal.LastPosition, seal.LastEntryHash, seal.SealedAt, seal.KeyID, seal.Signature); err != nil {
		return fmt.Errorf("write seal: %w", err)
	}
	s.unsealed.Store(0)
	s.lastSeal.Store(seal.SealedAt.Unix())
	return nil
}
