package chain

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ExportOptions say which entries of the chain to export. The zero value is
// all of them.
type ExportOptions struct {
	// Kinds keeps the entries of these kinds (KindDecision, KindAdminChange).
	Kinds []string
	// Since and Until bound the time of the records: Since is included, Until
	// is not. Zero means no bound.
	Since, Until time.Time
	// FromPosition starts after this chain position.
	FromPosition int64
}

// Entry is one entry of the chain with the record it covers, as exported for an
// auditor: everything needed to recompute the hash of the record and to check
// that the entries link, with a tool of one's own.
type Entry struct {
	Position    int64     `json:"position"`
	EventID     string    `json:"event_id"`
	Kind        string    `json:"kind"`
	OccurredAt  time.Time `json:"occurred_at"`
	ContentHash string    `json:"content_hash"` // hex SHA-256 of the canonical form of the record
	PrevHash    string    `json:"prev_hash"`    // hex entry_hash of the entry before
	EntryHash   string    `json:"entry_hash"`   // hex
	// Record is the record as it is in the outbox; null when retention has
	// removed it (Pruned), which only ever happens to decision records.
	Record json.RawMessage `json:"record"`
	Pruned bool            `json:"pruned,omitempty"`
}

// Export reads the chain in order, with the records it covers, and calls emit
// for each entry that matches. It returns how many it emitted. It only reads.
func Export(ctx context.Context, pool *pgxpool.Pool, opt ExportOptions, emit func(Entry) error) (int, error) {
	n := 0
	after := opt.FromPosition
	kinds := opt.Kinds
	if kinds == nil {
		kinds = []string{} // a NULL array would match nothing
	}
	for {
		rs, err := pool.Query(ctx, `
SELECT c.position, c.event_id, COALESCE(o.kind, $5), c.occurred_at, c.content_hash, c.prev_hash, c.entry_hash, o.payload::text
FROM audit_chain c LEFT JOIN outbox o ON o.event_id = c.event_id
WHERE c.position > $1
  AND (cardinality($2::text[]) = 0 OR COALESCE(o.kind, $5) = ANY($2::text[]))
  AND ($3::timestamptz IS NULL OR c.occurred_at >= $3)
  AND ($4::timestamptz IS NULL OR c.occurred_at < $4)
ORDER BY c.position LIMIT $6`, after, kinds, nilIfZero(opt.Since), nilIfZero(opt.Until), KindDecision, pageSize)
		if err != nil {
			return n, fmt.Errorf("read chain: %w", err)
		}
		got := 0
		for rs.Next() {
			var (
				e                    Entry
				content, prevH, hash []byte
				payload              *string
			)
			if err := rs.Scan(&e.Position, &e.EventID, &e.Kind, &e.OccurredAt, &content, &prevH, &hash, &payload); err != nil {
				rs.Close()
				return n, fmt.Errorf("read chain: %w", err)
			}
			e.OccurredAt = e.OccurredAt.UTC()
			e.ContentHash, e.PrevHash, e.EntryHash = hex.EncodeToString(content), hex.EncodeToString(prevH), hex.EncodeToString(hash)
			if payload == nil {
				e.Record, e.Pruned = json.RawMessage("null"), true
			} else {
				e.Record = json.RawMessage(*payload)
			}
			after = e.Position
			got++
			if err := emit(e); err != nil {
				rs.Close()
				return n, err
			}
			n++
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return n, fmt.Errorf("read chain: %w", err)
		}
		if got < pageSize {
			return n, nil
		}
	}
}

func nilIfZero(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
