package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// TokenUse is what is known of the use of one administration token. When it is
// written, Uses is the number of uses since the previous write; when it is
// read, the total.
type TokenUse struct {
	TokenID    string
	LastUsedAt time.Time
	Uses       int64
	LastRemote string
}

// AddTokenUse adds uses to what is recorded, in one statement: the counts are
// added, the last use is the latest of the two, and the address is the one of
// the latest use.
func (s *Store) AddTokenUse(ctx context.Context, uses []TokenUse) error {
	if len(uses) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, u := range uses {
		b.Queue(`
INSERT INTO admin_token_use (token_id, last_used_at, uses, last_remote) VALUES ($1, $2, $3, $4)
ON CONFLICT (token_id) DO UPDATE SET
    uses         = admin_token_use.uses + EXCLUDED.uses,
    last_remote  = CASE WHEN EXCLUDED.last_used_at >= admin_token_use.last_used_at THEN EXCLUDED.last_remote ELSE admin_token_use.last_remote END,
    last_used_at = GREATEST(admin_token_use.last_used_at, EXCLUDED.last_used_at)`,
			u.TokenID, u.LastUsedAt, u.Uses, u.LastRemote)
	}
	res := s.pool.SendBatch(ctx, b)
	for range uses {
		if _, err := res.Exec(); err != nil {
			_ = res.Close()
			return fmt.Errorf("write token use: %w", err)
		}
	}
	if err := res.Close(); err != nil {
		return fmt.Errorf("write token use: %w", err)
	}
	return nil
}

// TokenUses returns what is recorded, by token id.
func (s *Store) TokenUses(ctx context.Context) (map[string]TokenUse, error) {
	rs, err := s.pool.Query(ctx, `SELECT token_id, last_used_at, uses, last_remote FROM admin_token_use`)
	if err != nil {
		return nil, fmt.Errorf("read token use: %w", err)
	}
	defer rs.Close()
	out := map[string]TokenUse{}
	for rs.Next() {
		var u TokenUse
		if err := rs.Scan(&u.TokenID, &u.LastUsedAt, &u.Uses, &u.LastRemote); err != nil {
			return nil, fmt.Errorf("read token use: %w", err)
		}
		u.LastUsedAt = u.LastUsedAt.UTC()
		out[u.TokenID] = u
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("read token use: %w", err)
	}
	return out, nil
}
