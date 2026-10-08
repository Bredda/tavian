// Package store is Tavian's PostgreSQL access: versioned migrations, the
// transactional outbox and the record of configuration revisions (ADR-0001,
// ADR-0010). The data plane never queries it on the request path; it only
// appends events.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps a connection pool.
type Store struct{ pool *pgxpool.Pool }

// Open connects to PostgreSQL and verifies the connection.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		// pgx errors can echo the connection string; never wrap them whole.
		return nil, errors.New("database: invalid connection URL")
	}
	cfg.MaxConns = 8
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks that the database answers.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("database unreachable: %w", err)
	}
	return nil
}

// OutboxRow is one event to append to the outbox.
type OutboxRow struct {
	EventID    string
	Kind       string
	OccurredAt time.Time
	Payload    []byte // JSON
}

// InsertOutbox appends rows in one transaction. Rows whose event_id already
// exists are skipped, which makes retries and spool replays idempotent.
func (s *Store) InsertOutbox(ctx context.Context, rows []OutboxRow) error {
	if len(rows) == 0 {
		return nil
	}
	const q = `INSERT INTO outbox (event_id, kind, occurred_at, payload)
	           VALUES ($1, $2, $3, $4) ON CONFLICT (event_id) DO NOTHING`
	b := &pgx.Batch{}
	for _, r := range rows {
		b.Queue(q, r.EventID, r.Kind, r.OccurredAt, r.Payload)
	}
	res := s.pool.SendBatch(ctx, b)
	for range rows {
		if _, err := res.Exec(); err != nil {
			_ = res.Close()
			return fmt.Errorf("outbox insert: %w", err)
		}
	}
	if err := res.Close(); err != nil {
		return fmt.Errorf("outbox insert: %w", err)
	}
	return nil
}

// Revision is a configuration revision to record.
type Revision struct {
	ID      string
	Profile string
	YAML    []byte
	Version string
}

// SaveRevision records a configuration revision; recording the same revision
// twice is a no-op.
func (s *Store) SaveRevision(ctx context.Context, r Revision) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO config_revisions (revision, profile, config_yaml, tavian_version)
		 VALUES ($1, $2, $3, $4) ON CONFLICT (revision) DO NOTHING`,
		r.ID, r.Profile, string(r.YAML), r.Version)
	if err != nil {
		return fmt.Errorf("save config revision: %w", err)
	}
	return nil
}
