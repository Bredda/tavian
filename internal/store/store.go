// Package store is Tavian's PostgreSQL access: versioned migrations, the
// transactional outbox and the record of configuration revisions (ADR-0001,
// ADR-0010). The data plane never queries it on the request path; it only
// appends events.
package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps a connection pool.
type Store struct{ pool *pgxpool.Pool }

// DialFunc opens a network connection. Tavian passes the egress guard's.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Endpoints lists the "host:port" pairs a connection URL can connect to,
// read the way pgx reads it, so that they can be declared to the egress guard.
// Unix sockets are refused: the guard only covers TCP.
func Endpoints(url string) ([]string, error) {
	cfg, err := pgconn.ParseConfig(url)
	if err != nil {
		return nil, errInvalidURL
	}
	var out []string
	seen := map[string]bool{}
	// Fallbacks repeat the primary host (once per TLS variant): list each endpoint once.
	for _, c := range append([]*pgconn.FallbackConfig{{Host: cfg.Host, Port: cfg.Port}}, cfg.Fallbacks...) {
		if strings.HasPrefix(c.Host, "/") || strings.HasPrefix(c.Host, "@") {
			return nil, errors.New("database: unix sockets are not supported, use a TCP host")
		}
		ep := net.JoinHostPort(strings.ToLower(c.Host), strconv.Itoa(int(c.Port)))
		if !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out, nil
}

// pgx errors can echo the connection string; never wrap them whole.
var errInvalidURL = errors.New("database: invalid connection URL")

// Open connects to PostgreSQL and verifies the connection. Every connection
// is made through dial (the egress guard), and name resolution is left to it
// too: pgx would otherwise resolve host names itself and hand dial bare IPs,
// which the guard could not match against its allow-list.
func Open(ctx context.Context, url string, dial DialFunc) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errInvalidURL
	}
	if dial == nil {
		return nil, errors.New("database: a dial function is required")
	}
	cfg.ConnConfig.DialFunc = pgconn.DialFunc(dial)
	cfg.ConnConfig.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
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
	// Policies are the policy files of the revision, as JSON
	// ([{"name": ..., "yaml": ...}]); empty means none.
	Policies []byte
}

// SaveRevision records a configuration revision; recording the same revision
// twice is a no-op.
func (s *Store) SaveRevision(ctx context.Context, r Revision) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO config_revisions (revision, profile, config_yaml, tavian_version, policies)
		 VALUES ($1, $2, $3, $4, $5::jsonb) ON CONFLICT (revision) DO NOTHING`,
		r.ID, r.Profile, string(r.YAML), r.Version, policiesJSON(r.Policies))
	if err != nil {
		return fmt.Errorf("save config revision: %w", err)
	}
	return nil
}

func policiesJSON(b []byte) string {
	if len(b) == 0 {
		return "[]"
	}
	return string(b)
}
