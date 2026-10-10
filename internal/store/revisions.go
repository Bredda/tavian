package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrNotFound is returned for a revision that was never recorded.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when the active revision is not the one the caller
// based its change on.
var ErrConflict = errors.New("the active revision is not the expected one")

// StoredRevision is a revision as the database holds it.
type StoredRevision struct {
	Revision
	Seq           int64
	FirstLoadedAt time.Time
}

// GetRevision returns one revision with its content, or ErrNotFound.
func (s *Store) GetRevision(ctx context.Context, id string) (StoredRevision, error) {
	var r StoredRevision
	var yaml, policies string
	err := s.pool.QueryRow(ctx, `
SELECT revision, profile, config_yaml, tavian_version, policies::text, seq, first_loaded_at
FROM config_revisions WHERE revision = $1`, id).
		Scan(&r.ID, &r.Profile, &yaml, &r.Version, &policies, &r.Seq, &r.FirstLoadedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, fmt.Errorf("read revision: %w", err)
	}
	r.YAML, r.Policies = []byte(yaml), []byte(policies)
	return r, nil
}

// ListRevisions returns the revisions without their content, newest first.
// before, when positive, is the Seq to continue from (exclusive); next is the
// value for the following page, 0 when there is none.
func (s *Store) ListRevisions(ctx context.Context, limit int, before int64) (revs []StoredRevision, next int64, err error) {
	limit = min(max(limit, 1), 500)
	if before <= 0 {
		before = 1<<63 - 1
	}
	rs, err := s.pool.Query(ctx, `
SELECT revision, profile, tavian_version, seq, first_loaded_at
FROM config_revisions WHERE seq < $1 ORDER BY seq DESC LIMIT $2`, before, limit+1)
	if err != nil {
		return nil, 0, fmt.Errorf("list revisions: %w", err)
	}
	defer rs.Close()
	for rs.Next() {
		var r StoredRevision
		if err := rs.Scan(&r.ID, &r.Profile, &r.Version, &r.Seq, &r.FirstLoadedAt); err != nil {
			return nil, 0, fmt.Errorf("list revisions: %w", err)
		}
		revs = append(revs, r)
	}
	if err := rs.Err(); err != nil {
		return nil, 0, fmt.Errorf("list revisions: %w", err)
	}
	if len(revs) > limit {
		revs, next = revs[:limit], revs[limit-1].Seq
	}
	return revs, next, nil
}

// Active says which revision is active and where it came from.
type Active struct {
	Revision    string
	ActivatedAt time.Time
	ActivatedBy string
	// FileRevision is the revision of the configuration file the gateway last
	// started or reloaded from; empty if it never did.
	FileRevision string
}

// ActiveRevision returns the active revision; ok is false when none was ever
// activated.
func (s *Store) ActiveRevision(ctx context.Context) (a Active, ok bool, err error) {
	err = s.pool.QueryRow(ctx, `SELECT revision, activated_at, activated_by, file_revision FROM config_active`).
		Scan(&a.Revision, &a.ActivatedAt, &a.ActivatedBy, &a.FileRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, false, nil
	}
	if err != nil {
		return a, false, fmt.Errorf("read active revision: %w", err)
	}
	return a, true, nil
}

// Activation is a change of the active revision.
type Activation struct {
	// Revision is recorded if it is new.
	Revision Revision
	// Base is the revision the caller believes is active ("" when none is).
	Base string
	// FileRevision is set when the change comes from the configuration file;
	// empty leaves the recorded one alone.
	FileRevision string
	// Change is the record of who did it; its Target should be Revision.ID.
	Change AdminChange
}

// Activate makes a revision the active one, in one transaction with the
// revision itself and the record of the change (row and outbox event): all of
// it or nothing. It returns ErrConflict, and writes nothing, when the active
// revision is not Base.
func (s *Store) Activate(ctx context.Context, a Activation) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("activate revision: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	r := a.Revision
	if _, err := tx.Exec(ctx,
		`INSERT INTO config_revisions (revision, profile, config_yaml, tavian_version, policies)
		 VALUES ($1, $2, $3, $4, $5::jsonb) ON CONFLICT (revision) DO NOTHING`,
		r.ID, r.Profile, string(r.YAML), r.Version, policiesJSON(r.Policies)); err != nil {
		return fmt.Errorf("activate revision: %w", err)
	}
	var moved int64
	if a.Base == "" {
		tag, err := tx.Exec(ctx, `
INSERT INTO config_active (revision, activated_at, activated_by, file_revision) VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING`, r.ID, a.Change.OccurredAt, a.Change.Actor, a.FileRevision)
		if err != nil {
			return fmt.Errorf("activate revision: %w", err)
		}
		moved = tag.RowsAffected()
	} else {
		tag, err := tx.Exec(ctx, `
UPDATE config_active SET revision = $1, activated_at = $2, activated_by = $3,
    file_revision = CASE WHEN $4 = '' THEN file_revision ELSE $4 END
WHERE revision = $5`, r.ID, a.Change.OccurredAt, a.Change.Actor, a.FileRevision, a.Base)
		if err != nil {
			return fmt.Errorf("activate revision: %w", err)
		}
		moved = tag.RowsAffected()
	}
	if moved != 1 {
		return ErrConflict
	}
	if err := recordAdminChange(ctx, tx, a.Change); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("activate revision: %w", err)
	}
	return nil
}
