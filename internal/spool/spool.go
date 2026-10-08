// Package spool is a bounded, append-only queue on local disk. It holds usage
// events while PostgreSQL is unavailable (ADR-0010); when it is full the
// gateway stops admitting audited requests (ADR-0005).
//
// Records are single lines. The active file receives appends; Drain renames it
// aside and replays the renamed file, so appends never wait for the database.
// A crash can replay records, never lose them: consumers must be idempotent.
package spool

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrFull is returned by Append when the record does not fit.
var ErrFull = errors.New("spool full")

// ErrTooLarge is returned by Append for a record Drain could not read back:
// accepting it would block the replay of everything behind it.
var ErrTooLarge = errors.New("spool: record too large")

const (
	activeName   = "events.spool"
	drainingName = "events.draining"
	rejectedName = "events.rejected"
	// maxRecord bounds a single line when replaying.
	maxRecord = 1 << 20
)

// Spool is safe for concurrent use.
type Spool struct {
	dir string
	max int64

	mu       sync.Mutex
	active   *os.File
	size     int64 // bytes in the active and draining files
	draining int64 // bytes of the draining file alone
}

// Open creates dir if needed and picks up any records left by a previous run.
func Open(dir string, maxBytes int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	s := &Spool{dir: dir, max: maxBytes}
	f, err := os.OpenFile(filepath.Join(dir, activeName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // operator-chosen directory
	if err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	s.active = f
	for _, name := range []string{activeName, drainingName} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil {
			s.size += fi.Size()
			if name == drainingName {
				s.draining = fi.Size()
			}
		}
	}
	return s, nil
}

// Close closes the active file. Records stay on disk.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active.Close()
}

// Size is the number of bytes waiting to be replayed.
func (s *Spool) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}

// Remaining is the number of bytes that can still be appended.
func (s *Spool) Remaining() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return max(s.max-s.size, 0)
}

// Append durably adds one record. rec must not contain a newline (compact JSON
// does not).
func (s *Spool) Append(rec []byte) error {
	if bytes.IndexByte(rec, '\n') >= 0 {
		return errors.New("spool: record contains a newline")
	}
	if len(rec) >= maxRecord {
		return ErrTooLarge
	}
	n := int64(len(rec)) + 1
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.size+n > s.max {
		return ErrFull
	}
	line := append(append(make([]byte, 0, n), rec...), '\n')
	if _, err := s.active.Write(line); err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	if err := s.active.Sync(); err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	s.size += n
	return nil
}

// Reject sets a record aside in events.rejected, outside the size accounting,
// for an operator to inspect. Nothing reads that file back.
func (s *Spool) Reject(rec []byte) error {
	f, err := os.OpenFile(filepath.Join(s.dir, rejectedName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // operator-chosen directory
	if err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	defer func() { _ = f.Close() }()
	line := append(append(make([]byte, 0, len(rec)+1), rec...), '\n')
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	return f.Sync()
}

// Drain replays every record through fn, in batches of at most batchSize. A
// batch is only forgotten once fn accepted it and everything before it; if fn
// fails, Drain stops and the next call replays from the start of the file
// currently being drained, so fn may see a record more than once.
func (s *Spool) Drain(ctx context.Context, batchSize int, fn func(batch [][]byte) error) error {
	for {
		more, err := s.drainOne(ctx, batchSize, fn)
		if err != nil || !more {
			return err
		}
	}
}

// drainOne replays one file and reports whether more data arrived meanwhile.
func (s *Spool) drainOne(ctx context.Context, batchSize int, fn func([][]byte) error) (bool, error) {
	if err := s.rotate(); err != nil {
		return false, err
	}
	path := filepath.Join(s.dir, drainingName)
	f, err := os.Open(path) //nolint:gosec // operator-chosen directory
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("spool: %w", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxRecord)
	var batch [][]byte
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(batch); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		batch = append(batch, append([]byte(nil), sc.Bytes()...))
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return false, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("spool: read: %w", err)
	}
	if err := flush(); err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("spool: %w", err)
	}
	s.size -= s.draining
	s.draining = 0
	return s.size > 0, nil
}

// rotate moves the active file aside unless a previous drain is unfinished.
func (s *Spool) rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining > 0 {
		return nil
	}
	active := s.size - s.draining
	if active == 0 {
		return nil
	}
	if err := s.active.Close(); err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	if err := os.Rename(filepath.Join(s.dir, activeName), filepath.Join(s.dir, drainingName)); err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(s.dir, activeName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // operator-chosen directory
	if err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	s.active = f
	s.draining = active
	return nil
}

// Capacity is the configured maximum size in bytes.
func (s *Spool) Capacity() int64 { return s.max }
