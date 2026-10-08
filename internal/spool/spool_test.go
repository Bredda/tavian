package spool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func drainAll(t *testing.T, s *Spool, batch int) []string {
	t.Helper()
	var got []string
	err := s.Drain(context.Background(), batch, func(b [][]byte) error {
		for _, r := range b {
			got = append(got, string(r))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestAppendAndDrainInOrder(t *testing.T) {
	s, err := Open(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if err := s.Append(fmt.Appendf(nil, `{"n":%d}`, i)); err != nil {
			t.Fatal(err)
		}
	}
	var batches []int
	var got []string
	err = s.Drain(context.Background(), 2, func(b [][]byte) error {
		batches = append(batches, len(b))
		for _, r := range b {
			got = append(got, string(r))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || got[0] != `{"n":0}` || got[4] != `{"n":4}` {
		t.Errorf("got %v", got)
	}
	if fmt.Sprint(batches) != "[2 2 1]" {
		t.Errorf("batches = %v", batches)
	}
	if s.Size() != 0 {
		t.Errorf("size after drain = %d", s.Size())
	}
}

func TestFullSpoolRejects(t *testing.T) {
	s, _ := Open(t.TempDir(), 20)
	if err := s.Append([]byte("0123456789")); err != nil { // 11 bytes with newline
		t.Fatal(err)
	}
	if err := s.Append([]byte("0123456789")); !errors.Is(err, ErrFull) {
		t.Fatalf("err = %v, want ErrFull", err)
	}
	if s.Remaining() != 9 {
		t.Errorf("remaining = %d", s.Remaining())
	}
	drainAll(t, s, 10)
	if err := s.Append([]byte("0123456789")); err != nil {
		t.Errorf("append after drain: %v", err)
	}
}

func TestFailedDrainKeepsRecordsAndReplaysThem(t *testing.T) {
	s, _ := Open(t.TempDir(), 1<<20)
	_ = s.Append([]byte("a"))
	_ = s.Append([]byte("b"))
	boom := errors.New("db down")
	if err := s.Drain(context.Background(), 10, func([][]byte) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if s.Size() != 4 {
		t.Errorf("size = %d, want 4", s.Size())
	}
	// Appends keep working while a drain is pending and are replayed too.
	_ = s.Append([]byte("c"))
	if got := drainAll(t, s, 10); fmt.Sprint(got) != "[a b c]" {
		t.Errorf("got %v", got)
	}
}

func TestReopenPicksUpLeftovers(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 1<<20)
	_ = s.Append([]byte("a"))
	_ = s.Drain(context.Background(), 10, func([][]byte) error { return errors.New("down") })
	_ = s.Append([]byte("b"))
	_ = s.Close()

	s2, err := Open(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Size() != 4 {
		t.Errorf("size = %d, want 4", s2.Size())
	}
	if got := drainAll(t, s2, 10); fmt.Sprint(got) != "[a b]" {
		t.Errorf("got %v", got)
	}
}

func TestRejectsNewlines(t *testing.T) {
	s, _ := Open(t.TempDir(), 1<<20)
	if err := s.Append([]byte("a\nb")); err == nil {
		t.Error("expected an error")
	}
}

func TestFilesAreNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(filepath.Join(dir, "spool"), 1<<20)
	fi, err := os.Stat(filepath.Join(dir, "spool", activeName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("mode = %v", fi.Mode())
	}
	_ = s.Close()
}
