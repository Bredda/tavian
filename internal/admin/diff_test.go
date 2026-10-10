package admin

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@$`)

// applyDiff applies a unified diff to text, checking that the hunk headers say
// what the hunks hold and that the context matches the text.
func applyDiff(t *testing.T, before, diff string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "--- ") || !strings.HasPrefix(lines[1], "+++ ") {
		t.Fatalf("no file header:\n%s", diff)
	}
	src := splitLines(before)
	var out []string
	next := 0 // next line of src not yet copied
	for i := 2; i < len(lines); {
		m := hunkHeader.FindStringSubmatch(lines[i])
		if m == nil {
			t.Fatalf("expected a hunk header, got %q in:\n%s", lines[i], diff)
		}
		num := func(s string, def int) int {
			if s == "" {
				return def
			}
			n, _ := strconv.Atoi(s)
			return n
		}
		startA, countA := num(m[1], 0), num(m[2], 1)
		countB := num(m[4], 1)
		first := startA - 1
		if countA == 0 {
			first = startA // an empty range names the line before
		}
		if first < next {
			t.Fatalf("hunks overlap or are out of order:\n%s", diff)
		}
		out = append(out, src[next:first]...)
		next = first
		i++
		seenA, seenB := 0, 0
		for i < len(lines) && !strings.HasPrefix(lines[i], "@@") {
			l := lines[i]
			switch l[0] {
			case ' ':
				if next >= len(src) || src[next] != l[1:] {
					t.Fatalf("context %q does not match the text at line %d:\n%s", l[1:], next+1, diff)
				}
				out = append(out, l[1:])
				next++
				seenA++
				seenB++
			case '-':
				if next >= len(src) || src[next] != l[1:] {
					t.Fatalf("removed line %q does not match the text at line %d:\n%s", l[1:], next+1, diff)
				}
				next++
				seenA++
			case '+':
				out = append(out, l[1:])
				seenB++
			default:
				t.Fatalf("bad line %q", l)
			}
			i++
		}
		if seenA != countA || seenB != countB {
			t.Fatalf("hunk header says -%d +%d but holds -%d +%d:\n%s", countA, countB, seenA, seenB, diff)
		}
	}
	out = append(out, src[next:]...)
	return strings.Join(out, "\n")
}

func TestUnifiedDiffGolden(t *testing.T) {
	before := "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\n"
	after := "a\nb\nc\nd\nE\nf\ng\nh\ni\nj\nk\nl\nm\n"
	want := `--- a/x.yaml
+++ b/x.yaml
@@ -2,7 +2,7 @@
 b
 c
 d
-e
+E
 f
 g
 h
@@ -10,3 +10,4 @@
 j
 k
 l
+m
`
	if got := unifiedDiff("x.yaml", before, after, false, false); got != want {
		t.Errorf("diff:\n%s\nwant:\n%s", got, want)
	}
	if got := unifiedDiff("x.yaml", "a\nb\n", "a\nb\n", false, false); strings.Contains(got, "@@") {
		t.Errorf("identical files have a hunk:\n%s", got)
	}
	added := unifiedDiff("p.yaml", "", "one\ntwo\n", true, false)
	if added != "--- /dev/null\n+++ b/p.yaml\n@@ -0,0 +1,2 @@\n+one\n+two\n" {
		t.Errorf("added:\n%s", added)
	}
	removed := unifiedDiff("p.yaml", "one\n", "", false, true)
	if removed != "--- a/p.yaml\n+++ /dev/null\n@@ -1 +0,0 @@\n-one\n" {
		t.Errorf("removed:\n%s", removed)
	}
}

func TestUnifiedDiffReproducesTheNewFile(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	words := []string{"a", "b", "c", "d", "e", "f", "g"}
	gen := func() string {
		var l []string
		for range rnd.Intn(30) {
			l = append(l, words[rnd.Intn(len(words))])
		}
		if len(l) == 0 {
			return ""
		}
		return strings.Join(l, "\n") + "\n"
	}
	for i := 0; i < 500; i++ {
		before, after := gen(), gen()
		d := unifiedDiff("f", before, after, false, false)
		got := applyDiff(t, before, d)
		if want := strings.Join(splitLines(after), "\n"); got != want {
			t.Fatalf("case %d: applying the diff gives\n%q\nwant\n%q\ndiff:\n%s\nbefore:\n%q", i, got, want, d, before)
		}
		if before == after && strings.Contains(d, "@@") {
			t.Fatalf("case %d: identical files, but a hunk:\n%s", i, d)
		}
	}
}

func TestUnifiedDiffOfHugeFilesStillWorks(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&a, "line %d\n", i)
		fmt.Fprintf(&b, "other %d\n", i)
	}
	d := unifiedDiff("big", a.String(), b.String(), false, false)
	if got := applyDiff(t, a.String(), d); got != strings.Join(splitLines(b.String()), "\n") {
		t.Error("the diff of two large files does not reproduce the new one")
	}
}

func TestUnifiedDiffKeepsDistantChangesInSeparateHunks(t *testing.T) {
	var a, b []string
	for i := 0; i < 40; i++ {
		a = append(a, fmt.Sprint("l", i))
		b = append(b, fmt.Sprint("l", i))
	}
	b[2], b[30] = "X", "Y"
	d := unifiedDiff("f", strings.Join(a, "\n")+"\n", strings.Join(b, "\n")+"\n", false, false)
	if n := strings.Count(d, "@@ -"); n != 2 {
		t.Errorf("%d hunks, want 2:\n%s", n, d)
	}
	b[2] = a[2]
	b[8] = "Z" // within 2*context of 30? no: 22 apart, still separate
	b[30] = "Y"
	b[27] = "W" // 3 apart from 30: one hunk
	d = unifiedDiff("f", strings.Join(a, "\n")+"\n", strings.Join(b, "\n")+"\n", false, false)
	if n := strings.Count(d, "@@ -"); n != 2 {
		t.Errorf("%d hunks, want 2 (a pair of near changes and a distant one):\n%s", n, d)
	}
}
