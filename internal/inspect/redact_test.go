package inspect

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

func redactWith(t *testing.T, e *Engine, req Request, kinds ...string) Redaction {
	t.Helper()
	res, err := e.Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return Redact(req, res.Findings, func(f Finding) bool {
		for _, k := range kinds {
			if string(f.Type)+"."+f.Subtype == k {
				return true
			}
		}
		return false
	})
}

func TestRedactReplacesWithTypedNumberedPlaceholders(t *testing.T) {
	e := newTestEngine(t)
	req := text(
		"mail a@b.example and c@d.example, then again A@B.EXAMPLE; pay FR14 2004 1010 0505 0001 3M02 606.",
		"nothing here",
		"also a@b.example",
	)
	r := redactWith(t, e, req, "pii.email")
	want0 := "mail [EMAIL_1] and [EMAIL_2], then again [EMAIL_1]; pay FR14 2004 1010 0505 0001 3M02 606."
	if r.Replacements[0] != want0 || r.Replacements[2] != "also [EMAIL_1]" || len(r.Replacements) != 2 {
		t.Errorf("replacements = %v", r.Replacements)
	}
	if r.Counts["pii.email"] != 4 || len(r.Counts) != 1 {
		t.Errorf("counts = %v", r.Counts)
	}
	both := redactWith(t, e, req, "pii.email", "pii.iban")
	if !strings.Contains(both.Replacements[0], "pay [IBAN_1].") || strings.Contains(both.Replacements[0], "FR14") {
		t.Errorf("replacements = %v", both.Replacements)
	}
}

func TestRedactMergesOverlapsAndKeepsOtherText(t *testing.T) {
	// a card number is also found by the phone-like and other scanners in some
	// inputs; overlapping findings must collapse to one placeholder
	f := func(start, end int, sub, fp string) Finding {
		return Finding{Type: TypePII, Subtype: sub, Fingerprint: fp, Location: Location{Segment: 0, Start: start, End: end}}
	}
	req := text("0123456789abcdef")
	r := Redact(req, []Finding{f(2, 8, "iban", "x"), f(5, 12, "nir", "y"), f(14, 16, "iban", "z")}, func(Finding) bool { return true })
	if got := r.Replacements[0]; got != "01[IBAN_1]cd[IBAN_2]" {
		t.Errorf("got %q", got)
	}
	if r.Counts["pii.iban"] != 2 || r.Counts["pii.nir"] != 0 {
		t.Errorf("counts = %v: an overlapped finding is one span", r.Counts)
	}
	// findings outside the text are skipped, not a panic
	r = Redact(req, []Finding{f(10, 99, "iban", "x")}, func(Finding) bool { return true })
	if r.Replacements[0] != "0123456789abcdef" {
		t.Errorf("got %q", r.Replacements[0])
	}
	if got := Redact(req, nil, func(Finding) bool { return true }); len(got.Replacements) != 0 {
		t.Errorf("nothing to redact: %v", got.Replacements)
	}
}

func TestRedactUsesTheNormalizedText(t *testing.T) {
	e := newTestEngine(t)
	req := text("write to al​ice@exa​mple.org now")
	r := redactWith(t, e, req, "pii.email")
	if got := r.Replacements[0]; got != "write to [EMAIL_1] now" {
		t.Errorf("got %q", got)
	}
}

func TestPlaceholderNames(t *testing.T) {
	for in, want := range map[string]string{"iban": "IBAN", "payment_card": "PAYMENT_CARD", "contract-ref": "CONTRACT_REF", "ünï": "_N_", "": "REDACTED"} {
		if got := placeholderName(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

var placeholderRe = regexp.MustCompile(`\[[A-Z0-9_]+_[0-9]+\]`)

// What Redact guarantees: the result is the normalized text with some spans
// replaced by placeholders, nothing else added, removed or reordered, and the
// counts say how many spans were replaced. (It cannot promise that a value
// does not reappear: removing text changes what is next to what, and a value
// next to another can become detectable. The gateway checks for that and
// refuses the request.)
func FuzzRedactStructure(f *testing.F) {
	for _, s := range []string{"a@b.example", "FR14 2004 1010 0505 0001 3M02 606 and x@y.co", "4111 1111 1111 1111", "\xff@b.example", "al\u200bice@example.org", "+00000000+00000000"} {
		f.Add(s)
	}
	e := NewWith(30*1e9, testKey, builtinForTest()...)
	f.Fuzz(func(t *testing.T, s string) {
		req := text(s)
		res, err := e.Inspect(context.Background(), req)
		if err != nil || res.Truncated {
			return
		}
		r := Redact(req, res.Findings, func(Finding) bool { return true })
		if len(res.Findings) == 0 {
			if len(r.Replacements) != 0 {
				t.Fatalf("nothing found, yet %v", r.Replacements)
			}
			return
		}
		out, orig := r.Replacements[0], Normalize(s)
		spans := 0
		for _, n := range r.Counts {
			spans += n
		}
		if got := len(placeholderRe.FindAllString(out, -1)); got < spans {
			t.Fatalf("%d placeholders for %d spans in %q", got, spans, out)
		}
		// outside the placeholders, the pieces are a subsequence of the original
		at := 0
		for _, piece := range placeholderRe.Split(out, -1) {
			i := strings.Index(orig[at:], piece)
			if i < 0 {
				t.Fatalf("piece %q of %q is not in order in %q", piece, out, orig)
			}
			at += i + len(piece)
		}
	})
}
