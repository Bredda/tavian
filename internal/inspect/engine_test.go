package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func text(s ...string) Request {
	var r Request
	for i, t := range s {
		r.Segments = append(r.Segments, Segment{MessageIndex: i, Field: FieldContent, Part: -1, Text: t})
	}
	return r
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{FingerprintKeyEnv: "K"}, func(string) string { return string(testKey) })
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEmailFindingsCarryNoValue(t *testing.T) {
	const addr = "alice.martin@example.org"
	e := newTestEngine(t)
	res, err := e.Inspect(context.Background(), text("write to "+addr+" please", "nothing here"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusOK || len(res.Findings) != 1 {
		t.Fatalf("result = %+v", res)
	}
	f := res.Findings[0]
	if f.Detector != "pii.email" || f.Type != TypePII || f.Subtype != "email" {
		t.Errorf("finding = %+v", f)
	}
	if f.Location.Segment != 0 || f.Location.MessageIndex != 0 || f.Location.Field != FieldContent || f.Location.Start != 9 || f.Location.End != 9+len(addr) {
		t.Errorf("location = %+v", f.Location)
	}
	if len(f.Fingerprint) != 32 || f.Canonical != "" {
		t.Errorf("fingerprint = %q canonical = %q", f.Fingerprint, f.Canonical)
	}
	// Nothing that leaves the engine may contain the value.
	for name, v := range map[string]any{"finding": res.Findings, "summary": res.Summary()} {
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), "alice") || strings.Contains(string(b), "example.org") {
			t.Errorf("%s leaks the value: %s", name, b)
		}
	}
}

func TestFingerprints(t *testing.T) {
	e := newTestEngine(t)
	fp := func(e *Engine, s string) string {
		t.Helper()
		res, err := e.Inspect(context.Background(), text(s))
		if err != nil || len(res.Findings) != 1 {
			t.Fatalf("%q: %v %+v", s, err, res)
		}
		return res.Findings[0].Fingerprint
	}
	if fp(e, "a@b.example") != fp(e, "x A@B.EXAMPLE y") {
		t.Error("the same address in another case and context must give the same fingerprint")
	}
	if fp(e, "a@b.example") == fp(e, "c@b.example") {
		t.Error("different addresses must give different fingerprints")
	}
	other, err := New(Config{FingerprintKeyEnv: "K"}, func(string) string { return "another key, also long enough" })
	if err != nil {
		t.Fatal(err)
	}
	if fp(e, "a@b.example") == fp(other, "a@b.example") {
		t.Error("the fingerprint must depend on the key")
	}
}

func TestEphemeralKeyIsStableWithinAProcess(t *testing.T) {
	a, _ := New(Config{}, nil)
	b, _ := New(Config{}, nil)
	if !a.EphemeralKey() || !b.EphemeralKey() {
		t.Fatal("no key configured: expected an ephemeral key")
	}
	ra, _ := a.Inspect(context.Background(), text("a@b.example"))
	rb, _ := b.Inspect(context.Background(), text("a@b.example"))
	if ra.Findings[0].Fingerprint != rb.Findings[0].Fingerprint {
		t.Error("two engines of one process (a config reload) must agree on fingerprints")
	}
}

func TestConfigValidation(t *testing.T) {
	env := func(k string) string {
		if k == "SHORT" {
			return "short"
		}
		return ""
	}
	for name, cfg := range map[string]Config{
		"unset key":   {FingerprintKeyEnv: "MISSING"},
		"short key":   {FingerprintKeyEnv: "SHORT"},
		"tiny budget": {Budget: time.Microsecond},
		"huge budget": {Budget: time.Minute},
		"negative":    {Budget: -time.Second},
	} {
		if _, err := New(cfg, env); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	off := false
	e, err := New(Config{Enabled: &off}, env)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Inspect(context.Background(), text("a@b.example"))
	if err != nil || res.Status != StatusSkipped || len(res.Findings) != 0 {
		t.Errorf("disabled engine: %+v %v", res, err)
	}
}

// stub is a detector whose behaviour a test dictates.
type stub struct {
	name string
	fn   func(ctx context.Context, req Request) ([]Finding, error)
}

func (s stub) Name() string                 { return s.name }
func (s stub) Version() string              { return "t1" }
func (s stub) Health(context.Context) error { return nil }
func (s stub) Inspect(ctx context.Context, req Request) ([]Finding, error) {
	return s.fn(ctx, req)
}

func TestFailsClosed(t *testing.T) {
	boom := errors.New("secret-canary-in-an-error")
	cases := map[string]struct {
		budget time.Duration
		fn     func(context.Context, Request) ([]Finding, error)
	}{
		"error": {time.Second, func(context.Context, Request) ([]Finding, error) { return nil, boom }},
		"panic": {time.Second, func(context.Context, Request) ([]Finding, error) { panic("secret-canary-in-a-panic") }},
		"timeout": {20 * time.Millisecond, func(ctx context.Context, _ Request) ([]Finding, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}},
		"stuck detector": {20 * time.Millisecond, func(context.Context, Request) ([]Finding, error) {
			time.Sleep(300 * time.Millisecond) // ignores ctx
			return nil, nil
		}},
		"finding past the text": {time.Second, func(context.Context, Request) ([]Finding, error) {
			return []Finding{{Subtype: "x", Location: Location{Segment: 0, Start: 0, End: 999}}}, nil
		}},
		"finding in no segment": {time.Second, func(context.Context, Request) ([]Finding, error) {
			return []Finding{{Subtype: "x", Location: Location{Segment: 7, Start: 0, End: 1}}}, nil
		}},
		"empty finding": {time.Second, func(context.Context, Request) ([]Finding, error) {
			return []Finding{{Subtype: "x", Location: Location{Segment: 0, Start: 1, End: 1}}}, nil
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := NewWith(c.budget, testKey, stub{name: "t.stub", fn: c.fn})
			res, err := e.Inspect(context.Background(), text("hello"))
			if CodeOf(err) != CodeFailed || res.Status != StatusFailed || res.Reason != CodeFailed {
				t.Fatalf("err = %v result = %+v", err, res)
			}
			if strings.Contains(err.Error(), "canary") {
				t.Errorf("the error text must not carry detector messages: %v", err)
			}
		})
	}
}

func TestGapsRefuseTheRequest(t *testing.T) {
	e := newTestEngine(t)
	for _, kind := range []string{GapMultimodal, GapTooComplex} {
		req := text("fine")
		req.Gaps = []Gap{{Kind: kind}}
		res, err := e.Inspect(context.Background(), req)
		if CodeOf(err) != kind || res.Status != StatusFailed || res.Reason != kind {
			t.Errorf("%s: err = %v result = %+v", kind, err, res)
		}
	}
}

func TestCancelledContextFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newTestEngine(t).Inspect(ctx, text("a@b.example"))
	if CodeOf(err) != CodeFailed {
		t.Errorf("err = %v", err)
	}
}

func TestFindingsAreCappedAndSorted(t *testing.T) {
	// a generous budget: the race detector makes this slow
	e := NewWith(30*time.Second, testKey, builtinForTest()...)
	var b strings.Builder
	for i := 0; i < maxFindings+50; i++ {
		b.WriteString("u@b.example ")
	}
	res, err := e.Inspect(context.Background(), text(b.String()))
	if err != nil || !res.Truncated || len(res.Findings) != maxFindings {
		t.Fatalf("err = %v truncated = %v findings = %d", err, res.Truncated, len(res.Findings))
	}
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i-1].Location.Start >= res.Findings[i].Location.Start {
			t.Fatal("findings are not in text order")
		}
	}
	if s := res.Summary(); s.Findings != maxFindings || !s.Truncated || s.Counts["pii.email"] != maxFindings {
		t.Errorf("summary = %+v", s)
	}
}

func TestNormalizationDefeatsHidingTricks(t *testing.T) {
	e := newTestEngine(t)
	for name, s := range map[string]string{
		"zero-width space":   "al\u200bice@exa\u200bmple.org",
		"soft hyphen":        "alice@exam\u00adple.org",
		"bidi control":       "\u202ealice@example.org",
		"full-width":         "ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｏｒｇ",
		"invalid utf-8 prev": "\xff\xfe alice@example.org",
	} {
		res, err := e.Inspect(context.Background(), text(s))
		if err != nil || len(res.Findings) != 1 {
			t.Errorf("%s: err = %v findings = %d", name, err, len(res.Findings))
		}
	}
}

func TestSummary(t *testing.T) {
	e := newTestEngine(t)
	res, _ := e.Inspect(context.Background(), text("a@b.example and c@d.example", "none"))
	s := res.Summary()
	if s.Status != StatusOK || s.Findings != 2 || s.Counts["pii.email"] != 2 || s.Detectors["pii.email"] == "" {
		t.Errorf("summary = %+v", s)
	}
}

func TestEmailDetector(t *testing.T) {
	e := newTestEngine(t)
	count := func(s string) int {
		res, err := e.Inspect(context.Background(), text(s))
		if err != nil {
			t.Fatal(err)
		}
		return len(res.Findings)
	}
	for _, s := range []string{"a@b.co", "first.last+tag@sub.example.com", "<x_y@example.fr>", "mailto:me@example.org."} {
		if count(s) != 1 {
			t.Errorf("%q: want 1 finding", s)
		}
	}
	for _, s := range []string{"", "no address", "@example.org", "user@", "user@host", "a@b.c", "price @ 5 euros"} {
		if count(s) != 0 {
			t.Errorf("%q: want no finding", s)
		}
	}
}

func FuzzEngine(f *testing.F) {
	for _, s := range []string{"", "a@b.co", "x\u200by@z.example", "\xff\xfe@@..", "ａ＠ｂ．ｃｏ", strings.Repeat("a@", 100)} {
		f.Add(s, s)
	}
	e := NewWith(time.Second, testKey, builtinForTest()...)
	f.Fuzz(func(t *testing.T, a, b string) {
		res, err := e.Inspect(context.Background(), text(a, b))
		if err != nil {
			t.Fatalf("a well-formed engine failed on %q %q: %v", a, b, err)
		}
		for _, fi := range res.Findings {
			l := fi.Location
			seg := normalize([]string{a, b}[l.Segment])
			if l.Start < 0 || l.End <= l.Start || l.End > len(seg) {
				t.Fatalf("location out of range: %+v", l)
			}
			if fi.Canonical != "" || len(fi.Fingerprint) != 32 {
				t.Fatalf("finding not finalised: %+v", fi)
			}
			if v, _ := json.Marshal(fi); strings.Contains(string(v), seg[l.Start:l.End]) && len(seg[l.Start:l.End]) > 6 {
				t.Fatalf("finding carries the value: %s", v)
			}
		}
	})
}

func builtinForTest() []Detector {
	d, _ := builtin(Config{})
	return d
}

func BenchmarkInspect(b *testing.B) {
	e := NewWith(time.Second, testKey, builtinForTest()...)
	prose := strings.Repeat("Please summarise the quarterly report for the finance committee and list the open risks. ", 12)
	for name, size := range map[string]int{"1KB": 1 << 10, "10KB": 10 << 10, "100KB": 100 << 10} {
		clean := strings.Repeat(prose, size/len(prose)+1)[:size]
		dirty := clean[:size/2] + " contact alice@example.org " + clean[size/2:]
		for kind, txt := range map[string]string{"clean": clean, "match": dirty} {
			req := text(txt)
			b.Run(name+"/"+kind, func(b *testing.B) {
				b.SetBytes(int64(size))
				for i := 0; i < b.N; i++ {
					if _, err := e.Inspect(context.Background(), req); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
