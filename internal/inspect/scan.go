package inspect

import "context"

// hit is one match found by a matchFunc. Zero fields mean "the scanner's
// default".
type hit struct {
	start, end int
	canon      string
	subtype    string
	severity   Severity
	confidence float64
}

// matchFunc tries to match at byte offset i of t, where t[i] is one of the
// scanner's start bytes.
type matchFunc func(t string, i int) (hit, bool)

// scanner is the shape of the built-in detectors: one pass over the text, a
// cheap table lookup rejects most bytes, and a hand-written matcher looks at
// the few positions that could start a value. Unlike a regular expression
// run over the whole prompt this stays fast on large inputs, and the work per
// candidate is bounded by the length of the longest value.
type scanner struct {
	name, version string
	typ           Type
	subtype       string
	severity      Severity
	confidence    float64
	starts        [256]bool
	match         matchFunc
}

func newScanner(name string, typ Type, subtype string, sev Severity, conf float64, starts string, m matchFunc) *scanner {
	s := &scanner{name: name, version: "1", typ: typ, subtype: subtype, severity: sev, confidence: conf, match: m}
	for i := 0; i < len(starts); i++ {
		s.starts[starts[i]] = true
	}
	return s
}

func (s *scanner) Name() string                 { return s.name }
func (s *scanner) Version() string              { return s.version }
func (s *scanner) Health(context.Context) error { return nil }

func (s *scanner) Inspect(ctx context.Context, req Request) ([]Finding, error) {
	var out []Finding
	for si, seg := range req.Segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		t := seg.Text
		for i := 0; i < len(t); i++ {
			if !s.starts[t[i]] {
				continue
			}
			h, ok := s.match(t, i)
			if !ok || h.end <= i {
				continue
			}
			f := Finding{
				Type: s.typ, Subtype: s.subtype, Severity: s.severity, Confidence: s.confidence,
				Location:  Location{Segment: si, Start: h.start, End: h.end},
				Canonical: h.canon,
			}
			if h.subtype != "" {
				f.Subtype = h.subtype
			}
			if h.severity != "" {
				f.Severity = h.severity
			}
			if h.confidence != 0 {
				f.Confidence = h.confidence
			}
			out = append(out, f)
			i = h.end - 1
		}
	}
	return out, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
func isAlnum(c byte) bool { return isDigit(c) || isLetter(c) }

func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 32
	}
	return c
}

// boundaryBefore says that t[i] does not continue a word that started earlier.
func boundaryBefore(t string, i int) bool { return i == 0 || !isAlnum(t[i-1]) }

// boundaryAfter says that the byte at end does not continue the match.
func boundaryAfter(t string, end int) bool { return end >= len(t) || !isAlnum(t[end]) }
