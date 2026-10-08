package inspect

import (
	"context"
	"regexp"
	"strings"
)

// emailDomain matches the domain part at the start of its input. Candidates
// are cut around each "@" first, so the expression only ever sees at most 255
// bytes: scanning a large prompt costs one pass looking for '@', not a regular
// expression over every byte.
var emailDomain = regexp.MustCompile(`^[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}`)

const (
	maxEmailLocal  = 64
	maxEmailDomain = 255
)

type email struct{}

func (email) Name() string                 { return "pii.email" }
func (email) Version() string              { return "2" }
func (email) Health(context.Context) error { return nil }

func isEmailLocal(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == '%' || c == '+' || c == '-'
}

func isEmailDomain(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-'
}

func (email) Inspect(ctx context.Context, req Request) ([]Finding, error) {
	var out []Finding
	for i, seg := range req.Segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		t := seg.Text
		for from := 0; from < len(t); {
			j := strings.IndexByte(t[from:], '@')
			if j < 0 {
				break
			}
			at := from + j
			from = at + 1

			start := at
			for start > 0 && at-start < maxEmailLocal && isEmailLocal(t[start-1]) {
				start--
			}
			if start == at {
				continue
			}
			end := at + 1
			for end < len(t) && end-(at+1) < maxEmailDomain && isEmailDomain(t[end]) {
				end++
			}
			m := emailDomain.FindStringIndex(t[at+1 : end])
			if m == nil {
				continue
			}
			end = at + 1 + m[1]
			out = append(out, Finding{
				Type: TypePII, Subtype: "email", Severity: SeverityMedium, Confidence: 0.9,
				Location:  Location{Segment: i, Start: start, End: end},
				Canonical: strings.ToLower(t[start:end]),
			})
		}
	}
	return out, nil
}
