package inspect

import (
	"fmt"
	"sort"
	"strings"
)

// Redaction is the result of Redact.
type Redaction struct {
	// Replacements maps a segment index to its new text: the normalized text
	// with the chosen findings replaced by placeholders.
	Replacements map[int]string
	// Counts is how many spans were replaced per "type.subtype".
	Counts map[string]int
}

// Redact replaces the findings chosen by pick with typed placeholders such as
// [IBAN_1]. The same value (same fingerprint) gets the same number within a
// request, so a model can still tell that two mentions are one thing. Findings
// that overlap are replaced as one span, by the placeholder of the first.
//
// The replaced text is the normalized text of the segment, not the original:
// the findings' offsets refer to it.
func Redact(req Request, findings []Finding, pick func(Finding) bool) Redaction {
	bySegment := map[int][]Finding{}
	for _, f := range findings {
		if pick(f) {
			bySegment[f.Location.Segment] = append(bySegment[f.Location.Segment], f)
		}
	}
	out := Redaction{Replacements: map[int]string{}, Counts: map[string]int{}}
	numbers := map[string]map[string]int{} // placeholder name -> fingerprint -> n

	segs := make([]int, 0, len(bySegment))
	for s := range bySegment {
		segs = append(segs, s)
	}
	sort.Ints(segs)
	for _, si := range segs {
		fs := bySegment[si]
		sort.SliceStable(fs, func(i, j int) bool {
			if fs[i].Location.Start != fs[j].Location.Start {
				return fs[i].Location.Start < fs[j].Location.Start
			}
			return fs[i].Location.End > fs[j].Location.End
		})
		text := Normalize(req.Segments[si].Text)
		var b strings.Builder
		at := 0
		for i := 0; i < len(fs); {
			f := fs[i]
			start, end := f.Location.Start, f.Location.End
			j := i + 1
			for j < len(fs) && fs[j].Location.Start < end { // overlapping: one span
				end = max(end, fs[j].Location.End)
				j++
			}
			if start < at || end > len(text) {
				i = j
				continue // outside the text, or inside what was just replaced
			}
			name := placeholderName(f.Subtype)
			if numbers[name] == nil {
				numbers[name] = map[string]int{}
			}
			n, seen := numbers[name][f.Fingerprint]
			if !seen {
				n = len(numbers[name]) + 1
				numbers[name][f.Fingerprint] = n
			}
			b.WriteString(text[at:start])
			fmt.Fprintf(&b, "[%s_%d]", name, n)
			at = end
			out.Counts[string(f.Type)+"."+f.Subtype]++
			i = j
		}
		b.WriteString(text[at:])
		out.Replacements[si] = b.String()
	}
	return out
}

// placeholderName turns a subtype into the word inside a placeholder.
func placeholderName(subtype string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(subtype) {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "REDACTED"
	}
	return b.String()
}
