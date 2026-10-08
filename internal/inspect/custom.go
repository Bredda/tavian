package inspect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on what an operator can ask the engine to match, so that a
// configuration cannot make every request slow.
const (
	maxDictionaries   = 50
	maxDictionaryTerm = 10000
	maxTermBytes      = 128
	maxPatterns       = 100
	maxPatternBytes   = 1000
)

// Dictionary is a list of terms to look for: project code names, client names,
// document markings such as "DIFFUSION RESTREINTE".
type Dictionary struct {
	// Name identifies the dictionary; it becomes the subtype of its findings.
	Name     string   `yaml:"name"`
	Severity Severity `yaml:"severity"` // default medium
	Terms    []string `yaml:"terms"`
	// CaseSensitive turns off case folding (default: terms match regardless
	// of case, for all of Unicode).
	CaseSensitive bool `yaml:"case_sensitive"`
	// WholeWord (default true) requires that the term is not inside a longer
	// word.
	WholeWord *bool `yaml:"whole_word"`
}

// Pattern is a regular expression to look for (RE2 syntax: it runs in linear
// time, so a pattern cannot be turned against the gateway).
type Pattern struct {
	Name     string   `yaml:"name"`
	Regex    string   `yaml:"regex"`
	Severity Severity `yaml:"severity"` // default medium
}

var customName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func validSeverity(s Severity) bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

func customDetectors(cfg Config) ([]Detector, error) {
	if len(cfg.Dictionaries) > maxDictionaries {
		return nil, fmt.Errorf("dictionaries: at most %d", maxDictionaries)
	}
	if len(cfg.Patterns) > maxPatterns {
		return nil, fmt.Errorf("patterns: at most %d", maxPatterns)
	}
	var out []Detector
	seen := map[string]bool{}
	claim := func(where, name string) error {
		if !customName.MatchString(name) {
			return fmt.Errorf("%s: name %q must match %s", where, name, customName)
		}
		if seen[name] {
			return fmt.Errorf("%s: duplicate name %q", where, name)
		}
		seen[name] = true
		return nil
	}
	for i, d := range cfg.Dictionaries {
		where := fmt.Sprintf("dictionaries[%d]", i)
		if err := claim(where, d.Name); err != nil {
			return nil, err
		}
		det, err := newDictionary(d)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", where, d.Name, err)
		}
		out = append(out, det)
	}
	for i, p := range cfg.Patterns {
		where := fmt.Sprintf("patterns[%d]", i)
		if err := claim(where, p.Name); err != nil {
			return nil, err
		}
		det, err := newCustomPattern(p)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", where, p.Name, err)
		}
		out = append(out, det)
	}
	return out, nil
}

// --- patterns ---------------------------------------------------------------

type customPattern struct {
	name, version string
	severity      Severity
	re            *regexp.Regexp
}

func newCustomPattern(p Pattern) (*customPattern, error) {
	if p.Severity == "" {
		p.Severity = SeverityMedium
	}
	if !validSeverity(p.Severity) {
		return nil, fmt.Errorf("unknown severity %q", p.Severity)
	}
	if p.Regex == "" || len(p.Regex) > maxPatternBytes {
		return nil, fmt.Errorf("regex: between 1 and %d bytes required", maxPatternBytes)
	}
	re, err := regexp.Compile(p.Regex)
	if err != nil {
		return nil, fmt.Errorf("regex: %w", err)
	}
	if re.MatchString("") {
		return nil, fmt.Errorf("regex: matches the empty string")
	}
	sum := sha256.Sum256([]byte(p.Regex + "\x00" + string(p.Severity)))
	return &customPattern{name: "custom." + p.Name, version: "1:" + hex.EncodeToString(sum[:4]), severity: p.Severity, re: re}, nil
}

func (p *customPattern) Name() string                 { return p.name }
func (p *customPattern) Version() string              { return p.version }
func (p *customPattern) Health(context.Context) error { return nil }

func (p *customPattern) Inspect(ctx context.Context, req Request) ([]Finding, error) {
	var out []Finding
	subtype := strings.TrimPrefix(p.name, "custom.")
	for si, seg := range req.Segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, m := range p.re.FindAllStringIndex(seg.Text, -1) {
			if m[1] <= m[0] {
				continue
			}
			out = append(out, Finding{
				Type: TypeCustom, Subtype: subtype, Severity: p.severity, Confidence: 1,
				Location: Location{Segment: si, Start: m[0], End: m[1]},
			})
		}
	}
	return out, nil
}

// --- dictionaries -----------------------------------------------------------

type dictionary struct {
	name, version string
	severity      Severity
	wholeWord     bool
	fold          bool
	ac            *automaton
}

func newDictionary(d Dictionary) (*dictionary, error) {
	if d.Severity == "" {
		d.Severity = SeverityMedium
	}
	if !validSeverity(d.Severity) {
		return nil, fmt.Errorf("unknown severity %q", d.Severity)
	}
	if len(d.Terms) == 0 || len(d.Terms) > maxDictionaryTerm {
		return nil, fmt.Errorf("terms: between 1 and %d required", maxDictionaryTerm)
	}
	dict := &dictionary{
		name: "custom." + d.Name, severity: d.Severity,
		wholeWord: d.WholeWord == nil || *d.WholeWord, fold: !d.CaseSensitive,
	}
	// The terms go through the same normalization as the text, then folding.
	terms := make([]string, 0, len(d.Terms))
	for _, raw := range d.Terms {
		if !utf8.ValidString(raw) {
			return nil, fmt.Errorf("term is not valid UTF-8")
		}
		term := strings.TrimSpace(normalize(raw))
		switch {
		case utf8.RuneCountInString(term) < 2:
			return nil, fmt.Errorf("terms must have at least 2 characters (%q is too short)", term)
		case len(term) > maxTermBytes:
			return nil, fmt.Errorf("terms are limited to %d bytes", maxTermBytes)
		}
		terms = append(terms, dict.foldString(term))
	}
	sort.Strings(terms)
	terms = slices.Compact(terms)
	dict.ac = newAutomaton(terms)

	h := sha256.New()
	for _, t := range terms {
		h.Write([]byte(t))
		h.Write([]byte{0})
	}
	fmt.Fprintf(h, "%s|%v|%v", d.Severity, dict.wholeWord, dict.fold)
	dict.version = "1:" + hex.EncodeToString(h.Sum(nil)[:4])
	return dict, nil
}

func (d *dictionary) Name() string                 { return d.name }
func (d *dictionary) Version() string              { return d.version }
func (d *dictionary) Health(context.Context) error { return nil }

func (d *dictionary) foldRune(r rune) rune {
	if d.fold {
		return unicode.ToLower(r)
	}
	return r
}

func (d *dictionary) foldString(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteRune(d.foldRune(r))
	}
	return b.String()
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }

func (d *dictionary) Inspect(ctx context.Context, req Request) ([]Finding, error) {
	var out []Finding
	subtype := strings.TrimPrefix(d.name, "custom.")
	for si, seg := range req.Segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		type match struct {
			start, end int
			term       string
		}
		var ms []match
		t := seg.Text
		state := 0
		var enc [utf8.UTFMax]byte
		for pos := 0; pos < len(t); {
			r, size := utf8.DecodeRuneInString(t[pos:])
			pos += size
			n := utf8.EncodeRune(enc[:], d.foldRune(r))
			for _, b := range enc[:n] {
				state = d.ac.step(state, b)
			}
			for o := d.ac.output(state); o >= 0; o = d.ac.next(o) {
				start := d.startOf(t, pos, d.ac.length(o))
				if start < 0 || d.wholeWord && !wholeWordAt(t, start, pos) {
					continue
				}
				ms = append(ms, match{start, pos, d.ac.term(o)})
			}
		}
		// leftmost-longest, without overlaps: "Projet Aurore" hides "Aurore"
		sort.Slice(ms, func(i, j int) bool {
			if ms[i].start != ms[j].start {
				return ms[i].start < ms[j].start
			}
			return ms[i].end > ms[j].end
		})
		last := -1
		for _, m := range ms {
			if m.start < last {
				continue
			}
			last = m.end
			out = append(out, Finding{
				Type: TypeCustom, Subtype: subtype, Severity: d.severity, Confidence: 1,
				Location: Location{Segment: si, Start: m.start, End: m.end}, Canonical: m.term,
			})
		}
	}
	return out, nil
}

// startOf walks back from end over runes of t until their folded encodings add
// up to termLen bytes, and returns where that is (-1 if no rune boundary does).
func (d *dictionary) startOf(t string, end, termLen int) int {
	for pos, got := end, 0; pos > 0; {
		r, size := utf8.DecodeLastRuneInString(t[:pos])
		pos -= size
		got += utf8.RuneLen(d.foldRune(r))
		if got == termLen {
			return pos
		}
		if got > termLen {
			return -1
		}
	}
	return -1
}

func wholeWordAt(t string, start, end int) bool {
	if start > 0 {
		if r, _ := utf8.DecodeLastRuneInString(t[:start]); isWordRune(r) {
			return false
		}
	}
	if end < len(t) {
		if r, _ := utf8.DecodeRuneInString(t[end:]); isWordRune(r) {
			return false
		}
	}
	return true
}

// --- Aho-Corasick -----------------------------------------------------------

// automaton finds all occurrences of a set of byte strings in one pass.
type automaton struct {
	nodes []acNode
	terms []string
}

type acNode struct {
	next map[byte]int
	fail int
	// term is the index of the term ending at this node, or -1.
	term int
	// link is the nearest node on the fail chain that ends a term, or -1.
	link int
}

func newAutomaton(terms []string) *automaton {
	a := &automaton{nodes: []acNode{{next: map[byte]int{}, term: -1, link: -1}}, terms: terms}
	for i, t := range terms {
		s := 0
		for j := 0; j < len(t); j++ {
			n, ok := a.nodes[s].next[t[j]]
			if !ok {
				n = len(a.nodes)
				a.nodes = append(a.nodes, acNode{next: map[byte]int{}, term: -1, link: -1})
				a.nodes[s].next[t[j]] = n
			}
			s = n
		}
		a.nodes[s].term = i
	}
	// breadth-first fail links
	queue := make([]int, 0, len(a.nodes))
	for _, n := range a.nodes[0].next {
		queue = append(queue, n)
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for b, n := range a.nodes[s].next {
			f := a.nodes[s].fail
			for f != 0 {
				if _, ok := a.nodes[f].next[b]; ok {
					break
				}
				f = a.nodes[f].fail
			}
			if to, ok := a.nodes[f].next[b]; ok && to != n {
				f = to
			} else {
				f = 0
			}
			a.nodes[n].fail = f
			if a.nodes[f].term >= 0 {
				a.nodes[n].link = f
			} else {
				a.nodes[n].link = a.nodes[f].link
			}
			queue = append(queue, n)
		}
	}
	return a
}

// step moves from state s on byte b.
func (a *automaton) step(s int, b byte) int {
	for {
		if n, ok := a.nodes[s].next[b]; ok {
			return n
		}
		if s == 0 {
			return 0
		}
		s = a.nodes[s].fail
	}
}

// output returns the first node on the output chain of s that ends a term, as
// a node id, or -1.
func (a *automaton) output(s int) int {
	if a.nodes[s].term >= 0 {
		return s
	}
	return a.nodes[s].link
}

// next continues the output chain after node o.
func (a *automaton) next(o int) int { return a.nodes[o].link }

func (a *automaton) length(o int) int  { return len(a.terms[a.nodes[o].term]) }
func (a *automaton) term(o int) string { return a.terms[a.nodes[o].term] }
