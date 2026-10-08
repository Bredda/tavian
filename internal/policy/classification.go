// Package policy decides what may happen to a request given who sends it, what
// it contains and where it could go. Classification comes first: the label of
// a request is the most sensitive of what the caller declared, the default
// label, and what inspection inferred (docs/SECURITY.md#data-classification).
//
// The inference table below is the built-in default policy. The declarative
// policy engine (YAML + CEL, docs/POLICY.md, ADR-0006) will load this same
// shape from configuration; nothing here is a stopgap.
package policy

import (
	"errors"
	"strings"

	"github.com/bredda/tavian/internal/config"
)

// DefaultLabel is the label of a request that declares nothing and contains
// nothing recognised.
const DefaultLabel = config.LabelInternal

// DeclaredHeader is the request header with which an application raises the
// label of a request.
const DeclaredHeader = "X-Tavian-Classification"

// ErrBadLabel means the declared label is not one of the known labels.
var ErrBadLabel = errors.New("unknown classification label")

// rule maps findings to a minimum label. kind is "type.subtype", or "type.*"
// for every subtype of a type.
type rule struct {
	kind  string
	label config.Classification
}

// inference is the built-in default: secrets never leave the organization,
// identifiers of people and accounts stay on internal destinations. E-mail
// addresses, phone numbers and IP addresses are not raised on their own: the
// default label already keeps them internal.
var inference = []rule{
	{"secret.*", config.LabelRestricted},
	{"pii.iban", config.LabelConfidential},
	{"pii.payment_card", config.LabelConfidential},
	{"pii.nir", config.LabelConfidential},
}

// LabelSources says where the label of a request comes from. Empty means the
// source did not apply.
type LabelSources struct {
	Declared config.Classification `json:"declared,omitempty"`
	Default  config.Classification `json:"default"`
	Inferred config.Classification `json:"inferred,omitempty"`
}

// Classification is the label of a request and how it was reached.
type Classification struct {
	Label   config.Classification
	Sources LabelSources
}

// Classify computes the effective label: the most sensitive of declared (may be
// empty), the default, and what the kinds found by inspection imply. A caller
// can raise the label, never lower it below what inspection infers.
func Classify(declared config.Classification, kinds []string) Classification {
	c := Classification{Label: DefaultLabel, Sources: LabelSources{Declared: declared, Default: DefaultLabel, Inferred: infer(kinds)}}
	for _, l := range []config.Classification{declared, c.Sources.Inferred} {
		if l.Rank() > c.Label.Rank() {
			c.Label = l
		}
	}
	return c
}

func infer(kinds []string) config.Classification {
	var out config.Classification
	for _, k := range kinds {
		for _, r := range inference {
			if r.matches(k) && r.label.Rank() > out.Rank() {
				out = r.label
			}
		}
	}
	return out
}

func (r rule) matches(kind string) bool {
	if prefix, ok := strings.CutSuffix(r.kind, ".*"); ok {
		return strings.HasPrefix(kind, prefix+".")
	}
	return kind == r.kind
}

// Exceeds reports whether the label is more sensitive than a clearance.
func (c Classification) Exceeds(clearance config.Classification) bool {
	return c.Label.Rank() > clearance.Rank()
}

// ParseDeclared reads the values of the DeclaredHeader header. No value is
// fine (empty label); one known label is returned; anything else is an error.
func ParseDeclared(values []string) (config.Classification, error) {
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		l := config.Classification(strings.ToLower(strings.TrimSpace(values[0])))
		if l.Rank() < 0 {
			return "", ErrBadLabel
		}
		return l, nil
	}
	return "", ErrBadLabel
}
