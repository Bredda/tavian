package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bredda/tavian/internal/taxonomy"
)

// APIVersion and the only kind accepted so far.
const (
	APIVersion = "tavian/v1alpha1"
	KindPolicy = "Policy"
)

// Source is one policy file as read from disk. The raw bytes are kept because
// the configuration revision is derived from them and they are stored with it.
type Source struct {
	Name string `json:"name"`
	Raw  []byte `json:"yaml"`
}

// Limits, so that a policy directory cannot make loading or evaluation costly.
const (
	maxSources     = 100
	maxSourceBytes = 256 << 10
	maxDocuments   = 200
	maxRules       = 200
	maxExprBytes   = 1024
	maxPatterns    = 200
)

// Document is one policy as written in YAML. Unknown fields are rejected, and
// fields that are valid in the schema but not implemented yet are decoded into
// raw nodes so they can be refused with an explanation instead of ignored.
type Document struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata names a policy.
type Metadata struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Mode is "enforce" (default) or "shadow".
	Mode string `yaml:"mode"`
}

// Scope says which requests a policy applies to. Exactly one form is valid:
// the organization, or a team and/or an application (both must match).
type Scope struct {
	Organization bool   `yaml:"organization"`
	Team         string `yaml:"team"`
	Application  string `yaml:"application"`
	User         string `yaml:"user"`
}

// Spec is the body of a policy.
type Spec struct {
	Scope          Scope                               `yaml:"scope"`
	Models         ModelsSpec                          `yaml:"models"`
	Destinations   map[taxonomy.Label][]taxonomy.Class `yaml:"destinations"`
	Classification ClassificationSpec                  `yaml:"classification"`

	// Not implemented yet: refused with a message naming where they arrive.
	Inspection yaml.Node `yaml:"inspection"`
	Quotas     yaml.Node `yaml:"quotas"`
	Audit      yaml.Node `yaml:"audit"`
}

// ModelsSpec restricts which models may be used under a policy.
type ModelsSpec struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// ClassificationSpec sets the default label and the rules that raise it.
type ClassificationSpec struct {
	Default taxonomy.Label `yaml:"default"`
	Infer   []InferRule    `yaml:"infer"`
}

// InferRule raises the label of a request when its condition holds for a kind
// of finding.
type InferRule struct {
	ID    string         `yaml:"id"`
	When  string         `yaml:"when"`
	Label taxonomy.Label `yaml:"label"`
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// parseSource reads every document of a source.
func parseSource(src Source) ([]Document, error) {
	if len(src.Raw) > maxSourceBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", src.Name, maxSourceBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(src.Raw))
	dec.KnownFields(true)
	var docs []Document
	for {
		var d Document
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
		if len(docs) == maxDocuments {
			return nil, fmt.Errorf("%s: more than %d documents", src.Name, maxDocuments)
		}
		docs = append(docs, d)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("%s: no policy found", src.Name)
	}
	return docs, nil
}

// validate checks a document and returns every problem found, each prefixed
// with where it is. baseline is true for the built-in policy, which may use the
// reserved name.
func (d *Document) validate(where string, baseline bool) []error {
	var errs []error
	addf := func(format string, args ...any) { errs = append(errs, fmt.Errorf(where+": "+format, args...)) }

	if d.APIVersion != APIVersion {
		addf("apiVersion must be %q (got %q)", APIVersion, d.APIVersion)
	}
	if d.Kind != KindPolicy {
		addf("kind must be %q (got %q)", KindPolicy, d.Kind)
	}
	if !nameRe.MatchString(d.Metadata.Name) {
		addf("metadata.name %q must match %s", d.Metadata.Name, nameRe)
	} else if d.Metadata.Name == baselineName && !baseline {
		addf("metadata.name %q is reserved for the built-in policy", baselineName)
	}
	switch d.Metadata.Mode {
	case "", "enforce":
	case "shadow":
		addf("metadata.mode: shadow is not supported yet")
	default:
		addf("metadata.mode must be enforce or shadow (got %q)", d.Metadata.Mode)
	}

	sc := d.Spec.Scope
	switch {
	case sc.User != "":
		addf("spec.scope.user is not supported yet (scopes: organization, team, application)")
	case sc.Organization && (sc.Team != "" || sc.Application != ""):
		addf("spec.scope: organization cannot be combined with team or application")
	case !sc.Organization && sc.Team == "" && sc.Application == "":
		addf("spec.scope is required: organization: true, or a team and/or an application")
	}

	checkPatterns := func(field string, patterns []string) {
		if len(patterns) > maxPatterns {
			addf("%s: at most %d patterns", field, maxPatterns)
		}
		for _, p := range patterns {
			if p == "" || len(p) > 128 {
				addf("%s: patterns must be 1 to 128 bytes", field)
			}
		}
	}
	checkPatterns("spec.models.allow", d.Spec.Models.Allow)
	checkPatterns("spec.models.deny", d.Spec.Models.Deny)

	for label, classes := range d.Spec.Destinations {
		if label.Rank() < 0 {
			addf("spec.destinations: unknown label %q", label)
		}
		for _, c := range classes {
			if !c.Valid() {
				addf("spec.destinations.%s: unknown destination class %q", label, c)
			}
		}
	}

	if def := d.Spec.Classification.Default; def != "" && def.Rank() < 0 {
		addf("spec.classification.default: unknown label %q", def)
	}
	if len(d.Spec.Classification.Infer) > maxRules {
		addf("spec.classification.infer: at most %d rules", maxRules)
	}
	for i, r := range d.Spec.Classification.Infer {
		at := fmt.Sprintf("spec.classification.infer[%d]", i)
		if r.ID != "" && !nameRe.MatchString(r.ID) {
			addf("%s: id %q must match %s", at, r.ID, nameRe)
		}
		if strings.TrimSpace(r.When) == "" {
			addf("%s: when is required", at)
		}
		if len(r.When) > maxExprBytes {
			addf("%s: when is longer than %d bytes", at, maxExprBytes)
		}
		if r.Label.Rank() < 0 {
			addf("%s: label must be one of public, internal, confidential, restricted (got %q)", at, r.Label)
		}
	}

	for _, ns := range []struct {
		field string
		node  yaml.Node
		when  string
	}{
		{"spec.inspection", d.Spec.Inspection, "a later change"},
		{"spec.quotas", d.Spec.Quotas, "quotas (M2 step 2.5)"},
		{"spec.audit", d.Spec.Audit, "the audit trail work (M2 step 2.6 and M4)"},
	} {
		if !ns.node.IsZero() {
			addf("%s is not supported yet; it arrives with %s", ns.field, ns.when)
		}
	}
	return errs
}
