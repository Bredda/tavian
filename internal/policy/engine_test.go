package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/taxonomy"
)

func compile(t *testing.T, files ...string) *Engine {
	t.Helper()
	e, err := compileErr(files...)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return e
}

func compileErr(files ...string) (*Engine, error) {
	var src []Source
	for i, f := range files {
		src = append(src, Source{Name: "p" + string(rune('a'+i)) + ".yaml", Raw: []byte(f)})
	}
	return Compile(src)
}

func kind(typ inspect.Type, sub string) inspect.Kind {
	return inspect.Kind{Type: typ, Subtype: sub, Severity: inspect.SeverityHigh, Confidence: 0.9, Count: 1}
}

func decide(t *testing.T, e *Engine, id Identity, declared taxonomy.Label, kinds ...inspect.Kind) Decision {
	t.Helper()
	d, err := e.Decide(Input{Identity: id, Request: Request{Model: "m"}, Declared: declared, Kinds: kinds})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The built-in baseline alone behaves as the tables of the previous step did.
func TestBaselineClassification(t *testing.T) {
	e := compile(t)
	for _, c := range []struct {
		name     string
		declared taxonomy.Label
		kinds    []inspect.Kind
		want     taxonomy.Label
		inferred taxonomy.Label
	}{
		{"nothing found", "", nil, taxonomy.Internal, ""},
		{"e-mail alone", "", []inspect.Kind{kind("pii", "email")}, taxonomy.Internal, ""},
		{"phone and ip", "", []inspect.Kind{kind("pii", "phone"), kind("pii", "ipv4")}, taxonomy.Internal, ""},
		{"iban", "", []inspect.Kind{kind("pii", "iban")}, taxonomy.Confidential, taxonomy.Confidential},
		{"card", "", []inspect.Kind{kind("pii", "payment_card")}, taxonomy.Confidential, taxonomy.Confidential},
		{"nir", "", []inspect.Kind{kind("pii", "nir")}, taxonomy.Confidential, taxonomy.Confidential},
		{"any secret", "", []inspect.Kind{kind("secret", "aws_access_key")}, taxonomy.Restricted, taxonomy.Restricted},
		{"the most sensitive wins", "", []inspect.Kind{kind("pii", "iban"), kind("secret", "jwt"), kind("pii", "email")}, taxonomy.Restricted, taxonomy.Restricted},
		{"custom detectors do not raise the label", "", []inspect.Kind{kind("custom", "codenames")}, taxonomy.Internal, ""},
		{"declared raises", taxonomy.Confidential, nil, taxonomy.Confidential, ""},
		{"declared cannot lower what is inferred", taxonomy.Public, []inspect.Kind{kind("pii", "iban")}, taxonomy.Confidential, taxonomy.Confidential},
		{"declared public cannot lower the default", taxonomy.Public, nil, taxonomy.Internal, ""},
		{"declared above inferred", taxonomy.Restricted, []inspect.Kind{kind("pii", "iban")}, taxonomy.Restricted, taxonomy.Confidential},
	} {
		d := decide(t, e, Identity{}, c.declared, c.kinds...)
		if d.Label != c.want || d.Sources.Inferred != c.inferred || d.Sources.Declared != c.declared || d.Sources.Default != taxonomy.Internal {
			t.Errorf("%s: %+v, want label %s inferred %q", c.name, d, c.want, c.inferred)
		}
		if d.Constraints.Label != d.Label {
			t.Errorf("%s: constraints are for %s", c.name, d.Constraints.Label)
		}
	}
	d := decide(t, e, Identity{}, "", kind("pii", "iban"), kind("secret", "jwt"))
	if strings.Join(d.Matched, ",") != "baseline/financial-and-national-ids-are-confidential,baseline/secret-is-restricted" &&
		strings.Join(d.Matched, ",") != "baseline/secret-is-restricted,baseline/financial-and-national-ids-are-confidential" {
		t.Errorf("matched = %v, want both baseline rules named", d.Matched)
	}
}

func TestBaselineDestinations(t *testing.T) {
	e := compile(t)
	internal := [2]any{taxonomy.ClassInternal, taxonomy.Restricted}
	partner := [2]any{taxonomy.ClassApprovedExternal, taxonomy.Internal}
	partnerTrusted := [2]any{taxonomy.ClassApprovedExternal, taxonomy.Restricted} // an operator may vouch for a provider
	public := [2]any{taxonomy.ClassPublicExternal, taxonomy.Public}
	excl := func(label taxonomy.Label, b [2]any) string {
		d := decide(t, e, Identity{}, label)
		return d.Constraints.Excludes(b[0].(taxonomy.Class), b[1].(taxonomy.Label))
	}
	// Declaring "public" cannot go below the default, so test the table through
	// the constraints of each label directly.
	for _, c := range []struct {
		label taxonomy.Label
		b     [2]any
		want  string
	}{
		{taxonomy.Internal, internal, ""},
		{taxonomy.Internal, partner, ""},
		{taxonomy.Internal, public, ExcludedClearance},
		{taxonomy.Confidential, internal, ""},
		{taxonomy.Confidential, partner, ExcludedClearance},
		{taxonomy.Confidential, partnerTrusted, ExcludedClass}, // the backend's own clearance is not enough
		{taxonomy.Restricted, partnerTrusted, ExcludedClass},
		{taxonomy.Restricted, internal, ""},
		{taxonomy.Restricted, public, ExcludedClearance},
	} {
		if got := excl(c.label, c.b); got != c.want {
			t.Errorf("%s -> %v: %q, want %q", c.label, c.b, got, c.want)
		}
	}
	// the public row exists in the table even though no request defaults to it
	if got := classesFor(e.policies, taxonomy.Public); len(got) != 3 {
		t.Errorf("public may go to %v", got)
	}
	if got := classesFor(e.policies, "bogus"); len(got) != 0 {
		t.Errorf("an unknown label allows %v", got)
	}
}

const financeTeam = `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: finance }
spec:
  scope: { team: finance }
  models:
    allow: ["llama-*", "mistral-large"]
    deny: ["*-preview"]
  destinations:
    internal: [internal]
  classification:
    default: confidential
`

func TestScopesSelectPolicies(t *testing.T) {
	e := compile(t, financeTeam, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: ledger-app }
spec:
  scope: { team: finance, application: ledger }
  classification: { default: restricted }
---
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: any-notebook }
spec:
  scope: { application: notebook }
  classification: { default: confidential }
`)
	if got := strings.Join(e.Names(), ","); got != "baseline,finance,ledger-app,any-notebook" {
		t.Errorf("policies = %s", got)
	}
	for _, c := range []struct {
		who  Identity
		want taxonomy.Label
	}{
		{Identity{Team: "research"}, taxonomy.Internal},
		{Identity{Team: "finance"}, taxonomy.Confidential},
		{Identity{Team: "finance", Application: "ledger"}, taxonomy.Restricted},
		{Identity{Team: "finance", Application: "other"}, taxonomy.Confidential},
		{Identity{Team: "research", Application: "ledger"}, taxonomy.Internal}, // both team and application must match
		{Identity{Team: "research", Application: "notebook"}, taxonomy.Confidential},
	} {
		if got := decide(t, e, c.who, "").Label; got != c.want {
			t.Errorf("%+v: default label %s, want %s", c.who, got, c.want)
		}
	}
}

func TestPoliciesOnlyNarrow(t *testing.T) {
	e := compile(t, financeTeam, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: greedy }
spec:
  scope: { team: finance }
  destinations:
    confidential: [internal, approved-external, public-external]
    internal: [internal, approved-external]
`)
	fin := Identity{Team: "finance"}
	// the team default is confidential; the team's narrower table and the greedy
	// policy's wider one intersect with the baseline: still internal only
	d := decide(t, e, fin, "")
	if d.Label != taxonomy.Confidential || len(d.Constraints.Classes) != 1 || d.Constraints.Classes[0] != taxonomy.ClassInternal {
		t.Errorf("finance: %+v", d)
	}
	// the "internal" row narrowed by the finance policy applies to it only
	other := decide(t, e, Identity{Team: "research"}, "")
	if len(other.Constraints.Classes) != 2 {
		t.Errorf("research: %v, want internal and approved-external", other.Constraints.Classes)
	}
	// and the greedy policy is told that it widens nothing
	w := strings.Join(e.Warnings(), "\n")
	if !strings.Contains(w, "policy greedy: destinations.confidential lists approved-external") || !strings.Contains(w, "public-external") {
		t.Errorf("warnings = %q", w)
	}
	if strings.Contains(w, "policy finance") {
		t.Errorf("a narrowing policy got a warning: %q", w)
	}
}

func TestModelAuthorization(t *testing.T) {
	e := compile(t, financeTeam)
	fin, other := Identity{Team: "finance"}, Identity{Team: "research"}
	for _, c := range []struct {
		who     Identity
		model   string
		allowed bool
		policy  string
	}{
		{fin, "llama-70b", true, ""},
		{fin, "mistral-large", true, ""},
		{fin, "gpt-4", false, "finance"},           // not in the allow list
		{fin, "llama-3-preview", false, "finance"}, // deny wins over allow
		{other, "gpt-4", true, ""},                 // the finance policy does not apply to research
		{other, "llama-3-preview", true, ""},
	} {
		v := e.AuthorizeModel(c.who, c.model)
		if v.Allowed != c.allowed || v.Policy != c.policy {
			t.Errorf("%s %s: %+v, want allowed=%v by %q", c.who.Team, c.model, v, c.allowed, c.policy)
		}
	}
}

func TestInferRulesCanUseTheFindingAndTheCaller(t *testing.T) {
	e := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: org }
spec:
  scope: { organization: true }
  classification:
    infer:
      - id: codenames
        when: finding.type == "custom" && finding.subtype == "codenames"
        label: confidential
      - id: many-emails
        when: finding.subtype == "email" && finding.count >= 10
        label: confidential
      - id: sure-phones-from-notebooks
        when: finding.subtype == "phone" && finding.confidence > 0.8 && identity.application == "notebook"
        label: confidential
      - id: severe-from-tools
        when: finding.severity == "critical" && request.has_tools
        label: restricted
`)
	one := kind("pii", "email")
	many := inspect.Kind{Type: "pii", Subtype: "email", Severity: inspect.SeverityMedium, Confidence: 0.9, Count: 12}
	phone := inspect.Kind{Type: "pii", Subtype: "phone", Severity: inspect.SeverityMedium, Confidence: 0.85, Count: 1}
	codes := kind("custom", "codenames")

	if got := decide(t, e, Identity{}, "", codes).Label; got != taxonomy.Confidential {
		t.Errorf("custom detector rule: %s", got)
	}
	if got := decide(t, e, Identity{}, "", one).Label; got != taxonomy.Internal {
		t.Errorf("one e-mail: %s", got)
	}
	if got := decide(t, e, Identity{}, "", many).Label; got != taxonomy.Confidential {
		t.Errorf("many e-mails: %s", got)
	}
	if got := decide(t, e, Identity{Application: "notebook"}, "", phone).Label; got != taxonomy.Confidential {
		t.Errorf("phone from a notebook: %s", got)
	}
	if got := decide(t, e, Identity{Application: "web"}, "", phone).Label; got != taxonomy.Internal {
		t.Errorf("phone from elsewhere: %s", got)
	}
	d, _ := e.Decide(Input{Request: Request{HasTools: true}, Kinds: []inspect.Kind{{Type: "secret", Subtype: "x", Severity: inspect.SeverityCritical}}})
	if d.Label != taxonomy.Restricted || len(d.Matched) == 0 {
		t.Errorf("request fields in a rule: %+v", d)
	}
}

func TestAtLeast(t *testing.T) {
	e := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: order }
spec:
  scope: { organization: true }
  classification:
    infer:
      - { id: ok, when: '"confidential".atLeast("internal") && !"internal".atLeast("restricted")', label: restricted }
`)
	if got := decide(t, e, Identity{}, "", kind("any", "thing")).Label; got != taxonomy.Restricted {
		t.Errorf("atLeast ordering is wrong: %s", got)
	}
	if _, err := compileErr(`
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: order }
spec:
  scope: { organization: true }
  classification:
    infer:
      - { id: bad, when: '"secret".atLeast("internal")', label: restricted }
`); err == nil {
		t.Error(`atLeast with an unknown label must fail at load time (it is evaluated on a sample)`)
	}
}

func TestInvalidPolicies(t *testing.T) {
	head := "apiVersion: tavian/v1alpha1\nkind: Policy\n"
	for name, c := range map[string]struct{ doc, want string }{
		"typo in a field":     {head + "metadata: { name: x }\nspec:\n  scope: { organization: true }\n  modles: {}\n", "modles"},
		"wrong api version":   {"apiVersion: v2\nkind: Policy\nmetadata: { name: x }\nspec: { scope: { organization: true } }", "apiVersion"},
		"wrong kind":          {"apiVersion: tavian/v1alpha1\nkind: Rule\nmetadata: { name: x }\nspec: { scope: { organization: true } }", "kind must be"},
		"missing name":        {head + "spec: { scope: { organization: true } }", "metadata.name"},
		"reserved name":       {head + "metadata: { name: baseline }\nspec: { scope: { organization: true } }", "reserved"},
		"no scope":            {head + "metadata: { name: x }\nspec: {}", "scope is required"},
		"org with team":       {head + "metadata: { name: x }\nspec: { scope: { organization: true, team: a } }", "cannot be combined"},
		"user scope":          {head + "metadata: { name: x }\nspec: { scope: { user: bob } }", "scope.user is not supported yet"},
		"shadow mode":         {head + "metadata: { name: x, mode: shadow }\nspec: { scope: { organization: true } }", "shadow is not supported yet"},
		"unknown mode":        {head + "metadata: { name: x, mode: loud }\nspec: { scope: { organization: true } }", "mode must be"},
		"quotas":              {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [] }", "spec.quotas is not supported yet"},
		"audit":               {head + "metadata: { name: x }\nspec: { scope: { organization: true }, audit: { content: hash } }", "spec.audit is not supported yet"},
		"inspection":          {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { on_error: block } }", "spec.inspection is not supported yet"},
		"unknown label":       {head + "metadata: { name: x }\nspec: { scope: { organization: true }, destinations: { secret: [internal] } }", "unknown label"},
		"unknown class":       {head + "metadata: { name: x }\nspec: { scope: { organization: true }, destinations: { internal: [moon] } }", "unknown destination class"},
		"unknown default":     {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { default: tiny } }", "unknown label"},
		"rule without label":  {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { when: 'true' } ] } }", "label must be one of"},
		"rule without when":   {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { label: restricted } ] } }", "when is required"},
		"syntax error":        {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'finding.type ==', label: restricted } ] } }", "Syntax error"},
		"misspelled field":    {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'finding.subtyp == \"iban\"', label: restricted } ] } }", "check the field names"},
		"not a boolean":       {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'finding.count + 1', label: restricted } ] } }", "true or false"},
		"unknown variable":    {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'label == \"x\"', label: restricted } ] } }", "undeclared reference"},
		"duplicate rule id":   {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'true', label: restricted }, { id: r, when: 'true', label: restricted } ] } }", "duplicate id"},
		"expression too long": {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: '" + strings.Repeat("true && ", 200) + "true', label: restricted } ] } }", "longer than"},
		"empty file":          {"", "no policy found"},
	} {
		_, err := compileErr(c.doc)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, c.want)
		}
	}

	// names must be unique across files and documents
	one := head + "metadata: { name: same }\nspec: { scope: { organization: true } }"
	if _, err := compileErr(one, one); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("duplicate policy name: %v", err)
	}
	// every problem is reported, not only the first
	_, err := compileErr(head+"metadata: { name: a }\nspec: { scope: {} }", head+"metadata: { name: b }\nspec: { scope: {}, quotas: [] }")
	if err == nil || strings.Count(err.Error(), "scope is required") != 2 || !strings.Contains(err.Error(), "quotas") {
		t.Errorf("errors = %v", err)
	}
	if _, err := Compile(make([]Source, maxSources+1)); err == nil {
		t.Error("too many files must be refused")
	}
	if _, err := Compile([]Source{{Name: "big.yaml", Raw: make([]byte, maxSourceBytes+1)}}); err == nil {
		t.Error("a huge file must be refused")
	}
}

func TestRuntimeErrorsFailClosed(t *testing.T) {
	// a rule that fails on the sample input is refused at load time...
	if _, err := compileErr(`
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: x }
spec:
  scope: { organization: true }
  classification:
    infer:
      - { id: div, when: '10 / finding.count == 1', label: restricted }
`); err == nil || !strings.Contains(err.Error(), "division by zero") {
		t.Errorf("load-time check: %v", err)
	}
	// ...and one that only fails for some inputs fails the decision, naming the rule
	e2, err := compileErr(`
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: x }
spec:
  scope: { organization: true }
  classification:
    infer:
      - { id: div, when: 'finding.count == 0 || 10 / (finding.count - 1) == 1', label: restricted }
`)
	if err != nil {
		t.Fatal(err)
	}
	_, derr := e2.Decide(Input{Kinds: []inspect.Kind{{Type: "t", Subtype: "s", Count: 1}}})
	if derr == nil || !strings.Contains(derr.Error(), "x/div") {
		t.Errorf("a rule that fails to evaluate must fail the decision and name the rule: %v", derr)
	}
}

func TestAssertRecomputesTheConstraints(t *testing.T) {
	e := compile(t)
	id := Identity{Team: "t"}
	if err := e.Assert(id, taxonomy.Confidential, "local", taxonomy.ClassInternal, taxonomy.Restricted); err != nil {
		t.Errorf("internal backend for confidential data: %v", err)
	}
	for _, b := range []struct {
		class taxonomy.Class
		max   taxonomy.Label
	}{
		{taxonomy.ClassApprovedExternal, taxonomy.Restricted},
		{taxonomy.ClassInternal, taxonomy.Internal},
		{taxonomy.ClassPublicExternal, taxonomy.Public},
	} {
		if err := e.Assert(id, taxonomy.Confidential, "bad", b.class, b.max); err == nil {
			t.Errorf("a %s backend (max %s) passed the assertion for confidential data", b.class, b.max)
		}
	}
	// a team policy that narrows is honoured by the assertion too
	narrow := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: closed }
spec:
  scope: { team: t }
  destinations:
    internal: [internal]
`)
	if err := narrow.Assert(id, taxonomy.Internal, "partner", taxonomy.ClassApprovedExternal, taxonomy.Internal); err == nil {
		t.Error("the team policy forbids external destinations for internal data")
	}
	if err := narrow.Assert(Identity{Team: "other"}, taxonomy.Internal, "partner", taxonomy.ClassApprovedExternal, taxonomy.Internal); err != nil {
		t.Errorf("another team is not affected: %v", err)
	}
}

func TestConstraintsExcludeUnknownLabels(t *testing.T) {
	c := Constraints{Label: "bogus"}
	if c.Excludes(taxonomy.ClassInternal, taxonomy.Restricted) == "" {
		t.Error("an unknown label must not be routable anywhere")
	}
}

func TestParseDeclared(t *testing.T) {
	for in, want := range map[string]taxonomy.Label{"confidential": taxonomy.Confidential, " Restricted ": taxonomy.Restricted, "PUBLIC": taxonomy.Public} {
		if got, err := ParseDeclared([]string{in}); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if got, err := ParseDeclared(nil); err != nil || got != "" {
		t.Errorf("no header: %q %v", got, err)
	}
	for _, bad := range [][]string{{"secret"}, {""}, {"confidential", "public"}, {"top secret"}} {
		if _, err := ParseDeclared(bad); !errors.Is(err, ErrBadLabel) {
			t.Errorf("%q: err = %v, want ErrBadLabel", bad, err)
		}
	}
}

// The default label is the most sensitive among the policies that apply,
// whatever their order: a narrower scope cannot lower it.
func TestDefaultLabelIsTheHighestNotTheLast(t *testing.T) {
	e := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: strict }
spec:
  scope: { organization: true }
  classification: { default: restricted }
`, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: relaxed }
spec:
  scope: { team: finance }
  classification: { default: public }
`)
	if got := decide(t, e, Identity{Team: "finance"}, "").Label; got != taxonomy.Restricted {
		t.Errorf("default label = %s: a team policy lowered the organization's default", got)
	}
}
