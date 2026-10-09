package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/quota"
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
		"typo in a field":       {head + "metadata: { name: x }\nspec:\n  scope: { organization: true }\n  modles: {}\n", "modles"},
		"wrong api version":     {"apiVersion: v2\nkind: Policy\nmetadata: { name: x }\nspec: { scope: { organization: true } }", "apiVersion"},
		"wrong kind":            {"apiVersion: tavian/v1alpha1\nkind: Rule\nmetadata: { name: x }\nspec: { scope: { organization: true } }", "kind must be"},
		"missing name":          {head + "spec: { scope: { organization: true } }", "metadata.name"},
		"reserved name":         {head + "metadata: { name: baseline }\nspec: { scope: { organization: true } }", "reserved"},
		"no scope":              {head + "metadata: { name: x }\nspec: {}", "scope is required"},
		"org with team":         {head + "metadata: { name: x }\nspec: { scope: { organization: true, team: a } }", "cannot be combined"},
		"user scope":            {head + "metadata: { name: x }\nspec: { scope: { user: bob } }", "scope.user is not supported yet"},
		"unknown mode":          {head + "metadata: { name: x, mode: loud }\nspec: { scope: { organization: true } }", "mode must be"},
		"quota budget window":   {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: budget_eur, limit: 5, window: 1d } ] }", "window of budget_eur is month"},
		"quota budget huge":     {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: budget_eur, limit: 9000000000000 } ] }", "whole number of euros"},
		"quota string limit":    {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: rpm, limit: \"5\" } ] }", "not a whole number"},
		"quota exponent":        {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: rpm, limit: 1e3 } ] }", "not a whole number"},
		"quota budget decimal":  {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: budget_eur, limit: 2.5 } ] }", "not a whole number"},
		"quota unknown":         {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: rps, limit: 5 } ] }", "dimension must be one of"},
		"quota zero":            {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: rpm, limit: 0 } ] }", "limit must be at least 1"},
		"quota missing limit":   {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: rpm } ] }", "limit must be at least 1"},
		"quota duplicate":       {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: rpm, limit: 1 }, { dimension: rpm, limit: 2 } ] }", "already limited"},
		"quota window":          {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: rpm, limit: 1, window: 1h } ] }", "window of rpm is 1m"},
		"quota window none":     {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: concurrency, limit: 1, window: 1m } ] }", "concurrency has no window"},
		"quota mode":            {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: rpm, limit: 1, mode: firm } ] }", "mode must be hard or soft"},
		"quota typo":            {head + "metadata: { name: x }\nspec: { scope: { organization: true }, quotas: [ { dimension: rpm, limit: 1, per: user } ] }", "per"},
		"audit":                 {head + "metadata: { name: x }\nspec: { scope: { organization: true }, audit: { content: hash } }", "spec.audit is not supported yet"},
		"response inspection":   {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { response: { mode: observe } } }", "spec.inspection.response is not supported yet"},
		"rulesets":              {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { request: { rulesets: [a] } } }", "rulesets is not supported yet"},
		"on_error allow":        {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { on_error: allow } }", "always refused"},
		"on_error junk":         {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { on_error: shrug } }", "on_error must be block"},
		"unknown action":        {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { request: { on_finding: [ { when: 'true', action: delete } ] } } }", "action must be one of"},
		"action without when":   {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { request: { on_finding: [ { action: block } ] } } }", "when is required"},
		"reason on a redact":    {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { request: { on_finding: [ { when: 'true', action: redact, reason: NOPE } ] } } }", "reason is for block rules"},
		"lower-case reason":     {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { request: { on_finding: [ { when: 'true', action: block, reason: nope } ] } } }", "reason is for block rules"},
		"classes on a block":    {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { request: { on_finding: [ { when: 'true', action: block, classes: [internal] } ] } } }", "classes is only for restrict_destinations"},
		"unknown class in rule": {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { request: { on_finding: [ { when: 'true', action: restrict_destinations, classes: [moon] } ] } } }", "unknown destination class"},
		"action rule typo":      {head + "metadata: { name: x }\nspec: { scope: { organization: true }, inspection: { request: { on_finding: [ { id: r, when: 'finding.subtyp == \"x\"', action: flag } ] } } }", "check the field names"},
		"id shared with infer":  {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'true', label: restricted } ] }, inspection: { request: { on_finding: [ { id: r, when: 'true', action: flag } ] } } }", "duplicate id"},
		"unknown label":         {head + "metadata: { name: x }\nspec: { scope: { organization: true }, destinations: { secret: [internal] } }", "unknown label"},
		"unknown class":         {head + "metadata: { name: x }\nspec: { scope: { organization: true }, destinations: { internal: [moon] } }", "unknown destination class"},
		"unknown default":       {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { default: tiny } }", "unknown label"},
		"rule without label":    {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { when: 'true' } ] } }", "label must be one of"},
		"rule without when":     {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { label: restricted } ] } }", "when is required"},
		"syntax error":          {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'finding.type ==', label: restricted } ] } }", "Syntax error"},
		"misspelled field":      {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'finding.subtyp == \"iban\"', label: restricted } ] } }", "check the field names"},
		"not a boolean":         {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'finding.count + 1', label: restricted } ] } }", "true or false"},
		"unknown variable":      {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'label == \"x\"', label: restricted } ] } }", "undeclared reference"},
		"duplicate rule id":     {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: 'true', label: restricted }, { id: r, when: 'true', label: restricted } ] } }", "duplicate id"},
		"expression too long":   {head + "metadata: { name: x }\nspec: { scope: { organization: true }, classification: { infer: [ { id: r, when: '" + strings.Repeat("true && ", 200) + "true', label: restricted } ] } }", "longer than"},
		"empty file":            {"", "no policy found"},
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
	_, err := compileErr(head+"metadata: { name: a }\nspec: { scope: {} }", head+"metadata: { name: b }\nspec: { scope: {}, audit: { content: hash } }")
	if err == nil || strings.Count(err.Error(), "scope is required") != 2 || !strings.Contains(err.Error(), "spec.audit") {
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
	conf := Decision{Label: taxonomy.Confidential}
	if err := e.Assert(id, conf, Backend{ID: "local", Class: taxonomy.ClassInternal, Max: taxonomy.Restricted}); err != nil {
		t.Errorf("internal backend for confidential data: %v", err)
	}
	for _, b := range []Backend{
		{ID: "a", Class: taxonomy.ClassApprovedExternal, Max: taxonomy.Restricted},
		{ID: "b", Class: taxonomy.ClassInternal, Max: taxonomy.Internal},
		{ID: "c", Class: taxonomy.ClassPublicExternal, Max: taxonomy.Public},
	} {
		if err := e.Assert(id, conf, b); err == nil {
			t.Errorf("a %s backend (max %s) passed the assertion for confidential data", b.Class, b.Max)
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
	partner := Backend{ID: "partner", Class: taxonomy.ClassApprovedExternal, Max: taxonomy.Internal}
	internal := Decision{Label: taxonomy.Internal}
	if err := narrow.Assert(id, internal, partner); err == nil {
		t.Error("the team policy forbids external destinations for internal data")
	}
	if err := narrow.Assert(Identity{Team: "other"}, internal, partner); err != nil {
		t.Errorf("another team is not affected: %v", err)
	}
	// and so is a restrict_destinations action, carried by the decision
	restricted := Decision{Label: taxonomy.Internal, Restricted: []taxonomy.Class{taxonomy.ClassInternal}}
	if err := e.Assert(id, restricted, partner); err == nil {
		t.Error("a restrict_destinations action must hold in phase B")
	}
	// "nothing is allowed" is a restriction too, not the absence of one
	none := Decision{Label: taxonomy.Internal, Restricted: []taxonomy.Class{}}
	if err := e.Assert(id, none, Backend{ID: "local", Class: taxonomy.ClassInternal, Max: taxonomy.Restricted}); err == nil {
		t.Error("a restriction that leaves no class must refuse every backend")
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

// The example policies shipped in configs/policies must stay valid.
func TestExamplePoliciesCompile(t *testing.T) {
	dir := "../../configs/policies"
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no examples in %s: %v", dir, err)
	}
	var src []Source
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		src = append(src, Source{Name: e.Name(), Raw: raw})
	}
	e, err := Compile(src)
	if err != nil {
		t.Fatal(err)
	}
	if w := e.Warnings(); len(w) != 0 {
		t.Errorf("the examples should not widen anything: %v", w)
	}
	fin := Identity{Team: "finance"}
	d := decide(t, e, fin, "")
	if d.Label != taxonomy.Confidential || len(d.Constraints.Classes) != 1 {
		t.Errorf("finance default: %+v", d)
	}
	list := inspect.Kind{Type: "pii", Subtype: "email", Severity: inspect.SeverityMedium, Confidence: 0.9, Count: 25}
	if got := decide(t, e, fin, "", list).Label; got != taxonomy.Restricted {
		t.Errorf("customer list: %s", got)
	}
	if got := decide(t, e, Identity{Team: "research"}, "", kind("custom", "codenames")).Label; got != taxonomy.Confidential {
		t.Errorf("code names: %s", got)
	}
	if v := e.AuthorizeModel(fin, "gpt-4"); v.Allowed {
		t.Error("finance may only use llama-* and mistral-*")
	}
	// the actions of the examples
	if d := decide(t, e, Identity{Team: "research"}, "", kind("secret", "jwt")); d.Block == nil || d.Block.Reason != "SECRET_IN_PROMPT" {
		t.Errorf("secrets must be blocked for everyone: %+v", d.Block)
	}
	if d := decide(t, e, fin, "", kind("pii", "email")); len(d.Redact) != 1 {
		t.Errorf("e-mails must be redacted: %+v", d.Redact)
	}
	if d := decide(t, e, fin, "", kind("pii", "phone")); len(d.Flagged) != 1 {
		t.Errorf("phones must be flagged for finance: %+v", d.Flagged)
	}
}

const actionsPolicy = `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: acts }
spec:
  scope: { organization: true }
  inspection:
    request:
      on_finding:
        - { id: no-secrets, when: 'finding.type == "secret"', action: block, reason: SECRET_IN_PROMPT }
        - { id: mask-emails, when: 'finding.subtype == "email"', action: redact }
        - { id: ids-stay-home, when: 'finding.subtype == "iban" && label.atLeast("confidential")', action: restrict_destinations }
        - { id: watch-phones, when: 'finding.subtype == "phone"', action: flag }
        - { id: nothing, when: 'finding.subtype == "ipv4"', action: allow }
`

func TestActionsOnFindings(t *testing.T) {
	e := compile(t, actionsPolicy)
	email, iban, phone := kind("pii", "email"), kind("pii", "iban"), kind("pii", "phone")
	secret, ip := kind("secret", "jwt"), kind("pii", "ipv4")

	d := decide(t, e, Identity{}, "", email, phone)
	if d.Block != nil || len(d.Redact) != 1 || d.Redact[0] != (RedactKind{Type: "pii", Subtype: "email"}) ||
		len(d.Flagged) != 1 || d.Flagged[0] != "acts/watch-phones" || d.Restricted != nil {
		t.Errorf("email and phone: %+v", d)
	}
	if strings.Join(d.Matched, ",") != "acts/mask-emails,acts/watch-phones" {
		t.Errorf("matched = %v", d.Matched)
	}

	d = decide(t, e, Identity{}, "", secret, email)
	if d.Block == nil || d.Block.Rule != "acts/no-secrets" || d.Block.Reason != "SECRET_IN_PROMPT" {
		t.Errorf("a secret must be blocked: %+v", d.Block)
	}

	// the iban rule reads the label: confidential, so destinations are narrowed
	// to internal (which the baseline already does for confidential data...)
	d = decide(t, e, Identity{}, "", iban)
	if d.Restricted == nil || len(d.Restricted) != 1 || d.Restricted[0] != taxonomy.ClassInternal || len(d.Constraints.Classes) != 1 {
		t.Errorf("iban: %+v", d)
	}
	// allow matches but changes nothing
	d = decide(t, e, Identity{}, "", ip)
	if len(d.Matched) != 1 || d.Block != nil || d.Redact != nil || d.Flagged != nil || d.Restricted != nil {
		t.Errorf("allow: %+v", d)
	}
	// nothing found, nothing happens
	if d := decide(t, e, Identity{}, ""); len(d.Matched) != 0 || d.Block != nil {
		t.Errorf("no findings: %+v", d)
	}
}

func TestRestrictDestinationsNarrowsInternalDataToo(t *testing.T) {
	e := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: r }
spec:
  scope: { organization: true }
  inspection:
    request:
      on_finding:
        - { id: emails-home, when: 'finding.subtype == "email"', action: restrict_destinations }
        - { id: emails-partner, when: 'finding.subtype == "email"', action: restrict_destinations, classes: [approved-external, internal] }
        - { id: phones-partner, when: 'finding.subtype == "phone"', action: restrict_destinations, classes: [approved-external] }
`)
	d := decide(t, e, Identity{}, "", kind("pii", "email"))
	// internal data may go to internal and approved-external; the two rules
	// leave internal only
	if len(d.Constraints.Classes) != 1 || d.Constraints.Classes[0] != taxonomy.ClassInternal || len(d.Restricted) != 1 {
		t.Errorf("email: %+v", d.Constraints.Classes)
	}
	// restrict rules intersect: internal (emails) with approved-external (phones) leaves nothing
	d = decide(t, e, Identity{}, "", kind("pii", "email"), kind("pii", "phone"))
	if len(d.Constraints.Classes) != 0 || d.Restricted == nil || len(d.Restricted) != 0 {
		t.Errorf("email and phone: classes %v restricted %v", d.Constraints.Classes, d.Restricted)
	}
	if c := d.Constraints.Excludes(taxonomy.ClassInternal, taxonomy.Restricted); c == "" {
		t.Error("nothing may receive this request")
	}
}

func TestBlockWithoutAReasonUsesTheDefault(t *testing.T) {
	e := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: b }
spec:
  scope: { team: finance }
  inspection: { request: { on_finding: [ { when: 'finding.subtype == "email"', action: block } ] } }
`)
	d := decide(t, e, Identity{Team: "finance"}, "", kind("pii", "email"))
	if d.Block == nil || d.Block.Reason != DefaultBlockReason || d.Block.Rule != "b/action-0" {
		t.Errorf("block = %+v", d.Block)
	}
	if d := decide(t, e, Identity{Team: "research"}, "", kind("pii", "email")); d.Block != nil {
		t.Error("the rule is scoped to finance")
	}
}

func TestInferRulesCannotReadTheLabelButActionsCan(t *testing.T) {
	if _, err := compileErr(`
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: x }
spec:
  scope: { organization: true }
  classification: { infer: [ { id: r, when: 'label == "x"', label: restricted } ] }
`); err == nil || !strings.Contains(err.Error(), "undeclared reference") {
		t.Errorf("infer rules compute the label, they cannot read it: %v", err)
	}
	e := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: x }
spec:
  scope: { organization: true }
  inspection: { request: { on_finding: [ { id: r, when: 'label == "restricted"', action: flag } ] } }
`)
	if d := decide(t, e, Identity{}, "", kind("secret", "jwt")); len(d.Flagged) != 1 {
		t.Errorf("the action should see the effective label: %+v", d)
	}
	if d := decide(t, e, Identity{}, "", kind("pii", "email")); len(d.Flagged) != 0 {
		t.Errorf("label is internal: %+v", d)
	}
}

func TestActionRuntimeErrorsFailClosed(t *testing.T) {
	e := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: x }
spec:
  scope: { organization: true }
  inspection: { request: { on_finding: [ { id: div, when: 'finding.count == 0 || 10 / (finding.count - 1) == 1', action: flag } ] } }
`)
	_, err := e.Decide(Input{Kinds: []inspect.Kind{{Type: "t", Subtype: "s", Count: 1}}})
	if err == nil || !strings.Contains(err.Error(), "x/div") {
		t.Errorf("err = %v", err)
	}
}

func shadowDoc(rest string) string {
	return "apiVersion: tavian/v1alpha1\nkind: Policy\nmetadata: { name: trial, mode: shadow }\nspec:\n  scope: { organization: true }\n" + rest
}

func TestShadowPoliciesAreEvaluatedButNeverEnforced(t *testing.T) {
	email := kind("pii", "email")
	for name, c := range map[string]struct {
		doc   string
		check func(t *testing.T, d Decision)
	}{
		"block": {`  inspection: { request: { on_finding: [ { id: nope, when: 'finding.subtype == "email"', action: block, reason: NO_EMAILS } ] } }
`, func(t *testing.T, d Decision) {
			if d.Block != nil {
				t.Error("a shadow block was enforced")
			}
			if sh := d.Shadow; sh.WouldBlock == nil || sh.WouldBlock.Reason != "NO_EMAILS" || sh.WouldBlock.Rule != "trial/nope" || !sh.Differs() {
				t.Errorf("shadow = %+v", sh)
			}
		}},
		"label": {`  classification: { default: confidential }
`, func(t *testing.T, d Decision) {
			if d.Label != taxonomy.Internal {
				t.Errorf("a shadow default label was enforced: %s", d.Label)
			}
			if d.Shadow.Label != taxonomy.Confidential || !d.Shadow.ClassesChanged || len(d.Shadow.Classes) != 1 {
				t.Errorf("shadow = %+v", d.Shadow)
			}
		}},
		"destinations": {`  destinations: { internal: [internal] }
`, func(t *testing.T, d Decision) {
			if len(d.Constraints.Classes) != 2 {
				t.Errorf("shadow destinations were enforced: %v", d.Constraints.Classes)
			}
			if !d.Shadow.ClassesChanged || len(d.Shadow.Classes) != 1 || d.Shadow.Label != "" {
				t.Errorf("shadow = %+v", d.Shadow)
			}
		}},
		"redact": {`  inspection: { request: { on_finding: [ { id: mask, when: 'finding.subtype == "email"', action: redact } ] } }
`, func(t *testing.T, d Decision) {
			if len(d.Redact) != 0 {
				t.Error("a shadow redaction was enforced")
			}
			if len(d.Shadow.WouldRedact) != 1 || d.Shadow.WouldRedact[0].Subtype != "email" || len(d.Shadow.Matched) != 1 {
				t.Errorf("shadow = %+v", d.Shadow)
			}
		}},
		"nothing different": {`  inspection: { request: { on_finding: [ { id: x, when: 'finding.subtype == "ipv4"', action: flag } ] } }
`, func(t *testing.T, d Decision) {
			if d.Shadow == nil || d.Shadow.Differs() || len(d.Shadow.Policies) != 1 {
				t.Errorf("shadow = %+v", d.Shadow)
			}
		}},
	} {
		e := compile(t, shadowDoc(c.doc))
		d := decide(t, e, Identity{}, "", email)
		if d.Shadow == nil {
			t.Errorf("%s: no shadow outcome", name)
			continue
		}
		c.check(t, d)
		// the decision in force is exactly what it is without the shadow policy
		plain := decide(t, compile(t), Identity{}, "", email)
		if d.Label != plain.Label || len(d.Constraints.Classes) != len(plain.Constraints.Classes) || d.Block != nil || len(d.Redact) != 0 || len(d.Matched) != len(plain.Matched) {
			t.Errorf("%s: the shadow policy changed the decision: %+v vs %+v", name, d, plain)
		}
	}
}

func TestShadowOnlyAppliesToItsScope(t *testing.T) {
	e := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: trial, mode: shadow }
spec:
  scope: { team: finance }
  classification: { default: restricted }
`)
	if d := decide(t, e, Identity{Team: "research"}, ""); d.Shadow != nil {
		t.Errorf("research has no shadow policy: %+v", d.Shadow)
	}
	if d := decide(t, e, Identity{Team: "finance"}, ""); d.Shadow == nil || d.Shadow.Label != taxonomy.Restricted {
		t.Errorf("finance: %+v", d.Shadow)
	}
	if got := strings.Join(e.ShadowNames(), ","); got != "trial" {
		t.Errorf("shadow names = %q", got)
	}
}

// A shadow policy that breaks must not break the request: the failure is
// reported in the shadow outcome.
func TestShadowFailureDoesNotFailTheDecision(t *testing.T) {
	e := compile(t, shadowDoc(`  inspection: { request: { on_finding: [ { id: div, when: 'finding.count == 0 || 10 / (finding.count - 1) == 1', action: flag } ] } }
`))
	d, err := e.Decide(Input{Kinds: []inspect.Kind{{Type: "t", Subtype: "s", Count: 1}}})
	if err != nil {
		t.Fatalf("a shadow policy failed the request: %v", err)
	}
	if d.Shadow == nil || !strings.Contains(d.Shadow.Error, "trial/div") || !d.Shadow.Differs() {
		t.Errorf("shadow = %+v", d.Shadow)
	}
}

func TestShadowModelAuthorization(t *testing.T) {
	e := compile(t, shadowDoc(`  models: { deny: ["gpt-*"] }
`))
	v := e.AuthorizeModel(Identity{}, "gpt-4")
	if !v.Allowed || v.Shadow == nil || v.Shadow.Policy != "trial" {
		t.Errorf("verdict = %+v: the model is allowed, and the shadow policy would have refused it", v)
	}
	if v := e.AuthorizeModel(Identity{}, "llama"); !v.Allowed || v.Shadow != nil {
		t.Errorf("verdict = %+v", v)
	}
	// an enforced refusal is still a refusal
	e = compile(t, shadowDoc(`  models: { deny: ["gpt-*"] }
`), `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: real }
spec: { scope: { organization: true }, models: { deny: ["gpt-*"] } }
`)
	if v := e.AuthorizeModel(Identity{}, "gpt-4"); v.Allowed || v.Policy != "real" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestExplicitEnforceModeAndPhaseBIgnoreShadow(t *testing.T) {
	e := compile(t, `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: strict, mode: enforce }
spec: { scope: { organization: true }, classification: { default: confidential } }
`, shadowDoc(`  destinations: { confidential: [] }
`))
	d := decide(t, e, Identity{}, "")
	if d.Label != taxonomy.Confidential || d.Shadow == nil || !d.Shadow.ClassesChanged || len(d.Shadow.Classes) != 0 {
		t.Fatalf("decision = %+v shadow %+v", d, d.Shadow)
	}
	// phase B uses the policies in force only: an internal backend is fine
	if err := e.Assert(Identity{}, d, Backend{ID: "local", Class: taxonomy.ClassInternal, Max: taxonomy.Restricted}); err != nil {
		t.Errorf("a shadow policy leaked into phase B: %v", err)
	}
}

func TestLimitsFollowTheScopesThatApply(t *testing.T) {
	head := "apiVersion: tavian/v1alpha1\nkind: Policy\n"
	e := compile(t,
		head+"metadata: { name: org }\nspec:\n  scope: { organization: true }\n  quotas: [ { dimension: rpm, limit: 100 }, { dimension: concurrency, limit: 20 } ]\n",
		head+"metadata: { name: fin }\nspec:\n  scope: { team: finance }\n  quotas: [ { dimension: tpm, limit: 5000, mode: soft }, { dimension: tokens_per_day, limit: 100000, window: 1d } ]\n",
		head+"metadata: { name: app }\nspec:\n  scope: { team: finance, application: bot }\n  quotas: [ { dimension: rpm, limit: 5 } ]\n",
		head+"metadata: { name: trial, mode: shadow }\nspec:\n  scope: { team: finance }\n  quotas: [ { dimension: rpm, limit: 1 } ]\n",
	)
	got := e.Limits(Identity{Team: "finance", Application: "bot"})
	if len(got) != 6 {
		t.Fatalf("limits = %+v, want the six that apply", got)
	}
	byPolicy := map[string]int{}
	for _, l := range got {
		byPolicy[l.Policy]++
		switch l.Policy {
		case "fin":
			if l.Dimension == quota.TPM && !l.Soft || l.Dimension == quota.TokensPerDay && l.Soft {
				t.Errorf("mode lost: %+v", l)
			}
			if l.Scope != (quota.Scope{Team: "finance"}) {
				t.Errorf("scope = %+v", l.Scope)
			}
		case "app":
			if l.Scope != (quota.Scope{Team: "finance", Application: "bot"}) {
				t.Errorf("scope = %+v", l.Scope)
			}
		case "trial":
			if !l.Shadow || l.Effect() != "shadow" {
				t.Errorf("a shadow policy's limit must never refuse: %+v", l)
			}
		case "org":
			if l.Scope != (quota.Scope{Organization: true}) {
				t.Errorf("scope = %+v", l.Scope)
			}
		}
	}
	if byPolicy["org"] != 2 || byPolicy["fin"] != 2 || byPolicy["app"] != 1 || byPolicy["trial"] != 1 {
		t.Errorf("by policy = %v", byPolicy)
	}

	// another team sees only the organization's
	other := e.Limits(Identity{Team: "research", Application: "bot"})
	if len(other) != 2 {
		t.Errorf("research limits = %+v, want only the organization's", other)
	}
	// the same team, another application
	if n := len(e.Limits(Identity{Team: "finance", Application: "other"})); n != 5 {
		t.Errorf("finance/other limits = %d, want 5", n)
	}
	// nothing configured
	if n := len(compile(t).Limits(Identity{Team: "finance"})); n != 0 {
		t.Errorf("baseline alone has %d limits", n)
	}
}

func TestScopesListsEachScopeWithALimitOnce(t *testing.T) {
	head := "apiVersion: tavian/v1alpha1\nkind: Policy\n"
	e := compile(t,
		head+"metadata: { name: a }\nspec:\n  scope: { team: finance }\n  quotas: [ { dimension: tokens_per_day, limit: 10 }, { dimension: rpm, limit: 5 } ]\n",
		head+"metadata: { name: b }\nspec:\n  scope: { team: finance }\n  quotas: [ { dimension: tokens_per_day, limit: 20 } ]\n",
		head+"metadata: { name: c, mode: shadow }\nspec:\n  scope: { organization: true }\n  quotas: [ { dimension: tokens_per_day, limit: 99 } ]\n",
	)
	got := e.Scopes(quota.TokensPerDay)
	if len(got) != 2 || got[0] != (quota.Scope{Team: "finance"}) || got[1] != (quota.Scope{Organization: true}) {
		t.Errorf("scopes = %+v", got)
	}
	if got := e.Scopes(quota.Concurrency); len(got) != 0 {
		t.Errorf("concurrency scopes = %+v", got)
	}
}
