package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/pipeline"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/taxonomy"
)

// cmdPolicy dispatches `tavian policy <subcommand>`.
func cmdPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(stderr, "usage: tavian policy test [-config tavian.yaml] <fixtures.yaml|directory>...")
		return 2
	}
	return cmdPolicyTest(args[1:], stdout, stderr)
}

// A fixture file lists cases: who sends what, and the decision the policies and
// the routing of the configuration must reach. Cases run through the very code
// the gateway runs (internal/pipeline), against the configuration and policies
// given with -config, so a passing fixture is a statement about the gateway.
//
//	apiVersion: tavian/v1alpha1
//	kind: PolicyTest
//	metadata: { name: finance }
//	cases:
//	  - name: an IBAN from finance stays on premises
//	    caller: { team: finance, clearance: confidential }
//	    request: { model: shared }
//	    content: ["pay FR14 2004 1010 0505 0001 3M02 606"]
//	    expect: { outcome: served, label: confidential, backend: local }
type testFile struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Cases []testCase `yaml:"cases"`
}

type testCase struct {
	Name   string `yaml:"name"`
	Caller struct {
		User        string   `yaml:"user"`
		Groups      []string `yaml:"groups"`
		Roles       []string `yaml:"roles"`
		Team        string   `yaml:"team"`
		Application string   `yaml:"application"`
		AuthMethod  string   `yaml:"auth_method"`
		// Grants are the models the credentials allow (default: all).
		Grants []string `yaml:"grants"`
		// Clearance is the most sensitive label the caller may send (default
		// internal, as for a key that declares nothing).
		Clearance taxonomy.Label `yaml:"clearance"`
	} `yaml:"caller"`
	Request struct {
		Model         string         `yaml:"model"`
		Stream        bool           `yaml:"stream"`
		MaxTokens     int64          `yaml:"max_tokens"`
		HasTools      bool           `yaml:"has_tools"`
		DeclaredLabel taxonomy.Label `yaml:"declared_label"`
	} `yaml:"request"`
	// Content is text to inspect with the configured detectors, one message
	// each. Findings states findings directly. Use one or the other.
	Content  []string      `yaml:"content"`
	Findings []testFinding `yaml:"findings"`
	Expect   testExpect    `yaml:"expect"`
}

type testFinding struct {
	Type       string  `yaml:"type"`
	Subtype    string  `yaml:"subtype"`
	Severity   string  `yaml:"severity"`
	Confidence float64 `yaml:"confidence"`
	Count      int     `yaml:"count"`
}

// testExpect lists what must hold. Only what is given is checked, except the
// outcome, which is required.
type testExpect struct {
	Outcome string `yaml:"outcome"` // served | refused
	// Reason is the reason code of a refusal (MODEL_NOT_ALLOWED, a block
	// rule's own code, ...).
	Reason string `yaml:"reason"`
	Label  string `yaml:"label"`
	// Destinations is the exact set of destination classes allowed; an empty
	// list means none.
	Destinations *[]string `yaml:"destinations"`
	Backend      string    `yaml:"backend"`
	// Redact is the exact set of "type.subtype" kinds to redact.
	Redact *[]string `yaml:"redact"`
	// Flagged and Rules must each be among what fired ("policy/rule").
	Flagged []string `yaml:"flagged"`
	Rules   []string `yaml:"rules"`
	Shadow  *struct {
		WouldRefuse string `yaml:"would_refuse"`
		Label       string `yaml:"label"`
		Differs     *bool  `yaml:"differs"`
	} `yaml:"shadow"`
}

func cmdPolicyTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: tavian policy test [-config tavian.yaml] <fixtures.yaml|directory>...")
		return 2
	}
	cfg, raw, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	snap, err := config.Compile(cfg, raw, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	files, err := fixtureFiles(fs.Args())
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}

	passed, failed := 0, 0
	for _, f := range files {
		tf, err := readFixtures(f)
		if err != nil {
			fmt.Fprintf(stderr, "tavian: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "%s (%s)\n", f, tf.Metadata.Name)
		for _, c := range tf.Cases {
			problems := runCase(context.Background(), snap, c)
			if len(problems) == 0 {
				passed++
				fmt.Fprintf(stdout, "  ok    %s\n", c.Name)
				continue
			}
			failed++
			fmt.Fprintf(stdout, "  FAIL  %s\n", c.Name)
			for _, p := range problems {
				fmt.Fprintf(stdout, "          %s\n", p)
			}
		}
	}
	fmt.Fprintf(stdout, "%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// fixtureFiles expands directories to their *.yaml and *.yml files.
func fixtureFiles(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		fi, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			out = append(out, a)
			continue
		}
		entries, err := os.ReadDir(a)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if ext := filepath.Ext(e.Name()); !e.IsDir() && (ext == ".yaml" || ext == ".yml") && !strings.HasPrefix(e.Name(), ".") {
				out = append(out, filepath.Join(a, e.Name()))
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no fixture files found")
	}
	return out, nil
}

func readFixtures(path string) (*testFile, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is chosen by the operator on the command line
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var tf testFile
	if err := dec.Decode(&tf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if tf.APIVersion != policy.APIVersion || tf.Kind != "PolicyTest" {
		return nil, fmt.Errorf("%s: want apiVersion %s and kind PolicyTest", path, policy.APIVersion)
	}
	if len(tf.Cases) == 0 {
		return nil, fmt.Errorf("%s: no cases", path)
	}
	for i, c := range tf.Cases {
		switch {
		case c.Name == "":
			return nil, fmt.Errorf("%s: cases[%d]: name is required", path, i)
		case c.Request.Model == "":
			return nil, fmt.Errorf("%s: case %q: request.model is required", path, c.Name)
		case c.Expect.Outcome != "served" && c.Expect.Outcome != "refused":
			return nil, fmt.Errorf("%s: case %q: expect.outcome must be served or refused", path, c.Name)
		case len(c.Content) > 0 && len(c.Findings) > 0:
			return nil, fmt.Errorf("%s: case %q: give content or findings, not both", path, c.Name)
		}
		if c.Caller.Clearance != "" && c.Caller.Clearance.Rank() < 0 {
			return nil, fmt.Errorf("%s: case %q: unknown clearance %q", path, c.Name, c.Caller.Clearance)
		}
	}
	return &tf, nil
}

// runCase runs one case and returns what differs from its expectations.
func runCase(ctx context.Context, snap *config.Snapshot, c testCase) []string {
	grants := c.Caller.Grants
	if len(grants) == 0 {
		grants = []string{"*"}
	}
	clearance := c.Caller.Clearance
	if clearance == "" {
		clearance = config.DefaultClearance
	}
	caller := pipeline.Caller{
		Identity: policy.Identity{
			User: c.Caller.User, Groups: c.Caller.Groups, Roles: c.Caller.Roles,
			Team: c.Caller.Team, Application: c.Caller.Application, AuthMethod: c.Caller.AuthMethod,
		},
		Grants: grants, Clearance: clearance,
	}

	got := outcome{Outcome: "served", Reason: audit.Served.Code}
	refuse := func(r *pipeline.Refusal) { got.Outcome, got.Reason = "refused", r.Reason.Code }

	if r, _ := pipeline.AuthorizeModel(snap, caller, c.Request.Model); r != nil {
		refuse(r)
		return got.compare(c.Expect)
	}

	kinds, refusal := kindsOf(ctx, snap, c)
	if refusal != nil {
		refuse(refusal)
		return got.compare(c.Expect)
	}
	declared, err := policy.ParseDeclared(optional(string(c.Request.DeclaredLabel)))
	if err != nil {
		return []string{fmt.Sprintf("request.declared_label %q is not a label", c.Request.DeclaredLabel)}
	}

	res := pipeline.Evaluate(snap, nil, caller, policy.Input{
		Identity: caller.Identity,
		Request:  policy.Request{Model: c.Request.Model, Stream: c.Request.Stream, MaxTokens: c.Request.MaxTokens, HasTools: c.Request.HasTools},
		Declared: declared,
		Kinds:    kinds,
	})
	if res.Decided {
		d := res.Decision
		got.Label = string(d.Label)
		got.Destinations = d.Constraints.ClassNames()
		for _, k := range d.Redact {
			got.Redact = append(got.Redact, string(k.Type)+"."+k.Subtype)
		}
		got.Flagged, got.Rules, got.Shadow = d.Flagged, d.Matched, d.Shadow
	}
	if res.Refusal != nil {
		refuse(res.Refusal)
		if res.Err != nil {
			got.Note = res.Err.Error()
		}
		return got.compare(c.Expect)
	}
	got.Backend = res.Route.Backend.ID
	return got.compare(c.Expect)
}

func optional(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// kindsOf returns what inspection finds in the case, from its content or from
// the findings it states.
func kindsOf(ctx context.Context, snap *config.Snapshot, c testCase) ([]inspect.Kind, *pipeline.Refusal) {
	if len(c.Findings) > 0 {
		var kinds []inspect.Kind
		for _, f := range c.Findings {
			k := inspect.Kind{Type: inspect.Type(f.Type), Subtype: f.Subtype, Severity: inspect.Severity(f.Severity), Confidence: f.Confidence, Count: f.Count}
			if k.Severity == "" {
				k.Severity = inspect.SeverityMedium
			}
			if k.Confidence == 0 {
				k.Confidence = 0.9
			}
			if k.Count == 0 {
				k.Count = 1
			}
			kinds = append(kinds, k)
		}
		return kinds, nil
	}
	var req inspect.Request
	for i, text := range c.Content {
		req.Segments = append(req.Segments, inspect.Segment{MessageIndex: i, Field: inspect.FieldContent, Part: -1, Text: text})
	}
	res, err := snap.Inspector.Inspect(ctx, req)
	if err != nil {
		return nil, &pipeline.Refusal{Reason: audit.FromInspection(inspect.CodeOf(err))}
	}
	return res.Kinds, nil
}

// outcome is what a case produced, in the terms of its expectations.
type outcome struct {
	Outcome, Reason, Label, Backend string
	Destinations, Redact, Flagged   []string
	Rules                           []string
	Shadow                          *policy.Shadow
	Note                            string
}

func (o outcome) compare(e testExpect) []string {
	var bad []string
	diff := func(what, got, want string) {
		bad = append(bad, fmt.Sprintf("%s: got %s, want %s", what, quote(got), quote(want)))
	}
	if o.Outcome != e.Outcome {
		diff("outcome", o.Outcome, e.Outcome)
	}
	if e.Reason != "" && o.Reason != e.Reason {
		diff("reason", o.Reason, e.Reason)
	}
	if e.Label != "" && o.Label != e.Label {
		diff("label", o.Label, e.Label)
	}
	if e.Backend != "" && o.Backend != e.Backend {
		diff("backend", o.Backend, e.Backend)
	}
	if e.Destinations != nil && !sameSet(o.Destinations, *e.Destinations) {
		bad = append(bad, fmt.Sprintf("destinations: got %s, want %s", list(o.Destinations), list(*e.Destinations)))
	}
	if e.Redact != nil && !sameSet(o.Redact, *e.Redact) {
		bad = append(bad, fmt.Sprintf("redact: got %s, want %s", list(o.Redact), list(*e.Redact)))
	}
	for _, f := range e.Flagged {
		if !slices.Contains(o.Flagged, f) {
			bad = append(bad, fmt.Sprintf("flagged: %q did not fire (fired: %s)", f, list(o.Flagged)))
		}
	}
	for _, r := range e.Rules {
		if !slices.Contains(o.Rules, r) {
			bad = append(bad, fmt.Sprintf("rules: %q did not fire (fired: %s)", r, list(o.Rules)))
		}
	}
	if s := e.Shadow; s != nil {
		var sh policy.Shadow
		if o.Shadow != nil {
			sh = *o.Shadow
		}
		if s.WouldRefuse != "" && (sh.WouldBlock == nil || sh.WouldBlock.Reason != s.WouldRefuse) {
			bad = append(bad, fmt.Sprintf("shadow.would_refuse: want %q", s.WouldRefuse))
		}
		if s.Label != "" && string(sh.Label) != s.Label {
			diff("shadow.label", string(sh.Label), s.Label)
		}
		if s.Differs != nil && o.Shadow.Differs() != *s.Differs {
			bad = append(bad, fmt.Sprintf("shadow.differs: got %v, want %v", o.Shadow.Differs(), *s.Differs))
		}
	}
	if len(bad) > 0 && o.Note != "" {
		bad = append(bad, "(internal error: "+o.Note+")")
	}
	return bad
}

func quote(s string) string {
	if s == "" {
		return "(none)"
	}
	return `"` + s + `"`
}

func list(s []string) string {
	if len(s) == 0 {
		return "[]"
	}
	return "[" + strings.Join(s, ", ") + "]"
}

func sameSet(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}
