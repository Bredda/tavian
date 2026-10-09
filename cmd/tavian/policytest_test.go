package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures shipped in configs/policy-tests must keep passing: they document
// what the example policies do, and they run through the gateway's own code.
func TestShippedPolicyFixturesPass(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "test", "-config", "../../configs/policy-tests/tavian.yaml", "../../configs/policy-tests/cases"}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "0 failed") {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errOut.String())
	}
}

const testConfig = `
profile: controlled-egress
policy: { dir: policies }
backends:
  - { id: local, type: openai, base_url: "http://127.0.0.1:8000/v1", destination_class: internal }
  - { id: partner, type: openai, base_url: "https://eu.example.com/v1", destination_class: approved-external }
models:
  - { name: shared, type: chat, route: [{ backend: partner }, { backend: local }] }
api_keys:
  - { id: dev, hash: "sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + `", team: t, application: a, allowed_models: ["*"] }
`

const trialPolicy = `
apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: trial, mode: shadow }
spec:
  scope: { organization: true }
  inspection: { request: { on_finding: [ { id: nope, when: 'finding.subtype == "email"', action: block, reason: NO_EMAILS } ] } }
`

func workspace(t *testing.T, policies map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range policies {
		if err := os.WriteFile(filepath.Join(dir, "policies", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "tavian.yaml"), []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runTest(t *testing.T, dir, fixtures string) (int, string, string) {
	t.Helper()
	path := filepath.Join(dir, "cases.yaml")
	if err := os.WriteFile(path, []byte(fixtures), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "test", "-config", filepath.Join(dir, "tavian.yaml"), path}, &out, &errOut)
	return code, out.String(), errOut.String()
}

const fixtureHead = "apiVersion: tavian/v1alpha1\nkind: PolicyTest\nmetadata: { name: t }\ncases:\n"

func TestPolicyTestReportsWhatDiffersAndFails(t *testing.T) {
	dir := workspace(t, nil)
	code, out, _ := runTest(t, dir, fixtureHead+`
  - name: right
    caller: { team: t }
    request: { model: shared }
    content: ["pay FR14 2004 1010 0505 0001 3M02 606"]
    expect: { outcome: refused, reason: CLEARANCE_EXCEEDED, label: confidential }
  - name: wrong label and backend
    caller: { team: t, clearance: confidential }
    request: { model: shared }
    content: ["pay FR14 2004 1010 0505 0001 3M02 606"]
    expect: { outcome: served, label: internal, backend: partner, destinations: [internal, approved-external], flagged: [x/y], rules: [baseline/nothing] }
`)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	for _, want := range []string{"ok    right", "FAIL  wrong label and backend", `label: got "confidential", want "internal"`,
		`backend: got "local", want "partner"`, "destinations: got [internal], want [internal, approved-external]",
		`flagged: "x/y" did not fire`, `rules: "baseline/nothing" did not fire`, "1 passed, 1 failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestPolicyTestShadowExpectations(t *testing.T) {
	dir := workspace(t, map[string]string{"trial.yaml": trialPolicy})
	code, out, errOut := runTest(t, dir, fixtureHead+`
  - name: a shadow block is served and reported
    caller: { team: t }
    request: { model: shared }
    content: ["write to alice@example.org"]
    expect:
      outcome: served
      shadow: { would_refuse: NO_EMAILS, differs: true }
  - name: nothing to report without an address
    caller: { team: t }
    request: { model: shared }
    content: ["hello"]
    expect:
      outcome: served
      shadow: { differs: false }
  - name: wrong expectation about the shadow
    caller: { team: t }
    request: { model: shared }
    content: ["hello"]
    expect:
      outcome: served
      shadow: { would_refuse: NO_EMAILS }
`)
	if code != 1 || !strings.Contains(out, "2 passed, 1 failed") || !strings.Contains(out, `shadow.would_refuse: want "NO_EMAILS"`) {
		t.Errorf("exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestPolicyTestRefusalsFromEveryStage(t *testing.T) {
	dir := workspace(t, nil)
	code, out, _ := runTest(t, dir, fixtureHead+`
  - name: grants
    caller: { team: t, grants: ["other-*"] }
    request: { model: shared }
    content: ["hi"]
    expect: { outcome: refused, reason: MODEL_NOT_ALLOWED }
  - name: unknown model
    caller: { team: t }
    request: { model: nope }
    content: ["hi"]
    expect: { outcome: refused, reason: MODEL_NOT_FOUND }
  - name: secrets need restricted clearance
    caller: { team: t, clearance: confidential }
    request: { model: shared }
    findings: [ { type: secret, subtype: jwt } ]
    expect: { outcome: refused, reason: CLEARANCE_EXCEEDED, label: restricted }
  - name: no findings at all
    caller: { team: t }
    request: { model: shared }
    expect: { outcome: served, backend: partner, destinations: [internal, approved-external], redact: [] }
`)
	if code != 0 {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestPolicyTestRejectsBadFixtures(t *testing.T) {
	dir := workspace(t, nil)
	for name, f := range map[string]string{
		"typo":          fixtureHead + "  - name: a\n    request: { model: shared }\n    expect: { outcome: served }\n    expet: {}\n",
		"no name":       fixtureHead + "  - request: { model: shared }\n    expect: { outcome: served }\n",
		"no model":      fixtureHead + "  - name: a\n    expect: { outcome: served }\n",
		"no outcome":    fixtureHead + "  - name: a\n    request: { model: shared }\n    expect: {}\n",
		"both inputs":   fixtureHead + "  - name: a\n    request: { model: shared }\n    content: [x]\n    findings: [ { type: pii, subtype: email } ]\n    expect: { outcome: served }\n",
		"bad clearance": fixtureHead + "  - name: a\n    caller: { clearance: tiny }\n    request: { model: shared }\n    expect: { outcome: served }\n",
		"wrong kind":    "apiVersion: tavian/v1alpha1\nkind: Policy\ncases: []\n",
		"no cases":      "apiVersion: tavian/v1alpha1\nkind: PolicyTest\nmetadata: { name: x }\ncases: []\n",
	} {
		code, _, errOut := runTest(t, dir, f)
		if code != 1 || errOut == "" {
			t.Errorf("%s: exit %d, stderr %q", name, code, errOut)
		}
	}
}

func TestPolicyTestUsageAndConfigErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"policy"}, &out, &errOut); code != 2 {
		t.Errorf("policy alone: exit %d", code)
	}
	if code := run([]string{"policy", "test", "-config", "nope.yaml"}, &out, &errOut); code != 2 {
		t.Errorf("no fixtures: exit %d", code)
	}
	if code := run([]string{"policy", "test", "-config", "nope.yaml", "x.yaml"}, &out, &errOut); code != 1 {
		t.Errorf("missing config: exit %d", code)
	}
	dir := workspace(t, map[string]string{"bad.yaml": "apiVersion: tavian/v1alpha1\nkind: Policy\nmetadata: { name: b }\nspec: { scope: { organization: true }, audit: { content: hash } }\n"})
	if code, _, e := runTest(t, dir, fixtureHead+"  - name: a\n    request: { model: shared }\n    expect: { outcome: served }\n"); code != 1 || !strings.Contains(e, "audit") {
		t.Errorf("invalid policies: exit %d, %q", code, e)
	}
}

// The outcome is checked even when nothing else is: a case that expects a
// request to be served must fail when it is refused, and the other way round.
func TestPolicyTestChecksTheOutcomeAlone(t *testing.T) {
	dir := workspace(t, nil)
	code, out, _ := runTest(t, dir, fixtureHead+`
  - name: expects served, is refused
    caller: { team: t }
    request: { model: nope }
    expect: { outcome: served }
  - name: expects refused, is served
    caller: { team: t }
    request: { model: shared }
    expect: { outcome: refused }
`)
	if code != 1 || strings.Count(out, "FAIL") != 2 || !strings.Contains(out, `outcome: got "refused", want "served"`) || !strings.Contains(out, `outcome: got "served", want "refused"`) {
		t.Errorf("exit %d\n%s", code, out)
	}
}
