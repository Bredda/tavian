package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/config"
)

func chatWith(content string) string {
	return `{"model":"llama-70b","messages":[{"role":"user","content":"` + content + `"}]}`
}

func (f *fixture) postWithLabel(t *testing.T, key, body string, labels ...string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.gw.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	for _, l := range labels {
		req.Header.Add("X-Tavian-Classification", l)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func lastDecision(t *testing.T, f *fixture) audit.DecisionRecord {
	t.Helper()
	recs := decisions(f)
	if len(recs) == 0 {
		t.Fatal("no decision record")
	}
	return recs[len(recs)-1]
}

func TestLabelFollowsWhatInspectionFinds(t *testing.T) {
	f := newFixture(t, 0)
	for _, c := range []struct {
		name, key, content string
		label              config.Classification
		status             int
	}{
		{"nothing sensitive", f.key, "hello there", config.LabelInternal, 200},
		{"e-mail stays internal", f.key, "write to " + canaryEmail, config.LabelInternal, 200},
		{"iban within clearance", f.conf, "pay " + canaryIBAN, config.LabelConfidential, 200},
		{"secret within clearance", f.top, "key " + canarySec, config.LabelRestricted, 200},
		{"iban above a default clearance", f.key, "pay " + canaryIBAN, config.LabelConfidential, 403},
		{"secret above a confidential clearance", f.conf, "key " + canarySec, config.LabelRestricted, 403},
	} {
		resp := f.post(t, c.key, chatWith(c.content))
		d := lastDecision(t, f)
		if resp.StatusCode != c.status || d.Label != string(c.label) {
			t.Errorf("%s: status %d label %q, want %d and %s", c.name, resp.StatusCode, d.Label, c.status, c.label)
		}
		if c.status == 403 && (d.Outcome != audit.OutcomeRefused || d.ReasonCode != "CLEARANCE_EXCEEDED") {
			t.Errorf("%s: record = %s/%s", c.name, d.Outcome, d.ReasonCode)
		}
		if c.status == 200 && d.Outcome != audit.OutcomeServed {
			t.Errorf("%s: outcome %s", c.name, d.Outcome)
		}
	}
}

func TestClearanceRefusalIsExplainableAndLeaksNothing(t *testing.T) {
	f := newFixture(t, 0)
	resp := f.post(t, f.key, chatWith("pay "+canaryIBAN))
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if errorCode(t, resp) != "classification_exceeds_clearance" {
		t.Error("client code")
	}
	d := lastDecision(t, f)
	if d.LabelSources == nil || d.LabelSources.Inferred != "confidential" || d.LabelSources.Default != "internal" || d.LabelSources.Declared != "" {
		t.Errorf("sources = %+v", d.LabelSources)
	}
	if n := len(f.sink.Events()); n != 0 {
		t.Errorf("usage events = %d for a refused request", n)
	}
}

func TestDeclaredLabel(t *testing.T) {
	f := newFixture(t, 0)
	// raising: within clearance it is honoured, and recorded as declared
	resp := f.postWithLabel(t, f.conf, chatWith("hello"), "Confidential")
	d := lastDecision(t, f)
	if resp.StatusCode != 200 || d.Label != "confidential" || d.LabelSources.Declared != "confidential" || d.LabelSources.Inferred != "" {
		t.Errorf("declared confidential: status %d record %+v %+v", resp.StatusCode, d.Label, d.LabelSources)
	}
	// a declaration above the clearance is refused, not lowered
	resp = f.postWithLabel(t, f.key, chatWith("hello"), "restricted")
	if resp.StatusCode != 403 || lastDecision(t, f).ReasonCode != "CLEARANCE_EXCEEDED" {
		t.Errorf("declared restricted with a default clearance: status %d", resp.StatusCode)
	}
	// declaring less cannot lower what inspection infers
	resp = f.postWithLabel(t, f.conf, chatWith("pay "+canaryIBAN), "public")
	d = lastDecision(t, f)
	if resp.StatusCode != 200 || d.Label != "confidential" || d.LabelSources.Declared != "public" {
		t.Errorf("declared public with an IBAN: status %d label %s", resp.StatusCode, d.Label)
	}
	// declaring less than the default keeps the default
	f.postWithLabel(t, f.key, chatWith("hello"), "public")
	if got := lastDecision(t, f).Label; got != "internal" {
		t.Errorf("declared public: label %s, want internal", got)
	}
	// nonsense is a bad request, recorded
	for _, bad := range [][]string{{"top-secret"}, {""}, {"public", "restricted"}} {
		resp = f.postWithLabel(t, f.key, chatWith("hello"), bad...)
		if resp.StatusCode != 400 || errorCode(t, resp) != "invalid_request" || lastDecision(t, f).ReasonCode != "INVALID_REQUEST" {
			t.Errorf("header %q: status %d", bad, resp.StatusCode)
		}
	}
}

func TestUsageEventAndMetricCarryTheLabel(t *testing.T) {
	f := newFixture(t, 0)
	f.post(t, f.conf, chatWith("pay "+canaryIBAN)).Body.Close()
	f.post(t, f.key, chatWith("hello")).Body.Close()
	evs := f.sink.Events()
	if len(evs) != 2 || evs[0].Label != "confidential" || evs[1].Label != "internal" {
		t.Fatalf("events = %+v", evs)
	}
	m := metricsText(t, f)
	for _, want := range []string{
		`tavian_requests_by_label_total{label="confidential"} 1`,
		`tavian_requests_by_label_total{label="internal"} 1`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q:\n%s", want, grepLines(m, "by_label"))
		}
	}
}
