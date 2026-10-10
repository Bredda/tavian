package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cliToken = "tavadm_cli-test-token"

// fakeGateway answers the admin API with canned JSON and remembers what it was asked.
type fakeGateway struct {
	t      *testing.T
	srv    *httptest.Server
	routes map[string]func(w http.ResponseWriter, body string)
	seen   []string
	bodies map[string]string
	auths  []string
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{t: t, routes: map[string]func(http.ResponseWriter, string){}, bodies: map[string]string{}}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.RequestURI()
		g.seen = append(g.seen, key)
		g.bodies[key] = string(b)
		g.auths = append(g.auths, r.Header.Get("Authorization"))
		h, ok := g.routes[key]
		if !ok {
			http.Error(w, `{"error":{"code":"not_found","message":"no route `+key+`"}}`, 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		h(w, string(b))
	}))
	t.Cleanup(g.srv.Close)
	t.Setenv("TAVIAN_ADMIN_TOKEN", cliToken)
	t.Setenv("TAVIAN_ADMIN_URL", g.srv.URL)
	return g
}

func (g *fakeGateway) json(route, body string) {
	g.routes[route] = func(w http.ResponseWriter, _ string) { _, _ = io.WriteString(w, body) }
}

func (g *fakeGateway) fail(route string, status int, code, message string) {
	g.routes[route] = func(w http.ResponseWriter, _ string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
	}
}

func cli(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(append([]string{"config"}, args...), &out, &errOut)
	if strings.Contains(out.String()+errOut.String(), cliToken) {
		t.Errorf("the token was printed:\n%s%s", out.String(), errOut.String())
	}
	return out.String(), errOut.String(), code
}

const (
	revA = "aaaaaaaaaaaa"
	revB = "bbbbbbbbbbbb"
)

func TestConfigNeedsATokenAndAServer(t *testing.T) {
	t.Setenv("TAVIAN_ADMIN_TOKEN", "")
	if _, stderr, code := cli(t, "list"); code != 1 || !strings.Contains(stderr, "TAVIAN_ADMIN_TOKEN") {
		t.Errorf("without a token: %d %q", code, stderr)
	}
	t.Setenv("TAVIAN_ADMIN_TOKEN", cliToken)
	for _, server := range []string{"ftp://x", "127.0.0.1:9090", "http://127.0.0.1:9090/admin", "http://user:pw@127.0.0.1:9090", ""} {
		if _, stderr, code := cli(t, "list", "-server", server); code != 1 || !strings.Contains(stderr, "-server") {
			t.Errorf("server %q: %d %q", server, code, stderr)
		}
	}
	// a token in clear over a network is said out loud, not forbidden
	var warn bytes.Buffer
	c := &conn{server: "http://192.0.2.7:9090"}
	if _, err := c.newClient(&warn); err != nil || !strings.Contains(warn.String(), "not encrypted") {
		t.Errorf("remote http: %v %q", err, warn.String())
	}
	for _, ok := range []string{"http://127.0.0.1:9090", "http://localhost:9090", "http://[::1]:9090", "https://gateway.example:9090"} {
		warn.Reset()
		if _, err := (&conn{server: ok}).newClient(&warn); err != nil || warn.Len() != 0 {
			t.Errorf("%s: %v %q", ok, err, warn.String())
		}
	}
}

func TestConfigUsage(t *testing.T) {
	if out, _, code := cli(t); code != 2 || !strings.Contains(out, "Commands:") {
		t.Errorf("no command: %d", code)
	}
	if _, stderr, code := cli(t, "bogus"); code != 2 || !strings.Contains(stderr, "unknown command") {
		t.Errorf("unknown command: %d %q", code, stderr)
	}
	if out, _, code := cli(t, "help"); code != 0 || !strings.Contains(out, "rollback") {
		t.Errorf("help: %d", code)
	}
}

func TestConfigListFollowsThePages(t *testing.T) {
	g := newFakeGateway(t)
	g.json("GET /admin/v1/config/revisions?limit=3", `{"revisions":[
	  {"revision":"`+revB+`","profile":"standard","tavian_version":"v1","first_loaded_at":"2026-10-10T10:00:00Z","active":true},
	  {"revision":"cccccccccccc","profile":"standard","tavian_version":"v1","first_loaded_at":"2026-10-09T10:00:00Z","active":false}],"active":"`+revB+`","next":"7"}`)
	g.json("GET /admin/v1/config/revisions?limit=1&before=7", `{"revisions":[
	  {"revision":"`+revA+`","profile":"standard","tavian_version":"v0","first_loaded_at":"2026-10-08T10:00:00Z","active":false}],"active":"`+revB+`"}`)
	out, _, code := cli(t, "list", "-limit", "3")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "REVISION") || !strings.Contains(lines[1], revB) || !strings.Contains(lines[1], "active") ||
		strings.Contains(lines[2], "active") || !strings.Contains(lines[3], revA) {
		t.Errorf("table:\n%s", out)
	}
	for _, a := range g.auths {
		if a != "Bearer "+cliToken {
			t.Errorf("Authorization = %q", a)
		}
	}
	out, _, _ = cli(t, "list", "-limit", "3", "-json")
	var j struct{ Revisions []revisionSummary }
	if err := json.Unmarshal([]byte(out), &j); err != nil || len(j.Revisions) != 3 {
		t.Errorf("-json: %v %s", err, out)
	}
	if _, _, code := cli(t, "list", "-limit", "0"); code != 1 {
		t.Errorf("-limit 0: %d", code)
	}
}

func revisionJSON(rev, config string, policies ...[2]string) string {
	type f struct {
		Name string `json:"name"`
		YAML string `json:"yaml"`
	}
	fs := []f{}
	for _, p := range policies {
		fs = append(fs, f{p[0], p[1]})
	}
	b, _ := json.Marshal(map[string]any{"revision": rev, "profile": "standard", "tavian_version": "v1", "first_loaded_at": "2026-10-10T10:00:00Z", "active": true, "config": config, "policies": fs})
	return string(b)
}

func TestConfigShowAndExport(t *testing.T) {
	g := newFakeGateway(t)
	g.json("GET /admin/v1/config/revisions/active", revisionJSON(revA, "profile: standard\n", [2]string{"10-a.yaml", "kind: Policy\n"}))
	out, _, code := cli(t, "show")
	if code != 0 || !strings.Contains(out, "# revision "+revA+" (active)") || !strings.Contains(out, "profile: standard") ||
		!strings.Contains(out, "# ---- policies/10-a.yaml\nkind: Policy") {
		t.Errorf("show: %d\n%s", code, out)
	}
	if out, _, _ = cli(t, "show", "-json"); !strings.HasPrefix(out, "{") {
		t.Errorf("show -json: %s", out)
	}

	dir := filepath.Join(t.TempDir(), "out")
	out, _, code = cli(t, "export", "-o", dir)
	if code != 0 || !strings.Contains(out, "1 policy file") || !strings.Contains(out, "tavian config apply -config "+filepath.Join(dir, "tavian.yaml")) {
		t.Fatalf("export: %d %s", code, out)
	}
	for path, want := range map[string]string{"tavian.yaml": "profile: standard\n", "policies/10-a.yaml": "kind: Policy\n"} {
		b, err := os.ReadFile(filepath.Join(dir, path))
		info, _ := os.Stat(filepath.Join(dir, path))
		if err != nil || string(b) != want || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %q %v %v", path, b, err, info)
		}
	}
	// a directory with files in it is not written over unless asked
	if _, stderr, code := cli(t, "export", "-o", dir); code != 1 || !strings.Contains(stderr, "-force") {
		t.Errorf("non-empty directory: %d %q", code, stderr)
	}
	if _, _, code := cli(t, "export", "-o", dir, "-force"); code != 0 {
		t.Errorf("-force: %d", code)
	}
	if _, _, code := cli(t, "export"); code != 2 {
		t.Errorf("without -o: %d", code)
	}
	// a policy file name that leaves the directory is never written, whoever sent it
	g.json("GET /admin/v1/config/revisions/evil", revisionJSON(revB, "profile: standard\n", [2]string{"../../escape.yaml", "x"}))
	evil := filepath.Join(t.TempDir(), "evil")
	if _, stderr, code := cli(t, "export", "-o", evil, "-revision", "evil"); code != 1 || !strings.Contains(stderr, "unsafe") {
		t.Errorf("unsafe name: %d %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(evil, "..", "..", "escape.yaml")); err == nil {
		t.Error("a file was written outside the directory")
	}
}

func writeLocal(t *testing.T, policy bool) (cfgPath, polDir string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "tavian.yaml")
	body := "profile: standard\n"
	if policy {
		body += "policy: {dir: pol}\n"
	}
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	polDir = filepath.Join(dir, "pol")
	if err := os.MkdirAll(polDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(polDir, "10-a.yaml"), []byte("kind: Policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(polDir, "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, polDir
}

func TestConfigDiff(t *testing.T) {
	g := newFakeGateway(t)
	g.json("GET /admin/v1/config/diff?from="+revA+"&to="+revB, `{"from":"`+revA+`","to":"`+revB+`","files":[{"name":"tavian.yaml","status":"modified","diff":"--- a/tavian.yaml\n+++ b/tavian.yaml\n@@ -1 +1 @@\n-a\n+b\n"}]}`)
	g.json("GET /admin/v1/config/diff?from="+revA, `{"from":"`+revA+`","to":"`+revB+`","files":[]}`)
	if out, _, code := cli(t, "diff", revA, revB); code != 0 || !strings.Contains(out, "-a\n+b\n") {
		t.Errorf("diff: %d %s", code, out)
	}
	if out, _, code := cli(t, "diff", revA); code != 0 || !strings.Contains(out, "are the same") {
		t.Errorf("same: %d %s", code, out)
	}
	if _, _, code := cli(t, "diff"); code != 2 {
		t.Errorf("no argument: %d", code)
	}

	// a local configuration against the active revision
	g.json("GET /admin/v1/config/revisions/active", revisionJSON(revA, "profile: other\n", [2]string{"10-a.yaml", "kind: Policy\n"}, [2]string{"old.yaml", "x\n"}))
	cfg, _ := writeLocal(t, true)
	out, _, code := cli(t, "diff", "-config", cfg)
	if code != 0 || !strings.Contains(out, "-profile: other\n+profile: standard\n") || !strings.Contains(out, "--- a/policies/old.yaml\n+++ /dev/null") ||
		strings.Contains(out, "10-a.yaml") || strings.Contains(out, "notes.txt") {
		t.Errorf("local diff: %d\n%s", code, out)
	}
	g.json("GET /admin/v1/config/revisions/active", revisionJSON(revA, "profile: standard\npolicy: {dir: pol}\n", [2]string{"10-a.yaml", "kind: Policy\n"}))
	if out, _, code = cli(t, "diff", "-config", cfg); code != 0 || !strings.Contains(out, "is the same as revision "+revA) {
		t.Errorf("same local: %d %s", code, out)
	}
	if _, stderr, code := cli(t, "diff", "-config", filepath.Join(t.TempDir(), "missing.yaml")); code != 1 || stderr == "" {
		t.Errorf("missing file: %d %q", code, stderr)
	}
}

func TestConfigValidate(t *testing.T) {
	g := newFakeGateway(t)
	cfg, pol := writeLocal(t, false)
	g.json("POST /admin/v1/config/validate", `{"valid":true,"applicable":true,"revision":"`+revB+`","errors":[],"warnings":["model m has no price"]}`)
	out, _, code := cli(t, "validate", "-config", cfg, "-policies", pol)
	if code != 0 || !strings.Contains(out, "warning: model m has no price") || !strings.Contains(out, "the running gateway can take it") {
		t.Errorf("valid: %d %s", code, out)
	}
	var sent struct {
		Config   string
		Policies []struct{ Name, YAML string }
		Base     string
	}
	if err := json.Unmarshal([]byte(g.bodies["POST /admin/v1/config/validate"]), &sent); err != nil || sent.Config != "profile: standard\n" ||
		len(sent.Policies) != 1 || sent.Policies[0].Name != "10-a.yaml" {
		t.Errorf("sent %+v (%v)", sent, err)
	}
	g.json("POST /admin/v1/config/validate", `{"valid":true,"applicable":false,"revision":"`+revB+`","errors":[],"warnings":[],"reason":"restart_required: profile"}`)
	if out, _, code = cli(t, "validate", "-config", cfg, "-policies", pol); code != 1 || !strings.Contains(out, "cannot take it: restart_required") {
		t.Errorf("not applicable: %d %s", code, out)
	}
	g.json("POST /admin/v1/config/validate", `{"valid":false,"applicable":false,"errors":["models[0]: bad"],"warnings":[]}`)
	if out, _, code = cli(t, "validate", "-config", cfg, "-policies", pol); code != 1 || !strings.Contains(out, "error: models[0]: bad") || !strings.Contains(out, "invalid") {
		t.Errorf("invalid: %d %s", code, out)
	}
	if _, _, code = cli(t, "validate"); code != 1 {
		t.Errorf("no -config: %d", code)
	}
}

func TestConfigApply(t *testing.T) {
	g := newFakeGateway(t)
	cfg, _ := writeLocal(t, true) // policy.dir is read relative to the file
	g.json("GET /admin/v1/config", `{"revision":"`+revA+`"}`)
	g.json("POST /admin/v1/config/apply", `{"revision":"`+revB+`","previous":"`+revA+`","unchanged":false,"warnings":["w1"]}`)
	out, _, code := cli(t, "apply", "-config", cfg)
	if code != 0 || !strings.Contains(out, "applied: revision "+revB+" is active (it was "+revA+")") || !strings.Contains(out, "warning: w1") {
		t.Fatalf("apply: %d %s", code, out)
	}
	var sent struct {
		Config   string
		Policies []struct{ Name, YAML string }
		Base     string
	}
	if err := json.Unmarshal([]byte(g.bodies["POST /admin/v1/config/apply"]), &sent); err != nil || sent.Base != revA || !strings.Contains(sent.Config, "policy: {dir: pol}") ||
		len(sent.Policies) != 1 || sent.Policies[0].Name != "10-a.yaml" || sent.Policies[0].YAML != "kind: Policy\n" {
		t.Errorf("sent %+v (%v)", sent, err)
	}

	// the base can be pinned, and then nobody is asked what is active
	g.seen = nil
	if _, _, code = cli(t, "apply", "-config", cfg, "-base", "cccccccccccc"); code != 0 || strings.Contains(strings.Join(g.seen, ","), "GET /admin/v1/config") {
		t.Errorf("-base: %d %v", code, g.seen)
	}
	if !strings.Contains(g.bodies["POST /admin/v1/config/apply"], `"base":"cccccccccccc"`) {
		t.Errorf("the pinned base was not sent: %s", g.bodies["POST /admin/v1/config/apply"])
	}

	// nothing changed
	g.json("POST /admin/v1/config/apply", `{"revision":"`+revA+`","previous":"`+revA+`","unchanged":true,"warnings":[]}`)
	if out, _, _ = cli(t, "apply", "-config", cfg); !strings.Contains(out, "already active") {
		t.Errorf("unchanged: %s", out)
	}

	// refused: the code and the reason are shown, the exit status says so
	g.fail("POST /admin/v1/config/apply", 409, "conflict", "the active revision is "+revB+", not "+revA)
	_, stderr, code := cli(t, "apply", "-config", cfg)
	if code != 1 || !strings.Contains(stderr, "conflict") || !strings.Contains(stderr, "409") || !strings.Contains(stderr, "the active revision is "+revB) {
		t.Errorf("refused: %d %q", code, stderr)
	}
	if _, _, code = cli(t, "apply"); code != 1 {
		t.Errorf("no -config: %d", code)
	}
}

func TestConfigApplyDryRunChangesNothing(t *testing.T) {
	g := newFakeGateway(t)
	cfg, pol := writeLocal(t, false)
	g.json("GET /admin/v1/config", `{"revision":"`+revA+`"}`)
	g.json("GET /admin/v1/config/revisions/"+revA, revisionJSON(revA, "profile: other\n", [2]string{"10-a.yaml", "kind: Policy\n"}))
	g.json("POST /admin/v1/config/validate", `{"valid":true,"applicable":true,"revision":"`+revB+`","errors":[],"warnings":[]}`)
	out, _, code := cli(t, "apply", "-config", cfg, "-policies", pol, "-dry-run")
	if code != 0 || !strings.Contains(out, "would make revision "+revB+" active over "+revA) || !strings.Contains(out, "-profile: other\n+profile: standard\n") {
		t.Errorf("dry run: %d\n%s", code, out)
	}
	if strings.Contains(strings.Join(g.seen, ","), "apply") {
		t.Errorf("a dry run applied: %v", g.seen)
	}
	g.json("POST /admin/v1/config/validate", `{"valid":true,"applicable":false,"revision":"`+revB+`","errors":[],"warnings":[],"reason":"restart_required: profile"}`)
	if out, _, code = cli(t, "apply", "-config", cfg, "-policies", pol, "-dry-run"); code != 1 || !strings.Contains(out, "cannot be applied: restart_required") {
		t.Errorf("not applicable: %d %s", code, out)
	}
	g.json("POST /admin/v1/config/validate", `{"valid":true,"applicable":true,"revision":"`+revA+`","errors":[],"warnings":[]}`)
	g.json("GET /admin/v1/config/revisions/"+revA, revisionJSON(revA, "profile: standard\n", [2]string{"10-a.yaml", "kind: Policy\n"}))
	if out, _, code = cli(t, "apply", "-config", cfg, "-policies", pol, "-dry-run"); code != 0 || !strings.Contains(out, "nothing to apply") {
		t.Errorf("nothing to apply: %d %s", code, out)
	}
}

func TestConfigRollbackReloadAndHistory(t *testing.T) {
	g := newFakeGateway(t)
	g.json("GET /admin/v1/config", `{"revision":"`+revB+`"}`)
	g.json("POST /admin/v1/config/rollback", `{"revision":"`+revA+`","previous":"`+revB+`","unchanged":false,"warnings":[]}`)
	out, _, code := cli(t, "rollback", "-revision", revA)
	if code != 0 || !strings.Contains(out, "rolled back: revision "+revA+" is active (it was "+revB+")") {
		t.Errorf("rollback: %d %s", code, out)
	}
	if got := g.bodies["POST /admin/v1/config/rollback"]; !strings.Contains(got, `"revision":"`+revA+`"`) || !strings.Contains(got, `"base":"`+revB+`"`) {
		t.Errorf("rollback body: %s", got)
	}
	if _, _, code = cli(t, "rollback"); code != 2 {
		t.Errorf("rollback without a revision: %d", code)
	}
	g.fail("POST /admin/v1/config/rollback", 409, "credentials_would_return", "API key leaked would return")
	if _, stderr, code := cli(t, "rollback", "-revision", revA); code != 1 || !strings.Contains(stderr, "credentials_would_return") {
		t.Errorf("refused rollback: %d %q", code, stderr)
	}

	g.json("POST /admin/v1/config/reload", `{"revision":"`+revB+`","previous":"`+revA+`","unchanged":false,"warnings":[]}`)
	if out, _, code = cli(t, "reload"); code != 0 || !strings.Contains(out, "reloaded: revision "+revB) {
		t.Errorf("reload: %d %s", code, out)
	}

	g.json("GET /admin/v1/changes?limit=5", `{"changes":[{"event_id":"e1","occurred_at":"2026-10-10T10:00:00Z","actor":"ops-alice","action":"config.apply","target":"`+revB+`","outcome":"applied","remote_addr":"10.0.0.7"}]}`)
	out, _, code = cli(t, "history", "-limit", "5")
	if code != 0 || !strings.Contains(out, "ops-alice") || !strings.Contains(out, "config.apply") || !strings.Contains(out, "10.0.0.7") || !strings.HasPrefix(out, "WHEN") {
		t.Errorf("history: %d %s", code, out)
	}
	if _, stderr, code := cli(t, "history", "-limit", "501"); code != 1 || !strings.Contains(stderr, "-limit must be between 1 and 500") {
		t.Errorf("history -limit 501: %d %q", code, stderr)
	}
	if _, stderr, code := cli(t, "history", "-limit", "0"); code != 1 || !strings.Contains(stderr, "-limit must be") {
		t.Errorf("history -limit 0: %d %q", code, stderr)
	}
}

func TestConfigFailuresAreReadable(t *testing.T) {
	g := newFakeGateway(t)
	// the gateway is not there
	g.srv.Close()
	if _, stderr, code := cli(t, "reload"); code != 1 || !strings.Contains(stderr, "cannot reach the gateway") {
		t.Errorf("unreachable: %d %q", code, stderr)
	}
	// a token that is refused
	g2 := newFakeGateway(t)
	g2.fail("POST /admin/v1/config/reload", 401, "unauthenticated", "a valid admin token is required")
	if _, stderr, code := cli(t, "reload"); code != 1 || !strings.Contains(stderr, "a valid admin token is required") || !strings.Contains(stderr, "401") {
		t.Errorf("refused token: %d %q", code, stderr)
	}
	// something that is not the admin API
	g2.routes["POST /admin/v1/config/reload"] = func(w http.ResponseWriter, _ string) { _, _ = io.WriteString(w, "<html>proxy</html>") }
	if _, stderr, code := cli(t, "reload"); code != 1 || !strings.Contains(stderr, "not what this version expects") {
		t.Errorf("not json: %d %q", code, stderr)
	}
	g2.routes["POST /admin/v1/config/reload"] = func(w http.ResponseWriter, _ string) { http.Error(w, "bad gateway", http.StatusBadGateway) }
	if _, stderr, code := cli(t, "reload"); code != 1 || !strings.Contains(stderr, "502") || !strings.Contains(stderr, "bad gateway") {
		t.Errorf("plain error: %d %q", code, stderr)
	}
}

func TestConfigNeverFollowsARedirectWithTheToken(t *testing.T) {
	var leaked bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
	}))
	defer elsewhere.Close()
	g := newFakeGateway(t)
	g.routes["POST /admin/v1/config/reload"] = func(w http.ResponseWriter, _ string) {
		http.Redirect(w, &http.Request{}, elsewhere.URL, http.StatusTemporaryRedirect)
	}
	_, stderr, code := cli(t, "reload")
	if code != 1 || !strings.Contains(stderr, "redirect") {
		t.Errorf("redirect: %d %q", code, stderr)
	}
	if leaked {
		t.Error("the token followed a redirect")
	}
}

func TestConfigTokens(t *testing.T) {
	g := newFakeGateway(t)
	g.json("GET /admin/v1/tokens", `{"tokens":[
	  {"id":"ops-alice","role":"admin","expires_at":"2027-03-01T00:00:00Z","expired":false,"last_used_at":"2026-10-10T12:00:00Z","last_remote":"10.0.0.7","uses":42},
	  {"id":"old","role":"operator","expires_at":"2020-01-01T00:00:00Z","expired":true,"uses":0},
	  {"id":"audit-bob","role":"auditor","expired":false,"uses":0}]}`)
	out, _, code := cli(t, "tokens")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "ID") {
		t.Fatalf("table:\n%s", out)
	}
	if !strings.Contains(lines[1], "ops-alice") || !strings.Contains(lines[1], "admin") || !strings.Contains(lines[1], "10.0.0.7") || !strings.Contains(lines[1], "42") ||
		!strings.Contains(lines[2], "(expired)") || !strings.Contains(lines[2], "never") ||
		!strings.Contains(lines[3], "never") || strings.Contains(lines[3], "expired") {
		t.Errorf("table:\n%s", out)
	}
	if out, _, _ = cli(t, "tokens", "-json"); !strings.HasPrefix(out, "{\"tokens\"") {
		t.Errorf("-json: %s", out)
	}
	g.fail("GET /admin/v1/tokens", 403, "forbidden", "no")
	if _, stderr, code := cli(t, "tokens"); code != 1 || !strings.Contains(stderr, "forbidden") {
		t.Errorf("refused: %d %q", code, stderr)
	}
}
