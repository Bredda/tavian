//go:build e2e

// Package e2e runs the scenario that defines success (docs/VISION.md) against
// the real binaries, a real PostgreSQL and the configuration and policies of the
// demo stack (deploy/compose).
//
// It compiles the gateway, which keeps a CPU busy for a while, so it sits behind
// a build tag and runs on its own: next to the tests of the other packages it
// would make the timing-sensitive ones flaky.
//
//	TAVIAN_TEST_DATABASE_URL=postgres://... go test -tags e2e ./e2e
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/mockllm"
	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/store/storetest"
)

// The demo keys are public (README.md).
const (
	financeKey = "tav_EV1tUN4aJqmj1nDwAuRd_juZk1MpqqRyuqC9bZ75DK0" // team finance, cleared for confidential
	demoKey    = "tav_VavQsTNlrxWVesBv7GinuMLhYBbmhns_YNloIcWS3UI" // team demo-team, cleared for internal
)

// The IBAN of the scenario, written the way people write it and without spaces:
// neither may be found anywhere afterwards.
const (
	iban        = "FR14 2004 1010 0505 0001 3M02 606"
	ibanCompact = "FR1420041010050500013M02606"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot find the repository")
	}
	return filepath.Dir(filepath.Dir(file))
}

func build(t *testing.T, root, out string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, "./cmd/tavian")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
}

// backend stands for a model server and remembers what it was sent.
type backend struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies []string
}

func newBackend(t *testing.T, name string) *backend {
	t.Helper()
	b := &backend{}
	inner := mockllm.HandlerNamed(name)
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			b.mu.Lock()
			b.bodies = append(b.bodies, string(body))
			b.mu.Unlock()
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *backend) received() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.bodies, "\n")
}

func (b *backend) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.bodies)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// demoConfig is deploy/compose/tavian.yaml with what only Docker needs
// replaced: where the backends and the database are, and no OIDC provider.
// Models, prices, keys and policies are the demo's own.
func demoConfig(t *testing.T, root, dir string, onprem, partner *backend, data, admin, adminHash string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "tavian.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	delete(cfg, "oidc")
	cfg["listen"] = map[string]any{"data": data, "admin": admin}
	cfg["database"] = map[string]any{"url_env": "TAVIAN_DATABASE_URL", "spool_dir": filepath.Join(dir, "spool")}
	cfg["audit"] = map[string]any{"signing_key_file": filepath.Join(dir, "audit.key"), "seal_every_events": 4, "seal_every": "2s"}
	cfg["admin"] = map[string]any{"tokens": []any{map[string]any{"id": "e2e-admin", "hash": adminHash}}}
	cfg["workers"] = map[string]any{"poll_interval": "100ms"}
	cfg["policy"] = map[string]any{"dir": filepath.Join(dir, "policies")}
	for _, b := range cfg["backends"].([]any) {
		m := b.(map[string]any)
		switch m["id"] {
		case "mockllm":
			m["base_url"] = onprem.srv.URL + "/v1"
		case "partner-eu":
			m["base_url"] = partner.srv.URL + "/v1"
		default:
			t.Fatalf("the demo has a backend this test does not know: %v", m["id"])
		}
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tavian.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// copyPolicies copies the demo's policies and adds a small daily token limit for
// finance, to watch a quota being used up.
func copyPolicies(t *testing.T, root, dir string) {
	t.Helper()
	src := filepath.Join(root, "deploy", "compose", "policies")
	dst := filepath.Join(dir, "policies")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil || len(entries) == 0 {
		t.Fatalf("demo policies: %v", err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	extra := `apiVersion: tavian/v1alpha1
kind: Policy
metadata: { name: e2e-finance-daily }
spec:
  scope: { team: finance }
  quotas:
    - { dimension: tokens_per_day, limit: 400 }
`
	if err := os.WriteFile(filepath.Join(dst, "zz-e2e-finance-daily.yaml"), []byte(extra), 0o600); err != nil {
		t.Fatal(err)
	}
}

type gateway struct {
	t         *testing.T
	data      string
	admin     string
	log       string
	cmd       *exec.Cmd
	exited    chan error
	stopped   bool
	bin, cfg  string
	dbURL     string
	publicKey string
}

func (g *gateway) env() []string { return append(os.Environ(), "TAVIAN_DATABASE_URL="+g.dbURL) }

func (g *gateway) start() {
	g.t.Helper()
	logf, err := os.Create(g.log)
	if err != nil {
		g.t.Fatal(err)
	}
	g.cmd = exec.Command(g.bin, "serve", "-config", g.cfg)
	g.cmd.Env = g.env()
	g.cmd.Stdout, g.cmd.Stderr = logf, logf
	if err := g.cmd.Start(); err != nil {
		g.t.Fatal(err)
	}
	g.exited = make(chan error, 1)
	go func() { g.exited <- g.cmd.Wait(); _ = logf.Close() }()
	g.t.Cleanup(func() {
		if !g.stopped {
			_ = g.cmd.Process.Kill()
			<-g.exited
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-g.exited:
			g.stopped = true
			g.t.Fatalf("the gateway exited at startup: %v\n%s", err, g.logs())
		default:
		}
		if resp, err := http.Get("http://" + g.admin + "/readyz"); err == nil {
			ok := resp.StatusCode == 200
			_ = resp.Body.Close()
			if ok {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	g.t.Fatalf("the gateway did not become ready\n%s", g.logs())
}

// stop asks the gateway to shut down and returns how it exited.
func (g *gateway) stop() error {
	g.t.Helper()
	g.stopped = true
	_ = g.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-g.exited:
		return err
	case <-time.After(20 * time.Second):
		_ = g.cmd.Process.Kill()
		return fmt.Errorf("the gateway did not stop within 20 s")
	}
}

func (g *gateway) logs() string {
	b, _ := os.ReadFile(g.log)
	return string(b)
}

func (g *gateway) metrics() string {
	resp, err := http.Get("http://" + g.admin + "/metrics")
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

type reply struct {
	status     int
	backend    string // x_mock_backend of the answer
	code       string // error code
	message    string
	decisionID string // from the error body, else the header
	retryAfter string
}

// chat sends a chat completion. Every request sets max_tokens: the quota
// reserves the answer's cap, and the default one is far above the small limit
// of this test.
func (g *gateway) chat(key, model, content string) reply {
	g.t.Helper()
	body, _ := json.Marshal(map[string]any{
		"model": model, "max_tokens": 20,
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	req, _ := http.NewRequest(http.MethodPost, "http://"+g.data+"/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Backend string `json:"x_mock_backend"`
		Error   struct {
			Code       string `json:"code"`
			Message    string `json:"message"`
			DecisionID string `json:"decision_id"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	r := reply{
		status: resp.StatusCode, backend: out.Backend, code: out.Error.Code, message: out.Error.Message,
		decisionID: out.Error.DecisionID, retryAfter: resp.Header.Get("Retry-After"),
	}
	if r.decisionID == "" {
		r.decisionID = resp.Header.Get("X-Tavian-Decision-Id")
	}
	return r
}

func (g *gateway) tavian(args ...string) (string, int) {
	g.t.Helper()
	cmd := exec.Command(g.bin, args...)
	cmd.Env = g.env()
	out, err := cmd.CombinedOutput()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		g.t.Fatalf("tavian %v: %v", args, err)
	}
	return string(out), code
}

// decision reads a decision record from the database, waiting for it: the
// record of a served request is written as the answer ends.
func decision(t *testing.T, pool *pgxpool.Pool, id string) audit.DecisionRecord {
	t.Helper()
	if id == "" {
		t.Fatal("no decision id")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var payload []byte
		err := pool.QueryRow(context.Background(), `SELECT payload::text FROM outbox WHERE kind = 'decision' AND event_id = $1`, id).Scan(&payload)
		if err == nil {
			var d audit.DecisionRecord
			if err := json.Unmarshal(payload, &d); err != nil {
				t.Fatal(err)
			}
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("decision record %s never reached the database: %v", id, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func query[T any](t *testing.T, pool *pgxpool.Pool, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return v
}

// everything the system wrote down or said: the outbox, the logs, the metrics.
func everythingRecorded(t *testing.T, pool *pgxpool.Pool, g *gateway) string {
	t.Helper()
	var b strings.Builder
	rs, err := pool.Query(context.Background(), `SELECT payload::text FROM outbox`)
	if err != nil {
		t.Fatal(err)
	}
	for rs.Next() {
		var p string
		_ = rs.Scan(&p)
		b.WriteString(p)
		b.WriteByte('\n')
	}
	rs.Close()
	b.WriteString(g.logs())
	b.WriteString(g.metrics())
	return b.String()
}

// The scenario of docs/VISION.md, step by step.
func TestFinanceDemo(t *testing.T) {
	st, dbURL := storetest.New(t) // skips without TAVIAN_TEST_DATABASE_URL
	pool := st.Pool()
	root := repoRoot(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "tavian")
	build(t, root, bin)

	onprem, partner := newBackend(t, "on-prem"), newBackend(t, "partner-eu")
	copyPolicies(t, root, dir)
	g := &gateway{
		t: t, bin: bin, dbURL: dbURL, data: freeAddr(t), admin: freeAddr(t), log: filepath.Join(dir, "gateway.log"),
	}
	out, code := g.tavian("keygen", "-admin")
	var adminToken, adminHash string
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "token: "); ok {
			adminToken = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "hash:  "); ok {
			adminHash = strings.TrimSpace(v)
		}
	}
	if code != 0 || adminToken == "" || adminHash == "" {
		t.Fatalf("keygen -admin (exit %d): %s", code, out)
	}
	g.cfg = demoConfig(t, root, dir, onprem, partner, g.data, g.admin, adminHash)

	out, code = g.tavian("audit-keygen", "-out", filepath.Join(dir, "audit.key"))
	if code != 0 {
		t.Fatalf("audit-keygen: %s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if k, ok := strings.CutPrefix(l, "public key: "); ok {
			g.publicKey = k
		}
	}
	if g.publicKey == "" {
		t.Fatalf("no public key in %q", out)
	}
	if out, code := g.tavian("validate", "-config", g.cfg); code != 0 {
		t.Fatalf("the demo configuration does not validate:\n%s", out)
	}
	g.start()

	// 1. The finance team calls the gateway. Ordinary data goes where the model's
	//    route says: the external provider comes first.
	t.Run("ordinary data follows the route", func(t *testing.T) {
		r := g.chat(financeKey, "demo-shared", "Summarise the quarterly meeting notes")
		if r.status != 200 || r.backend != "partner-eu" {
			t.Fatalf("status %d answered by %q, want 200 by partner-eu", r.status, r.backend)
		}
		if d := decision(t, pool, r.decisionID); d.Label != "internal" || d.Backend != "partner-eu" {
			t.Errorf("record = label %q backend %q", d.Label, d.Backend)
		}
	})

	// 2. A request contains an IBAN. The inspector flags it, the label becomes
	//    confidential, destinations are restricted to internal, and the request
	//    goes to the on-prem model, although the client asked for a model that
	//    also exists on an external provider.
	var ibanDecision string
	t.Run("an IBAN stays on premises", func(t *testing.T) {
		before := partner.calls()
		r := g.chat(financeKey, "demo-shared", "Transfer 100 EUR to "+iban)
		if r.status != 200 || r.backend != "on-prem" {
			t.Fatalf("status %d answered by %q, want 200 by on-prem", r.status, r.backend)
		}
		if partner.calls() != before {
			t.Fatal("the external provider received the request")
		}
		ibanDecision = r.decisionID
		d := decision(t, pool, r.decisionID)
		if d.Outcome != audit.OutcomeServed || d.ReasonCode != "SERVED" || d.Label != "confidential" {
			t.Errorf("record = %s %s label %q", d.Outcome, d.ReasonCode, d.Label)
		}
		if d.LabelSources == nil || d.LabelSources.Inferred != "confidential" {
			t.Errorf("label sources = %+v: the label should come from what inspection found", d.LabelSources)
		}
		if len(d.Constraints) != 1 || d.Constraints[0] != "internal" {
			t.Errorf("constraints = %v, want only internal destinations", d.Constraints)
		}
		found := false
		for _, f := range d.Findings {
			if f.Type == "pii" && f.Subtype == "iban" && f.Fingerprint != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("findings = %+v: no IBAN, or no fingerprint", d.Findings)
		}
		want := []audit.Candidate{{Backend: "partner-eu", Excluded: policy.ExcludedClearance}, {Backend: "mockllm"}}
		if d.Backend != "mockllm" || len(d.Candidates) != 2 || d.Candidates[0] != want[0] || d.Candidates[1] != want[1] {
			t.Errorf("backend %q candidates %+v: the external provider should have been set aside, with the reason", d.Backend, d.Candidates)
		}
		if d.Cost == nil || d.Cost.MicroEUR == nil || *d.Cost.MicroEUR < 1 || d.Cost.EnergyWh == nil || *d.Cost.EnergyWh <= 0 || d.Cost.CO2eGrams == nil || *d.Cost.CO2eGrams <= 0 || !d.Cost.Estimate {
			t.Errorf("cost = %+v: money, energy and carbon were expected", d.Cost)
		}
	})

	// 3. An external-only model asked by the same team with the same data is
	//    refused with an explainable reason.
	t.Run("an external-only model is refused with a reason", func(t *testing.T) {
		before := partner.calls()
		r := g.chat(financeKey, "demo-partner", "Transfer 100 EUR to "+iban)
		if r.status != http.StatusForbidden || r.code != "no_eligible_backend" || r.decisionID == "" {
			t.Fatalf("%+v", r)
		}
		if partner.calls() != before {
			t.Fatal("the external provider received the request")
		}
		d := decision(t, pool, r.decisionID)
		if d.Outcome != audit.OutcomeRefused || d.ReasonCode != "NO_ELIGIBLE_BACKEND" || d.Label != "confidential" ||
			len(d.Candidates) != 1 || d.Candidates[0].Backend != "partner-eu" || d.Candidates[0].Excluded != policy.ExcludedClearance {
			t.Errorf("record = %s %s label %q candidates %+v", d.Outcome, d.ReasonCode, d.Label, d.Candidates)
		}
	})

	// A caller cleared only for internal data cannot send it at all.
	t.Run("a caller without the clearance is refused", func(t *testing.T) {
		r := g.chat(demoKey, "demo-shared", "Transfer 100 EUR to "+iban)
		if r.status != http.StatusForbidden || r.code != "classification_exceeds_clearance" {
			t.Fatalf("%+v", r)
		}
		if d := decision(t, pool, r.decisionID); d.ReasonCode != "CLEARANCE_EXCEEDED" {
			t.Errorf("reason = %s", d.ReasonCode)
		}
	})

	// 4. The team's quota is decremented: by what the requests really used.
	t.Run("the quota is used up by real usage", func(t *testing.T) {
		served := 0
		var last reply
		for i := 0; i < 60; i++ {
			last = g.chat(financeKey, "demo-shared", fmt.Sprintf("Question number %d about the budget", i))
			if last.status != 200 {
				break
			}
			served++
		}
		if served < 2 || last.status != http.StatusTooManyRequests || last.code != "quota_exceeded" {
			t.Fatalf("served %d requests, then %+v", served, last)
		}
		if last.retryAfter == "" {
			t.Error("no Retry-After for an empty day")
		}
		d := decision(t, pool, last.decisionID)
		if d.ReasonCode != "QUOTA_EXCEEDED" || d.Quota == nil || len(d.Quota.Exceeded) == 0 {
			t.Fatalf("record = %s %+v", d.ReasonCode, d.Quota)
		}
		x := d.Quota.Exceeded[0]
		if x.Policy != "e2e-finance-daily" || x.Dimension != "tokens_per_day" || x.Limit != 400 || x.Effect != "refused" {
			t.Errorf("exceeded = %+v", x)
		}
		// what the counter holds is exactly the tokens finance used
		deadline := time.Now().Add(10 * time.Second)
		for {
			used := query[int64](t, pool, `SELECT COALESCE(sum((payload->>'input_tokens')::bigint + (payload->>'output_tokens')::bigint), 0)::bigint
				FROM outbox WHERE kind = 'usage' AND payload->>'team' = 'finance'`)
			if used == x.Used {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the quota counted %d tokens, finance used %d", x.Used, used)
			}
			time.Sleep(50 * time.Millisecond)
		}
		// another team is not affected
		if r := g.chat(demoKey, "demo-chat", "Hello"); r.status != 200 {
			t.Errorf("the demo team: %+v", r)
		}
	})

	// 4b. The administrators change the configuration through the API and by
	//     signal. Each change is recorded with its author before it takes
	//     effect, and ends up in the audit chain.
	t.Run("the administrators' changes are recorded and chained", func(t *testing.T) {
		adminCall := func(method, path, token string) (int, string) {
			req, _ := http.NewRequest(method, "http://"+g.admin+path, nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
		rewrite := func(mutate func(cfg map[string]any)) {
			raw, err := os.ReadFile(g.cfg)
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err := yaml.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			mutate(cfg)
			out, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(g.cfg, out, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		running := func() string {
			code, body := adminCall("GET", "/admin/v1/config", adminToken)
			var c struct{ Revision string }
			if err := json.Unmarshal([]byte(body), &c); err != nil || code != 200 {
				t.Fatalf("GET /admin/v1/config: %d %s", code, body)
			}
			return c.Revision
		}

		if code, _ := adminCall("GET", "/admin/v1/whoami", ""); code != 401 {
			t.Errorf("whoami without a token = %d", code)
		}
		if code, _ := adminCall("GET", "/admin/v1/whoami", financeKey); code != 401 {
			t.Errorf("a data-plane key opened the admin API: %d", code)
		}
		if code, body := adminCall("GET", "/admin/v1/whoami", adminToken); code != 200 || !strings.Contains(body, "e2e-admin") {
			t.Fatalf("whoami = %d %s", code, body)
		}
		before := running()

		// a valid change, by the API
		rewrite(func(cfg map[string]any) { cfg["log"] = map[string]any{"level": "debug"} })
		code, body := adminCall("POST", "/admin/v1/config/reload", adminToken)
		var res struct{ Revision, Previous string }
		_ = json.Unmarshal([]byte(body), &res)
		if code != 200 || res.Previous != before || res.Revision == before || running() != res.Revision {
			t.Fatalf("reload = %d %s (running before: %s)", code, body, before)
		}
		applied := res.Revision
		good, err := os.ReadFile(g.cfg)
		if err != nil {
			t.Fatal(err)
		}

		// an invalid one is refused, and the revision stays
		rewrite(func(cfg map[string]any) { cfg["models"] = "not a list" })
		if code, body := adminCall("POST", "/admin/v1/config/reload", adminToken); code != 422 || !strings.Contains(body, "invalid_configuration") {
			t.Fatalf("invalid reload = %d %s", code, body)
		}
		if running() != applied {
			t.Error("a refused configuration replaced the running one")
		}

		// back to the good file, reloaded by signal
		if err := os.WriteFile(g.cfg, good, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := g.cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		type change struct {
			EventID    string          `json:"event_id"`
			Actor      string          `json:"actor"`
			Action     string          `json:"action"`
			Target     string          `json:"target"`
			Outcome    string          `json:"outcome"`
			RemoteAddr string          `json:"remote_addr"`
			Detail     json.RawMessage `json:"detail"`
		}
		var changes []change
		deadline := time.Now().Add(10 * time.Second)
		for {
			code, body := adminCall("GET", "/admin/v1/changes", adminToken)
			var page struct{ Changes []change }
			if err := json.Unmarshal([]byte(body), &page); err != nil || code != 200 {
				t.Fatalf("GET /admin/v1/changes: %d %s", code, body)
			}
			if changes = page.Changes; len(changes) >= 3 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the signal reload was never recorded: %s\n%s", body, g.logs())
			}
			time.Sleep(100 * time.Millisecond)
		}
		// newest first: the signal, the refusal, the API reload
		sig, refused, api := changes[0], changes[1], changes[2]
		if sig.Actor != "sighup" || sig.Outcome != "applied" || sig.Action != "config.reload" || sig.Target != applied {
			t.Errorf("signal reload = %+v", sig)
		}
		if refused.Actor != "e2e-admin" || refused.Outcome != "rejected" || !strings.Contains(string(refused.Detail), "invalid_configuration") {
			t.Errorf("refused reload = %+v", refused)
		}
		if api.Actor != "e2e-admin" || api.Outcome != "applied" || api.Target != applied || api.RemoteAddr != "127.0.0.1" ||
			!strings.Contains(string(api.Detail), before) {
			t.Errorf("API reload = %+v", api)
		}

		// the chain takes them in, like the decision records
		ids := []string{sig.EventID, refused.EventID, api.EventID}
		deadline = time.Now().Add(15 * time.Second)
		for {
			n := query[int](t, pool, `SELECT count(*) FROM audit_chain WHERE event_id = ANY($1)`, ids)
			if n == len(ids) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d of the %d admin changes are in the chain", n, len(ids))
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	// 5. The auditor opens the audit trail and verifies that it has not been
	//    tampered with.
	var seals string
	t.Run("the audit chain verifies", func(t *testing.T) {
		// the sealer works in the background: wait until it has caught up
		var out string
		deadline := time.Now().Add(30 * time.Second)
		for {
			var code int
			out, code = g.tavian("verify-audit", "-config", g.cfg, "-public-key", g.publicKey, "-export-seals", filepath.Join(dir, "seals.jsonl"))
			if code == 0 && !strings.Contains(out, "pending:") && !strings.Contains(out, "no seals yet") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("verify-audit never came back clean (exit %d):\n%s", code, out)
			}
			time.Sleep(300 * time.Millisecond)
		}
		if !strings.Contains(out, "signatures verified") || !strings.Contains(out, "OK: no problem found") {
			t.Fatalf("%s", out)
		}
		seals = filepath.Join(dir, "seals.jsonl")
		if out, code := g.tavian("verify-audit", "-config", g.cfg, "-public-key", g.publicKey, "-anchors", seals); code != 0 {
			t.Fatalf("anchors: %s", out)
		}
	})

	// The IBAN is nowhere: not in a record, a log or a metric.
	t.Run("the IBAN was never written down", func(t *testing.T) {
		all := strings.ToUpper(everythingRecorded(t, pool, g))
		for _, needle := range []string{iban, ibanCompact, "2004 1010", "20041010", "3M02", adminToken, adminHash} {
			if strings.Contains(all, strings.ToUpper(needle)) {
				t.Errorf("found %q in what the gateway recorded, logged or exposed", needle)
			}
		}
		// the model that may know it did receive it, the one that may not did not
		if !strings.Contains(onprem.received(), "2004 1010") {
			t.Error("the on-prem model did not get the IBAN: the scenario did not run as intended")
		}
		if strings.Contains(partner.received(), "2004 1010") || strings.Contains(partner.received(), "20041010") {
			t.Error("the external provider received part of the IBAN")
		}
	})

	// Changing a record afterwards is found.
	t.Run("a changed record is found", func(t *testing.T) {
		if _, err := pool.Exec(context.Background(), `UPDATE outbox SET payload = jsonb_set(payload, '{outcome}', '"refused"') WHERE event_id = $1`, ibanDecision); err != nil {
			t.Fatal(err)
		}
		out, code := g.tavian("verify-audit", "-config", g.cfg, "-public-key", g.publicKey, "-anchors", seals)
		if code != 1 || !strings.Contains(out, "FAILED") || !strings.Contains(out, ibanDecision) || !strings.Contains(out, "altered") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})

	if err := g.stop(); err != nil {
		t.Errorf("the gateway did not stop cleanly: %v\n%s", err, g.logs())
	}
}
