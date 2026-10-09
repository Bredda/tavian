package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/policy"
	"github.com/bredda/tavian/internal/quota"
)

// clock is a time source a test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// quotaFixture is a gateway whose quotas run on clocks the test controls: the
// store's and the one that spaces the records of refusals.
type quotaFixture struct {
	*fixture
	store, refusals *clock
}

func quotaGateway(t *testing.T, backend http.Handler, files ...policy.Source) *quotaFixture {
	t.Helper()
	q := &quotaFixture{store: newClock(), refusals: newClock()}
	q.fixture = buildFixture(t, fixtureSpec{
		maxBody: 1 << 20, backend: backend, policies: files,
		deps: []func(*Deps){func(d *Deps) {
			d.Quota = quota.NewStore(q.store.now)
			d.Coalescer = quota.NewCoalescer(q.refusals.now)
		}},
	})
	return q
}

func quotaPolicy(name, scope, mode, quotas string) policy.Source {
	return policyFile(name+".yaml", `
metadata: { name: `+name+`, mode: `+mode+` }
spec:
  scope: `+scope+`
  quotas: `+quotas+`
`)
}

type apiError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	DecisionID string `json:"decision_id"`
}

func readError(t *testing.T, resp *http.Response) apiError {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	var e struct {
		Error apiError `json:"error"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("error body %q: %v", b, err)
	}
	return e.Error
}

func TestRequestsPerMinuteAreRefusedWithARetryAfterAndARecord(t *testing.T) {
	rec := newRecorder()
	q := quotaGateway(t, rec, quotaPolicy("research-rate", "{ team: research }", "enforce", "[ { dimension: rpm, limit: 2 } ]"))
	for i := 0; i < 2; i++ {
		if resp := q.post(t, q.key, chatBody); resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
		q.store.advance(10 * time.Second)
	}
	resp := q.post(t, q.key, chatBody)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third request in a minute: status %d, want 429", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "40" {
		t.Errorf("Retry-After = %q, want 40 (the first request is 20 s old)", got)
	}
	e := readError(t, resp)
	if e.Code != "rate_limit_exceeded" || !strings.Contains(e.Message, "requests per minute") || !strings.Contains(e.Message, "team") {
		t.Errorf("error = %+v", e)
	}
	if rec.count() != 2 {
		t.Errorf("the backend saw %d requests, want 2: a refused request must not reach it", rec.count())
	}

	d := lastDecision(t, q.fixture)
	if d.Outcome != "refused" || d.ReasonCode != "RATE_LIMITED" || d.Status != 429 || e.DecisionID != d.DecisionID || resp.Header.Get(decisionHeader) != d.DecisionID {
		t.Errorf("record = %s/%s %d id %q (body %q, header %q)", d.Outcome, d.ReasonCode, d.Status, d.DecisionID, e.DecisionID, resp.Header.Get(decisionHeader))
	}
	if d.Quota == nil || len(d.Quota.Exceeded) != 1 {
		t.Fatalf("quota = %+v", d.Quota)
	}
	x := d.Quota.Exceeded[0]
	if x.Policy != "research-rate" || x.Dimension != "rpm" || x.Scope != "team" || x.Limit != 2 || x.Used != 2 || x.Requested != 1 || x.Effect != "refused" {
		t.Errorf("exceeded = %+v", x)
	}
	if d.Inspection != nil {
		t.Error("the request was inspected before the cheap quotas were checked")
	}

	// another team is not affected, and the window clears with time
	if resp := q.post(t, q.conf, chatBody); resp.StatusCode != 200 {
		t.Errorf("finance: status %d, the limit belongs to research", resp.StatusCode)
	}
	q.store.advance(41 * time.Second)
	if resp := q.post(t, q.key, chatBody); resp.StatusCode != 200 {
		t.Errorf("after Retry-After: status %d", resp.StatusCode)
	}
}

func TestOrganizationLimitIsSharedByEveryone(t *testing.T) {
	q := quotaGateway(t, nil, quotaPolicy("org-rate", "{ organization: true }", "enforce", "[ { dimension: rpm, limit: 3 } ]"))
	for i, key := range []string{q.key, q.conf, q.top} {
		if resp := q.post(t, key, chatBody); resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
	resp := q.post(t, q.key, chatBody)
	if resp.StatusCode != 429 {
		t.Fatalf("status %d: the organization's three requests are used", resp.StatusCode)
	}
	if e := readError(t, resp); strings.Contains(e.Message, "research") || strings.Contains(e.Message, "finance") {
		t.Errorf("the message names a team: %q", e.Message)
	}
}

func TestRefusedAndAnonymousRequestsCostNothing(t *testing.T) {
	q := quotaGateway(t, nil, quotaPolicy("rate", "{ organization: true }", "enforce", "[ { dimension: rpm, limit: 2 } ]"))
	for i := 0; i < 20; i++ {
		if resp := q.post(t, "tav_notakey", chatBody); resp.StatusCode != 401 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	for i := 0; i < 2; i++ {
		if resp := q.post(t, q.key, chatBody); resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d, anonymous requests used the organization's quota", i, resp.StatusCode)
		}
	}
	for i := 0; i < 5; i++ {
		q.post(t, q.key, chatBody) // refused
	}
	q.store.advance(61 * time.Second)
	if resp := q.post(t, q.key, chatBody); resp.StatusCode != 200 {
		t.Errorf("status %d: refusals extended the window", resp.StatusCode)
	}
}

// A client that ignores its 429s must not fill the audit trail: refusals are
// all counted, recorded at most once a second per caller and limit.
func TestRefusalsAreRecordedOncePerSecondAndAllCounted(t *testing.T) {
	q := quotaGateway(t, nil, quotaPolicy("rate", "{ organization: true }", "enforce", "[ { dimension: rpm, limit: 1 } ]"))
	q.post(t, q.key, chatBody)
	var withID, withoutID int
	for i := 0; i < 20; i++ {
		resp := q.post(t, q.key, chatBody)
		if resp.StatusCode != 429 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		e := readError(t, resp)
		if (e.DecisionID == "") != (resp.Header.Get(decisionHeader) == "") {
			t.Fatalf("header %q and body %q disagree about the decision id", resp.Header.Get(decisionHeader), e.DecisionID)
		}
		if e.DecisionID == "" {
			withoutID++
		} else {
			withID++
		}
	}
	if withID != 1 || withoutID != 19 {
		t.Fatalf("%d refusals with a decision id, %d without; want 1 and 19", withID, withoutID)
	}
	if n := len(decisions(q.fixture)); n != 2 { // the served one and one refusal
		t.Fatalf("%d decision records, want 2", n)
	}
	if !strings.Contains(metricsText(t, q.fixture), `tavian_quota_exceeded_total{dimension="rpm",effect="refused",scope="organization"} 20`) {
		t.Error("the 20 refusals are not all counted")
	}

	// a second later the next refusal is recorded and says how many it stands for
	q.refusals.advance(time.Second)
	resp := q.post(t, q.key, chatBody)
	if resp.StatusCode != 429 || readError(t, resp).DecisionID == "" {
		t.Fatal("the refusal after a second was not recorded")
	}
	d := lastDecision(t, q.fixture)
	if d.Quota == nil || d.Quota.Suppressed != 19 {
		t.Errorf("suppressed = %+v, want 19", d.Quota)
	}

	// another caller refused by the same limit is recorded on its own
	resp = q.post(t, q.conf, chatBody)
	if resp.StatusCode != 429 || readError(t, resp).DecisionID == "" {
		t.Error("a second caller's refusal was hidden by the first one's")
	}
}

func TestConcurrencyIsHeldWhileTheAnswerIsStreamed(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","object":"chat.completion","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	})
	q := quotaGateway(t, slow, quotaPolicy("conc", "{ team: research }", "enforce", "[ { dimension: concurrency, limit: 1 } ]"))
	done := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, q.gw.URL+"/v1/chat/completions", strings.NewReader(chatBody))
		req.Header.Set("Authorization", "Bearer "+q.key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- 0
			return
		}
		defer resp.Body.Close()
		done <- resp.StatusCode
	}()
	<-started
	resp := q.post(t, q.key, chatBody)
	if resp.StatusCode != 429 || readError(t, resp).Code != "rate_limit_exceeded" {
		t.Fatalf("second concurrent request: status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q", got)
	}
	close(release)
	if st := <-done; st != 200 {
		t.Fatalf("first request: status %d", st)
	}
	if resp := q.post(t, q.key, chatBody); resp.StatusCode != 200 {
		t.Errorf("after the first request ended: status %d, the slot was not given back", resp.StatusCode)
	}
}

func TestTokensAreReservedThenSettledWithWhatWasUsed(t *testing.T) {
	// one reservation is about 1060 tokens (the request and the default answer
	// cap of 1024); the mock uses about ten. If settle did not give the
	// difference back, the second request would already be refused.
	q := quotaGateway(t, nil, quotaPolicy("daily", "{ team: research }", "enforce", "[ { dimension: tokens_per_day, limit: 1500 } ]"))
	for i := 0; i < 10; i++ {
		if resp := q.post(t, q.key, chatBody); resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d, the reservation was not settled", i, resp.StatusCode)
		}
	}
	d := lastDecision(t, q.fixture)
	if d.Quota == nil || d.Quota.ReservedTokens < 1024 || d.Quota.ReservedTokens > 1100 {
		t.Errorf("quota = %+v, want the default answer cap plus the request", d.Quota)
	}
	if !strings.Contains(metricsText(t, q.fixture), "tavian_quota_estimate_ratio_count 10") {
		t.Error("the estimate ratio was not observed")
	}
}

func TestMaxTokensSetsTheReservation(t *testing.T) {
	q := quotaGateway(t, nil, quotaPolicy("daily", "{ team: research }", "enforce", "[ { dimension: tokens_per_day, limit: 5000 } ]"))
	body := func(n string) string {
		return `{"model":"llama-70b","max_tokens":` + n + `,"messages":[{"role":"user","content":"hello"}]}`
	}
	if resp := q.post(t, q.key, body("100")); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := lastDecision(t, q.fixture).Quota.ReservedTokens; got < 100 || got > 200 {
		t.Errorf("reserved %d tokens for max_tokens 100", got)
	}
	resp := q.post(t, q.key, body("4000000"))
	if resp.StatusCode != 429 {
		t.Fatalf("a request that may need more than the day's limit: status %d", resp.StatusCode)
	}
	e := readError(t, resp)
	if e.Code != "quota_exceeded" || !strings.Contains(e.Message, "larger than the limit") {
		t.Errorf("error = %+v", e)
	}
	if resp.Header.Get("Retry-After") != "" {
		t.Error("Retry-After promised a retry that cannot succeed")
	}
}

func TestDailyTokensRunOutAfterActualUse(t *testing.T) {
	q := quotaGateway(t, nil, quotaPolicy("daily", "{ team: research }", "enforce", "[ { dimension: tokens_per_day, limit: 100 } ]"))
	body := `{"model":"llama-70b","max_tokens":10,"messages":[{"role":"user","content":"a b c d e"}]}`
	served := 0
	var last *http.Response
	for i := 0; i < 40; i++ {
		last = q.post(t, q.key, body)
		if last.StatusCode != 200 {
			break
		}
		served++
	}
	if served < 2 || served > 20 || last.StatusCode != 429 {
		t.Fatalf("served %d requests, then status %d", served, last.StatusCode)
	}
	if e := readError(t, last); e.Code != "quota_exceeded" {
		t.Errorf("error code = %q: SDKs retry rate limits, not an empty day", e.Code)
	}
	if got := last.Header.Get("Retry-After"); got != strconv.Itoa(12*3600) {
		t.Errorf("Retry-After = %q, want the 12 h left until midnight UTC", got)
	}
	if d := lastDecision(t, q.fixture); d.ReasonCode != "QUOTA_EXCEEDED" || d.Quota.Exceeded[0].Dimension != "tokens_per_day" {
		t.Errorf("record = %s %+v", d.ReasonCode, d.Quota)
	}
	q.store.advance(12 * time.Hour)
	if resp := q.post(t, q.key, body); resp.StatusCode != 200 {
		t.Errorf("after midnight: status %d", resp.StatusCode)
	}
}

func TestFailedCallsGiveTheirReservationBack(t *testing.T) {
	// room for one reservation only
	q := quotaGateway(t, nil, quotaPolicy("daily", "{ team: research }", "enforce", "[ { dimension: tokens_per_day, limit: 1200 } ]"))
	for i := 0; i < 5; i++ {
		resp := q.post(t, q.key, `{"model":"broken","messages":[{"role":"user","content":"hello"}]}`)
		if resp.StatusCode != 500 {
			t.Fatalf("broken model: status %d", resp.StatusCode)
		}
	}
	if resp := q.post(t, q.key, chatBody); resp.StatusCode != 200 {
		t.Errorf("status %d: failed calls kept their reservation", resp.StatusCode)
	}
}

func TestSoftAndShadowQuotasServeButAreRecorded(t *testing.T) {
	q := quotaGateway(t, nil,
		quotaPolicy("soft", "{ team: research }", "enforce", "[ { dimension: rpm, limit: 1, mode: soft } ]"),
		quotaPolicy("trial", "{ organization: true }", "shadow", "[ { dimension: rpm, limit: 1 } ]"),
	)
	for i := 0; i < 3; i++ {
		if resp := q.post(t, q.key, chatBody); resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d, only a hard limit refuses", i, resp.StatusCode)
		}
	}
	d := lastDecision(t, q.fixture)
	if d.Outcome != "served" || d.Quota == nil || len(d.Quota.Exceeded) != 2 {
		t.Fatalf("record = %s %+v", d.Outcome, d.Quota)
	}
	effects := map[string]string{}
	for _, x := range d.Quota.Exceeded {
		effects[x.Policy] = x.Effect
	}
	if effects["soft"] != "soft" || effects["trial"] != "shadow" {
		t.Errorf("effects = %v", effects)
	}
	m := metricsText(t, q.fixture)
	for _, want := range []string{
		`tavian_quota_exceeded_total{dimension="rpm",effect="soft",scope="team"} 2`,
		`tavian_quota_exceeded_total{dimension="rpm",effect="shadow",scope="organization"} 2`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if strings.Contains(m, `effect="refused"`) {
		t.Error("something was counted as refused")
	}
}

func TestHardLimitAmongSoftOnesStillRefuses(t *testing.T) {
	q := quotaGateway(t, nil,
		quotaPolicy("soft", "{ organization: true }", "enforce", "[ { dimension: rpm, limit: 1, mode: soft } ]"),
		quotaPolicy("hard", "{ team: research }", "enforce", "[ { dimension: rpm, limit: 1 } ]"),
	)
	q.post(t, q.key, chatBody)
	resp := q.post(t, q.key, chatBody)
	if resp.StatusCode != 429 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	d := lastDecision(t, q.fixture)
	if d.Quota == nil || len(d.Quota.Exceeded) != 2 {
		t.Errorf("the record should list both limits: %+v", d.Quota)
	}
	if !strings.Contains(readError(t, resp).Message, "team") {
		t.Error("the message should name the limit that refused, not the soft one")
	}
}

func TestNoQuotasMeansNoQuotaSection(t *testing.T) {
	f := newFixture(t, 0)
	f.post(t, f.key, chatBody)
	if d := lastDecision(t, f); d.Quota != nil {
		t.Errorf("quota = %+v", d.Quota)
	}
}
