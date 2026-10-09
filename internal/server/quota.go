package server

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/bredda/tavian/internal/audit"
	"github.com/bredda/tavian/internal/auth"
	"github.com/bredda/tavian/internal/quota"
)

// noteQuota counts the limits a request went over and keeps them for its
// decision record, enforced or not: a soft or shadow limit exists to be seen.
func (s *server) noteQuota(c *call, res quota.Result) {
	for _, chk := range res.Exceeded {
		l := chk.Limit
		s.Metrics.quotaExceeded.WithLabelValues(string(l.Dimension), l.Scope.Kind(), l.Effect()).Inc()
		if c.quota == nil {
			c.quota = &audit.Quota{}
		}
		c.quota.Exceeded = append(c.quota.Exceeded, audit.QuotaCheck{
			Policy: l.Policy, Dimension: string(l.Dimension), Scope: l.Scope.Kind(),
			Limit: l.Max, Used: chk.Used, Requested: chk.Requested, Effect: l.Effect(),
		})
	}
}

// refuseQuota answers 429 for a request that went over an enforced limit.
//
// The record is written like any refusal, but at most once a second for each
// caller and limit (quota.Coalescer): a client that ignores its 429s must not
// be able to fill the audit trail and put the whole gateway into fail-closed.
// A refusal that is not recorded has no decision_id to give; metrics count
// every one.
func (s *server) refuseQuota(ctx context.Context, w http.ResponseWriter, c *call, res quota.Result) string {
	p := res.Primary()
	reason, outcome := audit.RateLimited, "rate_limited"
	if p.Never || p.Limit.Dimension == quota.TokensPerDay || p.Limit.Dimension == quota.BudgetEUR {
		reason, outcome = audit.QuotaExceeded, "quota_exceeded"
	}
	msg := quotaMessage(*p)
	if p.Retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(p.Retry.Seconds())))))
	}

	record, suppressed := s.Coalescer.Allow(p.Limit.Scope, p.Limit.Dimension, callerKey(c.id))
	if !record {
		w.Header().Del(decisionHeader)
		writeError(w, reason.Status, reason.Type, reason.Client, msg)
		return outcome
	}
	if suppressed > 0 {
		c.quota.Suppressed = suppressed
	}
	return s.refuse(ctx, w, c, reason, msg, outcome)
}

// callerKey tells callers apart for coalescing: the key or the subject. Both
// are known by now (the request is authenticated).
func callerKey(id *auth.Identity) string {
	if id.KeyID != "" {
		return "key:" + id.KeyID
	}
	return "sub:" + id.Subject
}

// quotaMessage says which limit was reached and where, without the usage of
// other callers.
func quotaMessage(c quota.Check) string {
	l := c.Limit
	what := map[quota.Dimension]string{
		quota.RPM: "requests per minute", quota.Concurrency: "concurrent requests",
		quota.TPM: "tokens per minute", quota.TokensPerDay: "tokens per day",
		quota.BudgetEUR: "euros per month",
	}[l.Dimension]
	max := l.Max
	if l.Dimension == quota.BudgetEUR {
		max /= 1_000_000 // the limit is written in euros
	}
	where := strings.ReplaceAll(l.Scope.Kind(), "_", " and ")
	if c.Never {
		return fmt.Sprintf("this request is larger than the limit of %d %s of the %s", max, what, where)
	}
	return fmt.Sprintf("the limit of %d %s of the %s is reached", max, what, where)
}
