// Package audit holds decision records and, later, the tamper-evident hash
// chain and content encryption (M2 for hash-level audit, M4 for encrypted
// content). See docs/SECURITY.md#audit and ADR-0010.
//
// A DecisionRecord says what the gateway decided about one request and why.
// Like findings, it never contains request or response content.
package audit

import (
	"time"

	"github.com/bredda/tavian/internal/inspect"
)

// KindDecision is the outbox kind of a DecisionRecord.
const KindDecision = "decision"

// Outcomes of a decision.
const (
	OutcomeServed  = "served"  // the backend answered with a success status
	OutcomeRefused = "refused" // the gateway did not serve the request
	OutcomeFailed  = "failed"  // the request was accepted, then the backend or the client failed
)

// MaxFindings bounds the detailed findings of one record, far below what the
// spool can replay in one line. Counts in Inspection stay complete.
const MaxFindings = 200

// LabelSources says where the label of a request comes from. Empty means the
// source did not apply.
type LabelSources struct {
	Declared string `json:"declared,omitempty"`
	Default  string `json:"default"`
	Inferred string `json:"inferred,omitempty"`
}

// Candidate is a backend that routing considered for a request. Excluded is
// why it was set aside (a policy exclusion code), empty for the one chosen.
type Candidate struct {
	Backend  string `json:"backend"`
	Excluded string `json:"excluded,omitempty"`
}

// Shadow is what policies in shadow mode would have changed. It is recorded
// only when they apply to the request; the policies in force decided.
type Shadow struct {
	Policies     []string `json:"policies"`
	RulesMatched []string `json:"rules_matched,omitempty"`
	// WouldRefuse is the reason code of a block that would have refused the
	// request, and WouldDenyModel the policy that would have refused the model.
	WouldRefuse      string `json:"would_refuse,omitempty"`
	WouldDenyModel   string `json:"would_deny_model,omitempty"`
	Label            string `json:"label,omitempty"`
	ExceedsClearance bool   `json:"exceeds_clearance,omitempty"`
	// Constraints are the destination classes that would have applied, when
	// they differ (an empty list means none).
	Constraints *[]string `json:"constraints,omitempty"`
	WouldRedact []string  `json:"would_redact,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// Quota says what the quotas did to a request.
type Quota struct {
	// ReservedTokens is what was set aside before the backend was called, in
	// the same unit as the limits (input estimate plus the answer's cap).
	ReservedTokens int64 `json:"reserved_tokens,omitempty"`
	// Exceeded lists the limits the request went over, whatever their effect.
	Exceeded []QuotaCheck `json:"exceeded,omitempty"`
	// Suppressed counts refusals of the same caller and limit, in the second
	// before this record, that were not recorded one by one.
	Suppressed int64 `json:"suppressed,omitempty"`
}

// QuotaCheck is one limit a request went over.
type QuotaCheck struct {
	Policy    string `json:"policy"`
	Dimension string `json:"dimension"`
	// Scope is the kind of scope (organization, team, application,
	// team_application), never the name of someone else's team.
	Scope string `json:"scope"`
	Limit int64  `json:"limit"`
	Used  int64  `json:"used"`
	// Requested is what the request asked for (1 request, or tokens).
	Requested int64 `json:"requested"`
	// Effect is refused, soft (counted, not refused) or shadow (from a policy
	// in shadow mode).
	Effect string `json:"effect"`
}

// DecisionRecord is written once for every authenticated chat request, refused
// ones included. Requests refused before the caller is known (bad
// credentials, overload) leave metrics and logs only: recording them would let
// anyone fill the audit trail.
//
// Fields for later steps (classification label, rules matched, constraints)
// join this shape without changing it.
type DecisionRecord struct {
	DecisionID string    `json:"decision_id"`
	RequestID  string    `json:"request_id"`
	Time       time.Time `json:"time"`
	Revision   string    `json:"config_revision"`

	AuthMethod  string `json:"auth_method"`
	KeyID       string `json:"key_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	Team        string `json:"team"`
	Application string `json:"application"`

	// Model is the model the caller asked for (client-supplied text, bounded
	// by the request size; treat it as data).
	Model         string `json:"model,omitempty"`
	UpstreamModel string `json:"upstream_model,omitempty"`
	Backend       string `json:"backend,omitempty"`
	// Candidates are the backends routing looked at, in order, with the reason
	// each one before the chosen one was set aside.
	Candidates []Candidate `json:"candidates,omitempty"`

	// Label is the classification of the request and LabelSources where it
	// comes from: what the caller declared, the default, what inspection found.
	Label        string        `json:"label,omitempty"`
	LabelSources *LabelSources `json:"label_sources,omitempty"`
	// Constraints are the destination classes the policy allowed for the label.
	Constraints []string `json:"constraints,omitempty"`
	// RulesMatched are the policy rules that fired, as "policy/rule".
	RulesMatched []string `json:"rules_matched,omitempty"`
	// Redactions counts the spans replaced by placeholders, per "type.subtype".
	Redactions map[string]int `json:"redactions,omitempty"`
	// Shadow is what policies in shadow mode would have changed.
	Shadow *Shadow `json:"shadow,omitempty"`
	// Quota is set when quotas reserved tokens for the request or it went over
	// a limit.
	Quota *Quota `json:"quota,omitempty"`

	Outcome    string `json:"outcome"`
	ReasonCode string `json:"reason_code"`
	Status     int    `json:"status"`

	// Inspection is the summary; Findings are the details (positions and
	// keyed fingerprints, never values), capped at MaxFindings.
	Inspection        *inspect.Summary  `json:"inspection,omitempty"`
	Findings          []inspect.Finding `json:"findings,omitempty"`
	FindingsTruncated bool              `json:"findings_truncated,omitempty"`
}

// Kind, ID and At let a DecisionRecord travel through the same sinks as usage
// events.
func (DecisionRecord) Kind() string    { return KindDecision }
func (d DecisionRecord) ID() string    { return d.DecisionID }
func (d DecisionRecord) At() time.Time { return d.Time }

// WithInspection attaches the outcome of an inspection.
func (d *DecisionRecord) WithInspection(r inspect.Result) {
	s := r.Summary()
	d.Inspection = &s
	if len(r.Findings) > 0 {
		d.Findings = r.Findings
		if len(d.Findings) > MaxFindings {
			d.Findings = d.Findings[:MaxFindings]
		}
		d.FindingsTruncated = r.Truncated || len(r.Findings) > MaxFindings
	}
}
