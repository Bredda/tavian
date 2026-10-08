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
