// Package policy decides what may happen to a request given who sends it, what
// it contains and where it could go (docs/POLICY.md, ADR-0006).
//
// Policies are YAML documents with CEL conditions. They apply by scope
// (organization, team, application) and only ever narrow: the built-in baseline
// policy is the floor, and what a narrower scope says is intersected with it.
// The same engine serves the gateway and `tavian policy test`.
package policy

import (
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"cel.dev/cel-go/cel"

	"github.com/bredda/tavian/internal/glob"
	"github.com/bredda/tavian/internal/inspect"
	"github.com/bredda/tavian/internal/quota"
	"github.com/bredda/tavian/internal/taxonomy"
)

const baselineName = "baseline"

//go:embed baseline.yaml
var baselineYAML []byte

// Identity is who is calling, as policies see it.
type Identity struct {
	User        string
	Groups      []string
	Roles       []string
	Team        string
	Application string
	AuthMethod  string
}

// Request is what is asked, as policies see it.
type Request struct {
	Model     string
	Stream    bool
	MaxTokens int64
	HasTools  bool
}

// policy is a compiled document.
type policy struct {
	name   string
	source string
	scope  Scope
	// shadow policies are evaluated and compared, never enforced.
	shadow bool

	modelsAllow, modelsDeny []string
	// destinations maps a label to the classes this policy allows for it; a
	// label it does not mention is left to the other policies.
	destinations map[taxonomy.Label]map[taxonomy.Class]bool
	defaultLabel taxonomy.Label
	infer        []inferRule
	actions      []actionRule
	quotas       []quota.Limit
}

type actionRule struct {
	id      string // policy/rule
	cond    *condition
	action  string
	reason  string
	classes map[taxonomy.Class]bool // for restrict_destinations
}

type inferRule struct {
	id    string // policy/rule
	cond  *condition
	label taxonomy.Label
}

// Engine is an immutable set of compiled policies: the baseline first, then the
// operator's, ordered by name.
type Engine struct {
	policies []*policy
	warnings []string
}

// Compile builds an Engine from policy files. It reports every problem found.
func Compile(sources []Source) (*Engine, error) {
	if len(sources) > maxSources {
		return nil, fmt.Errorf("policies: at most %d files", maxSources)
	}
	inferEnv, err := newEnv(false)
	if err != nil {
		return nil, fmt.Errorf("policies: %w", err)
	}
	actionEnv, err := newEnv(true)
	if err != nil {
		return nil, fmt.Errorf("policies: %w", err)
	}

	var errs []error
	type located struct {
		doc   Document
		where string
		src   string
	}
	var docs []located

	base, err := parseSource(Source{Name: "built-in baseline", Raw: baselineYAML})
	if err != nil {
		return nil, fmt.Errorf("policies: %w", err)
	}
	docs = append(docs, located{base[0], "baseline", "built-in"})

	ordered := append([]Source(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	for _, src := range ordered {
		parsed, err := parseSource(src)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for i, d := range parsed {
			docs = append(docs, located{d, fmt.Sprintf("%s (document %d)", src.Name, i+1), src.Name})
		}
	}

	e := &Engine{}
	seen := map[string]string{}
	for i, l := range docs {
		if verrs := l.doc.validate(l.where, i == 0); len(verrs) > 0 {
			errs = append(errs, verrs...)
			continue
		}
		if prev, dup := seen[l.doc.Metadata.Name]; dup {
			errs = append(errs, fmt.Errorf("%s: policy name %q is already used in %s", l.where, l.doc.Metadata.Name, prev))
			continue
		}
		seen[l.doc.Metadata.Name] = l.where
		p, cerrs := compilePolicy(inferEnv, actionEnv, l.doc, l.where, l.src)
		if len(cerrs) > 0 {
			errs = append(errs, cerrs...)
			continue
		}
		e.policies = append(e.policies, p)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid policies:\n%w", errors.Join(errs...))
	}
	e.warnings = widenings(e.policies)
	return e, nil
}

func compilePolicy(inferEnv, actionEnv *cel.Env, d Document, where, source string) (*policy, []error) {
	var errs []error
	p := &policy{
		name: d.Metadata.Name, source: source, scope: d.Spec.Scope, shadow: d.Metadata.Mode == "shadow",
		modelsAllow: d.Spec.Models.Allow, modelsDeny: d.Spec.Models.Deny,
		defaultLabel: d.Spec.Classification.Default,
	}
	if len(d.Spec.Destinations) > 0 {
		p.destinations = map[taxonomy.Label]map[taxonomy.Class]bool{}
		for label, classes := range d.Spec.Destinations {
			set := map[taxonomy.Class]bool{}
			for _, c := range classes {
				set[c] = true
			}
			p.destinations[label] = set
		}
	}
	ids := map[string]bool{}
	for i, r := range d.Spec.Classification.Infer {
		id := r.ID
		if id == "" {
			id = fmt.Sprintf("infer-%d", i)
		}
		if ids[id] {
			errs = append(errs, fmt.Errorf("%s: spec.classification.infer[%d]: duplicate id %q", where, i, id))
			continue
		}
		ids[id] = true
		cond, err := compileCondition(inferEnv, r.When)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: spec.classification.infer[%d] (%s): when: %w", where, i, id, err))
			continue
		}
		p.infer = append(p.infer, inferRule{id: p.name + "/" + id, cond: cond, label: r.Label})
	}
	for i, r := range d.Spec.Inspection.Request.OnFinding {
		id := r.ID
		if id == "" {
			id = fmt.Sprintf("action-%d", i)
		}
		if ids[id] {
			errs = append(errs, fmt.Errorf("%s: spec.inspection.request.on_finding[%d]: duplicate id %q", where, i, id))
			continue
		}
		ids[id] = true
		cond, err := compileCondition(actionEnv, r.When)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: spec.inspection.request.on_finding[%d] (%s): when: %w", where, i, id, err))
			continue
		}
		rule := actionRule{id: p.name + "/" + id, cond: cond, action: r.Action, reason: r.Reason}
		if rule.action == ActionRestrict {
			rule.classes = map[taxonomy.Class]bool{taxonomy.ClassInternal: true}
			if len(r.Classes) > 0 {
				rule.classes = map[taxonomy.Class]bool{}
				for _, c := range r.Classes {
					rule.classes[c] = true
				}
			}
		}
		p.actions = append(p.actions, rule)
	}
	scope := quota.Scope{Organization: d.Spec.Scope.Organization, Team: d.Spec.Scope.Team, Application: d.Spec.Scope.Application}
	for _, q := range d.Spec.Quotas {
		max := int64(q.Limit)
		if q.Dimension == quota.BudgetEUR {
			max *= 1_000_000 // the counters count micro-euros
		}
		p.quotas = append(p.quotas, quota.Limit{
			Policy: p.name, Scope: scope, Dimension: q.Dimension, Max: max,
			Soft: q.Mode == QuotaSoft, Shadow: p.shadow,
		})
	}
	return p, errs
}

// Scopes lists the scopes that have a limit on dim, each once.
func (e *Engine) Scopes(dim quota.Dimension) []quota.Scope {
	var out []quota.Scope
	seen := map[quota.Scope]bool{}
	for _, p := range e.policies {
		for _, l := range p.quotas {
			if l.Dimension == dim && !seen[l.Scope] {
				seen[l.Scope] = true
				out = append(out, l.Scope)
			}
		}
	}
	return out
}

// Limits lists the quotas that apply to the caller: every policy's, including
// those in shadow mode (marked as such, so they count and report but never
// refuse). Every one of them must pass.
func (e *Engine) Limits(id Identity) []quota.Limit {
	var out []quota.Limit
	for _, p := range e.applicable(id, true) {
		out = append(out, p.quotas...)
	}
	return out
}

// widenings lists the places where a policy names something the baseline does
// not allow: harmless, since policies only narrow, but almost certainly not
// what the author meant.
func widenings(ps []*policy) []string {
	if len(ps) == 0 {
		return nil
	}
	base := ps[0]
	var out []string
	for _, p := range ps[1:] {
		for _, label := range taxonomy.Labels() {
			for _, class := range sortedClasses(p.destinations[label]) {
				if !base.destinations[label][class] {
					out = append(out, fmt.Sprintf("policy %s: destinations.%s lists %s, which the baseline does not allow; policies can only narrow, so this has no effect", p.name, label, class))
				}
			}
		}
	}
	return out
}

// Warnings lists non-fatal findings from loading, for `tavian validate`.
func (e *Engine) Warnings() []string { return append([]string(nil), e.warnings...) }

// Names lists the policies in force, the baseline first.
func (e *Engine) Names() []string {
	out := make([]string, len(e.policies))
	for i, p := range e.policies {
		out[i] = p.name
	}
	return out
}

func (p *policy) applies(id Identity) bool {
	if p.scope.Organization {
		return true
	}
	return (p.scope.Team == "" || p.scope.Team == id.Team) && (p.scope.Application == "" || p.scope.Application == id.Application)
}

// applicable lists the policies that apply to the caller: the ones in force,
// and with withShadow also the ones in shadow mode.
func (e *Engine) applicable(id Identity, withShadow bool) []*policy {
	var out []*policy
	for _, p := range e.policies {
		if p.applies(id) && (withShadow || !p.shadow) {
			out = append(out, p)
		}
	}
	return out
}

func hasShadow(ps []*policy) bool {
	for _, p := range ps {
		if p.shadow {
			return true
		}
	}
	return false
}

func shadowNames(ps []*policy) []string {
	var out []string
	for _, p := range ps {
		if p.shadow {
			out = append(out, p.name)
		}
	}
	return out
}

// ShadowNames lists the policies in shadow mode.
func (e *Engine) ShadowNames() []string { return shadowNames(e.policies) }

// Verdict is the answer of a model authorization.
type Verdict struct {
	Allowed bool
	// Policy names the policy that refused, when Allowed is false.
	Policy string
	// Shadow is set when the model is allowed but a policy in shadow mode would
	// have refused it.
	Shadow *ShadowModel
}

// ShadowModel says which policy in shadow mode would have refused a model.
type ShadowModel struct{ Policy string }

// AuthorizeModel says whether the policies let this caller use the model. A
// deny anywhere wins; where a policy has an allow list, the model must be in
// it. This comes on top of the models the caller's credentials grant.
func (e *Engine) AuthorizeModel(id Identity, model string) Verdict {
	if name := firstModelRefusal(e.applicable(id, false), model); name != "" {
		return Verdict{Policy: name}
	}
	v := Verdict{Allowed: true}
	if name := firstModelRefusal(e.applicable(id, true), model); name != "" {
		v.Shadow = &ShadowModel{Policy: name}
	}
	return v
}

func firstModelRefusal(ps []*policy, model string) string {
	for _, p := range ps {
		if glob.MatchAny(p.modelsDeny, model) {
			return p.name
		}
		if len(p.modelsAllow) > 0 && !glob.MatchAny(p.modelsAllow, model) {
			return p.name
		}
	}
	return ""
}

// LabelSources says where the label of a request comes from. Empty means the
// source did not apply.
type LabelSources struct {
	Declared taxonomy.Label `json:"declared,omitempty"`
	Default  taxonomy.Label `json:"default"`
	Inferred taxonomy.Label `json:"inferred,omitempty"`
}

// Input is what phase A of the policy looks at.
type Input struct {
	Identity Identity
	Request  Request
	// Declared is the label the caller asked for, if any.
	Declared taxonomy.Label
	// Kinds is what inspection found.
	Kinds []inspect.Kind
}

// Block says that a rule refuses the request.
type Block struct {
	Rule   string // policy/rule
	Reason string // the rule's reason code, or POLICY_BLOCKED
}

// DefaultBlockReason is the code of a block rule that names none.
const DefaultBlockReason = "POLICY_BLOCKED"

// RedactKind is a kind of finding that must be replaced in the request.
type RedactKind struct {
	Type    inspect.Type
	Subtype string
}

// Decision is the outcome of phase A.
type Decision struct {
	Label       taxonomy.Label
	Sources     LabelSources
	Constraints Constraints
	// Matched lists the rules that fired, as "policy/rule".
	Matched []string

	// Block is set when a rule refuses the request; nothing else matters then.
	Block *Block
	// Redact lists the kinds of finding to replace by placeholders.
	Redact []RedactKind
	// Flagged lists the flag rules that fired: recorded, nothing more.
	Flagged []string
	// Shadow is set when policies in shadow mode apply to the caller; see
	// Shadow.Differs for whether they would have changed anything.
	Shadow *Shadow

	// Restricted is what restrict_destinations rules left of the destination
	// classes: nil if no such rule applied, and an empty non-nil slice if they
	// left none. Constraints already reflect it.
	Restricted []taxonomy.Class
}

// Decide computes the label of a request and the constraints that follow from
// it. The label is the most sensitive of the declared label, the default and
// what the rules infer from the findings; a caller can raise it, never lower
// it below what inspection infers. An error means a condition could not be
// evaluated: the caller must refuse the request.
func (e *Engine) Decide(in Input) (Decision, error) {
	d, err := e.decide(e.applicable(in.Identity, false), in)
	if err != nil {
		return Decision{}, err
	}
	// Policies in shadow mode are evaluated on the side. They can never change
	// the decision, and a failure in one must not fail the request.
	if all := e.applicable(in.Identity, true); hasShadow(all) {
		d.Shadow = shadowOf(d, all, in, e)
	}
	return d, nil
}

func (e *Engine) decide(ps []*policy, in Input) (Decision, error) {
	def := taxonomy.Internal
	for _, p := range ps {
		def = taxonomy.Max(def, p.defaultLabel)
	}
	var inferred taxonomy.Label
	var matched []string
	for _, p := range ps {
		for _, r := range p.infer {
			for _, k := range in.Kinds {
				ok, err := r.cond.eval(activation(in.Identity, in.Request, kindish(k), ""))
				if err != nil {
					return Decision{}, fmt.Errorf("rule %s: %w", r.id, err)
				}
				if ok {
					inferred = taxonomy.Max(inferred, r.label)
					matched = appendOnce(matched, r.id)
				}
			}
		}
	}

	label := taxonomy.Max(taxonomy.Max(def, in.Declared), inferred)
	d := Decision{
		Label:       label,
		Sources:     LabelSources{Declared: in.Declared, Default: def, Inferred: inferred},
		Constraints: Constraints{Label: label, Classes: classesFor(ps, label)},
		Matched:     matched,
	}
	if err := e.act(ps, in, &d); err != nil {
		return Decision{}, err
	}
	return d, nil
}

func kindish(k inspect.Kind) Kindish {
	return Kindish{Type: string(k.Type), Subtype: k.Subtype, Severity: string(k.Severity), Confidence: k.Confidence, Count: int64(k.Count)}
}

// act applies the on_finding rules to d. When several apply the most
// restrictive wins: block, then restrict_destinations, redact, flag, allow. A
// block stops everything else, so it is the only thing left in the decision.
func (e *Engine) act(ps []*policy, in Input, d *Decision) error {
	var restricted map[taxonomy.Class]bool
	for _, p := range ps {
		for _, r := range p.actions {
			for _, k := range in.Kinds {
				ok, err := r.cond.eval(activation(in.Identity, in.Request, kindish(k), string(d.Label)))
				if err != nil {
					return fmt.Errorf("rule %s: %w", r.id, err)
				}
				if !ok {
					continue
				}
				d.Matched = appendOnce(d.Matched, r.id)
				switch r.action {
				case ActionBlock:
					if d.Block == nil {
						reason := r.reason
						if reason == "" {
							reason = DefaultBlockReason
						}
						d.Block = &Block{Rule: r.id, Reason: reason}
					}
				case ActionRestrict:
					if restricted == nil {
						restricted = map[taxonomy.Class]bool{}
						for c := range r.classes {
							restricted[c] = true
						}
					} else {
						for c := range restricted {
							if !r.classes[c] {
								delete(restricted, c)
							}
						}
					}
				case ActionRedact:
					rk := RedactKind{Type: k.Type, Subtype: k.Subtype}
					if !slices.Contains(d.Redact, rk) {
						d.Redact = append(d.Redact, rk)
					}
				case ActionFlag:
					d.Flagged = appendOnce(d.Flagged, r.id)
				}
			}
		}
	}
	if restricted != nil {
		// non-nil even when empty: "no class is allowed" is a restriction, and
		// phase B must not mistake it for "no restriction"
		d.Restricted = append([]taxonomy.Class{}, sortedClasses(restricted)...)
		d.Constraints.Classes = intersectClasses(d.Constraints.Classes, restricted)
	}
	return nil
}

func intersectClasses(classes []taxonomy.Class, with map[taxonomy.Class]bool) []taxonomy.Class {
	var out []taxonomy.Class
	for _, c := range classes {
		if with[c] {
			out = append(out, c)
		}
	}
	return out
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// classOrder gives a stable order to destination classes.
var classOrder = []taxonomy.Class{taxonomy.ClassInternal, taxonomy.ClassApprovedExternal, taxonomy.ClassPublicExternal}

func sortedClasses(set map[taxonomy.Class]bool) []taxonomy.Class {
	var out []taxonomy.Class
	for _, c := range classOrder {
		if set[c] {
			out = append(out, c)
		}
	}
	return out
}

// classesFor intersects what every applicable policy allows for the label. An
// unknown label allows nothing.
func classesFor(ps []*policy, label taxonomy.Label) []taxonomy.Class {
	if label.Rank() < 0 {
		return nil
	}
	allowed := map[taxonomy.Class]bool{}
	for _, c := range classOrder {
		allowed[c] = true
	}
	for _, p := range ps {
		set, ok := p.destinations[label]
		if !ok {
			continue
		}
		for c := range allowed {
			if !set[c] {
				delete(allowed, c)
			}
		}
	}
	return sortedClasses(allowed)
}

// Constraints is what phase A produces before routing: where a request of a
// given label may go.
type Constraints struct {
	Label   taxonomy.Label
	Classes []taxonomy.Class
}

// ClassNames lists the allowed classes as strings, for records.
func (c Constraints) ClassNames() []string {
	out := make([]string, len(c.Classes))
	for i, cl := range c.Classes {
		out[i] = string(cl)
	}
	return out
}

// Exclusion codes: why a backend may not receive a request.
const (
	ExcludedClearance = "BACKEND_CLASSIFICATION_TOO_LOW" // the backend's max_classification is below the label
	ExcludedClass     = "DESTINATION_CLASS_NOT_ALLOWED"  // the policy does not allow this class for the label
)

// Excludes returns why a backend of the given class and clearance may not
// receive a request under c, or "" if it may.
func (c Constraints) Excludes(class taxonomy.Class, max taxonomy.Label) string {
	if max.Rank() < c.Label.Rank() {
		return ExcludedClearance
	}
	for _, allowed := range c.Classes {
		if allowed == class {
			return ""
		}
	}
	return ExcludedClass
}

// Assert is phase B: after routing, check that the chosen backend satisfies the
// policy for the label. It recomputes the constraints from the policies instead
// of trusting what routing was given, so a bug in routing, or in the way
// constraints are passed to it, cannot send data where it must not go. A
// non-nil error means exactly such a bug.
func (e *Engine) Assert(id Identity, d Decision, b Backend) error {
	classes := classesFor(e.applicable(id, false), d.Label)
	if d.Restricted != nil {
		restricted := map[taxonomy.Class]bool{}
		for _, c := range d.Restricted {
			restricted[c] = true
		}
		classes = intersectClasses(classes, restricted)
	}
	c := Constraints{Label: d.Label, Classes: classes}
	if why := c.Excludes(b.Class, b.Max); why != "" {
		return fmt.Errorf("routing chose backend %q (class %s, max %s) for a %s request: %s",
			b.ID, b.Class, b.Max, d.Label, strings.ToLower(why))
	}
	return nil
}

// Backend is a backend as the assertion sees it.
type Backend struct {
	ID    string
	Class taxonomy.Class
	Max   taxonomy.Label
}

// Shadow is what policies in shadow mode would have changed.
type Shadow struct {
	// Policies are the shadow policies that apply to the caller.
	Policies []string
	// Matched are the rules of those policies that fired.
	Matched []string
	// WouldBlock is set when a shadow rule would have refused a request that
	// the policies in force let through.
	WouldBlock *Block
	// Label is the label the request would have had, when it differs.
	Label taxonomy.Label
	// ClassesChanged says that the destination classes would differ; Classes
	// are the ones that would have applied.
	ClassesChanged bool
	Classes        []taxonomy.Class
	// WouldRedact are kinds that would have been redacted beyond the ones that were.
	WouldRedact []RedactKind
	// ExceedsClearance is set by the pipeline when the label the request would
	// have had is above the caller's clearance and the real one is not.
	ExceedsClearance bool
	// Error is set when the shadow evaluation itself failed.
	Error string
}

// Differs says whether the shadow policies would have changed the outcome.
func (s *Shadow) Differs() bool {
	return s != nil && (s.WouldBlock != nil || s.Label != "" || s.ClassesChanged || len(s.WouldRedact) > 0 || s.ExceedsClearance || s.Error != "")
}

// shadowOf evaluates the request with the shadow policies added and reports
// what differs from the decision actually taken.
func shadowOf(enforced Decision, all []*policy, in Input, e *Engine) *Shadow {
	sh := &Shadow{Policies: shadowNames(all)}
	full, err := e.decide(all, in)
	if err != nil {
		sh.Error = err.Error()
		return sh
	}
	for _, m := range full.Matched {
		if !slices.Contains(enforced.Matched, m) {
			sh.Matched = append(sh.Matched, m)
		}
	}
	if enforced.Block == nil && full.Block != nil {
		sh.WouldBlock = full.Block
	}
	if full.Label != enforced.Label {
		sh.Label = full.Label
	}
	if !slices.Equal(full.Constraints.Classes, enforced.Constraints.Classes) {
		sh.ClassesChanged, sh.Classes = true, full.Constraints.Classes
	}
	for _, k := range full.Redact {
		if !slices.Contains(enforced.Redact, k) {
			sh.WouldRedact = append(sh.WouldRedact, k)
		}
	}
	return sh
}
