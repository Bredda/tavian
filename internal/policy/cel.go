package policy

import (
	"fmt"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/bredda/tavian/internal/taxonomy"
)

// costLimit bounds the work of one expression evaluation. CEL has no loops that
// can run away, but a comprehension over a long list can still be costly.
const costLimit = 10_000

// newEnv declares what an expression can see: identity, request and finding as
// maps, and the function label.atLeast("confidential"), because CEL compares
// strings alphabetically and labels have their own order.
func newEnv(withLabel bool) (*cel.Env, error) {
	m := cel.MapType(cel.StringType, cel.DynType)
	opts := []cel.EnvOption{
		cel.Variable("identity", m),
		cel.Variable("request", m),
		cel.Variable("finding", m),
	}
	if withLabel {
		// the label is what the rules of `infer` compute, so only the rules
		// that come after it can read it
		opts = append(opts, cel.Variable("label", cel.StringType))
	}
	opts = append(opts,
		cel.Function("atLeast",
			cel.MemberOverload("string_at_least_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(l, r ref.Val) ref.Val {
					a, aok := l.Value().(string)
					b, bok := r.Value().(string)
					if !aok || !bok || taxonomy.Label(a).Rank() < 0 || taxonomy.Label(b).Rank() < 0 {
						return types.NewErr("atLeast: unknown label")
					}
					return types.Bool(taxonomy.Label(a).Rank() >= taxonomy.Label(b).Rank())
				}))),
	)
	return cel.NewEnv(opts...)
}

// condition is a compiled `when` expression.
type condition struct {
	src  string
	prog cel.Program
}

// compileCondition type-checks expr, requires a boolean result, and proves
// that it evaluates on a sample input, which catches a misspelled field such as
// finding.subtyp at load time instead of on the first request that has one.
func compileCondition(env *cel.Env, expr string) (*condition, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if out := ast.OutputType(); out != cel.BoolType && out != cel.DynType {
		return nil, fmt.Errorf("the condition must be true or false, not %s", out)
	}
	prog, err := env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return nil, err
	}
	c := &condition{src: expr, prog: prog}
	if _, err := c.eval(sampleActivation()); err != nil {
		return nil, fmt.Errorf("it cannot be evaluated (%w); check the field names", err)
	}
	return c, nil
}

func (c *condition) eval(act map[string]any) (bool, error) {
	out, _, err := c.prog.Eval(act)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("the condition did not give true or false")
	}
	return b, nil
}

// sampleActivation has every field with a zero value.
func sampleActivation() map[string]any {
	return activation(Identity{}, Request{}, Kindish{Severity: "low"}, string(taxonomy.Internal))
}

// Kindish is what `finding.*` shows an expression: one kind of finding.
type Kindish struct {
	Type       string
	Subtype    string
	Severity   string
	Confidence float64
	Count      int64
}

func activation(id Identity, req Request, f Kindish, label string) map[string]any {
	return map[string]any{
		"label": label,
		"identity": map[string]any{
			"user": id.User, "groups": nonNil(id.Groups), "roles": nonNil(id.Roles),
			"team": id.Team, "application": id.Application, "auth_method": id.AuthMethod,
		},
		"request": map[string]any{
			"model": req.Model, "type": "chat", "stream": req.Stream,
			"max_tokens": req.MaxTokens, "has_tools": req.HasTools, "has_multimodal": false,
		},
		"finding": map[string]any{
			"type": f.Type, "subtype": f.Subtype, "severity": f.Severity,
			"confidence": f.Confidence, "count": f.Count,
		},
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
