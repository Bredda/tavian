package router

import (
	"errors"
	"testing"

	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/policy"
)

// constraintsFor gives the constraints the built-in policy sets for a request
// of the label.
func constraintsFor(t *testing.T, label config.Classification) policy.Constraints {
	t.Helper()
	e, err := policy.Compile(nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Decide(policy.Input{Declared: label})
	if err != nil {
		t.Fatal(err)
	}
	return d.Constraints
}

func snapshot() (*config.Snapshot, map[string]*config.Backend) {
	bs := map[string]*config.Backend{
		"partner": {ID: "partner", DestinationClass: config.ClassApprovedExternal, MaxClassification: config.LabelInternal},
		"local":   {ID: "local", DestinationClass: config.ClassInternal, MaxClassification: config.LabelRestricted},
	}
	return &config.Snapshot{
		Backends: bs,
		Models: map[string]*config.Model{
			"llama":    {Name: "llama", Route: []config.Target{{Backend: "local", UpstreamModel: "meta/llama"}}},
			"shared":   {Name: "shared", Route: []config.Target{{Backend: "partner", UpstreamModel: "p-model"}, {Backend: "local", UpstreamModel: "l-model"}}},
			"partner":  {Name: "partner", Route: []config.Target{{Backend: "partner", UpstreamModel: "p-only"}}},
			"empty":    {Name: "empty"},
			"dangling": {Name: "dangling", Route: []config.Target{{Backend: "gone"}}},
		},
	}, bs
}

func TestResolveKeepsTheRouteOrderWhenEverythingIsAllowed(t *testing.T) {
	s, bs := snapshot()
	r, seen, err := Resolve(s, "llama", constraintsFor(t, config.LabelInternal))
	if err != nil || r.Backend != bs["local"] || r.UpstreamModel != "meta/llama" || len(seen) != 1 || seen[0].Excluded != "" {
		t.Fatalf("route = %+v seen = %+v err = %v", r, seen, err)
	}
	r, _, err = Resolve(s, "shared", constraintsFor(t, config.LabelInternal))
	if err != nil || r.Backend != bs["partner"] || r.UpstreamModel != "p-model" {
		t.Errorf("internal data may use the first target: %+v %v", r, err)
	}
}

func TestSensitiveDataSkipsToAnAllowedTarget(t *testing.T) {
	s, bs := snapshot()
	r, seen, err := Resolve(s, "shared", constraintsFor(t, config.LabelConfidential))
	if err != nil || r.Backend != bs["local"] || r.UpstreamModel != "l-model" {
		t.Fatalf("route = %+v err = %v", r, err)
	}
	if len(seen) != 2 || seen[0].Backend != "partner" || seen[0].Excluded != policy.ExcludedClearance || seen[1].Backend != "local" || seen[1].Excluded != "" {
		t.Errorf("candidates = %+v, want the set-aside partner then the chosen local", seen)
	}
}

func TestNoEligibleBackend(t *testing.T) {
	s, _ := snapshot()
	_, seen, err := Resolve(s, "partner", constraintsFor(t, config.LabelConfidential))
	if !errors.Is(err, ErrNoEligibleBackend) || len(seen) != 1 || seen[0].Excluded == "" {
		t.Errorf("err = %v seen = %+v", err, seen)
	}
}

func TestUnknownModels(t *testing.T) {
	s, _ := snapshot()
	for _, name := range []string{"missing", "empty", "dangling"} {
		if _, _, err := Resolve(s, name, constraintsFor(t, config.LabelInternal)); !errors.Is(err, ErrUnknownModel) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
