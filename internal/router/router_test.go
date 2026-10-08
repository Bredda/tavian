package router

import (
	"errors"
	"testing"

	"github.com/bredda/tavian/internal/config"
)

func TestResolve(t *testing.T) {
	b := &config.Backend{ID: "local"}
	s := &config.Snapshot{
		Backends: map[string]*config.Backend{"local": b},
		Models: map[string]*config.Model{
			"llama": {Name: "llama", Route: []config.Target{{Backend: "local", UpstreamModel: "meta/llama"}}},
			"empty": {Name: "empty"},
		},
	}
	r, err := Resolve(s, "llama")
	if err != nil {
		t.Fatal(err)
	}
	if r.Backend != b || r.UpstreamModel != "meta/llama" {
		t.Errorf("route = %+v", r)
	}
	for _, name := range []string{"missing", "empty"} {
		if _, err := Resolve(s, name); !errors.Is(err, ErrUnknownModel) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
