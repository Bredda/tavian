package policy

import (
	"testing"

	"github.com/bredda/tavian/internal/config"
)

func backend(class config.DestinationClass, max config.Classification) *config.Backend {
	return &config.Backend{ID: string(class), DestinationClass: class, MaxClassification: max}
}

func TestConstraintsPerLabel(t *testing.T) {
	internal := backend(config.ClassInternal, config.LabelRestricted)
	partner := backend(config.ClassApprovedExternal, config.LabelInternal)
	partnerTrusted := backend(config.ClassApprovedExternal, config.LabelRestricted) // an operator may vouch for a provider
	public := backend(config.ClassPublicExternal, config.LabelPublic)

	for _, c := range []struct {
		label config.Classification
		b     *config.Backend
		want  string
	}{
		{config.LabelPublic, internal, ""},
		{config.LabelPublic, partner, ""},
		{config.LabelPublic, public, ""},
		{config.LabelInternal, internal, ""},
		{config.LabelInternal, partner, ""},
		{config.LabelInternal, public, ExcludedClearance},
		{config.LabelConfidential, internal, ""},
		{config.LabelConfidential, partner, ExcludedClearance},
		// the backend's own clearance is not enough: the label table forbids external destinations
		{config.LabelConfidential, partnerTrusted, ExcludedClass},
		{config.LabelRestricted, partnerTrusted, ExcludedClass},
		{config.LabelRestricted, internal, ""},
		{config.LabelRestricted, public, ExcludedClearance},
	} {
		if got := ConstraintsFor(c.label).Excludes(c.b); got != c.want {
			t.Errorf("%s -> %s (%s): %q, want %q", c.label, c.b.DestinationClass, c.b.MaxClassification, got, c.want)
		}
	}
}

func TestUnknownLabelAllowsNothing(t *testing.T) {
	if why := ConstraintsFor("bogus").Excludes(backend(config.ClassInternal, config.LabelRestricted)); why == "" {
		t.Error("an unknown label must not be routable anywhere")
	}
}

func TestConstraintsAreACopy(t *testing.T) {
	c := ConstraintsFor(config.LabelConfidential)
	c.Classes[0] = config.ClassPublicExternal
	if ConstraintsFor(config.LabelConfidential).Classes[0] != config.ClassInternal {
		t.Error("mutating a Constraints value changed the built-in table")
	}
}

func TestAssertCatchesARoutingBug(t *testing.T) {
	if err := Assert(config.LabelConfidential, backend(config.ClassInternal, config.LabelRestricted)); err != nil {
		t.Errorf("internal backend for confidential data: %v", err)
	}
	for _, b := range []*config.Backend{
		backend(config.ClassApprovedExternal, config.LabelRestricted),
		backend(config.ClassInternal, config.LabelInternal),
		backend(config.ClassPublicExternal, config.LabelPublic),
	} {
		if err := Assert(config.LabelConfidential, b); err == nil {
			t.Errorf("a %s backend (max %s) passed the assertion for confidential data", b.DestinationClass, b.MaxClassification)
		}
	}
}
