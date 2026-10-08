package policy

import (
	"fmt"

	"github.com/bredda/tavian/internal/config"
)

// destinations says which destination classes may receive data of each label.
// It is the built-in default, and an organization-wide guardrail in spirit:
// the policy engine will load the same table from configuration and let
// narrower scopes only remove entries from it (docs/POLICY.md).
var destinations = map[config.Classification][]config.DestinationClass{
	config.LabelPublic:       {config.ClassInternal, config.ClassApprovedExternal, config.ClassPublicExternal},
	config.LabelInternal:     {config.ClassInternal, config.ClassApprovedExternal},
	config.LabelConfidential: {config.ClassInternal},
	config.LabelRestricted:   {config.ClassInternal},
}

// Constraints is what phase A of the policy produces before routing: where a
// request of a given label may go.
type Constraints struct {
	Label   config.Classification
	Classes []config.DestinationClass
}

// ConstraintsFor returns the constraints for a label. An unknown label allows
// no destination at all.
func ConstraintsFor(label config.Classification) Constraints {
	return Constraints{Label: label, Classes: append([]config.DestinationClass(nil), destinations[label]...)}
}

// Exclusion codes: why a backend may not receive a request.
const (
	ExcludedClearance = "BACKEND_CLASSIFICATION_TOO_LOW" // backend max_classification is below the label
	ExcludedClass     = "DESTINATION_CLASS_NOT_ALLOWED"  // the policy does not allow this class for the label
)

// Excludes returns why backend b may not receive a request under c, or "" if it
// may.
func (c Constraints) Excludes(b *config.Backend) string {
	if b.MaxClassification.Rank() < c.Label.Rank() {
		return ExcludedClearance
	}
	for _, class := range c.Classes {
		if class == b.DestinationClass {
			return ""
		}
	}
	return ExcludedClass
}

// Assert is phase B: after routing, check that the chosen backend satisfies the
// constraints for the label. Routing already filters on them; this recomputes
// them from the label alone, so a bug in routing cannot send data somewhere it
// must not go. A non-nil error means exactly such a bug.
func Assert(label config.Classification, b *config.Backend) error {
	if why := ConstraintsFor(label).Excludes(b); why != "" {
		return fmt.Errorf("routing chose backend %q (class %s, max %s) for a %s request: %s",
			b.ID, b.DestinationClass, b.MaxClassification, label, why)
	}
	return nil
}
