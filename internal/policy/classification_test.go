package policy

import (
	"errors"
	"testing"

	"github.com/bredda/tavian/internal/config"
)

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		name     string
		declared config.Classification
		kinds    []string
		want     config.Classification
		inferred config.Classification
	}{
		{"nothing found", "", nil, config.LabelInternal, ""},
		{"e-mail alone", "", []string{"pii.email"}, config.LabelInternal, ""},
		{"phone and ip", "", []string{"pii.phone", "pii.ipv4"}, config.LabelInternal, ""},
		{"iban", "", []string{"pii.iban"}, config.LabelConfidential, config.LabelConfidential},
		{"card", "", []string{"pii.payment_card"}, config.LabelConfidential, config.LabelConfidential},
		{"nir", "", []string{"pii.nir"}, config.LabelConfidential, config.LabelConfidential},
		{"any secret", "", []string{"secret.aws_access_key"}, config.LabelRestricted, config.LabelRestricted},
		{"the most sensitive wins", "", []string{"pii.iban", "secret.jwt", "pii.email"}, config.LabelRestricted, config.LabelRestricted},
		{"custom detectors do not raise the label", "", []string{"custom.codenames"}, config.LabelInternal, ""},
		{"declared raises", config.LabelConfidential, nil, config.LabelConfidential, ""},
		{"declared cannot lower what is inferred", config.LabelPublic, []string{"pii.iban"}, config.LabelConfidential, config.LabelConfidential},
		{"declared public cannot lower the default", config.LabelPublic, nil, config.LabelInternal, ""},
		{"inferred beats a lower declaration", config.LabelInternal, []string{"secret.jwt"}, config.LabelRestricted, config.LabelRestricted},
		{"declared above inferred", config.LabelRestricted, []string{"pii.iban"}, config.LabelRestricted, config.LabelConfidential},
	} {
		got := Classify(c.declared, c.kinds)
		if got.Label != c.want || got.Sources.Inferred != c.inferred || got.Sources.Declared != c.declared || got.Sources.Default != DefaultLabel {
			t.Errorf("%s: %+v, want label %s inferred %q", c.name, got, c.want, c.inferred)
		}
	}
}

func TestExceeds(t *testing.T) {
	conf := Classify("", []string{"pii.iban"})
	for clearance, want := range map[config.Classification]bool{
		config.LabelPublic: true, config.LabelInternal: true, config.LabelConfidential: false, config.LabelRestricted: false,
	} {
		if got := conf.Exceeds(clearance); got != want {
			t.Errorf("confidential vs clearance %s: %v, want %v", clearance, got, want)
		}
	}
	if Classify("", nil).Exceeds(config.LabelInternal) {
		t.Error("a default-label request must fit the default clearance")
	}
}

func TestParseDeclared(t *testing.T) {
	for in, want := range map[string]config.Classification{"confidential": config.LabelConfidential, " Restricted ": config.LabelRestricted, "PUBLIC": config.LabelPublic} {
		if got, err := ParseDeclared([]string{in}); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if got, err := ParseDeclared(nil); err != nil || got != "" {
		t.Errorf("no header: %q %v", got, err)
	}
	for _, bad := range [][]string{{"secret"}, {""}, {"confidential", "public"}, {"top secret"}} {
		if _, err := ParseDeclared(bad); !errors.Is(err, ErrBadLabel) {
			t.Errorf("%q: err = %v, want ErrBadLabel", bad, err)
		}
	}
}

func TestAnIdentityWithoutAClearanceIsClearedForNothing(t *testing.T) {
	if !Classify("", nil).Exceeds("") {
		t.Error("no clearance must fail closed, not default to something")
	}
}
