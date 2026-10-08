package inspect

import (
	"fmt"
	"slices"
)

// Builtins lists the names of the detectors that ship with the gateway.
func Builtins() []string {
	var names []string
	for _, d := range builtinSet() {
		names = append(names, d.Name())
	}
	return names
}

func builtinSet() []Detector {
	return []Detector{
		email{},
		newScanner("pii.iban", TypePII, "iban", SeverityHigh, 0.95, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", matchIBAN),
		newScanner("pii.card", TypePII, "payment_card", SeverityHigh, 0.85, "23456", matchCard),
		newScanner("pii.nir", TypePII, "nir", SeverityHigh, 0.95, "123478", matchNIR),
		newScanner("pii.phone", TypePII, "phone", SeverityMedium, 0.7, "+0", matchPhone),
		newScanner("pii.ip", TypePII, "ipv4", SeverityLow, 0.8, "0123456789", matchIPv4),
		newTokenDetector(),
		newCredentialDetector(),
	}
}

// builtin returns the detectors in use: the built-in ones minus those disabled,
// then the deployment's own.
func builtin(cfg Config) ([]Detector, error) {
	all := builtinSet()
	for _, name := range cfg.Disable {
		i := slices.IndexFunc(all, func(d Detector) bool { return d.Name() == name })
		if i < 0 {
			return nil, fmt.Errorf("disable: %q is not a built-in detector (have %v)", name, Builtins())
		}
		all = slices.Delete(all, i, i+1)
	}
	custom, err := customDetectors(cfg)
	if err != nil {
		return nil, err
	}
	return append(all, custom...), nil
}
