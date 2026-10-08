package inspect

// builtin returns the detectors that ship with the gateway.
func builtin(Config) ([]Detector, error) {
	return []Detector{
		email{},
	}, nil
}
