// Package taxonomy holds the vocabulary shared by configuration, policy and
// routing: how sensitive data is (labels) and where a backend sits (destination
// classes). It depends on nothing, so that both the configuration compiler and
// the policy engine can use it.
package taxonomy

// Label is a data sensitivity label. The default scheme is ordered
// public < internal < confidential < restricted (docs/SECURITY.md).
type Label string

const (
	Public       Label = "public"
	Internal     Label = "internal"
	Confidential Label = "confidential"
	Restricted   Label = "restricted"
)

// Rank returns the position of l in the scheme, or -1 if unknown.
func (l Label) Rank() int {
	switch l {
	case Public:
		return 0
	case Internal:
		return 1
	case Confidential:
		return 2
	case Restricted:
		return 3
	}
	return -1
}

// Labels lists the labels from least to most sensitive.
func Labels() []Label { return []Label{Public, Internal, Confidential, Restricted} }

// Max returns the more sensitive of two labels; an unknown label loses.
func Max(a, b Label) Label {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// Class says where a backend runs, from a data-governance viewpoint.
type Class string

const (
	ClassInternal         Class = "internal"
	ClassApprovedExternal Class = "approved-external"
	ClassPublicExternal   Class = "public-external"
)

// Valid reports whether c is a known destination class.
func (c Class) Valid() bool {
	switch c {
	case ClassInternal, ClassApprovedExternal, ClassPublicExternal:
		return true
	}
	return false
}
