// Package ids generates opaque identifiers for requests and events.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
)

// New returns a random 128-bit identifier encoded as 32 hex characters.
func New() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the platform is unusable; never fall back
		// to a predictable identifier.
		panic("ids: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

var valid = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

// Valid reports whether s is acceptable as a caller-supplied request id.
func Valid(s string) bool { return valid.MatchString(s) }
