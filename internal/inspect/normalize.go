package inspect

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// normalize removes the cheap ways of hiding a value from a pattern: invalid
// UTF-8, invisible format characters (zero-width spaces, soft hyphens, bidi
// controls), exotic spaces and full-width ASCII look-alikes. Offsets in
// findings refer to the normalized text. Plain ASCII, the common case, is
// returned as is.
func normalize(s string) string { return Normalize(s) }

// Normalize is the normalization applied to every segment before detectors
// run. Offsets in findings refer to its output.
func Normalize(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			// invalid bytes (or a literal U+FFFD): keep one placeholder so
			// neighbours do not merge into a match
			b.WriteRune(' ')
		case unicode.Is(unicode.Cf, r):
			// invisible: dropped
		case r >= 0xFF01 && r <= 0xFF5E:
			b.WriteRune(r - 0xFEE0) // full-width ! .. ~ -> ASCII
		case unicode.Is(unicode.Zs, r):
			b.WriteRune(' ') // no-break and ideographic spaces become plain spaces
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
