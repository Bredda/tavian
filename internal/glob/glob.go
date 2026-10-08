// Package glob implements the minimal wildcard matching used by model
// allow lists: '*' matches any run of characters (including '/'), every other
// character matches itself. There is deliberately no '?' or character class.
package glob

// Match reports whether s matches pattern.
func Match(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case px < len(pattern) && pattern[px] == s[sx]:
			px++
			sx++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// MatchAny reports whether s matches at least one of patterns.
func MatchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if Match(p, s) {
			return true
		}
	}
	return false
}
