package glob

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "anything/at/all", true},
		{"llama-*", "llama-70b", true},
		{"llama-*", "mistral-large", false},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "abd", false},
		{"*-70b", "llama-70b", true},
		{"internal/*", "internal/llama", true},
		{"internal/*", "external/llama", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"", "", true},
		{"", "x", false},
	}
	for _, tc := range tests {
		if got := Match(tc.pattern, tc.s); got != tc.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

func TestMatchAny(t *testing.T) {
	if !MatchAny([]string{"a", "b*"}, "bcd") {
		t.Error("expected match")
	}
	if MatchAny(nil, "x") {
		t.Error("empty pattern list must match nothing")
	}
}
