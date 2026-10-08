package inspect

import (
	"regexp"
	"strings"
)

// tokenRule recognises a credential with a fixed, well-known prefix. The
// expression is anchored and only ever runs on a window of maxLen bytes that
// starts at the prefix.
type tokenRule struct {
	subtype  string
	severity Severity
	prefixes []string
	re       *regexp.Regexp
	maxLen   int
	// exact: the token has a fixed length, so a following letter or digit means
	// this is something longer and not a token.
	exact bool
}

var tokenRules = []tokenRule{
	{"aws_access_key", SeverityCritical, []string{"AKIA", "ASIA"}, regexp.MustCompile(`^(?:AKIA|ASIA)[A-Z2-7]{16}`), 20, true},
	{"github_token", SeverityCritical, []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{36,255}`), 300, false},
	{"github_token", SeverityCritical, []string{"github_pat_"}, regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{22,255}`), 300, false},
	{"gitlab_token", SeverityCritical, []string{"glpat-"}, regexp.MustCompile(`^glpat-[A-Za-z0-9_-]{20,255}`), 300, false},
	{"slack_token", SeverityCritical, []string{"xox"}, regexp.MustCompile(`^xox[abprs]-[A-Za-z0-9-]{10,255}`), 300, false},
	{"stripe_key", SeverityCritical, []string{"sk_live_", "rk_live_", "sk_test_", "rk_test_"}, regexp.MustCompile(`^[sr]k_(?:live|test)_[A-Za-z0-9]{16,255}`), 300, false},
	{"google_api_key", SeverityHigh, []string{"AIza"}, regexp.MustCompile(`^AIza[0-9A-Za-z_-]{35}`), 39, true},
	{"private_key", SeverityCritical, []string{"-----BEGIN "}, regexp.MustCompile(`^-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`), 80, false},
	{"jwt", SeverityHigh, []string{"eyJ"}, regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), 8192, false},
}

func newTokenDetector() *scanner {
	byFirst := map[byte][]*tokenRule{}
	var starts strings.Builder
	for i := range tokenRules {
		r := &tokenRules[i]
		for _, p := range r.prefixes {
			if len(byFirst[p[0]]) == 0 {
				starts.WriteByte(p[0])
			}
			byFirst[p[0]] = append(byFirst[p[0]], r)
		}
	}
	match := func(t string, i int) (hit, bool) {
		if !boundaryBefore(t, i) {
			return hit{}, false
		}
		for _, r := range byFirst[t[i]] {
			for _, p := range r.prefixes {
				if !strings.HasPrefix(t[i:], p) {
					continue
				}
				window := t[i:min(len(t), i+r.maxLen)]
				m := r.re.FindStringIndex(window)
				if m == nil {
					continue
				}
				end := i + m[1]
				if r.exact && !boundaryAfter(t, end) {
					continue
				}
				return hit{start: i, end: end, subtype: r.subtype, severity: r.severity}, true
			}
		}
		return hit{}, false
	}
	s := newScanner("secret.token", TypeSecret, "token", SeverityCritical, 0.95, starts.String(), match)
	return s
}

// credentialKeywords are the names that, followed by = or :, introduce a
// secret value ("db_password = ...", `"api_key": "..."`).
var credentialKeywords = []string{
	"password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "api-key",
	"access_key", "private_key", "client_secret", "credential",
}

const (
	minCredentialValue = 8
	maxCredentialValue = 256
)

func isCredentialChar(c byte) bool {
	return isAlnum(c) || strings.IndexByte("_-+/=.~!@#$%^&*", c) >= 0
}

// matchCredential matches the value in `keyword = value` assignments. To limit
// false positives the value must be at least 8 characters and mix letters with
// digits or symbols; a plain word after "password:" is not reported.
func matchCredential(t string, i int) (hit, bool) {
	k := i
	for k > 0 && (t[k-1] == ' ' || t[k-1] == '"' || t[k-1] == '\'' || t[k-1] == '`') {
		k--
	}
	lo := max(0, k-16)
	if !hasKeywordSuffix(strings.ToLower(t[lo:k])) {
		return hit{}, false
	}
	j := i + 1
	for j < len(t) && (t[j] == ' ' || t[j] == '"' || t[j] == '\'' || t[j] == '`') {
		j++
	}
	start := j
	for j < len(t) && j-start < maxCredentialValue && isCredentialChar(t[j]) {
		j++
	}
	if j-start < minCredentialValue {
		return hit{}, false
	}
	var letter, other bool
	for _, c := range []byte(t[start:j]) {
		if isLetter(c) {
			letter = true
		} else {
			other = true
		}
	}
	if !letter || !other {
		return hit{}, false
	}
	return hit{start: start, end: j, canon: t[start:j]}, true
}

func hasKeywordSuffix(s string) bool {
	for _, k := range credentialKeywords {
		if strings.HasSuffix(s, k) {
			return true
		}
	}
	return false
}

func newCredentialDetector() *scanner {
	return newScanner("secret.credential", TypeSecret, "credential", SeverityHigh, 0.6, "=:", matchCredential)
}
