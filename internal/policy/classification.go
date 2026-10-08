package policy

import (
	"errors"
	"strings"

	"github.com/bredda/tavian/internal/taxonomy"
)

// DeclaredHeader is the request header with which an application raises the
// label of a request.
const DeclaredHeader = "X-Tavian-Classification"

// ErrBadLabel means the declared label is not one of the known labels.
var ErrBadLabel = errors.New("unknown classification label")

// ParseDeclared reads the values of the DeclaredHeader header. No value is
// fine (empty label); one known label is returned; anything else is an error.
func ParseDeclared(values []string) (taxonomy.Label, error) {
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		l := taxonomy.Label(strings.ToLower(strings.TrimSpace(values[0])))
		if l.Rank() < 0 {
			return "", ErrBadLabel
		}
		return l, nil
	}
	return "", ErrBadLabel
}
