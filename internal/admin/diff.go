package admin

import (
	"fmt"
	"strings"
)

const (
	diffContext = 3
	// diffCells bounds the work of comparing two files line by line (the
	// product of their lengths once what they share at both ends is removed).
	// Above it the file is shown as removed and added whole.
	diffCells = 4_000_000
)

type diffOp struct {
	kind byte // ' ', '-' or '+'
	text string
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// unifiedDiff renders the difference between two versions of a file in the
// unified format, with three lines of context. added and removed say that one
// side does not exist.
func unifiedDiff(name, before, after string, added, removed bool) string {
	a, b := splitLines(before), splitLines(after)
	var sb strings.Builder
	switch {
	case added:
		sb.WriteString("--- /dev/null\n+++ b/" + name + "\n")
	case removed:
		sb.WriteString("--- a/" + name + "\n+++ /dev/null\n")
	default:
		sb.WriteString("--- a/" + name + "\n+++ b/" + name + "\n")
	}
	ops := diffOps(a, b)
	// positions in a and b of each op, for the hunk headers
	type pos struct{ a, b int }
	at := make([]pos, len(ops)+1)
	for i, op := range ops {
		at[i+1] = at[i]
		if op.kind != '+' {
			at[i+1].a++
		}
		if op.kind != '-' {
			at[i+1].b++
		}
	}
	for i := 0; i < len(ops); {
		for i < len(ops) && ops[i].kind == ' ' {
			i++
		}
		if i == len(ops) {
			break
		}
		start := max(0, i-diffContext)
		end := i
		for {
			for end < len(ops) && ops[end].kind != ' ' {
				end++
			}
			// the run of unchanged lines that follows: if it is short the
			// next change belongs to the same hunk
			k := end
			for k < len(ops) && ops[k].kind == ' ' {
				k++
			}
			if k == len(ops) || k-end > 2*diffContext {
				end = min(end+diffContext, len(ops))
				break
			}
			end = k
		}
		la, lb := at[end].a-at[start].a, at[end].b-at[start].b
		fmt.Fprintf(&sb, "@@ -%s +%s @@\n", rng(at[start].a, la), rng(at[start].b, lb))
		for _, op := range ops[start:end] {
			sb.WriteByte(op.kind)
			sb.WriteString(op.text)
			sb.WriteByte('\n')
		}
		i = end
	}
	return sb.String()
}

// rng is a hunk range: the first line (counting from 1) and how many lines.
func rng(start, n int) string {
	if n == 0 {
		return fmt.Sprintf("%d,0", start)
	}
	if n == 1 {
		return fmt.Sprint(start + 1)
	}
	return fmt.Sprintf("%d,%d", start+1, n)
}

// diffOps is a shortest edit script from a to b, by longest common
// subsequence on the lines between the common prefix and suffix.
func diffOps(a, b []string) []diffOp {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]
	var ops []diffOp
	for _, l := range a[:pre] {
		ops = append(ops, diffOp{' ', l})
	}
	ops = append(ops, middle(ma, mb)...)
	for _, l := range a[len(a)-suf:] {
		ops = append(ops, diffOp{' ', l})
	}
	return ops
}

func middle(a, b []string) []diffOp {
	var ops []diffOp
	if len(a) == 0 || len(b) == 0 || (len(a)+1)*(len(b)+1) > diffCells {
		for _, l := range a {
			ops = append(ops, diffOp{'-', l})
		}
		for _, l := range b {
			ops = append(ops, diffOp{'+', l})
		}
		return ops
	}
	// lcs[i][j] is the length of the longest common subsequence of a[i:] and b[j:]
	w := len(b) + 1
	lcs := make([]int32, (len(a)+1)*w)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			} else {
				lcs[i*w+j] = max(lcs[(i+1)*w+j], lcs[i*w+j+1])
			}
		}
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{' ', a[i]})
			i++
			j++
		case lcs[(i+1)*w+j] >= lcs[i*w+j+1]:
			ops = append(ops, diffOp{'-', a[i]})
			i++
		default:
			ops = append(ops, diffOp{'+', b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		ops = append(ops, diffOp{'-', a[i]})
	}
	for ; j < len(b); j++ {
		ops = append(ops, diffOp{'+', b[j]})
	}
	return ops
}
