package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bredda/tavian/internal/admin"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/textdiff"
)

const configUsage = `Usage: tavian config <command> [flags]

Manages the configuration of a running gateway through its administration API
(docs/ADMIN_API.md). The token is read from TAVIAN_ADMIN_TOKEN, never from a
flag; the server defaults to TAVIAN_ADMIN_URL or http://127.0.0.1:9090.

Commands:
  list       List the revisions, newest first, with the active one marked
  show       Print a revision (default: the active one)
  export     Write a revision to a directory: tavian.yaml and policies/
  diff       Compare two revisions, or a local configuration with one
  validate   Check a local configuration like "tavian validate" does, and say
             whether the running gateway could take it
  apply      Make a local configuration the active one
  rollback   Make an earlier revision the active one again
  reload     Make the gateway read its configuration file again
  history    List the changes the administrators made
  tokens     List the admin tokens: role, expiry and last use

Every command takes -server and -json (print the API's answer as it is).
`

// cmdConfig runs "tavian config".
func cmdConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, configUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	commands := map[string]func([]string, io.Writer, io.Writer) int{
		"list": cmdConfigList, "show": cmdConfigShow, "export": cmdConfigExport, "diff": cmdConfigDiff,
		"validate": cmdConfigValidate, "apply": cmdConfigApply, "rollback": cmdConfigRollback,
		"reload": cmdConfigReload, "history": cmdConfigHistory, "tokens": cmdConfigTokens,
	}
	run, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "tavian config: unknown command %q\n\n%s", args[0], configUsage)
		return 2
	}
	return run(args[1:], stdout, stderr)
}

// conn is what every command needs to talk to the gateway.
type conn struct {
	server string
	json   bool
}

func connFlags(fs *flag.FlagSet) *conn {
	c := &conn{}
	def := os.Getenv("TAVIAN_ADMIN_URL")
	if def == "" {
		def = "http://127.0.0.1:9090"
	}
	fs.StringVar(&c.server, "server", def, "base URL of the admin listener (TAVIAN_ADMIN_URL)")
	fs.BoolVar(&c.json, "json", false, "print the API's answer as JSON")
	return c
}

// apiError is an answer of the API that says no.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s (%d %s)", e.Message, e.Status, e.Code)
}

// client calls the administration API.
type client struct {
	base  string
	token string
	http  *http.Client
}

// newClient checks the server URL and finds the token. It warns when the token
// would cross a network in clear.
func (c *conn) newClient(stderr io.Writer) (*client, error) {
	token := strings.TrimSpace(os.Getenv("TAVIAN_ADMIN_TOKEN"))
	if token == "" {
		return nil, errors.New("TAVIAN_ADMIN_TOKEN is not set (the token made by `tavian keygen -admin`)")
	}
	u, err := url.Parse(strings.TrimRight(c.server, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("-server must be a URL like http://127.0.0.1:9090, got %q", c.server)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		fmt.Fprintf(stderr, "tavian: warning: %s is not encrypted, the admin token travels in clear; use a private network or a TLS proxy\n", u.Host)
	}
	return &client{
		base: u.String(), token: token,
		// A redirect would carry the token somewhere else: it is an error.
		http: &http.Client{
			Timeout:       60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// maxAnswer bounds what the CLI reads from the gateway.
const maxAnswer = 32 << 20

// call sends a request and decodes the answer into out (when not nil). It
// returns the raw answer too. A refusal is an *apiError.
func (c *client) call(method, path string, body, out any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the gateway at %s: %w", c.base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if err != nil {
		return nil, fmt.Errorf("reading the answer: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &apiError{Status: resp.StatusCode, Code: http.StatusText(resp.StatusCode), Message: strings.TrimSpace(string(raw))}
		var body struct {
			Error struct{ Code, Message string }
		}
		if json.Unmarshal(raw, &body) == nil && body.Error.Code != "" {
			e.Code, e.Message = body.Error.Code, body.Error.Message
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			e.Message = "the gateway answered with a redirect to " + resp.Header.Get("Location") + ", which is not followed: the token would go with it"
		}
		return raw, e
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, fmt.Errorf("the answer of the gateway is not what this version expects: %w", err)
		}
	}
	return raw, nil
}

// fail prints an error the way every command does.
func fail(stderr io.Writer, what string, err error) int {
	fmt.Fprintf(stderr, "tavian config %s: %v\n", what, err)
	return 1
}

// begin parses flags and opens the connection; ok is false when the command
// must stop with the returned exit code.
func begin(name string, args []string, stderr io.Writer, setup func(*flag.FlagSet) *conn) (c *client, cn *conn, rest []string, code int, ok bool) {
	fs := flag.NewFlagSet("config "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cn = setup(fs)
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, 2, false
	}
	c, err := cn.newClient(stderr)
	if err != nil {
		return nil, nil, nil, fail(stderr, name, err), false
	}
	return c, cn, fs.Args(), 0, true
}

func plain(fs *flag.FlagSet) *conn { return connFlags(fs) }

// show prints raw when -json was given, and says whether it did.
func (cn *conn) raw(stdout io.Writer, raw []byte) bool {
	if !cn.json {
		return false
	}
	fmt.Fprintln(stdout, strings.TrimSpace(string(raw)))
	return true
}

type revisionSummary struct {
	Revision      string    `json:"revision"`
	Profile       string    `json:"profile"`
	TavianVersion string    `json:"tavian_version"`
	FirstLoadedAt time.Time `json:"first_loaded_at"`
	Active        bool      `json:"active"`
}

type revisionContent struct {
	revisionSummary
	Config   string       `json:"config"`
	Policies []admin.File `json:"policies"`
}

func cmdConfigList(args []string, stdout, stderr io.Writer) int {
	var limit int
	c, cn, _, code, ok := begin("list", args, stderr, func(fs *flag.FlagSet) *conn {
		fs.IntVar(&limit, "limit", 20, "how many revisions to list")
		return connFlags(fs)
	})
	if !ok {
		return code
	}
	if limit < 1 {
		return fail(stderr, "list", errors.New("-limit must be at least 1"))
	}
	var all []revisionSummary
	for before := ""; len(all) < limit; {
		var page struct {
			Revisions []revisionSummary `json:"revisions"`
			Next      string            `json:"next"`
		}
		path := "/admin/v1/config/revisions?limit=" + strconv.Itoa(min(limit-len(all), 500))
		if before != "" {
			path += "&before=" + url.QueryEscape(before)
		}
		if _, err := c.call("GET", path, nil, &page); err != nil {
			return fail(stderr, "list", err)
		}
		all = append(all, page.Revisions...)
		if page.Next == "" {
			break
		}
		before = page.Next
	}
	if cn.json {
		b, _ := json.Marshal(map[string]any{"revisions": all})
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REVISION\t\tFIRST LOADED\tPROFILE\tVERSION")
	for _, r := range all {
		mark := ""
		if r.Active {
			mark = "active"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Revision, mark, r.FirstLoadedAt.Local().Format("2006-01-02 15:04:05"), r.Profile, r.TavianVersion)
	}
	_ = tw.Flush()
	return 0
}

func fetchRevision(c *client, id string) (revisionContent, []byte, error) {
	var r revisionContent
	raw, err := c.call("GET", "/admin/v1/config/revisions/"+url.PathEscape(id), nil, &r)
	return r, raw, err
}

func cmdConfigShow(args []string, stdout, stderr io.Writer) int {
	c, cn, rest, code, ok := begin("show", args, stderr, plain)
	if !ok {
		return code
	}
	id := "active"
	if len(rest) == 1 {
		id = rest[0]
	} else if len(rest) > 1 {
		fmt.Fprintln(stderr, "usage: tavian config show [REVISION]")
		return 2
	}
	r, raw, err := fetchRevision(c, id)
	if err != nil {
		return fail(stderr, "show", err)
	}
	if cn.raw(stdout, raw) {
		return 0
	}
	active := ""
	if r.Active {
		active = " (active)"
	}
	fmt.Fprintf(stdout, "# revision %s%s, profile %s, first loaded %s by gateway %s\n", r.Revision, active, r.Profile,
		r.FirstLoadedAt.Local().Format(time.RFC3339), r.TavianVersion)
	fmt.Fprint(stdout, r.Config)
	if !strings.HasSuffix(r.Config, "\n") {
		fmt.Fprintln(stdout)
	}
	for _, p := range r.Policies {
		fmt.Fprintf(stdout, "\n# ---- policies/%s\n%s", p.Name, p.YAML)
		if !strings.HasSuffix(p.YAML, "\n") {
			fmt.Fprintln(stdout)
		}
	}
	return 0
}

func cmdConfigExport(args []string, stdout, stderr io.Writer) int {
	var out, revision string
	var force bool
	c, _, _, code, ok := begin("export", args, stderr, func(fs *flag.FlagSet) *conn {
		fs.StringVar(&out, "o", "", "directory to write (required)")
		fs.StringVar(&revision, "revision", "active", "the revision to export")
		fs.BoolVar(&force, "force", false, "write into a directory that already holds files")
		return connFlags(fs)
	})
	if !ok {
		return code
	}
	if out == "" {
		fmt.Fprintln(stderr, "usage: tavian config export -o DIR [-revision ID] [-force]")
		return 2
	}
	r, _, err := fetchRevision(c, revision)
	if err != nil {
		return fail(stderr, "export", err)
	}
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 && !force {
		return fail(stderr, "export", fmt.Errorf("%s is not empty: use -force to write into it", out))
	}
	pdir := filepath.Join(out, "policies")
	if err := os.MkdirAll(pdir, 0o700); err != nil {
		return fail(stderr, "export", err)
	}
	for _, p := range r.Policies {
		// the gateway checks this too; a file name that leaves the directory
		// is refused here whoever sent it
		if !config.ValidPolicyFileName(p.Name) {
			return fail(stderr, "export", fmt.Errorf("the revision has a policy file with an unsafe name: %q", p.Name))
		}
		if err := os.WriteFile(filepath.Join(pdir, p.Name), []byte(p.YAML), 0o600); err != nil {
			return fail(stderr, "export", err)
		}
	}
	if err := os.WriteFile(filepath.Join(out, "tavian.yaml"), []byte(r.Config), 0o600); err != nil {
		return fail(stderr, "export", err)
	}
	fmt.Fprintf(stdout, "revision %s written to %s: tavian.yaml and %d policy file(s) in policies/\n", r.Revision, out, len(r.Policies))
	fmt.Fprintf(stdout, "after editing: tavian config apply -config %s -policies %s\n", filepath.Join(out, "tavian.yaml"), pdir)
	return 0
}

// local reads a configuration the way the gateway reads its file: the YAML and
// the policy files of policy.dir, or of dir when one is given.
func local(file, dir string) (admin.ApplyRequest, error) {
	if file == "" {
		return admin.ApplyRequest{}, errors.New("-config is required")
	}
	raw, err := os.ReadFile(file) //nolint:gosec // the path is chosen by the operator on the command line
	if err != nil {
		return admin.ApplyRequest{}, err
	}
	var sources []admin.File
	if dir != "" {
		ps, err := config.ReadPolicyDir(dir)
		if err != nil {
			return admin.ApplyRequest{}, err
		}
		for _, p := range ps {
			sources = append(sources, admin.File{Name: p.Name, YAML: string(p.Raw)})
		}
	} else {
		cfg, _, err := config.Load(file)
		if err != nil {
			return admin.ApplyRequest{}, err
		}
		for _, p := range cfg.PolicySources {
			sources = append(sources, admin.File{Name: p.Name, YAML: string(p.Raw)})
		}
	}
	return admin.ApplyRequest{Config: string(raw), Policies: sources}, nil
}

func (r revisionContent) named() []textdiff.Named {
	out := []textdiff.Named{{Name: "tavian.yaml", Text: r.Config}}
	for _, p := range r.Policies {
		out = append(out, textdiff.Named{Name: "policies/" + p.Name, Text: p.YAML})
	}
	return out
}

func localNamed(req admin.ApplyRequest) []textdiff.Named {
	out := []textdiff.Named{{Name: "tavian.yaml", Text: req.Config}}
	for _, p := range req.Policies {
		out = append(out, textdiff.Named{Name: "policies/" + p.Name, Text: p.YAML})
	}
	return out
}

func printDiffs(stdout io.Writer, files []textdiff.FileDiff) {
	for _, f := range files {
		fmt.Fprint(stdout, f.Diff)
	}
}

func cmdConfigDiff(args []string, stdout, stderr io.Writer) int {
	var file, dir string
	c, cn, rest, code, ok := begin("diff", args, stderr, func(fs *flag.FlagSet) *conn {
		fs.StringVar(&file, "config", "", "compare a local configuration file with a revision (default: the active one)")
		fs.StringVar(&dir, "policies", "", "policy directory of the local configuration (default: its policy.dir)")
		return connFlags(fs)
	})
	if !ok {
		return code
	}
	if file != "" {
		if len(rest) > 1 {
			fmt.Fprintln(stderr, "usage: tavian config diff -config FILE [-policies DIR] [REVISION]")
			return 2
		}
		id := "active"
		if len(rest) == 1 {
			id = rest[0]
		}
		req, err := local(file, dir)
		if err != nil {
			return fail(stderr, "diff", err)
		}
		r, _, err := fetchRevision(c, id)
		if err != nil {
			return fail(stderr, "diff", err)
		}
		files := textdiff.Files(r.named(), localNamed(req))
		if cn.json {
			b, _ := json.Marshal(map[string]any{"from": r.Revision, "to": "local", "files": files})
			fmt.Fprintln(stdout, string(b))
			return 0
		}
		if len(files) == 0 {
			fmt.Fprintf(stdout, "%s is the same as revision %s\n", file, r.Revision)
			return 0
		}
		printDiffs(stdout, files)
		return 0
	}
	if len(rest) < 1 || len(rest) > 2 {
		fmt.Fprintln(stderr, "usage: tavian config diff FROM [TO]   (revisions; TO defaults to the active one)\n       tavian config diff -config FILE [REVISION]")
		return 2
	}
	path := "/admin/v1/config/diff?from=" + url.QueryEscape(rest[0])
	if len(rest) == 2 {
		path += "&to=" + url.QueryEscape(rest[1])
	}
	var d struct {
		From, To string
		Files    []textdiff.FileDiff
	}
	raw, err := c.call("GET", path, nil, &d)
	if err != nil {
		return fail(stderr, "diff", err)
	}
	if cn.raw(stdout, raw) {
		return 0
	}
	if len(d.Files) == 0 {
		fmt.Fprintf(stdout, "revisions %s and %s are the same\n", d.From, d.To)
		return 0
	}
	printDiffs(stdout, d.Files)
	return 0
}

// activeRevision asks for the revision the gateway believes is active.
func activeRevision(c *client) (string, error) {
	var cfg struct{ Revision string }
	if _, err := c.call("GET", "/admin/v1/config", nil, &cfg); err != nil {
		return "", err
	}
	return cfg.Revision, nil
}

func cmdConfigValidate(args []string, stdout, stderr io.Writer) int {
	var file, dir string
	c, cn, _, code, ok := begin("validate", args, stderr, func(fs *flag.FlagSet) *conn {
		fs.StringVar(&file, "config", "", "the configuration file (required)")
		fs.StringVar(&dir, "policies", "", "policy directory (default: policy.dir of the configuration)")
		return connFlags(fs)
	})
	if !ok {
		return code
	}
	req, err := local(file, dir)
	if err != nil {
		return fail(stderr, "validate", err)
	}
	var v admin.Validation
	raw, err := c.call("POST", "/admin/v1/config/validate", req, &v)
	if err != nil {
		return fail(stderr, "validate", err)
	}
	if cn.raw(stdout, raw) {
		return exitValidation(v)
	}
	for _, e := range v.Errors {
		fmt.Fprintln(stdout, "error:", e)
	}
	for _, w := range v.Warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	switch {
	case !v.Valid:
		fmt.Fprintln(stdout, "invalid")
	case !v.Applicable:
		fmt.Fprintf(stdout, "valid (revision %s), but the running gateway cannot take it: %s\n", v.Revision, v.Reason)
	default:
		fmt.Fprintf(stdout, "valid (revision %s), the running gateway can take it\n", v.Revision)
	}
	return exitValidation(v)
}

func exitValidation(v admin.Validation) int {
	if v.Valid && v.Applicable {
		return 0
	}
	return 1
}

func cmdConfigApply(args []string, stdout, stderr io.Writer) int {
	var file, dir, base string
	var dry bool
	c, cn, _, code, ok := begin("apply", args, stderr, func(fs *flag.FlagSet) *conn {
		fs.StringVar(&file, "config", "", "the configuration file (required)")
		fs.StringVar(&dir, "policies", "", "policy directory (default: policy.dir of the configuration)")
		fs.StringVar(&base, "base", "", "the revision you believe is active (default: the active one now)")
		fs.BoolVar(&dry, "dry-run", false, "validate and show what would change, without applying")
		return connFlags(fs)
	})
	if !ok {
		return code
	}
	req, err := local(file, dir)
	if err != nil {
		return fail(stderr, "apply", err)
	}
	if base == "" {
		if base, err = activeRevision(c); err != nil {
			return fail(stderr, "apply", err)
		}
	}
	req.Base = base
	if dry {
		var v admin.Validation
		if _, err := c.call("POST", "/admin/v1/config/validate", req, &v); err != nil {
			return fail(stderr, "apply", err)
		}
		for _, e := range v.Errors {
			fmt.Fprintln(stdout, "error:", e)
		}
		if !v.Valid || !v.Applicable {
			if v.Reason != "" {
				fmt.Fprintln(stdout, "cannot be applied:", v.Reason)
			}
			return 1
		}
		r, _, err := fetchRevision(c, base)
		if err != nil {
			return fail(stderr, "apply", err)
		}
		files := textdiff.Files(r.named(), localNamed(req))
		if len(files) == 0 {
			fmt.Fprintf(stdout, "nothing to apply: the configuration is the active revision %s\n", base)
			return 0
		}
		fmt.Fprintf(stdout, "would make revision %s active over %s:\n", v.Revision, base)
		printDiffs(stdout, files)
		return 0
	}
	var res admin.Result
	raw, err := c.call("POST", "/admin/v1/config/apply", req, &res)
	if err != nil {
		return fail(stderr, "apply", err)
	}
	return printResult(stdout, cn, raw, res, "applied")
}

func printResult(stdout io.Writer, cn *conn, raw []byte, res admin.Result, verb string) int {
	if cn.raw(stdout, raw) {
		return 0
	}
	if res.Unchanged {
		fmt.Fprintf(stdout, "revision %s was already active: nothing changed (the attempt is recorded)\n", res.Revision)
	} else {
		fmt.Fprintf(stdout, "%s: revision %s is active (it was %s)\n", verb, res.Revision, res.Previous)
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	return 0
}

func cmdConfigRollback(args []string, stdout, stderr io.Writer) int {
	var revision, base string
	c, cn, _, code, ok := begin("rollback", args, stderr, func(fs *flag.FlagSet) *conn {
		fs.StringVar(&revision, "revision", "", "the revision to return to (required)")
		fs.StringVar(&base, "base", "", "the revision you believe is active (default: the active one now)")
		return connFlags(fs)
	})
	if !ok {
		return code
	}
	if revision == "" {
		fmt.Fprintln(stderr, "usage: tavian config rollback -revision ID [-base ID]")
		return 2
	}
	var err error
	if base == "" {
		if base, err = activeRevision(c); err != nil {
			return fail(stderr, "rollback", err)
		}
	}
	var res admin.Result
	raw, err := c.call("POST", "/admin/v1/config/rollback", admin.RollbackRequest{Revision: revision, Base: base}, &res)
	if err != nil {
		return fail(stderr, "rollback", err)
	}
	return printResult(stdout, cn, raw, res, "rolled back")
}

func cmdConfigReload(args []string, stdout, stderr io.Writer) int {
	c, cn, _, code, ok := begin("reload", args, stderr, plain)
	if !ok {
		return code
	}
	var res admin.Result
	raw, err := c.call("POST", "/admin/v1/config/reload", nil, &res)
	if err != nil {
		return fail(stderr, "reload", err)
	}
	return printResult(stdout, cn, raw, res, "reloaded")
}

func cmdConfigHistory(args []string, stdout, stderr io.Writer) int {
	var limit int
	c, cn, _, code, ok := begin("history", args, stderr, func(fs *flag.FlagSet) *conn {
		fs.IntVar(&limit, "limit", 20, "how many changes to list (1 to 500)")
		return connFlags(fs)
	})
	if !ok {
		return code
	}
	if limit < 1 || limit > 500 {
		return fail(stderr, "history", errors.New("-limit must be between 1 and 500"))
	}
	var page struct {
		Changes []struct {
			OccurredAt time.Time `json:"occurred_at"`
			Actor      string    `json:"actor"`
			Action     string    `json:"action"`
			Target     string    `json:"target"`
			Outcome    string    `json:"outcome"`
			RemoteAddr string    `json:"remote_addr"`
		} `json:"changes"`
	}
	raw, err := c.call("GET", "/admin/v1/changes?limit="+strconv.Itoa(limit), nil, &page)
	if err != nil {
		return fail(stderr, "history", err)
	}
	if cn.raw(stdout, raw) {
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tWHO\tACTION\tOUTCOME\tREVISION\tFROM")
	for _, ch := range page.Changes {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", ch.OccurredAt.Local().Format("2006-01-02 15:04:05"), ch.Actor, ch.Action, ch.Outcome, ch.Target, ch.RemoteAddr)
	}
	_ = tw.Flush()
	return 0
}

func cmdConfigTokens(args []string, stdout, stderr io.Writer) int {
	c, cn, _, code, ok := begin("tokens", args, stderr, plain)
	if !ok {
		return code
	}
	var page struct {
		Tokens []struct {
			ID         string     `json:"id"`
			Role       string     `json:"role"`
			ExpiresAt  *time.Time `json:"expires_at"`
			Expired    bool       `json:"expired"`
			LastUsedAt *time.Time `json:"last_used_at"`
			LastRemote string     `json:"last_remote"`
			Uses       int64      `json:"uses"`
		} `json:"tokens"`
	}
	raw, err := c.call("GET", "/admin/v1/tokens", nil, &page)
	if err != nil {
		return fail(stderr, "tokens", err)
	}
	if cn.raw(stdout, raw) {
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tROLE\tEXPIRES\tLAST USED\tFROM\tUSES")
	for _, t := range page.Tokens {
		expires := "never"
		if t.ExpiresAt != nil {
			expires = t.ExpiresAt.Local().Format("2006-01-02 15:04")
			if t.Expired {
				expires += " (expired)"
			}
		}
		last := "never"
		if t.LastUsedAt != nil {
			last = t.LastUsedAt.Local().Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", t.ID, t.Role, expires, last, t.LastRemote, t.Uses)
	}
	_ = tw.Flush()
	return 0
}
