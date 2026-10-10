package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bredda/tavian/internal/chain"
	"github.com/bredda/tavian/internal/config"
	"github.com/bredda/tavian/internal/store"
)

// cmdAuditKeygen creates the key that signs the seals of the audit chain.
func cmdAuditKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit-keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "file to write the private key to (mode 0600)")
	ifMissing := fs.Bool("if-missing", false, "do nothing when the file already exists (for provisioning)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, "tavian: -out is required")
		return 2
	}
	if _, err := os.Stat(*out); err == nil && *ifMissing {
		signer, err := chain.LoadSigner(*out)
		if err != nil {
			fmt.Fprintln(stderr, "tavian:", err)
			return 1
		}
		fmt.Fprintf(stdout, "public key: %s\n", chain.PublicKeyString(signer.Public()))
		return 0
	}
	pub, err := chain.GenerateKeyFile(*out)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	fmt.Fprintf(stdout, "public key: %s\nkey id:     %s\n", chain.PublicKeyString(pub), chain.KeyID(pub))
	fmt.Fprintf(stderr, "\nPrivate key written to %s. Keep it out of the database and out of backups that the people who can edit the database can reach.\nPut the path in audit.signing_key_file; give the public key to your auditors (tavian verify-audit -public-key).\n", *out)
	return 0
}

// cmdVerifyAudit checks the audit chain, the records it covers, its seals and
// the copies of seals kept outside the database.
func cmdVerifyAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	keys := fs.String("public-key", "", `public key(s) that verify the seals: "ed25519:<base64>", comma-separated, or a file holding them one per line`)
	anchors := fs.String("anchors", "", "file of seals exported earlier (-export-seals): each must still be in the database, unchanged")
	export := fs.String("export-seals", "", "write all seals to this file (JSON lines) to keep them outside the database")
	from := fs.Int64("from-seal", 0, "start after this seal instead of from the first entry (needs -public-key)")
	pruned := fs.Bool("allow-pruned", false, "accept entries whose record was removed from the outbox once a signed seal covers them")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	opt := chain.Options{FromSeal: *from, AllowPruned: *pruned}
	var err error
	if opt.PublicKeys, err = readPublicKeys(*keys); err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 2
	}
	if *anchors != "" {
		if opt.Anchors, err = readSeals(*anchors); err != nil {
			fmt.Fprintln(stderr, "tavian:", err)
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	st, code := openAuditStore(ctx, *path, stderr)
	if st == nil {
		return code
	}
	defer st.Close()

	if *export != "" {
		seals, err := chain.Seals(ctx, st.Pool())
		if err == nil {
			err = writeSeals(*export, seals)
		}
		if err != nil {
			fmt.Fprintln(stderr, "tavian:", err)
			return 1
		}
		fmt.Fprintf(stdout, "exported %d seals to %s\n", len(seals), *export)
	}

	rep, err := chain.Verify(ctx, st.Pool(), opt)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	printReport(stdout, rep, opt)
	if !rep.OK() {
		return 1
	}
	return 0
}

// openAuditStore opens the database named by the configuration, for the
// commands of the auditor, and checks that its schema is the one of this
// binary. Everything they do afterwards only reads. When it returns nil the
// caller stops with the exit code returned.
func openAuditStore(ctx context.Context, path string, stderr io.Writer) (*store.Store, int) {
	cfg, raw, err := config.Load(path)
	if err == nil && cfg.Database.URLEnv == "" {
		err = errors.New("database.url_env is not set in the configuration")
	}
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return nil, 1
	}
	snap, err := config.Compile(cfg, raw, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return nil, 1
	}
	holder := &config.Holder{}
	holder.Store(snap)
	st, err := openStore(ctx, cfg, holder)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return nil, 1
	}
	if err := st.CheckSchema(ctx); err != nil {
		st.Close()
		fmt.Fprintln(stderr, "tavian:", err)
		return nil, 1
	}
	return st, 0
}

// cmdAuditRole prints the script that creates the read-only role of an auditor.
func cmdAuditRole(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit-role", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "tavian_auditor", "name of the role")
	database := fs.String("database", "tavian", "name of the database")
	schema := fs.String("schema", "public", "schema the tables are in")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	script, err := store.AuditorRoleSQL(*name, *database, *schema)
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 2
	}
	fmt.Fprint(stdout, script)
	fmt.Fprintln(stderr, "\nNothing was run: give this script to your database administrator (psql -f).")
	return 0
}

// cmdAuditExport writes the entries of the audit chain with the records they
// cover, as JSON lines.
func cmdAuditExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit-export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	kinds := fs.String("kind", "", "only these kinds, comma-separated: decision, admin_change (default: both)")
	since := fs.String("since", "", "only records from this time on (RFC 3339 or a date, UTC)")
	until := fs.String("until", "", "only records before this time (RFC 3339 or a date, UTC)")
	from := fs.Int64("from-position", 0, "only entries after this chain position")
	out := fs.String("o", "", "write to this file (mode 0600, never over an existing one unless -force) instead of the standard output")
	force := fs.Bool("force", false, "write over an existing file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	opt := chain.ExportOptions{FromPosition: *from}
	var err error
	for _, k := range strings.Split(*kinds, ",") {
		switch k = strings.TrimSpace(k); k {
		case "":
		case chain.KindDecision, chain.KindAdminChange:
			opt.Kinds = append(opt.Kinds, k)
		default:
			fmt.Fprintf(stderr, "tavian: unknown kind %q: use decision or admin_change\n", k)
			return 2
		}
	}
	if opt.Since, err = parseWhen(*since); err == nil {
		opt.Until, err = parseWhen(*until)
	}
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 2
	}
	w := stdout
	var file *os.File
	if *out != "" {
		flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if *force {
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		f, err := os.OpenFile(*out, flags, 0o600) //nolint:gosec // the path is chosen by the auditor on the command line
		if err != nil {
			fmt.Fprintln(stderr, "tavian:", err)
			return 1
		}
		file, w = f, f
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	st, code := openAuditStore(ctx, *path, stderr)
	if st == nil {
		return code
	}
	defer st.Close()
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	n, err := chain.Export(ctx, st.Pool(), opt, func(e chain.Entry) error { return enc.Encode(e) })
	if err == nil {
		err = bw.Flush()
	}
	if file != nil {
		// a file that cannot be closed may not have been written
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "tavian:", err)
		return 1
	}
	fmt.Fprintf(stderr, "exported %d entries\n", n)
	return 0
}

// parseWhen reads a time given as RFC 3339 or as a date (00:00 UTC); empty is
// no bound.
func parseWhen(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%q is neither an RFC 3339 time nor a date (2026-10-10)", s)
}

func printReport(w io.Writer, rep *chain.Report, opt chain.Options) {
	fmt.Fprintf(w, "chain: %d entries checked, %d seals", rep.Entries, rep.Seals)
	if opt.FromSeal > 0 {
		fmt.Fprintf(w, " (starting after seal %d)", opt.FromSeal)
	}
	fmt.Fprintln(w)
	if rep.SignaturesChecked {
		fmt.Fprintln(w, "seals: signatures verified")
	} else {
		fmt.Fprintln(w, "seals: signatures NOT verified")
	}
	if len(opt.Anchors) > 0 {
		fmt.Fprintf(w, "anchors: %d seals compared with the copies kept outside the database\n", len(opt.Anchors))
	}
	if rep.Unsealed > 0 {
		fmt.Fprintf(w, "unsealed: %d entries after the last seal are not covered by a signature yet\n", rep.Unsealed)
	}
	if rep.Pending > 0 {
		fmt.Fprintf(w, "pending: %d decision records have not been chained yet\n", rep.Pending)
	}
	if rep.Pruned > 0 {
		fmt.Fprintf(w, "pruned: %d records are no longer in the outbox (covered by signed seals)\n", rep.Pruned)
	}
	for _, m := range rep.Warnings {
		fmt.Fprintln(w, "warning:", m)
	}
	if rep.OK() {
		fmt.Fprintln(w, "OK: no problem found")
		return
	}
	fmt.Fprintf(w, "FAILED: %d problems\n", len(rep.Problems))
	for _, p := range rep.Problems {
		fmt.Fprintln(w, "  -", p)
	}
}

// readPublicKeys reads keys given inline (comma-separated) or from a file.
func readPublicKeys(arg string) ([]ed25519.PublicKey, error) {
	if arg == "" {
		return nil, nil
	}
	var parts []string
	if strings.HasPrefix(strings.TrimSpace(arg), "ed25519:") {
		parts = strings.Split(arg, ",")
	} else {
		raw, err := os.ReadFile(arg) //nolint:gosec // the path is chosen by the operator on the command line
		if err != nil {
			return nil, fmt.Errorf("public key: %w", err)
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				parts = append(parts, l)
			}
		}
	}
	var out []ed25519.PublicKey
	for _, p := range parts {
		k, err := chain.ParsePublicKey(p)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

func readSeals(path string) ([]chain.Seal, error) {
	f, err := os.Open(path) //nolint:gosec // the path is chosen by the operator on the command line
	if err != nil {
		return nil, fmt.Errorf("anchors: %w", err)
	}
	defer func() { _ = f.Close() }()
	var out []chain.Seal
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var s chain.Seal
		if err := json.Unmarshal(line, &s); err != nil {
			return nil, fmt.Errorf("anchors: %s: line %d: %w", path, len(out)+1, err)
		}
		s.SealedAt = s.SealedAt.UTC()
		out = append(out, s)
	}
	return out, sc.Err()
}

func writeSeals(path string, seals []chain.Seal) error {
	var b bytes.Buffer
	for _, s := range seals {
		line, err := json.Marshal(s)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil { //nolint:gosec // seals are meant to be copied around; they hold no secret
		return fmt.Errorf("export seals: %w", err)
	}
	return nil
}
