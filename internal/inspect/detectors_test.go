package inspect

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// found returns "subtype:matched text" for each finding of the built-in
// detectors in text.
func found(t *testing.T, e *Engine, text string) []string {
	t.Helper()
	res, err := e.Inspect(context.Background(), Request{Segments: []Segment{{MessageIndex: 0, Field: FieldContent, Part: -1, Text: text}}})
	if err != nil {
		t.Fatalf("%q: %v", text, err)
	}
	norm := normalize(text)
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Subtype+":"+norm[f.Location.Start:f.Location.End])
	}
	return out
}

type detectorCase struct {
	text string
	want []string // nil: nothing
}

func runCases(t *testing.T, e *Engine, cases []detectorCase) {
	t.Helper()
	for _, c := range cases {
		got := found(t, e, c.text)
		if !slices.Equal(got, c.want) {
			t.Errorf("%q:\n got %q\nwant %q", c.text, got, c.want)
		}
	}
}

func TestIBAN(t *testing.T) {
	runCases(t, newTestEngine(t), []detectorCase{
		{"FR14 2004 1010 0505 0001 3M02 606", []string{"iban:FR14 2004 1010 0505 0001 3M02 606"}},
		{"iban: GB82WEST12345698765432.", []string{"iban:GB82WEST12345698765432"}},
		{"DE89-3704-0044-0532-0130-00", []string{"iban:DE89-3704-0044-0532-0130-00"}},
		{"virement vers fr76 3000 6000 0112 3456 7890 189 merci", []string{"iban:fr76 3000 6000 0112 3456 7890 189"}},
		{"FR76 3000 6000 0112 3456 7890 188", nil},                                                  // bad checksum
		{"FR76 3000 6000 0112 3456 789", nil},                                                       // too short for France
		{"FR76 3000 6000 0112 3456 7890 189 0", []string{"iban:FR76 3000 6000 0112 3456 7890 189"}}, // a separate number follows
		{"FR76 3000 6000 0112 3456 7890 1890", nil},                                                 // a longer number
		{"XX82 WEST 1234 5698 7654 32", nil},                                                        // not a country
		{"xGB82WEST12345698765432", nil},                                                            // inside a word
		{"GB82 WEST 1234 5698 7654 32X", nil},
		{"GB82  WEST 1234 5698 7654 32", nil}, // two spaces
	})
}

func TestPaymentCard(t *testing.T) {
	runCases(t, newTestEngine(t), []detectorCase{
		{"card 4111 1111 1111 1111 exp 12/29", []string{"payment_card:4111 1111 1111 1111"}},
		{"5555-5555-5555-4444", []string{"payment_card:5555-5555-5555-4444"}},
		{"3782 822463 10005", []string{"payment_card:3782 822463 10005"}},
		{"6011111111111117", []string{"payment_card:6011111111111117"}},
		{"3530111333300000", []string{"payment_card:3530111333300000"}},
		{"2223000048400011", []string{"payment_card:2223000048400011"}},
		{"4111111111111112", nil},     // Luhn fails
		{"6000 0000 0000 0000", nil},  // Luhn ok, no card scheme
		{"41111111111111111111", nil}, // 20 digits
		{"x4111111111111111", nil},
		{"4111 1111 1111", nil},
	})
}

func TestNIR(t *testing.T) {
	runCases(t, newTestEngine(t), []detectorCase{
		{"NIR 1 85 05 78 006 084 91 ok", []string{"nir:1 85 05 78 006 084 91"}},
		{"185057800608491", []string{"nir:185057800608491"}},
		{"1.85.05.78.006.084.91", []string{"nir:1.85.05.78.006.084.91"}},
		{"2 99 05 2A 123 456 73", []string{"nir:2 99 05 2A 123 456 73"}},
		{"2 99 05 2b 123 456 03", []string{"nir:2 99 05 2b 123 456 03"}},
		{"1 85 05 78 006 084 92", nil}, // wrong key
		{"1 85 13 78 006 084 91", nil}, // month 13
		{"5 85 05 78 006 084 91", nil}, // cannot start with 5
		{"1850578006084911", nil},      // 16 digits
	})
}

func TestPhone(t *testing.T) {
	runCases(t, newTestEngine(t), []detectorCase{
		{"appelle le 06 12 34 56 78 stp", []string{"phone:06 12 34 56 78"}},
		{"0612345678", []string{"phone:0612345678"}},
		{"01.23.45.67.89", []string{"phone:01.23.45.67.89"}},
		{"+33 6 12 34 56 78", []string{"phone:+33 6 12 34 56 78"}},
		{"+44 20 7946 0958.", []string{"phone:+44 20 7946 0958"}},
		{"+1 (415) 555-0132", []string{"phone:+1 (415) 555-0132"}},
		{"0612345678 12 fois", []string{"phone:0612345678"}},
		{"00 12 34 56 78", nil}, // 00 is not a national prefix
		{"06123456789", nil},    // 11 digits
		{"+123", nil},           // too short
		{"3 + 4 = 7", nil},
	})
}

func TestIPv4(t *testing.T) {
	runCases(t, newTestEngine(t), []detectorCase{
		{"host 192.168.1.10:8080", []string{"ipv4:192.168.1.10"}},
		{"ping 8.8.8.8.", []string{"ipv4:8.8.8.8"}},
		{"0.0.0.0", []string{"ipv4:0.0.0.0"}},
		{"256.1.1.1", nil},
		{"1.2.3", nil},
		{"1.2.3.4.5", nil},
		{"v1.2.3.4", nil},
		{"01.2.3.4", nil},
		{"1.2.3.4abc", nil},
	})
}

func TestTokens(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("a1B2", 9)
	runCases(t, newTestEngine(t), []detectorCase{
		{"key=AKIAIOSFODNN7EXAMPLE rest", []string{"aws_access_key:AKIAIOSFODNN7EXAMPLE"}},
		{"AKIAIOSFODNN7EXAMPLEX", nil},
		{"token " + ghp, []string{"github_token:" + ghp}},
		{"ghp_short", nil},
		{"glpat-abcdefghij0123456789", []string{"gitlab_token:glpat-abcdefghij0123456789"}},
		{"xoxb-123456789012-abcdefghij", []string{"slack_token:xoxb-123456789012-abcdefghij"}},
		{"sk_live_abcdefghijklmnop1234", []string{"stripe_key:sk_live_abcdefghijklmnop1234"}},
		{"AIza" + strings.Repeat("x", 35), []string{"google_api_key:AIza" + strings.Repeat("x", 35)}},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIE", []string{"private_key:-----BEGIN RSA PRIVATE KEY-----"}},
		{"-----BEGIN PRIVATE KEY-----", []string{"private_key:-----BEGIN PRIVATE KEY-----"}},
		{"-----BEGIN CERTIFICATE-----", nil},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl", []string{"jwt:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"}},
		{"eyJhbGciOiJIUzI1NiJ9", nil},
	})
}

func TestCredentialAssignments(t *testing.T) {
	runCases(t, newTestEngine(t), []detectorCase{
		{`DB_PASSWORD=Summer2024!x`, []string{"credential:Summer2024!x"}},
		{`password: "hunter2hunter2"`, []string{"credential:hunter2hunter2"}},
		{`{"api_key": "k3y-abcdef-123456"}`, []string{"credential:k3y-abcdef-123456"}},
		{`client_secret = 'Zm9vYmFyMTIz'`, []string{"credential:Zm9vYmFyMTIz"}},
		{`password: mypassword`, nil}, // letters only
		{`password: x1`, nil},         // too short
		{`token: <your-token>`, nil},  // placeholder
		{`the time: 12345678`, nil},   // no keyword
		{`token:`, nil},
	})
}

func TestDetectorsLeaveProseAlone(t *testing.T) {
	e := newTestEngine(t)
	prose := "Please summarise the quarterly report for the finance committee, list the open risks, " +
		"and compare the 2024 figures (up 12.5%) with the 2023 plan: revenue 4,500,000 EUR, margin 18%. " +
		"Meeting on 2024-05-14 at 10:30, room B12, version 2.4.1, ticket JIRA-1234."
	if got := found(t, e, prose); len(got) != 0 {
		t.Errorf("false positives on ordinary prose: %q", got)
	}
}

func TestDictionary(t *testing.T) {
	e, err := New(Config{Dictionaries: []Dictionary{
		{Name: "codenames", Severity: SeverityHigh, Terms: []string{"Projet Aurore", "Falcon", "Aurore"}},
		{Name: "markings", Terms: []string{"CONFIDENTIEL", "Société Générale"}, WholeWord: ptr(true)},
		{Name: "exact", Terms: []string{"Zeta"}, CaseSensitive: true},
		{Name: "inside", Terms: []string{"corp"}, WholeWord: ptr(false)},
	}, Disable: []string{"pii.ip"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runCases(t, e, []detectorCase{
		{"le projet aurore avance", []string{"codenames:projet aurore"}}, // longest, no overlap
		{"Aurore et FALCON", []string{"codenames:Aurore", "codenames:FALCON"}},
		{"Falconry", nil}, // whole word
		{"document confidentiel!", []string{"markings:confidentiel"}},
		{"SOCIÉTÉ GÉNÉRALE vs société générale", []string{"markings:SOCIÉTÉ GÉNÉRALE", "markings:société générale"}},
		{"Zeta zeta", []string{"exact:Zeta"}},
		{"megacorporation", []string{"inside:corp"}},
		{"nothing to see", nil},
	})

	// the same term gives the same fingerprint whatever its case
	fp := func(s string) string {
		res, _ := e.Inspect(context.Background(), text(s))
		return res.Findings[0].Fingerprint
	}
	if fp("falcon") != fp("FALCON") {
		t.Error("case variants of a term must correlate")
	}
	res, _ := e.Inspect(context.Background(), text("Falcon"))
	if res.Findings[0].Type != TypeCustom || res.Findings[0].Severity != SeverityHigh || !strings.HasPrefix(res.Detectors[len(res.Detectors)-4].Version, "1:") {
		t.Errorf("finding = %+v detectors = %+v", res.Findings[0], res.Detectors)
	}
}

func ptr[T any](v T) *T { return &v }

func TestDictionaryOffsetsWithMultiByteRunes(t *testing.T) {
	e, _ := New(Config{Dictionaries: []Dictionary{{Name: "d", Terms: []string{"İstanbul", "naïve"}}}}, nil)
	txt := "été à Naïve — İSTANBUL"
	res, err := e.Inspect(context.Background(), text(txt))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range res.Findings {
		if f.Subtype == "d" {
			got = append(got, txt[f.Location.Start:f.Location.End])
		}
	}
	if !slices.Equal(got, []string{"Naïve"}) && !slices.Equal(got, []string{"Naïve", "İSTANBUL"}) {
		t.Errorf("matched %q", got)
	}
}

func TestCustomPattern(t *testing.T) {
	e, err := New(Config{Patterns: []Pattern{{Name: "contract", Regex: `CTR-\d{6}`, Severity: SeverityHigh}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runCases(t, e, []detectorCase{
		{"see CTR-123456 and CTR-12", []string{"contract:CTR-123456"}},
	})
}

func TestCustomConfigValidation(t *testing.T) {
	long := strings.Repeat("x", 200)
	bad := map[string]Config{
		"unknown disable":      {Disable: []string{"pii.nope"}},
		"bad dictionary name":  {Dictionaries: []Dictionary{{Name: "Bad Name", Terms: []string{"abc"}}}},
		"duplicate name":       {Dictionaries: []Dictionary{{Name: "a", Terms: []string{"abc"}}}, Patterns: []Pattern{{Name: "a", Regex: "x+"}}},
		"no terms":             {Dictionaries: []Dictionary{{Name: "a"}}},
		"one-letter term":      {Dictionaries: []Dictionary{{Name: "a", Terms: []string{"a"}}}},
		"huge term":            {Dictionaries: []Dictionary{{Name: "a", Terms: []string{long}}}},
		"invalid utf-8":        {Dictionaries: []Dictionary{{Name: "a", Terms: []string{"\xff\xfe"}}}},
		"bad severity":         {Dictionaries: []Dictionary{{Name: "a", Terms: []string{"abc"}, Severity: "urgent"}}},
		"bad regex":            {Patterns: []Pattern{{Name: "p", Regex: "("}}},
		"empty-matching regex": {Patterns: []Pattern{{Name: "p", Regex: "a*"}}},
		"empty regex":          {Patterns: []Pattern{{Name: "p"}}},
		"regex too long":       {Patterns: []Pattern{{Name: "p", Regex: strings.Repeat("a", maxPatternBytes+1)}}},
	}
	for name, cfg := range bad {
		if _, err := New(cfg, nil); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// A hostile prompt must not make inspection explode: pathological inputs for
// each scanner stay within the default budget.
func TestPathologicalInputsStayFast(t *testing.T) {
	e := NewWith(5*time.Second, testKey, builtinSet()...)
	inputs := map[string]string{
		"digits":         strings.Repeat("1 ", 100000),
		"zeros":          strings.Repeat("0", 200000),
		"phone-like":     strings.Repeat("+1 ", 70000),
		"ats":            strings.Repeat("a@", 100000),
		"letters+digits": strings.Repeat("AB12 ", 40000),
		"equals":         strings.Repeat("password=", 30000),
		"prefixes":       strings.Repeat("ghp_AKIAeyJ-----BEGIN ", 10000),
		"dots":           strings.Repeat("1.2.3.4.", 50000),
	}
	for name, in := range inputs {
		start := time.Now()
		if _, err := e.Inspect(context.Background(), text(in)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: took %v for %d bytes", name, d, len(in))
		}
	}
}

func FuzzDetectors(f *testing.F) {
	for _, s := range []string{
		"FR14 2004 1010 0505 0001 3M02 606", "4111 1111 1111 1111", "1 85 05 78 006 084 91", "+33 6 12 34 56 78",
		"192.168.1.10", "AKIAIOSFODNN7EXAMPLE", "password=abc12345678", "-----BEGIN PRIVATE KEY-----", "Projet Aurore",
		"CTR-123456", "\xff\xfe+0", "２２２２", "eyJa.eyJb.c",
	} {
		f.Add(s)
	}
	cfg := Config{
		Dictionaries: []Dictionary{{Name: "d", Terms: []string{"Projet Aurore", "İstanbul", "ab"}}},
		Patterns:     []Pattern{{Name: "p", Regex: `CTR-\d+`}},
	}
	e, err := New(cfg, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		res, err := e.Inspect(context.Background(), text(s, s+" "+s))
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		for _, fi := range res.Findings {
			seg := normalize([]string{s, s + " " + s}[fi.Location.Segment])
			l := fi.Location
			if l.Start < 0 || l.End <= l.Start || l.End > len(seg) {
				t.Fatalf("location out of range: %+v", l)
			}
			if fi.Fingerprint == "" || fi.Canonical != "" {
				t.Fatalf("finding not finalised: %+v", fi)
			}
		}
	})
}
