package chain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalIsIndependentOfKeyOrderAndSpacing(t *testing.T) {
	a, err := Canonical([]byte(`{"b": 1, "a": {"y": [1, 2.50, "x"], "x": null}, "c": true}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Canonical([]byte(`{"c":true,"a":{"x":null,"y":[1,2.50,"x"]},"b":1}`))
	if !bytes.Equal(a, b) {
		t.Fatalf("%s != %s", a, b)
	}
	if want := `{"a":{"x":null,"y":[1,2.50,"x"]},"b":1,"c":true}`; string(a) != want {
		t.Fatalf("canonical = %s, want %s", a, want)
	}
}

func TestCanonicalKeepsDifferencesThatMatter(t *testing.T) {
	base, _ := Canonical([]byte(`{"a":"x","n":1}`))
	for name, doc := range map[string]string{
		"value":    `{"a":"y","n":1}`,
		"number":   `{"a":"x","n":2}`,
		"type":     `{"a":"x","n":"1"}`,
		"key":      `{"b":"x","n":1}`,
		"extra":    `{"a":"x","n":1,"z":null}`,
		"in array": `{"a":["x"],"n":1}`,
	} {
		other, err := Canonical([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(base, other) {
			t.Errorf("%s: documents that differ have the same canonical form", name)
		}
	}
}

func TestCanonicalStrings(t *testing.T) {
	got, err := Canonical([]byte(`{"s":"<a>&é\n\"q\""}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"s":"<a>&é\n\"q\""}`; string(got) != want {
		t.Fatalf("canonical = %s, want %s (no HTML escaping)", got, want)
	}
}

func TestCanonicalRejectsWhatIsNotOneDocument(t *testing.T) {
	for _, doc := range []string{``, `{`, `{"a":1} {"b":2}`, `{"a":1}x`} {
		if _, err := Canonical([]byte(doc)); err == nil {
			t.Errorf("%q accepted", doc)
		}
	}
}

// These values are the format. If one changes, every chain already written
// stops verifying: change the domain strings and migrate instead.
func TestHashVectors(t *testing.T) {
	content, err := ContentHash([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 3, 10, 12, 0, 0, 123456000, time.UTC)
	e1 := EntryHash(1, Genesis(), "evt-1", at, content)
	e2 := EntryHash(2, e1, "evt-2", at, content)
	if hex.EncodeToString(Genesis()) != vectorGenesis || hex.EncodeToString(content) != vectorContent ||
		hex.EncodeToString(e1) != vectorEntry1 || hex.EncodeToString(e2) != vectorEntry2 {
		t.Fatal("hash vectors changed")
	}
}

func TestEntryHashCommitsToEveryField(t *testing.T) {
	content, _ := ContentHash([]byte(`{}`))
	at := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	prev := Genesis()
	base := EntryHash(1, prev, "e", at, content)
	other, _ := ContentHash([]byte(`{"a":1}`))
	for name, got := range map[string][]byte{
		"position": EntryHash(2, prev, "e", at, content),
		"prev":     EntryHash(1, base, "e", at, content),
		"event id": EntryHash(1, prev, "f", at, content),
		"time":     EntryHash(1, prev, "e", at.Add(time.Microsecond), content),
		"content":  EntryHash(1, prev, "e", at, other),
	} {
		if bytes.Equal(got, base) {
			t.Errorf("changing the %s does not change the entry hash", name)
		}
	}
	// ambiguity between the event id and what follows
	if bytes.Equal(EntryHash(1, prev, "ab", at, content), EntryHash(1, prev, "a", at, content)) {
		t.Error("ids of different lengths collide")
	}
}

func TestSealSignatures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.key")
	pub, err := GenerateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKeyFile(path); err == nil {
		t.Fatal("an existing key was overwritten")
	}
	signer, err := LoadSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.Public(), pub) {
		t.Fatal("the key on disk is not the one reported")
	}
	seal := Seal{ID: 1, FirstPosition: 1, LastPosition: 10, LastEntryHash: Genesis(), SealedAt: time.Now().UTC().Truncate(time.Microsecond)}
	signer.Sign(&seal)
	if err := VerifySeal(pub, seal); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Seal){
		"id":    func(s *Seal) { s.ID++ },
		"first": func(s *Seal) { s.FirstPosition++ },
		"last":  func(s *Seal) { s.LastPosition++ },
		"hash":  func(s *Seal) { s.LastEntryHash = append([]byte{0}, s.LastEntryHash[1:]...) },
		"time":  func(s *Seal) { s.SealedAt = s.SealedAt.Add(time.Microsecond) },
		"key":   func(s *Seal) { s.KeyID = "0000000000000000" },
		"sig":   func(s *Seal) { s.Signature = append([]byte{0}, s.Signature[1:]...) },
	} {
		s := seal
		s.LastEntryHash = append([]byte(nil), seal.LastEntryHash...)
		s.Signature = append([]byte(nil), seal.Signature...)
		mutate(&s)
		if VerifySeal(pub, s) == nil {
			t.Errorf("changing the %s of a seal keeps its signature valid", name)
		}
	}
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if VerifySeal(otherPub, seal) == nil {
		t.Error("another key verifies the seal")
	}
}

func TestKeyFileHygiene(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v", info.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Errorf("a world-readable key was loaded: %v", err)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(bad); err == nil {
		t.Error("garbage loaded as a key")
	}
	if _, err := LoadSigner(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing key loaded")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	got, err := ParsePublicKey(" " + PublicKeyString(pub) + "\n")
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "ed25519:", "ed25519:!!!", "rsa:AAAA", "ed25519:" + "AAAA"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
