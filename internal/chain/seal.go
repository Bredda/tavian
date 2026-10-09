package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Seal is a signed statement: "the chain up to LastPosition ends with
// LastEntryHash". Seals are numbered without gaps.
type Seal struct {
	ID            int64     `json:"id"`
	FirstPosition int64     `json:"first_position"`
	LastPosition  int64     `json:"last_position"`
	LastEntryHash []byte    `json:"last_entry_hash"`
	SealedAt      time.Time `json:"sealed_at"`
	KeyID         string    `json:"key_id"`
	Signature     []byte    `json:"signature"`
}

const sealDomain = "tavian-audit-seal-v1\x00"

// message is what is signed.
func (s Seal) message() []byte {
	var b bytes.Buffer
	b.WriteString(sealDomain)
	for _, n := range []int64{s.ID, s.FirstPosition, s.LastPosition, s.SealedAt.UnixMicro()} {
		_ = binary.Write(&b, binary.BigEndian, n)
	}
	b.Write(s.LastEntryHash)
	_ = binary.Write(&b, binary.BigEndian, int64(len(s.KeyID)))
	b.WriteString(s.KeyID)
	return b.Bytes()
}

// Equal reports whether two seals say the same thing, signature included.
func (s Seal) Equal(o Seal) bool {
	return s.ID == o.ID && s.FirstPosition == o.FirstPosition && s.LastPosition == o.LastPosition &&
		bytes.Equal(s.LastEntryHash, o.LastEntryHash) && s.SealedAt.UnixMicro() == o.SealedAt.UnixMicro() &&
		s.KeyID == o.KeyID && bytes.Equal(s.Signature, o.Signature)
}

// KeyID names a public key: the start of its hash.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// PublicKeyString is how a public key is written down: "ed25519:<base64>".
func PublicKeyString(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey reads the PublicKeyString form.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), "ed25519:")
	if !ok {
		return nil, errors.New(`public key: expected "ed25519:<base64>"`)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("public key: not a valid Ed25519 key")
	}
	return ed25519.PublicKey(b), nil
}

// VerifySeal checks the signature of a seal against a public key.
func VerifySeal(pub ed25519.PublicKey, s Seal) error {
	if s.KeyID != KeyID(pub) {
		return fmt.Errorf("signed with key %s, not %s", s.KeyID, KeyID(pub))
	}
	if !ed25519.Verify(pub, s.message(), s.Signature) {
		return errors.New("signature does not verify")
	}
	return nil
}

// Signer signs seals with a private key that is kept out of the database.
type Signer struct {
	key ed25519.PrivateKey
}

// KeyID names the signing key.
func (s *Signer) KeyID() string { return KeyID(s.Public()) }

// Public is the verification key.
func (s *Signer) Public() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// Sign fills in the key id and the signature of seal.
func (s *Signer) Sign(seal *Seal) {
	seal.KeyID = s.KeyID()
	seal.Signature = ed25519.Sign(s.key, seal.message())
}

// GenerateKeyFile creates a new signing key at path (PKCS #8, PEM, mode 0600),
// refusing to overwrite a file, and returns the public key.
func GenerateKeyFile(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the path is chosen by the operator
	if err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("audit key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}
	return pub, nil
}

// LoadSigner reads a key written by GenerateKeyFile. A key that others can
// read is refused: whoever holds it can forge seals.
func LoadSigner(path string) (*Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("audit key %s: permissions %v let others read it, use 0600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the path is chosen by the operator in the configuration
	if err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("audit key %s: not a PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit key %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("audit key %s: not an Ed25519 key", path)
	}
	return &Signer{key: priv}, nil
}
