package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	genesisDomain = "tavian-audit-genesis-v1"
	entryDomain   = "tavian-audit-entry-v1\x00"
)

// Genesis is the hash the first entry of a chain links to.
func Genesis() []byte {
	h := sha256.Sum256([]byte(genesisDomain))
	return h[:]
}

// Canonical re-encodes a JSON document deterministically: object keys sorted,
// no insignificant whitespace, numbers exactly as written. The same document
// always gives the same bytes, whatever the order of keys it came in.
//
// What is hashed is the payload as the database holds it (jsonb does not keep
// the bytes that were inserted), so the hash is of what an auditor can read.
func Canonical(doc []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonical json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("canonical json: data after the document")
	}
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(map[bool]string{true: "true", false: "false"}[t])
	case json.Number:
		b.WriteString(t.String())
	case string:
		return writeString(b, t)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := writeCanonical(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unexpected %T", v)
	}
	return nil
}

func writeString(b *bytes.Buffer, s string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	b.WriteString(strings.TrimSuffix(buf.String(), "\n"))
	return nil
}

// ContentHash is the hash of a record: SHA-256 of its canonical form.
func ContentHash(payload []byte) ([]byte, error) {
	c, err := Canonical(payload)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(c)
	return h[:], nil
}

// EntryHash links an entry to the one before it. Every field is fixed-width or
// length-prefixed, so two different entries cannot give the same bytes.
func EntryHash(position int64, prev []byte, eventID string, occurred time.Time, content []byte) []byte {
	var b bytes.Buffer
	b.WriteString(entryDomain)
	_ = binary.Write(&b, binary.BigEndian, position)
	b.Write(prev)
	_ = binary.Write(&b, binary.BigEndian, int64(len(eventID)))
	b.WriteString(eventID)
	// PostgreSQL keeps microseconds
	_ = binary.Write(&b, binary.BigEndian, occurred.UnixMicro())
	b.Write(content)
	h := sha256.Sum256(b.Bytes())
	return h[:]
}
