// Package inspect is the content inspection engine: detectors turn the text of
// a request into findings. Detectors run locally and never call out; the
// interface is serializable so L2 detectors can run in a local sidecar
// (ADR-0012). See docs/SECURITY.md#content-inspection.
//
// Nothing in this package keeps, returns or logs the text it inspects. Findings
// say where something is and carry a keyed fingerprint, never the value.
package inspect

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Statuses of an inspection.
const (
	StatusOK      = "ok"
	StatusSkipped = "skipped" // inspection is disabled
	StatusFailed  = "failed"  // the request must not be served
)

// CodeFailed is the error code when inspection could not complete (detector
// error, timeout, invalid finding). Failing closed is the only behaviour.
const CodeFailed = "inspection_failed"

// maxFindings bounds what one request can produce; a 4 MiB prompt of e-mail
// addresses must not become a 100k-element event.
const maxFindings = 1000

// Config is the `inspection` section of the configuration.
type Config struct {
	// Enabled defaults to true. Turning inspection off is an explicit decision:
	// requests are then served uninspected and the events say "skipped".
	Enabled *bool `yaml:"enabled"`
	// Budget bounds the whole inspection of one request. Exceeding it fails
	// the request (default 50ms).
	Budget time.Duration `yaml:"budget"`
	// FingerprintKeyEnv names the environment variable holding the secret used
	// to fingerprint values (at least 16 bytes). Without it a random key is
	// generated per process: fingerprints then only correlate within one run.
	FingerprintKeyEnv string `yaml:"fingerprint_key_env"`
	// Disable lists built-in detectors to turn off (see Builtins), for example
	// when a detector is too noisy for the data a deployment handles.
	Disable []string `yaml:"disable"`
	// Dictionaries and Patterns are the deployment's own detectors (L1).
	Dictionaries []Dictionary `yaml:"dictionaries"`
	Patterns     []Pattern    `yaml:"patterns"`
}

// ApplyDefaults fills in unset values.
func (c *Config) ApplyDefaults() {
	if c.Budget == 0 {
		c.Budget = 50 * time.Millisecond
	}
}

// DetectorInfo identifies a detector and its behaviour version.
type DetectorInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Result is the outcome of inspecting one request.
type Result struct {
	Status string
	// Reason is the error code when Status is failed.
	Reason    string
	Findings  []Finding
	Truncated bool // more findings existed than maxFindings
	Detectors []DetectorInfo
	Duration  time.Duration
}

// Summary is the part of a Result that goes into the usage event: counts and
// versions, no locations, no fingerprints.
type Summary struct {
	Status     string            `json:"status"`
	Reason     string            `json:"reason,omitempty"`
	Findings   int               `json:"findings"`
	Truncated  bool              `json:"truncated,omitempty"`
	Counts     map[string]int    `json:"counts,omitempty"` // "pii.iban" -> n
	Detectors  map[string]string `json:"detectors,omitempty"`
	DurationUS int64             `json:"duration_us"`
}

// Summary condenses r.
func (r Result) Summary() Summary {
	s := Summary{
		Status: r.Status, Reason: r.Reason, Findings: len(r.Findings), Truncated: r.Truncated,
		DurationUS: r.Duration.Microseconds(),
	}
	for _, f := range r.Findings {
		if s.Counts == nil {
			s.Counts = map[string]int{}
		}
		s.Counts[string(f.Type)+"."+f.Subtype]++
	}
	for _, d := range r.Detectors {
		if s.Detectors == nil {
			s.Detectors = map[string]string{}
		}
		s.Detectors[d.Name] = d.Version
	}
	return s
}

// Error is returned when a request must not be served. Its text names the code
// and the detector at most: it can be logged without leaking content.
type Error struct {
	Code     string
	Detector string
	Err      error // for errors.Is/As and tests; never log its text
}

func (e *Error) Error() string {
	if e.Detector != "" {
		return fmt.Sprintf("inspection refused the request (%s, detector %s)", e.Code, e.Detector)
	}
	return fmt.Sprintf("inspection refused the request (%s)", e.Code)
}

func (e *Error) Unwrap() error { return e.Err }

// CodeOf returns the code of an inspection error, or "" for other errors.
func CodeOf(err error) string {
	var ie *Error
	if errors.As(err, &ie) {
		return ie.Code
	}
	return ""
}

// Engine runs the detectors. It is immutable and safe for concurrent use.
type Engine struct {
	enabled   bool
	budget    time.Duration
	key       []byte
	ephemeral bool
	detectors []Detector
	infos     []DetectorInfo
}

var ephemeralKey = sync.OnceValue(func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("inspect: no randomness available: " + err.Error())
	}
	return k
})

// New builds the engine for cfg with the built-in detectors. getenv resolves
// the fingerprint key.
func New(cfg Config, getenv func(string) string) (*Engine, error) {
	cfg.ApplyDefaults()
	if cfg.Budget < time.Millisecond || cfg.Budget > 10*time.Second {
		return nil, errors.New("budget must be between 1ms and 10s")
	}
	var key []byte
	ephemeral := cfg.FingerprintKeyEnv == ""
	if ephemeral {
		key = ephemeralKey()
	} else {
		key = []byte(getenv(cfg.FingerprintKeyEnv))
		if len(key) < 16 {
			return nil, fmt.Errorf("fingerprint_key_env: environment variable %s is unset or shorter than 16 bytes", cfg.FingerprintKeyEnv)
		}
	}
	dets, err := builtin(cfg)
	if err != nil {
		return nil, err
	}
	e := NewWith(cfg.Budget, key, dets...)
	e.enabled = cfg.Enabled == nil || *cfg.Enabled
	e.ephemeral = ephemeral
	return e, nil
}

// NewWith builds an enabled engine from explicit parts. It is meant for tests
// and for embedding custom detectors.
func NewWith(budget time.Duration, key []byte, dets ...Detector) *Engine {
	e := &Engine{enabled: true, budget: budget, key: key, detectors: dets}
	for _, d := range dets {
		e.infos = append(e.infos, DetectorInfo{Name: d.Name(), Version: d.Version()})
	}
	return e
}

// Enabled says whether requests are inspected.
func (e *Engine) Enabled() bool { return e.enabled }

// EphemeralKey says that fingerprints use a per-process random key.
func (e *Engine) EphemeralKey() bool { return e.ephemeral }

// Detectors lists the detectors in use.
func (e *Engine) Detectors() []DetectorInfo { return append([]DetectorInfo(nil), e.infos...) }

// Health reports the first detector that cannot serve.
func (e *Engine) Health(ctx context.Context) error {
	for _, d := range e.detectors {
		if err := d.Health(ctx); err != nil {
			return fmt.Errorf("detector %s: %w", d.Name(), err)
		}
	}
	return nil
}

// Inspect looks for sensitive content in req. A non-nil error (an *Error) means
// the request must be refused; the Result is still filled for the record.
func (e *Engine) Inspect(ctx context.Context, req Request) (Result, error) {
	if !e.enabled {
		return Result{Status: StatusSkipped}, nil
	}
	start := time.Now()
	res := Result{Status: StatusOK, Detectors: e.infos}
	fail := func(code, detector string, cause error) (Result, error) {
		res.Status, res.Reason, res.Duration = StatusFailed, code, time.Since(start)
		return res, &Error{Code: code, Detector: detector, Err: cause}
	}

	if len(req.Gaps) > 0 {
		return fail(req.Gaps[0].Kind, "", errors.New(req.Gaps[0].Kind))
	}

	ctx, cancel := context.WithTimeout(ctx, e.budget)
	defer cancel()
	type outcome struct {
		findings  []Finding
		truncated bool
		detector  string
		err       error
	}
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			if recover() != nil {
				o.err = errors.New("panic")
			}
			done <- o
		}()
		o.findings, o.truncated, o.detector, o.err = e.run(ctx, req)
	}()

	select {
	case o := <-done:
		if o.err != nil {
			return fail(CodeFailed, o.detector, o.err)
		}
		res.Findings, res.Truncated, res.Duration = o.findings, o.truncated, time.Since(start)
		return res, nil
	case <-ctx.Done():
		// The goroutine finishes on its own: regular expressions run in time
		// linear in the input, and the in-flight cap bounds how many exist.
		return fail(CodeFailed, "", ctx.Err())
	}
}

func (e *Engine) run(ctx context.Context, req Request) (out []Finding, truncated bool, detector string, err error) {
	segs := make([]Segment, len(req.Segments))
	for i, s := range req.Segments {
		s.Text = normalize(s.Text)
		segs[i] = s
	}
	nreq := Request{Segments: segs}

	for _, d := range e.detectors {
		if err := ctx.Err(); err != nil {
			return nil, false, d.Name(), err
		}
		fs, err := call(ctx, d, nreq)
		if err != nil {
			return nil, false, d.Name(), err
		}
		for _, f := range fs {
			l := f.Location
			if l.Segment < 0 || l.Segment >= len(segs) || l.Start < 0 || l.End <= l.Start || l.End > len(segs[l.Segment].Text) {
				return nil, false, d.Name(), errors.New("finding outside the inspected text")
			}
			seg := segs[l.Segment]
			value := f.Canonical
			if value == "" {
				value = seg.Text[l.Start:l.End]
			}
			f.Fingerprint = e.fingerprint(f.Subtype, value)
			f.Canonical = ""
			f.Detector = d.Name()
			f.Location.MessageIndex, f.Location.Field, f.Location.Part = seg.MessageIndex, seg.Field, seg.Part
			out = append(out, f)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Location, out[j].Location
		if a.Segment != b.Segment {
			return a.Segment < b.Segment
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		return a.End < b.End
	})
	if len(out) > maxFindings {
		out, truncated = out[:maxFindings], true
	}
	return out, truncated, "", nil
}

// call runs one detector; a panic is an error, not a crash.
func call(ctx context.Context, d Detector, req Request) (fs []Finding, err error) {
	defer func() {
		if recover() != nil {
			fs, err = nil, errors.New("panic")
		}
	}()
	return d.Inspect(ctx, req)
}

// fingerprint is HMAC-SHA256(key, subtype NUL value), truncated to 128 bits.
func (e *Engine) fingerprint(subtype, value string) string {
	m := hmac.New(sha256.New, e.key)
	m.Write([]byte(subtype))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil)[:16])
}
