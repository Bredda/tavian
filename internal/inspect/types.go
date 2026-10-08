package inspect

import "context"

// Type is the family of a finding.
type Type string

const (
	TypePII    Type = "pii"
	TypeSecret Type = "secret"
	TypeCustom Type = "custom"
)

// Severity ranks how bad it is to let a finding leave the organization.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Field names where a segment of text was found. The vocabulary is fixed so
// that locations never carry names chosen by the caller.
const (
	FieldContent      = "content"
	FieldName         = "name"
	FieldRefusal      = "refusal"
	FieldToolCalls    = "tool_calls"
	FieldFunctionCall = "function_call"
	FieldPrediction   = "prediction"
	FieldTools        = "tools"
	FieldMetadata     = "metadata"
	FieldOther        = "other"
)

// Segment is one string of the request, as the caller sent it.
type Segment struct {
	// MessageIndex is the position in "messages", or -1 outside of them.
	MessageIndex int `json:"message_index"`
	// Field is one of the Field* names.
	Field string `json:"field"`
	// Part is the index inside a content array or the tool calls, -1 if none.
	Part int    `json:"part"`
	Text string `json:"text"`
}

// Gap kinds: reasons why a request cannot be inspected completely. The kind is
// also the stable error code returned to the client.
const (
	GapMultimodal = "multimodal_not_inspectable"
	GapTooComplex = "request_too_complex"
)

// Gap says that part of a request could not be turned into text.
type Gap struct {
	Kind         string `json:"kind"`
	MessageIndex int    `json:"message_index"`
	Part         int    `json:"part"`
}

// Request is what detectors look at. It is serializable on purpose: a detector
// may live in another process (ADR-0012).
type Request struct {
	Segments []Segment `json:"segments"`
	// Gaps are handled by the engine before any detector runs.
	Gaps []Gap `json:"gaps,omitempty"`
}

// Location says where a finding is. Detectors fill Segment, Start and End (byte
// offsets in the normalized text of that segment); the engine fills the rest.
type Location struct {
	Segment      int    `json:"segment"`
	MessageIndex int    `json:"message_index"`
	Field        string `json:"field"`
	Part         int    `json:"part"`
	Start        int    `json:"start"`
	End          int    `json:"end"`
}

// Finding is something a detector recognised. It never holds the matched text:
// only where it is and a keyed fingerprint of it.
type Finding struct {
	Detector   string   `json:"detector"`
	Type       Type     `json:"type"`
	Subtype    string   `json:"subtype"`
	Severity   Severity `json:"severity"`
	Confidence float64  `json:"confidence"`
	Location   Location `json:"location"`
	// Fingerprint is a keyed hash of the value, for correlation without
	// recovery. The engine computes it.
	Fingerprint string `json:"fingerprint"`

	// Canonical is the value in a normal form (an IBAN without spaces), set by
	// in-process detectors so equal values get equal fingerprints. It is never
	// serialized and the engine clears it once the fingerprint is computed.
	// Without it the fingerprint is taken from the matched text.
	Canonical string `json:"-"`
}

// Detector finds sensitive content. Implementations must not retain req, must
// honour ctx, and must never put matched text into a returned error.
type Detector interface {
	// Name identifies the detector in findings ("pii.email").
	Name() string
	// Version changes whenever the detector's behaviour does.
	Version() string
	// Inspect returns findings with Location.{Segment,Start,End} set.
	Inspect(ctx context.Context, req Request) ([]Finding, error)
	// Health reports whether the detector can serve (always true in-process).
	Health(ctx context.Context) error
}
