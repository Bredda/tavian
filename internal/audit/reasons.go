package audit

import "net/http"

// Reason is a stable, documented explanation of why the gateway answered a
// request the way it did. Code is what decision records carry and what audit
// queries filter on; Client is the OpenAI-compatible error code SDKs already
// receive, which never changes with it.
type Reason struct {
	Code   string
	Client string
	Status int
	Type   string // OpenAI error type
}

const (
	typeInvalid = "invalid_request_error"
	typeServer  = "server_error"
)

// The catalogue. Add reasons here only: server code refers to these values and
// a test checks that codes are unique and well formed.
var (
	Served = Reason{Code: "SERVED"} // not an error: the request was answered

	InvalidRequest         = Reason{"INVALID_REQUEST", "invalid_request", http.StatusBadRequest, typeInvalid}
	RequestTooLarge        = Reason{"REQUEST_TOO_LARGE", "request_too_large", http.StatusRequestEntityTooLarge, typeInvalid}
	ModelNotAllowed        = Reason{"MODEL_NOT_ALLOWED", "model_not_allowed", http.StatusForbidden, typeInvalid}
	ClearanceExceeded      = Reason{"CLEARANCE_EXCEEDED", "classification_exceeds_clearance", http.StatusForbidden, typeInvalid}
	ModelNotFound          = Reason{"MODEL_NOT_FOUND", "model_not_found", http.StatusNotFound, typeInvalid}
	MultimodalNotInspected = Reason{"MULTIMODAL_NOT_INSPECTABLE", "multimodal_not_inspectable", http.StatusBadRequest, typeInvalid}
	RequestTooComplex      = Reason{"REQUEST_TOO_COMPLEX", "request_too_complex", http.StatusBadRequest, typeInvalid}
	InspectionFailed       = Reason{"INSPECTION_FAILED", "inspection_failed", http.StatusServiceUnavailable, typeServer}
	UpstreamUnavailable    = Reason{"UPSTREAM_UNAVAILABLE", "upstream_unavailable", http.StatusBadGateway, typeServer}

	// Outcomes after the request was accepted: the status is whatever the
	// backend or the connection produced, so there is no client error code.
	UpstreamError      = Reason{Code: "UPSTREAM_ERROR"}      // the backend answered with an error status, relayed as is
	StreamInterrupted  = Reason{Code: "STREAM_INTERRUPTED"}  // the backend failed after the response had started
	ClientDisconnected = Reason{Code: "CLIENT_DISCONNECTED"} // the caller went away before the end
)

// All lists the catalogue, for documentation and tests.
func All() []Reason {
	return []Reason{
		Served, InvalidRequest, RequestTooLarge, ModelNotAllowed, ClearanceExceeded, ModelNotFound, MultimodalNotInspected,
		RequestTooComplex, InspectionFailed, UpstreamUnavailable, UpstreamError, StreamInterrupted, ClientDisconnected,
	}
}

// FromInspection maps the code of an inspection error to its reason.
func FromInspection(code string) Reason {
	switch code {
	case MultimodalNotInspected.Client:
		return MultimodalNotInspected
	case RequestTooComplex.Client:
		return RequestTooComplex
	}
	return InspectionFailed
}
