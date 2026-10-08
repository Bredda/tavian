// Package openai is the provider adapter for OpenAI-compatible backends
// (vLLM, llama.cpp server, Azure OpenAI v1, …). It forwards a chat completion
// request and relays the response, streaming included, while extracting token
// usage on the way through.
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/bredda/tavian/internal/config"
)

var (
	// ErrInvalidRequest marks a request body the gateway cannot interpret.
	ErrInvalidRequest = errors.New("invalid chat completion request")
	// ErrUpstream marks a failure to obtain a response from the backend.
	ErrUpstream = errors.New("upstream failure")
)

// maxBufferedResponse bounds non-streaming responses held in memory.
const maxBufferedResponse = 32 << 20

// Usage is the token accounting reported by the backend.
type Usage struct {
	Input, Output, Cached, Reasoning int64
	Known                            bool
}

// Result describes what happened during a proxied call.
type Result struct {
	// Started is true once the response status has been written to the client.
	// If an error is returned with Started == false, the caller may still send
	// its own error response.
	Started  bool
	Status   int
	Streamed bool
	Usage    Usage
	TTFB     time.Duration
}

// Client talks to OpenAI-compatible backends through an http.Client, which
// must be the egress-guarded one.
type Client struct {
	http      *http.Client
	userAgent string
}

// New returns a Client.
func New(hc *http.Client, userAgent string) *Client { return &Client{http: hc, userAgent: userAgent} }

// PeekChat extracts the routing-relevant fields of a chat completion request.
func PeekChat(raw []byte) (model string, stream bool, err error) {
	var p struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", false, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	if p.Model == "" {
		return "", false, fmt.Errorf("%w: missing \"model\"", ErrInvalidRequest)
	}
	return p.Model, p.Stream, nil
}

// RewriteChat returns the request to send upstream: the model name is replaced
// and, for streaming requests, usage reporting is forced on so the stream
// carries token counts. Unknown fields are preserved untouched.
func RewriteChat(raw []byte, upstreamModel string) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var stream bool
	if v, ok := m["stream"]; ok {
		if err := json.Unmarshal(v, &stream); err != nil {
			return nil, fmt.Errorf("%w: \"stream\" must be a boolean", ErrInvalidRequest)
		}
	}
	m["model"], _ = json.Marshal(upstreamModel)
	if stream {
		opts := map[string]json.RawMessage{}
		if v, ok := m["stream_options"]; ok {
			_ = json.Unmarshal(v, &opts) // a malformed value is replaced
		}
		opts["include_usage"] = json.RawMessage("true")
		m["stream_options"], _ = json.Marshal(opts)
	}
	return json.Marshal(m)
}

// ChatCompletions sends body to the backend and relays the answer to w.
//
// asModel, when not empty, is the model name the client asked for: Tavian maps
// it to the backend's own name on the way in, so on the way out the "model"
// field of the response (and of every stream chunk) is put back, and the client
// never sees a name it did not use. Error responses are relayed untouched.
//
// Only an explicit set of headers is sent upstream: in particular the client's
// Authorization header (a Tavian key) must never reach a provider.
func (c *Client) ChatCompletions(ctx context.Context, w http.ResponseWriter, b *config.Backend, body []byte, accept, asModel string) (Result, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL.JoinPath("chat/completions").String(), bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if accept == "" {
		accept = "application/json"
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", c.userAgent)
	if b.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+b.Credential)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	defer func() { _ = resp.Body.Close() }()

	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	res := Result{Status: resp.StatusCode, Streamed: mt == "text/event-stream"}

	if !res.Streamed {
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxBufferedResponse+1))
		if err != nil {
			return Result{}, fmt.Errorf("%w: reading response: %w", ErrUpstream, err)
		}
		if len(data) > maxBufferedResponse {
			return Result{}, fmt.Errorf("%w: response exceeds %d bytes", ErrUpstream, maxBufferedResponse)
		}
		if res.Status/100 == 2 {
			res.Usage = parseUsage(data)
			data, _ = rewriteModel(data, asModel)
		}
		copyHeaders(w.Header(), resp.Header)
		w.Header().Del("Content-Length")
		w.WriteHeader(res.Status)
		res.Started = true
		if _, err := w.Write(data); err != nil {
			return res, err
		}
		res.TTFB = time.Since(start)
		return res, nil
	}

	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(res.Status)
	res.Started = true
	rc := http.NewResponseController(w)
	tap := &sseTap{model: asModel}
	buf := make([]byte, 16<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if res.TTFB == 0 {
				res.TTFB = time.Since(start)
			}
			if out := tap.filter(buf[:n]); len(out) > 0 {
				if _, werr := w.Write(out); werr != nil {
					res.Usage = tap.usage
					return res, werr
				}
				_ = rc.Flush() // ErrNotSupported is fine: the bytes still go out
			}
		}
		if rerr == io.EOF {
			if rest := tap.rest(); len(rest) > 0 {
				if _, werr := w.Write(rest); werr != nil {
					res.Usage = tap.usage
					return res, werr
				}
			}
			break
		}
		if rerr != nil {
			res.Usage = tap.usage
			return res, fmt.Errorf("%w: stream interrupted: %w", ErrUpstream, rerr)
		}
	}
	res.Usage = tap.usage
	return res, nil
}

// copyHeaders forwards the few response headers that matter to clients.
func copyHeaders(dst, src http.Header) {
	for _, h := range []string{"Content-Type", "Cache-Control", "Retry-After"} {
		if v := src.Get(h); v != "" {
			dst.Set(h, v)
		}
	}
}

type usageJSON struct {
	PromptTokens        int64 `json:"prompt_tokens"`
	CompletionTokens    int64 `json:"completion_tokens"`
	PromptTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionTokensDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

func (u *usageJSON) toUsage() Usage {
	out := Usage{Input: u.PromptTokens, Output: u.CompletionTokens, Known: true}
	if u.PromptTokensDetails != nil {
		out.Cached = u.PromptTokensDetails.CachedTokens
	}
	if u.CompletionTokensDetails != nil {
		out.Reasoning = u.CompletionTokensDetails.ReasoningTokens
	}
	return out
}

func parseUsage(data []byte) Usage {
	var env struct {
		Usage *usageJSON `json:"usage"`
	}
	if json.Unmarshal(data, &env) != nil || env.Usage == nil {
		return Usage{}
	}
	return env.Usage.toUsage()
}

// rewriteModel sets the "model" field of a JSON object to name and reports
// whether it changed anything. Anything that is not a JSON object with a
// "model" field, or an empty name, is returned as it came.
func rewriteModel(data []byte, name string) ([]byte, bool) {
	if name == "" || !bytes.Contains(data, []byte(`"model"`)) {
		return data, false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil {
		return data, false
	}
	if _, ok := m["model"]; !ok {
		return data, false
	}
	m["model"], _ = json.Marshal(name)
	out, err := json.Marshal(m)
	if err != nil {
		return data, false
	}
	return out, true
}

// sseTap sits between a server-sent-events stream and the client. It forwards
// whole lines, putting the client's model name into each data chunk when model
// is set, and remembers the last usage object it sees.
type sseTap struct {
	model string
	buf   []byte
	usage Usage
}

const maxSSELine = 1 << 20

// filter takes the next bytes of the stream and returns what can be forwarded:
// the complete lines so far. A partial last line is held back until its end
// arrives, or until it is so long that it is passed through unexamined.
func (t *sseTap) filter(p []byte) []byte {
	t.buf = append(t.buf, p...)
	var out []byte
	for {
		i := bytes.IndexByte(t.buf, '\n')
		if i < 0 {
			break
		}
		out = append(out, t.line(t.buf[:i])...)
		out = append(out, '\n')
		t.buf = t.buf[i+1:]
	}
	if len(t.buf) > maxSSELine {
		// A single absurdly long line: stop tracking it.
		out = append(out, t.buf...)
		t.buf = nil
	}
	return out
}

// rest returns the bytes held back at the end of the stream.
func (t *sseTap) rest() []byte {
	r := t.buf
	t.buf = nil
	return r
}

// line handles one line without its newline and returns what to forward.
func (t *sseTap) line(l []byte) []byte {
	body := bytes.TrimSuffix(l, []byte("\r"))
	payload, ok := bytes.CutPrefix(body, []byte("data:"))
	if !ok {
		return l
	}
	payload = bytes.TrimSpace(payload)
	if string(payload) == "[DONE]" {
		return l
	}
	if strings.Contains(string(payload), `"usage"`) {
		if u := parseUsage(payload); u.Known {
			t.usage = u
		}
	}
	rewritten, changed := rewriteModel(payload, t.model)
	if !changed {
		return l
	}
	out := append([]byte("data: "), rewritten...)
	if len(body) != len(l) {
		out = append(out, '\r')
	}
	return out
}
