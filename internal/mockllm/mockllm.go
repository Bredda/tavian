// Package mockllm is a tiny OpenAI-compatible server used by tests and by the
// demo compose stack, so Tavian can be exercised without a GPU or a network.
package mockllm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Handler serves GET /v1/models and POST /v1/chat/completions.
//
// Requesting the model "mock-fail" yields an HTTP 500, which is handy to test
// error paths.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"object": "list",
			"data":   []map[string]any{{"id": "mock", "object": "model", "owned_by": "mockllm"}},
		})
	})
	mux.HandleFunc("POST /v1/chat/completions", chat)
	return mux
}

type chatRequest struct {
	Model         string `json:"model"`
	Stream        bool   `json:"stream"`
	StreamOptions *struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
}

func chat(w http.ResponseWriter, r *http.Request) {
	var req chatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid JSON: "+err.Error()))
		return
	}
	if req.Model == "mock-fail" {
		writeJSON(w, http.StatusInternalServerError, errBody("mock failure"))
		return
	}

	prompt := ""
	promptWords := 0
	for _, m := range req.Messages {
		text := contentText(m.Content)
		promptWords += len(strings.Fields(text))
		if m.Role == "user" {
			prompt = text
		}
	}
	if len(prompt) > 200 {
		prompt = prompt[:200]
	}
	reply := "mock reply to: " + prompt
	words := strings.Fields(reply)
	usage := map[string]any{
		"prompt_tokens":     promptWords,
		"completion_tokens": len(words),
		"total_tokens":      promptWords + len(words),
	}
	created := time.Now().Unix()

	if !req.Stream {
		writeJSON(w, http.StatusOK, map[string]any{
			"id": "chatcmpl-mock", "object": "chat.completion", "created": created, "model": req.Model,
			"choices": []map[string]any{{
				"index": 0, "finish_reason": "stop",
				"message": map[string]any{"role": "assistant", "content": reply},
			}},
			"usage": usage,
		})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	rc := http.NewResponseController(w)
	send := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "data: %s\n\n", b)
		_ = rc.Flush()
	}
	chunk := func(delta map[string]any, finish any) map[string]any {
		return map[string]any{
			"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": created, "model": req.Model,
			"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": finish}},
		}
	}
	send(chunk(map[string]any{"role": "assistant"}, nil))
	for i, word := range words {
		if i < len(words)-1 {
			word += " "
		}
		send(chunk(map[string]any{"content": word}, nil))
	}
	send(chunk(map[string]any{}, "stop"))
	if req.StreamOptions != nil && req.StreamOptions.IncludeUsage {
		send(map[string]any{
			"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": created, "model": req.Model,
			"choices": []any{}, "usage": usage,
		})
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	_ = rc.Flush()
}

// contentText returns the text of a message content, which is either a string
// or an array of typed parts.
func contentText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(p.Text)
			b.WriteByte(' ')
		}
		return strings.TrimSpace(b.String())
	}
	return ""
}

func errBody(msg string) map[string]any {
	return map[string]any{"error": map[string]any{"message": msg, "type": "mock_error"}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
