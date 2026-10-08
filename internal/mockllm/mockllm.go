// Package mockllm is a tiny OpenAI-compatible server used by tests and by the
// demo compose stack, so Tavian can be exercised without a GPU or a network.
package mockllm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Handler serves GET /v1/models and POST /v1/chat/completions.
//
// Requesting the model "mock-fail" yields an HTTP 500, which is handy to test
// error paths. When a request carries tools the mock answers with a tool call
// (arguments {"echo": "<last user message>"}) unless the conversation already
// ends with a tool result. Responses expose the top-level request fields in
// system_fingerprint so tests can check what a gateway forwarded.
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
	Tools []struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	} `json:"tools"`
	ToolChoice json.RawMessage `json:"tool_choice"`
	Messages   []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
}

func chat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("could not read body"))
		return
	}
	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid JSON: "+err.Error()))
		return
	}
	if req.Model == "mock-fail" {
		writeJSON(w, http.StatusInternalServerError, errBody("mock failure"))
		return
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(body, &fields)
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fingerprint := "mock keys=" + strings.Join(keys, ",")

	prompt, lastRole, promptWords := "", "", 0
	for _, m := range req.Messages {
		text := contentText(m.Content)
		promptWords += len(strings.Fields(text))
		lastRole = m.Role
		if m.Role == "user" || m.Role == "tool" {
			prompt = text
		}
	}
	if len(prompt) > 200 {
		prompt = prompt[:200]
	}

	var (
		reply    string
		toolName string
		toolArgs string
		finish   = "stop"
	)
	if len(req.Tools) > 0 && lastRole != "tool" && string(req.ToolChoice) != `"none"` {
		toolName = req.Tools[0].Function.Name
		args, _ := json.Marshal(map[string]string{"echo": prompt})
		toolArgs = string(args)
		finish = "tool_calls"
	} else if lastRole == "tool" {
		reply = "mock reply to tool result: " + prompt
	} else {
		reply = "mock reply to: " + prompt
	}
	words := strings.Fields(reply)
	completion := len(words)
	if toolName != "" {
		completion = 5
	}
	usage := map[string]any{
		"prompt_tokens":     promptWords,
		"completion_tokens": completion,
		"total_tokens":      promptWords + completion,
	}
	created := time.Now().Unix()
	envelope := func(object string) map[string]any {
		return map[string]any{
			"id": "chatcmpl-mock", "object": object, "created": created, "model": req.Model,
			"system_fingerprint": fingerprint,
			// Not part of the OpenAI schema: lets tests see which model name
			// the backend was actually asked for.
			"x_mock_received_model": req.Model,
		}
	}

	if !req.Stream {
		msg := map[string]any{"role": "assistant", "content": reply}
		if toolName != "" {
			msg["content"] = nil
			msg["tool_calls"] = []map[string]any{{
				"id": "call_mock", "type": "function",
				"function": map[string]any{"name": toolName, "arguments": toolArgs},
			}}
		}
		resp := envelope("chat.completion")
		resp["choices"] = []map[string]any{{"index": 0, "finish_reason": finish, "message": msg}}
		resp["usage"] = usage
		writeJSON(w, http.StatusOK, resp)
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
		c := envelope("chat.completion.chunk")
		c["choices"] = []map[string]any{{"index": 0, "delta": delta, "finish_reason": finish}}
		return c
	}
	if toolName != "" {
		// Like OpenAI: the call's id and name first, then the arguments in pieces.
		send(chunk(map[string]any{"role": "assistant", "content": nil, "tool_calls": []map[string]any{{
			"index": 0, "id": "call_mock", "type": "function",
			"function": map[string]any{"name": toolName, "arguments": ""},
		}}}, nil))
		cut := len(toolArgs) / 2
		for _, piece := range []string{toolArgs[:cut], toolArgs[cut:]} {
			send(chunk(map[string]any{"tool_calls": []map[string]any{{
				"index": 0, "function": map[string]any{"arguments": piece},
			}}}, nil))
		}
	} else {
		send(chunk(map[string]any{"role": "assistant", "content": ""}, nil))
		for i, word := range words {
			if i < len(words)-1 {
				word += " "
			}
			send(chunk(map[string]any{"content": word}, nil))
		}
	}
	send(chunk(map[string]any{}, finish))
	if req.StreamOptions != nil && req.StreamOptions.IncludeUsage {
		u := envelope("chat.completion.chunk")
		u["choices"] = []any{}
		u["usage"] = usage
		send(u)
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
