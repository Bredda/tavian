package mockllm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func post(t *testing.T, body string) *http.Response {
	t.Helper()
	srv := httptest.NewServer(Handler())
	t.Cleanup(srv.Close)
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

const weather = `"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}]`

func TestToolCallNonStreaming(t *testing.T) {
	resp := post(t, `{"model":"m","messages":[{"role":"user","content":"Paris?"}],`+weather+`}`)
	var out struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   *string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct{ Name, Arguments string }
				} `json:"tool_calls"`
			}
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	c := out.Choices[0]
	if c.FinishReason != "tool_calls" || c.Message.Content != nil || len(c.Message.ToolCalls) != 1 {
		t.Fatalf("choice = %+v", c)
	}
	call := c.Message.ToolCalls[0]
	if call.Function.Name != "get_weather" || call.Function.Arguments != `{"echo":"Paris?"}` {
		t.Errorf("call = %+v", call)
	}
}

func TestToolResultGetsATextReply(t *testing.T) {
	resp := post(t, `{"model":"m","messages":[{"role":"user","content":"Paris?"},
		{"role":"assistant","content":null,"tool_calls":[{"id":"call_mock","type":"function","function":{"name":"get_weather","arguments":"{}"}}]},
		{"role":"tool","tool_call_id":"call_mock","content":"sunny"}],`+weather+`}`)
	var out struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct{ Content string }
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if c := out.Choices[0]; c.FinishReason != "stop" || !strings.Contains(c.Message.Content, "sunny") {
		t.Errorf("choice = %+v", c)
	}
}

func TestToolCallStreamingSplitsArguments(t *testing.T) {
	resp := post(t, `{"model":"m","stream":true,"messages":[{"role":"user","content":"Paris?"}],`+weather+`}`)
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var args strings.Builder
	var name, finish string
	for _, line := range strings.Split(string(raw), "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var ch struct {
			Choices []struct {
				FinishReason *string `json:"finish_reason"`
				Delta        struct {
					ToolCalls []struct {
						Function struct{ Name, Arguments string }
					} `json:"tool_calls"`
				}
			}
		}
		if err := json.Unmarshal([]byte(data), &ch); err != nil {
			t.Fatal(err)
		}
		for _, c := range ch.Choices {
			for _, tc := range c.Delta.ToolCalls {
				name += tc.Function.Name
				args.WriteString(tc.Function.Arguments)
			}
			if c.FinishReason != nil {
				finish = *c.FinishReason
			}
		}
	}
	if name != "get_weather" || args.String() != `{"echo":"Paris?"}` || finish != "tool_calls" {
		t.Errorf("name=%q args=%q finish=%q", name, args.String(), finish)
	}
}

func TestFingerprintListsForwardedFields(t *testing.T) {
	resp := post(t, `{"model":"m","messages":[],"temperature":0.2,"vendor_extension":{"a":1}}`)
	var out struct {
		SystemFingerprint string `json:"system_fingerprint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.SystemFingerprint != "mock keys=messages,model,temperature,vendor_extension" {
		t.Errorf("fingerprint = %q", out.SystemFingerprint)
	}
}
