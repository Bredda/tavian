package openai

import (
	"errors"
	"strings"
	"testing"

	"github.com/bredda/tavian/internal/inspect"
)

type seg struct {
	msg   int
	field string
	part  int
	text  string
}

func segs(r inspect.Request) []seg {
	var out []seg
	for _, s := range r.Segments {
		out = append(out, seg{s.MessageIndex, s.Field, s.Part, s.Text})
	}
	return out
}

func TestExtractChatText(t *testing.T) {
	req, err := ExtractChat([]byte(`{
	  "model": "m",
	  "messages": [
	    {"role": "system", "content": "be brief"},
	    {"role": "user", "name": "alice", "content": [{"type": "text", "text": "first"}, {"type": "text", "text": "second"}]},
	    {"role": "assistant", "content": null, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{\"iban\":\"x\"}"}}]},
	    {"role": "tool", "content": "tool says"}
	  ],
	  "prediction": {"type": "content", "content": "predicted"},
	  "metadata": {"k": "meta"},
	  "extra_vllm_param": {"documents": ["doc one"]},
	  "stop": ["END"],
	  "n": 1
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Gaps) != 0 {
		t.Fatalf("gaps = %+v", req.Gaps)
	}
	want := []seg{
		{-1, "other", -1, "m"},
		{0, "other", -1, "system"},
		{0, "content", -1, "be brief"},
		{1, "other", -1, "user"},
		{1, "name", -1, "alice"},
		{1, "content", 0, "text"},
		{1, "content", 0, "first"},
		{1, "content", 1, "text"},
		{1, "content", 1, "second"},
		{2, "other", -1, "assistant"},
		{2, "tool_calls", 0, "c1"},
		{2, "tool_calls", 0, "function"},
		{2, "tool_calls", 0, "f"},
		{2, "tool_calls", 0, `{"iban":"x"}`},
		{3, "other", -1, "tool"},
		{3, "content", -1, "tool says"},
		{-1, "prediction", -1, "content"},
		{-1, "prediction", -1, "predicted"},
		{-1, "metadata", -1, "meta"},
		{-1, "other", 0, "doc one"},
		{-1, "other", 0, "END"},
	}
	got := segs(req)
	if len(got) != len(want) {
		t.Fatalf("segments:\n got %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("segment %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestExtractChatLocationsNeverCarryCallerNames(t *testing.T) {
	req, err := ExtractChat([]byte(`{"model":"m","messages":[{"role":"user","content":"x","my-secret-key-name":"v"}],"my-top-level-name":"w"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range req.Segments {
		if strings.Contains(s.Field, "my-") {
			t.Errorf("field %q carries a caller-chosen name", s.Field)
		}
	}
}

func TestExtractChatGaps(t *testing.T) {
	for name, body := range map[string]string{
		"image part":     `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]}`,
		"audio part":     `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`,
		"file part":      `{"messages":[{"role":"user","content":[{"type":"file","file":{"file_id":"f"}}]}]}`,
		"unknown type":   `{"messages":[{"role":"user","content":[{"type":"hologram","x":1}]}]}`,
		"typeless media": `{"messages":[{"role":"user","content":[{"image_url":{"url":"http://x"}}]}]}`,
		"upper-case key": `{"MESSAGES":[{"role":"user","CONTENT":[{"TYPE":"image_url"}]}]}`,
		"object content": `{"messages":[{"role":"user","content":{"type":"image_url"}}]}`,
		"prediction":     `{"messages":[],"prediction":{"type":"content","content":[{"type":"image_url"}]}}`,
		"duplicate keys": `{"messages":[{"role":"user","content":[{"type":"image_url"}],"content":"plain"}]}`,
	} {
		req, err := ExtractChat([]byte(body))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(req.Gaps) != 1 || req.Gaps[0].Kind != inspect.GapMultimodal {
			t.Errorf("%s: gaps = %+v", name, req.Gaps)
		}
	}
	req, _ := ExtractChat([]byte(`{"messages":[{"role":"user","content":"ok"},{"role":"user","content":[{"type":"image_url"}]}]}`))
	if len(req.Gaps) != 1 || req.Gaps[0].MessageIndex != 1 || req.Gaps[0].Part != 0 {
		t.Errorf("gap location = %+v", req.Gaps)
	}
	for name, body := range map[string]string{
		"refusal part": `{"messages":[{"role":"assistant","content":[{"type":"refusal","refusal":"no"}]}]}`,
		"plain":        `{"messages":[{"role":"user","content":"fine"}],"file":"not a part, just a key"}`,
	} {
		if req, err := ExtractChat([]byte(body)); err != nil || len(req.Gaps) != 0 {
			t.Errorf("%s: err = %v gaps = %+v", name, err, req.Gaps)
		}
	}
}

func TestExtractChatLimits(t *testing.T) {
	deep := strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1)
	if req, err := ExtractChat([]byte(`{"x":` + deep + `}`)); err != nil || len(req.Gaps) != 1 || req.Gaps[0].Kind != inspect.GapTooComplex {
		t.Errorf("deep nesting: err = %v gaps = %+v", err, req.Gaps)
	}
	many := `{"stop":[` + strings.Repeat(`"abc",`, maxSegments) + `"abc"]}`
	if req, err := ExtractChat([]byte(many)); err != nil || len(req.Gaps) != 1 || req.Gaps[0].Kind != inspect.GapTooComplex || len(req.Segments) > maxSegments {
		t.Errorf("many strings: err = %v gaps = %+v segments = %d", err, req.Gaps, len(req.Segments))
	}
}

func TestExtractChatDecodesEscapes(t *testing.T) {
	req, err := ExtractChat([]byte(`{"messages":[{"role":"user","content":"FR76 1234 😀"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Segments[1].Text; got != "FR76 1234 😀" {
		t.Errorf("text = %q: escapes must be decoded before detectors see the text", got)
	}
}

func TestExtractChatMalformed(t *testing.T) {
	for _, bad := range []string{`{"messages":[`, `{"a":}`, `not json`, `{"a":"\x"}`} {
		if _, err := ExtractChat([]byte(bad)); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%q: err = %v, want ErrInvalidRequest", bad, err)
		}
	}
}

func FuzzExtractChat(f *testing.F) {
	for _, s := range []string{
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
		`{"messages":[{"content":[{"type":"text","text":"a"},{"type":"image_url"}]}]}`,
		`{"prediction":{"content":[{}]},"a":[[[["x"]]]]}`,
		`[]`, `"x"`, `{"messages":{}}`, `{"messages":["s",null,1,[]]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := ExtractChat(body)
		if err != nil {
			return // malformed input is an error, never a panic
		}
		if len(req.Segments) > maxSegments {
			t.Fatalf("%d segments", len(req.Segments))
		}
		for _, s := range req.Segments {
			if s.Text == "" || s.MessageIndex < -1 || s.Part < -1 || fieldNames[s.Field] == "" && s.Field != inspect.FieldOther {
				t.Fatalf("bad segment %+v", s)
			}
		}
	})
}
