package openai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bredda/tavian/internal/inspect"
)

// Bounds on what ExtractChat accepts as inspectable. An honest chat request has
// a few hundred strings; past these limits the request is declared
// not inspectable instead of being inspected partially.
const (
	maxSegments = 20000
	maxDepth    = 64
)

// mediaKeys are content-part keys that carry something other than text.
var mediaKeys = map[string]bool{
	"image_url": true, "input_audio": true, "file": true, "audio": true, "video_url": true,
	"audio_url": true, "image": true, "video": true, "input_image": true, "input_file": true,
}

// fieldNames maps the keys we name in locations; everything else is "other", so
// a location never carries a name chosen by the caller.
var fieldNames = map[string]string{
	"content": inspect.FieldContent, "name": inspect.FieldName, "refusal": inspect.FieldRefusal,
	"tool_calls": inspect.FieldToolCalls, "function_call": inspect.FieldFunctionCall,
	"prediction": inspect.FieldPrediction, "tools": inspect.FieldTools, "metadata": inspect.FieldMetadata,
}

type frame struct {
	obj       bool
	key       string // lower-cased key whose value is being read (objects)
	expectKey bool
	idx       int // index of the element being read (arrays)
}

// ExtractChat turns a chat completion request into the text to inspect.
//
// Every string value anywhere in the body is inspected, not only the fields the
// API documents: backends such as vLLM accept extra parameters (documents,
// chat_template_kwargs, ...) and anything the gateway forwards is content that
// leaves it. Object keys are not inspected. Content parts that are not text
// (images, audio, files, anything unknown) are reported as gaps.
//
// The body is walked token by token, so duplicate keys are all seen, whichever
// one a backend would keep.
func ExtractChat(raw []byte) (inspect.Request, error) {
	req, _, err := scanChat(raw)
	return req, err
}

// span is where the literal of one string value sits in the request body.
type span struct{ start, end int }

// scanChat is ExtractChat that also returns, for each segment, where its string
// literal is in raw, so that RedactChat can replace exactly those bytes.
func scanChat(raw []byte) (inspect.Request, []span, error) {
	var req inspect.Request
	var spans []span
	dec := json.NewDecoder(bytes.NewReader(raw))
	var st []frame
	prev := 0 // offset after the previous token

	gap := func(kind string, msg, part int) {
		for _, g := range req.Gaps {
			if g.Kind == kind {
				return
			}
		}
		req.Gaps = append(req.Gaps, inspect.Gap{Kind: kind, MessageIndex: msg, Part: part})
	}
	done := func() { // a value has been read
		if len(st) == 0 {
			return
		}
		if top := &st[len(st)-1]; top.obj {
			top.expectKey = true
		} else {
			top.idx++
		}
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if len(st) != 0 {
				return inspect.Request{}, nil, fmt.Errorf("%w: unexpected end of JSON input", ErrInvalidRequest)
			}
			return req, spans, nil
		}
		if err != nil {
			return inspect.Request{}, nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		tokStart, tokEnd := prev, int(dec.InputOffset())
		prev = tokEnd
		switch t := tok.(type) {
		case json.Delim:
			if t == '{' || t == '[' {
				if len(st) >= maxDepth {
					gap(inspect.GapTooComplex, -1, -1)
					return req, spans, nil
				}
				if t == '{' && isContentValue(st) {
					msg, part := position(st)
					gap(inspect.GapMultimodal, msg, part)
				}
				st = append(st, frame{obj: t == '{', expectKey: t == '{'})
				continue
			}
			st = st[:len(st)-1]
			done()
		case string:
			if len(st) == 0 {
				continue
			}
			top := &st[len(st)-1]
			if top.obj && top.expectKey {
				top.key, top.expectKey = strings.ToLower(t), false
				if mediaKeys[top.key] && isContentPart(st) {
					msg, part := position(st)
					gap(inspect.GapMultimodal, msg, part)
				}
				continue
			}
			if top.obj && top.key == "type" && isContentPart(st) && t != "text" && t != "refusal" {
				msg, part := position(st)
				gap(inspect.GapMultimodal, msg, part)
			}
			if t != "" {
				if len(req.Segments) >= maxSegments {
					gap(inspect.GapTooComplex, -1, -1)
					return req, spans, nil
				}
				msg, part := position(st)
				req.Segments = append(req.Segments, inspect.Segment{
					MessageIndex: msg, Field: field(st), Part: part, Text: t,
				})
				// Between tokens there is only whitespace, ',' and ':', so the
				// literal starts at the first quote after the previous token.
				open := bytes.IndexByte(raw[tokStart:tokEnd], '"')
				spans = append(spans, span{start: tokStart + open, end: tokEnd})
			}
			done()
		default: // number, boolean, null
			done()
		}
	}
}

// isMessage reports whether st ends inside messages[i] (an object).
func isMessage(st []frame) bool {
	return len(st) >= 3 && st[0].key == "messages" && !st[1].obj && st[2].obj
}

// isContentValue reports whether a value about to be opened is the content of a
// message or of a prediction.
func isContentValue(st []frame) bool {
	if len(st) == 3 && isMessage(st) {
		return st[2].key == "content"
	}
	return len(st) == 2 && st[0].key == "prediction" && st[1].obj && st[1].key == "content"
}

// isContentPart reports whether the innermost object of st is one element of a
// content array (of a message, or of a prediction).
func isContentPart(st []frame) bool {
	n := len(st)
	if n == 5 && isMessage(st) {
		return st[2].key == "content" && !st[3].obj && st[4].obj
	}
	return n == 4 && st[0].key == "prediction" && st[1].obj && st[1].key == "content" && !st[2].obj && st[3].obj
}

// position returns the message index (-1 outside messages) and the index of the
// first array element on the way down (-1 if none).
func position(st []frame) (msg, part int) {
	msg, part = -1, -1
	from := 1
	if isMessage(st) {
		msg, from = st[1].idx, 3
	} else if len(st) >= 2 && st[0].key == "messages" && !st[1].obj {
		msg = st[1].idx
	}
	for i := from; i < len(st); i++ {
		if !st[i].obj {
			part = st[i].idx
			break
		}
	}
	return msg, part
}

// field names where in the request the string at the top of st sits.
func field(st []frame) string {
	key := st[0].key
	if isMessage(st) {
		key = st[2].key
	}
	if name, ok := fieldNames[key]; ok {
		return name
	}
	return inspect.FieldOther
}

// RedactChat returns raw with the string values at the given segment indexes
// (as numbered by ExtractChat) replaced by the given texts. Everything else,
// key order, numbers, whitespace, is kept byte for byte.
func RedactChat(raw []byte, replacements map[int]string) ([]byte, error) {
	req, spans, err := scanChat(raw)
	if err != nil {
		return nil, err
	}
	if len(req.Gaps) > 0 {
		return nil, fmt.Errorf("%w: the request has parts that cannot be rewritten", ErrInvalidRequest)
	}
	idx := make([]int, 0, len(replacements))
	for i := range replacements {
		if i < 0 || i >= len(spans) {
			return nil, fmt.Errorf("redaction targets segment %d of %d", i, len(spans))
		}
		idx = append(idx, i)
	}
	sort.Ints(idx)
	var out bytes.Buffer
	out.Grow(len(raw))
	at := 0
	for _, i := range idx {
		out.Write(raw[at:spans[i].start])
		var lit bytes.Buffer
		enc := json.NewEncoder(&lit)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(replacements[i]); err != nil {
			return nil, err
		}
		out.Write(bytes.TrimRight(lit.Bytes(), "\n"))
		at = spans[i].end
	}
	out.Write(raw[at:])
	return out.Bytes(), nil
}
