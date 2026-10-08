# SDK conformance suite

Tavian's promise is "point the OpenAI SDK at it and nothing else changes".
This suite checks it with the **official OpenAI Python and Node SDKs**, against
a real gateway (built from the working tree) in front of the mock backend.

```bash
make conformance              # or conformance/run.sh [python|node]
```

It needs Go, plus Python 3 and/or Node 20+. Dependencies are pinned
(`python/requirements.txt`, `node/package-lock.json`) and installed locally by
the script; Dependabot keeps them current, so an SDK release that breaks
compatibility shows up as a failing PR.

## What is covered (identically in both SDKs)

| Area | Checks |
| --- | --- |
| Models | listing, per-key filtering |
| Chat | plain and multipart content, `system` messages, unknown fields reaching the backend, model-name mapping in both directions (request and response, every stream chunk), `X-Request-Id` |
| Streaming | the iterator API and the `stream()` helpers, with and without `include_usage` (Tavian forces usage upstream and relays the extra final chunk), early close |
| Tool calls | non-streamed and streamed (SDK helper and by hand), `tool_choice: none`, a full tool round trip |
| Errors | 401, 403, 404, 400, relayed backend 5xx, OpenAI-shaped bodies, unsupported endpoints, no model-existence leak |
| Python only | `AsyncOpenAI` for chat and streaming |

The mock backend (`internal/mockllm`) answers tool requests with a tool call
and reports the request fields it received in `system_fingerprint`, which is
how the suite sees what the gateway forwarded.

## Limits

The backend is a mock: this proves the gateway relays the protocol faithfully,
not that a given model supports tools or JSON mode. Not covered yet: embeddings
and other endpoints (the gateway does not serve them), vision payloads,
structured outputs, and the OpenAI Go SDK.

The test API keys in `tavian.yaml` are public. Never reuse them.
