import assert from "node:assert/strict";
import { test } from "node:test";
import { client, user } from "./helpers.mjs";

test("chat completion", async () => {
  const resp = await client().chat.completions.create({ model: "chat", messages: user("Say hello") });
  assert.equal(resp.object, "chat.completion");
  const choice = resp.choices[0];
  assert.equal(choice.message.role, "assistant");
  assert.equal(choice.message.content, "mock reply to: Say hello");
  assert.equal(choice.finish_reason, "stop");
  assert.ok(resp.usage.prompt_tokens > 0 && resp.usage.completion_tokens > 0);
  assert.equal(resp.usage.total_tokens, resp.usage.prompt_tokens + resp.usage.completion_tokens);
});

test("multipart content", async () => {
  const resp = await client().chat.completions.create({
    model: "chat",
    messages: [
      { role: "system", content: "Be brief." },
      { role: "user", content: [{ type: "text", text: "Describe a cat" }] },
    ],
  });
  assert.equal(resp.choices[0].message.content, "mock reply to: Describe a cat");
});

test("unknown request fields reach the backend", async () => {
  // The mock reports the top-level fields it received in system_fingerprint.
  const resp = await client().chat.completions.create({
    model: "chat",
    messages: user("hi"),
    temperature: 0.2,
    max_tokens: 16,
    seed: 7,
    vendor_extension: { a: 1 }, // not in the SDK's types: sent as is
  });
  const keys = resp.system_fingerprint.replace("mock keys=", "").split(",");
  for (const expected of ["temperature", "max_tokens", "seed", "vendor_extension"]) {
    assert.ok(keys.includes(expected), keys.join());
  }
});

test("the backend sees its own model name", async () => {
  const resp = await client().chat.completions.create({ model: "chat", messages: user("hi") });
  assert.equal(resp.model, "mock");
});

test("request id header, and the caller's one is kept", async () => {
  const c = client();
  const plain = await c.chat.completions.create({ model: "chat", messages: user("hi") }).asResponse();
  assert.ok(plain.headers.get("x-request-id"));
  const mine = await c.chat.completions
    .create({ model: "chat", messages: user("hi") }, { headers: { "X-Request-Id": "conformance-123" } })
    .asResponse();
  assert.equal(mine.headers.get("x-request-id"), "conformance-123");
});
