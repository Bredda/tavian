import assert from "node:assert/strict";
import { test } from "node:test";
import { client, collect, user } from "./helpers.mjs";

test("stream assembles the same text", async () => {
  const stream = await client().chat.completions.create({ model: "chat", messages: user("Count"), stream: true });
  const { chunks, text } = await collect(stream);
  assert.equal(text, "mock reply to: Count");
  assert.ok(chunks.length > 3, "really streamed, not one buffered blob");
  assert.equal(chunks[0].choices[0].delta.role, "assistant");
  const finishes = chunks.filter((c) => c.choices.length).map((c) => c.choices[0].finish_reason);
  assert.equal(finishes.at(-1), "stop");
});

test("usage chunk when requested", async () => {
  const stream = await client().chat.completions.create({
    model: "chat",
    messages: user("Count"),
    stream: true,
    stream_options: { include_usage: true },
  });
  const { chunks } = await collect(stream);
  const last = chunks.at(-1);
  assert.deepEqual(last.choices, []);
  assert.ok(last.usage.total_tokens > 0);
});

test("stream works without asking for usage", async () => {
  // Tavian forces usage reporting upstream to meter streams; the extra final
  // chunk it relays must not trip the SDK.
  const stream = await client().chat.completions.create({ model: "chat", messages: user("Count"), stream: true });
  const { chunks, text } = await collect(stream);
  assert.equal(text, "mock reply to: Count");
  assert.deepEqual(chunks.at(-1).choices, []);
  assert.ok(chunks.at(-1).usage.total_tokens > 0);
});

test("the stream helper builds the final completion", async () => {
  const stream = client().chat.completions.stream({ model: "chat", messages: user("Helper") });
  const final = await stream.finalChatCompletion();
  assert.equal(final.choices[0].message.content, "mock reply to: Helper");
  assert.equal(final.choices[0].finish_reason, "stop");
});

test("aborting early leaves the gateway usable", async () => {
  const c = client();
  const stream = await c.chat.completions.create({ model: "chat", messages: user("Count"), stream: true });
  for await (const _ of stream) break; // leaving the loop cancels the stream
  const resp = await c.chat.completions.create({ model: "chat", messages: user("after") });
  assert.equal(resp.choices[0].message.content, "mock reply to: after");
});
