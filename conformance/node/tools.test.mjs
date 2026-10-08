import assert from "node:assert/strict";
import { test } from "node:test";
import { WEATHER_TOOL, client, user } from "./helpers.mjs";

test("tool call", async () => {
  const resp = await client().chat.completions.create({
    model: "chat",
    messages: user("Paris?"),
    tools: [WEATHER_TOOL],
  });
  const choice = resp.choices[0];
  assert.equal(choice.finish_reason, "tool_calls");
  assert.equal(choice.message.content, null);
  assert.equal(choice.message.tool_calls.length, 1);
  const call = choice.message.tool_calls[0];
  assert.equal(call.type, "function");
  assert.equal(call.function.name, "get_weather");
  assert.deepEqual(JSON.parse(call.function.arguments), { echo: "Paris?" });
});

test("tool round trip", async () => {
  const c = client();
  const first = await c.chat.completions.create({ model: "chat", messages: user("Paris?"), tools: [WEATHER_TOOL] });
  const call = first.choices[0].message.tool_calls[0];
  const followup = await c.chat.completions.create({
    model: "chat",
    tools: [WEATHER_TOOL],
    messages: [
      ...user("Paris?"),
      first.choices[0].message,
      { role: "tool", tool_call_id: call.id, content: "sunny" },
    ],
  });
  assert.equal(followup.choices[0].finish_reason, "stop");
  assert.match(followup.choices[0].message.content, /sunny/);
});

test("tool_choice none is respected", async () => {
  const resp = await client().chat.completions.create({
    model: "chat",
    messages: user("Paris?"),
    tools: [WEATHER_TOOL],
    tool_choice: "none",
  });
  assert.equal(resp.choices[0].finish_reason, "stop");
  assert.ok(!resp.choices[0].message.tool_calls?.length);
});

test("streamed tool call with the stream helper", async () => {
  const stream = client().chat.completions.stream({ model: "chat", messages: user("Paris?"), tools: [WEATHER_TOOL] });
  const final = await stream.finalChatCompletion();
  const choice = final.choices[0];
  assert.equal(choice.finish_reason, "tool_calls");
  assert.equal(choice.message.tool_calls.length, 1);
  assert.equal(choice.message.tool_calls[0].function.name, "get_weather");
  assert.deepEqual(JSON.parse(choice.message.tool_calls[0].function.arguments), { echo: "Paris?" });
});

test("streamed tool call assembled by hand", async () => {
  const stream = await client().chat.completions.create({
    model: "chat",
    messages: user("Paris?"),
    tools: [WEATHER_TOOL],
    stream: true,
  });
  let name = "";
  let args = "";
  let finish = null;
  for await (const chunk of stream) {
    const c = chunk.choices[0];
    if (!c) continue;
    for (const tc of c.delta.tool_calls ?? []) {
      name += tc.function?.name ?? "";
      args += tc.function?.arguments ?? "";
    }
    finish = c.finish_reason ?? finish;
  }
  assert.equal(name, "get_weather");
  assert.equal(finish, "tool_calls");
  assert.deepEqual(JSON.parse(args), { echo: "Paris?" });
});
