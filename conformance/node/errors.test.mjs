import assert from "node:assert/strict";
import { test } from "node:test";
import OpenAI from "openai";
import { BASE_URL, NARROW_KEY, client, user } from "./helpers.mjs";

const reject = (promise, Class, props = {}) =>
  assert.rejects(promise, (err) => {
    assert.ok(err instanceof Class, `expected ${Class.name}, got ${err?.constructor?.name}: ${err?.message}`);
    for (const [k, v] of Object.entries(props)) assert.equal(err[k], v);
    return true;
  });

test("wrong key is 401", async () => {
  const bad = new OpenAI({ baseURL: BASE_URL, apiKey: "tav_not-a-real-key", maxRetries: 0 });
  await reject(bad.chat.completions.create({ model: "chat", messages: user("hi") }), OpenAI.AuthenticationError, {
    status: 401,
    code: "invalid_api_key",
  });
});

test("model outside the allow-list is 403", async () => {
  await reject(
    client(NARROW_KEY).chat.completions.create({ model: "other", messages: user("hi") }),
    OpenAI.PermissionDeniedError,
    { code: "model_not_allowed" },
  );
});

test("allowed but unconfigured model is 404", async () => {
  await reject(
    client().chat.completions.create({ model: "ghost-model", messages: user("hi") }),
    OpenAI.NotFoundError,
    { status: 404, code: "model_not_found" },
  );
});

test("models outside the allow-list do not reveal whether they exist", async () => {
  for (const model of ["other", "does-not-exist"]) {
    await reject(client(NARROW_KEY).chat.completions.create({ model, messages: user("hi") }), OpenAI.PermissionDeniedError);
  }
});

test("backend error is relayed as a server error", async () => {
  await reject(client().chat.completions.create({ model: "broken", messages: user("hi") }), OpenAI.InternalServerError, {
    status: 500,
  });
});

test("error bodies are OpenAI shaped", async () => {
  try {
    await client().chat.completions.create({ model: "ghost-model", messages: user("hi") });
    assert.fail("expected an error");
  } catch (err) {
    assert.equal(err.type, "invalid_request_error");
    assert.ok(err.message.length > 0);
  }
});

test("unsupported endpoint is a JSON 404", async () => {
  await reject(client().embeddings.create({ model: "chat", input: "hello" }), OpenAI.NotFoundError, {
    code: "not_found",
  });
});
