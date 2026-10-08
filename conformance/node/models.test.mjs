import assert from "node:assert/strict";
import { test } from "node:test";
import { NARROW_KEY, client } from "./helpers.mjs";

test("list models returns what the key may use", async () => {
  const page = await client().models.list();
  assert.deepEqual(new Set(page.data.map((m) => m.id)), new Set(["chat", "other", "broken"]));
  for (const m of page.data) {
    assert.equal(m.object, "model");
    assert.equal(m.owned_by, "tavian");
    assert.ok(m.created > 0);
  }
});

test("list models is filtered per key", async () => {
  const page = await client(NARROW_KEY).models.list();
  assert.deepEqual(page.data.map((m) => m.id), ["chat"]);
});
