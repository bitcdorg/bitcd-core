import { test } from "node:test";
import assert from "node:assert/strict";
import { artifactSource, manifest } from "../src/artifacts.mjs";

test("BITCD_SIERRA makes the source 'env'", () => {
  const before = process.env.BITCD_SIERRA;
  process.env.BITCD_SIERRA = "/tmp/x.json";
  try { assert.equal(artifactSource(), "env"); } finally {
    if (before === undefined) delete process.env.BITCD_SIERRA; else process.env.BITCD_SIERRA = before;
  }
});

test("the bundled manifest pins a class hash", () => {
  assert.match(manifest().classHash, /^0x[0-9a-f]+$/);
  assert.ok(["local-build", "bundled"].includes(artifactSource()));
});
