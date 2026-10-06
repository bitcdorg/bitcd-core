// Pure unit tests for @bitcd/core/protocol — the on-chain vocabulary. These
// felts are protocol identity: the contract compares against exactly these
// values, so an accidental rename here is a silent consensus break.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { shortString } from "starknet";
import {
  ACTION, CONDITION_FELT, GLOBAL, SHORTSTRING_MAX, STORAGE_CLASS,
  assertShortString, digestOf, str,
} from "../src/protocol.mjs";

test("str() round-trips through the Cairo shortstring encoding", () => {
  for (const s of ["tf/lock", "SET_VALUE", "a", "x".repeat(SHORTSTRING_MAX)]) {
    assert.equal(shortString.decodeShortString(str(s)), s);
  }
});

test("digestOf() is deterministic and content-sensitive", () => {
  const a = digestOf("desired config v1");
  assert.equal(a, digestOf("desired config v1"));
  assert.notEqual(a, digestOf("desired config v2"));
  assert.match(a, /^0x[0-9a-f]+$/);
});

test("protocol felts are distinct and stable", () => {
  const felts = [
    ...Object.values(ACTION),
    ...Object.values(CONDITION_FELT),
    ...Object.values(STORAGE_CLASS),
    GLOBAL,
  ];
  assert.equal(new Set(felts).size, felts.length, "felt collision");
  // Spot-pin the tags the contract dispatches on (contracts/src/lib.cairo).
  assert.equal(ACTION.SET_VALUE, str("SET_VALUE"));
  assert.equal(ACTION.FORCE_UNLOCK, str("FORCE_UNLOCK"));
  assert.equal(GLOBAL, str("GLOBAL"));
});

test("assertShortString() rejects out-of-capacity keys early", () => {
  assert.equal(assertShortString("k8s/lease"), "k8s/lease");
  assert.throws(() => assertShortString("x".repeat(SHORTSTRING_MAX + 1)));
  assert.throws(() => assertShortString(""));
  assert.throws(() => assertShortString(42));
});
