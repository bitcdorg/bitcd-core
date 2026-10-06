import { test } from "node:test";
import assert from "node:assert/strict";
import { pickApprovers } from "../src/org/approvers.mjs";

const signer = (name, human, operator, role = "OPERATOR") => ({ name, address: name, human, operator, role });
const q = (threshold, min_humans, max_per_operator = 1, role = "OPERATOR") => ({ threshold, role, min_humans, max_per_operator });

test("humans first, capped per operator", () => {
  const pool = [signer("bot", false, "OP_A"), signer("alice", true, "OP_A"), signer("bob", true, "OP_B")];
  assert.deepEqual(pickApprovers(pool, q(2, 1)).map((s) => s.name), ["alice", "bob"]);
});

test("a human floor above the threshold keeps picking humans", () => {
  const pool = [signer("alice", true, "OP_A"), signer("bob", true, "OP_B"), signer("bot", false, "OP_C")];
  assert.deepEqual(pickApprovers(pool, q(1, 2)).map((s) => s.name), ["alice", "bob"]);
});

test("unsatisfiable pools return null", () => {
  assert.equal(pickApprovers([signer("alice", true, "OP_A"), signer("carol", true, "OP_A")], q(2, 1)), null, "cap 1 per operator");
  assert.equal(pickApprovers([signer("bot", false, "OP_A"), signer("bot2", false, "OP_B")], q(2, 1)), null, "no human");
  assert.equal(pickApprovers([signer("x", true, "OP_A", "EXEC")], q(1, 0)), null, "wrong role");
});
