// voteOnce's bookkeeping: a proposal counts as decided only once its votes
// landed, and an escalation that never landed is asked for again.
import { test } from "node:test";
import assert from "node:assert/strict";
import { voteOnce, contractReason, VOTE } from "../src/fleet.mjs";

const ME = "0x123";
const skill = {
  name: "s", role: "AGENT", operatorId: "op-a", address: ME,
  appliesTo: () => true,
  check: async () => ({ pass: true, reason: "ok", evidence: {} }),
};
const proposal = (over = {}) => ({
  id: 1, action: "SET_VALUE", prefix: "fleet/x", proposer: "0xa", committed: false,
  approvers: new Set(), escalatedBy: new Set(), ...over,
});
function harness({ approveFails = 0, escalateFails = 0 } = {}) {
  const calls = { approve: 0, review: 0 };
  const lines = [];
  const ops = {
    getSigner: async () => ({ active: true, is_human: false, operator_id: "op-a", role: "AGENT" }),
    approve: async () => { calls.approve++; if (calls.approve <= approveFails) throw new Error("fetch failed"); },
    requestHumanReview: async () => { calls.review++; if (calls.review <= escalateFails) throw new Error("fetch failed"); },
  };
  const run = (p, seen, escalate) => voteOnce({
    self: ME, ops, skill, fetchCtx: async () => ({}), proposals: [p], seen,
    evidence: { append: (r) => lines.push(r) }, escalate,
  });
  return { calls, lines, run };
}

test("a failed approve is retried on the next pass", async () => {
  const h = harness({ approveFails: 1 });
  const seen = new Set();
  assert.deepEqual((await h.run(proposal(), seen)).map((d) => d.failed), [true]);
  assert.equal(seen.has(1), false);
  const r = await h.run(proposal(), seen);
  assert.equal(r[0].vote, VOTE.APPROVE);
  assert.equal(h.calls.approve, 2);
  assert.equal(h.lines.length, 1);
});

test("an agent whose approval landed without its escalation asks for the escalation again", async () => {
  const h = harness();
  const seen = new Set();
  const always = async () => true;
  // the chain shows our approval (say, from a process that died) but no escalation from us
  const r = await h.run(proposal({ approvers: new Set([ME]) }), seen, always);
  assert.equal(h.calls.approve, 0, "never approves twice");
  assert.equal(h.calls.review, 1);
  assert.equal(r[0].escalated, true);
  assert.equal(h.lines.length, 1);
});

test("an agent that already approved and escalated is skipped without deciding", async () => {
  const h = harness();
  const out = await h.run(proposal({ approvers: new Set([ME]), escalatedBy: new Set([ME]) }), new Set(), async () => true);
  assert.deepEqual(out, []);
  assert.equal(h.calls.approve + h.calls.review, 0);
});

test("contract revert reasons are told apart from transport errors", () => {
  assert.equal(contractReason("Execution failed: 0x70726f ('proposal: executed')"), "proposal: executed");
  assert.equal(contractReason("Failure reason: 0x43 ('Caller is not the owner')."), "Caller is not the owner");
  assert.equal(contractReason("fetch failed"), null);
  assert.equal(contractReason("connect ECONNREFUSED 127.0.0.1:5051"), null);
});

test("an escalation that fails leaves the vote unsent, so nothing can be committed around it", async () => {
  const h = harness({ escalateFails: 1 });
  const seen = new Set();
  const first = await h.run(proposal(), seen, async () => true);
  assert.equal(h.calls.review, 1);
  assert.equal(h.calls.approve, 0, "no approval before the escalation lands");
  assert.deepEqual(first.map((d) => [d.id, d.failed]), [[1, true]], "reported, so the daemon holds its commit back");
  assert.equal(seen.has(1), false);
  await h.run(proposal(), seen, async () => true);
  assert.equal(h.calls.review, 2);
  assert.equal(h.calls.approve, 1);
});

test("held: a failed vote is held at once, and released when the chain shows it landed", async () => {
  const h = harness({ approveFails: 1 });
  const held = new Set();
  await voteOnce({ self: ME, ops: { getSigner: async () => ({ active: true, is_human: false, operator_id: "op-a", role: "AGENT" }),
    approve: async () => { throw new Error("timeout"); }, requestHumanReview: async () => {} },
  skill, fetchCtx: async () => ({}), proposals: [proposal()], seen: new Set(), held });
  assert.ok(held.has(1), "held the moment its vote failed");
  // the approval had in fact landed (a receipt timeout): the next round sees it on chain
  await voteOnce({ self: ME, ops: { getSigner: async () => ({}) }, skill, fetchCtx: async () => ({}),
    proposals: [proposal({ approvers: new Set([ME]) })], seen: new Set(), held });
  assert.equal(held.has(1), false, "released once the chain shows the vote");
  void h;
});

test("a decision that throws holds its proposal and the round goes on", async () => {
  const held = new Set();
  const out = await voteOnce({ self: ME, ops: { getSigner: async () => { throw new Error("rpc down"); } },
    skill, fetchCtx: async () => ({}), proposals: [proposal({ id: 1 }), proposal({ id: 2 })], seen: new Set(), held });
  assert.deepEqual([...held].sort(), [1, 2]);
  assert.equal(out.length, 2);
});

test("an owed escalation is sent again, and a later WITHHOLD doesn't cancel it", async () => {
  const held = new Set();
  const owed = new Set();
  let reviews = 0;
  let failReview = true;
  const ops = {
    getSigner: async () => ({ active: true, is_human: false, operator_id: "op-a", role: "AGENT" }),
    approve: async () => {},
    requestHumanReview: async () => { reviews++; if (failReview) throw new Error("timeout"); },
  };
  const risky = { ...skill, check: async () => ({ pass: true, reason: "ok", evidence: { risk: "high" } }) };
  await voteOnce({ self: ME, ops, skill: risky, fetchCtx: async () => ({}), proposals: [proposal()], seen: new Set(), held, owed,
    escalate: async (_p, d) => d.evidence?.risk === "high" });
  assert.ok(owed.has(1) && held.has(1), "owed and held after the escalation failed");
  // next round: the context is missing, so the check would WITHHOLD — the owed escalation is sent anyway
  failReview = false;
  const withholding = { ...skill, check: async () => ({ pass: false, reason: "no incident" }) };
  await voteOnce({ self: ME, ops, skill: withholding, fetchCtx: async () => ({}), proposals: [proposal()], seen: new Set(), held, owed,
    escalate: async (_p, d) => d.evidence?.risk === "high" });
  assert.equal(reviews, 2);
  assert.equal(owed.has(1), false);
});

test("a hold survives a round that skips the proposal", async () => {
  const held = new Set([1]);
  await voteOnce({ self: ME, ops: {}, skill, fetchCtx: async () => ({}), proposals: [proposal()], seen: new Set([1]), held });
  assert.ok(held.has(1));
});

test("a reverted transaction is not a cast vote", async () => {
  const { waitSucceeded } = await import("../src/fleet.mjs");
  const provider = (status) => ({ waitForTransaction: async () => ({ execution_status: status, revert_reason: "request_human: not a signer" }) });
  await assert.rejects(waitSucceeded(provider("REVERTED"), "0x1"), /reverted: request_human: not a signer/);
  assert.equal((await waitSucceeded(provider("SUCCEEDED"), "0x1")).execution_status, "SUCCEEDED");
});
