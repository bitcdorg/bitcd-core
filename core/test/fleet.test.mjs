// The pure decision core: APPROVE / WITHHOLD / ABSTAIN / ineligible, no chain
// (the injected-IO pattern from reconcileOnce, applied to voters).
import { test } from "node:test";
import assert from "node:assert/strict";
import { decide, VOTE } from "../src/fleet.mjs";

const PROPOSAL = { id: 7, action: "SET_VALUE", prefix: "demo/notarygate", proposer: "0xa" };

const skill = (overrides = {}) => ({
  name: "provenance",
  role: "APPROVER",
  operatorId: "notary-prov",
  address: "0x123",
  appliesTo: (p) => p.action === "SET_VALUE" && p.prefix === "demo/notarygate",
  async check(_p, ctx) {
    const ok = ctx.allowlist.has(ctx.specDigest);
    return {
      pass: ok,
      reason: ok ? "digest allowlisted" : "digest not allowlisted",
      evidence: { specDigest: ctx.specDigest, allowlistRev: ctx.allowlist.rev },
    };
  },
  ...overrides,
});

const io = ({ active = true, role = "APPROVER", ctx } = {}) => ({
  getSigner: async () => ({ active, is_human: false, operator_id: "notary-prov", role }),
  fetchCtx: async () => ctx,
});

test("predicate passes -> APPROVE with evidence", async () => {
  const allowlist = new Set(["0xd1"]);
  allowlist.rev = "rev-3";
  const d = await decide(PROPOSAL, { ...io({ ctx: { specDigest: "0xd1", allowlist } }), skill: skill() });
  assert.equal(d.vote, VOTE.APPROVE);
  assert.equal(d.reason, "digest allowlisted");
  assert.deepEqual(d.evidence, { specDigest: "0xd1", allowlistRev: "rev-3" });
});

test("predicate fails -> WITHHOLD, never a silent skip", async () => {
  const allowlist = new Set(["0xd1"]);
  const d = await decide(PROPOSAL, { ...io({ ctx: { specDigest: "0xbad", allowlist } }), skill: skill() });
  assert.equal(d.vote, VOTE.WITHHOLD);
  assert.equal(d.reason, "digest not allowlisted");
});

test("out-of-scope proposal -> ABSTAIN before any IO", async () => {
  const d = await decide(
    { ...PROPOSAL, prefix: "iam/prod" },
    {
      getSigner: async () => assert.fail("getSigner must not be called"),
      fetchCtx: async () => assert.fail("fetchCtx must not be called"),
      skill: skill(),
    },
  );
  assert.deepEqual(d, { vote: VOTE.ABSTAIN });
});

test("inactive signer -> ABSTAIN ineligible (revoked notary cannot vote)", async () => {
  const d = await decide(PROPOSAL, { ...io({ active: false }), skill: skill() });
  assert.deepEqual(d, { vote: VOTE.ABSTAIN, reason: "ineligible" });
});

test("role mismatch -> ABSTAIN ineligible (single-role eligibility filter)", async () => {
  const d = await decide(PROPOSAL, { ...io({ role: "OPERATOR" }), skill: skill() });
  assert.deepEqual(d, { vote: VOTE.ABSTAIN, reason: "ineligible" });
});
