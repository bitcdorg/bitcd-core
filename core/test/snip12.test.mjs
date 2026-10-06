// Pure unit tests for @bitcd/core/snip12 — the intent-binding typed data.
// The INV-11 property under test: the signed message binds
// {verifyingContract, chainId, proposalId, action, prefix, paramsHash} + the
// approver, so no field can be swapped without changing the hash (no replay,
// no param swap, no re-attribution). The on-chain half of the regression is
// assertRoundTrip() against `approval_digest` (exercised by the e2e rig).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { ACTION, str } from "../src/protocol.mjs";
import { approvalMessageHash, approvalTypedData, paramsHash } from "../src/snip12.mjs";

const APPROVER = "0x078662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1";
const BASE = {
  verifyingContract: "0x0123",
  chainId: "0x534e5f5345504f4c4941",
  proposalId: 7,
  action: ACTION.SET_VALUE,
  prefix: str("app/config"),
  params: [str("app/config/db"), "0xabc", str("appcfg/v1"), str("S3"), 3],
};

test("paramsHash is deterministic, length-prefixed, and order-sensitive", () => {
  assert.equal(paramsHash([1, 2, 3]), paramsHash([1, 2, 3]));
  assert.notEqual(paramsHash([1, 2, 3]), paramsHash([3, 2, 1]));
  // Length is part of the hash: [1,2] must not collide with [1,2,0].
  assert.notEqual(paramsHash([1, 2]), paramsHash([1, 2, 0]));
  assert.notEqual(paramsHash([]), paramsHash([0]));
});

test("the SNIP-12 domain is protocol identity (baked into approval_digest)", () => {
  const { domain, primaryType } = approvalTypedData(BASE);
  assert.equal(domain.name, "bitcd");
  assert.equal(domain.version, "1");
  assert.equal(domain.revision, "1");
  assert.equal(primaryType, "Approval");
});

test("every bound field changes the message hash (no swap/replay surface)", () => {
  const base = approvalMessageHash(BASE, APPROVER);
  assert.equal(approvalMessageHash({ ...BASE }, APPROVER), base, "not deterministic");
  const variants = {
    verifyingContract: { ...BASE, verifyingContract: "0x0124" },
    chainId: { ...BASE, chainId: "0x534e5f4d41494e" },
    proposalId: { ...BASE, proposalId: 8 },
    action: { ...BASE, action: ACTION.FORCE_UNLOCK },
    prefix: { ...BASE, prefix: str("tf/lock") },
    params: { ...BASE, params: [...BASE.params.slice(0, -1), 4] },
  };
  for (const [field, args] of Object.entries(variants)) {
    assert.notEqual(approvalMessageHash(args, APPROVER), base, `${field} not bound`);
  }
  // Re-attribution: the same intent signed FOR a different approver is a
  // different message (the relayer cannot re-credit a vote).
  assert.notEqual(approvalMessageHash(BASE, "0x0999"), base, "approver not bound");
});
