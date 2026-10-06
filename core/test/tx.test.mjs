// Unit tests for the transaction wait: inclusion is not execution. Each path
// that sends a transaction fails on a revert — the ceremony before it sends
// anything further (renounce above all), the executor before it believes its
// attestation landed.
import test from "node:test";
import assert from "node:assert/strict";
import { waitSucceeded } from "../src/tx.mjs";
import { waitSucceeded as fromFleet } from "../src/fleet.mjs";
import { waitSucceeded as fromClient } from "../src/client.mjs";
import { runCeremony } from "../src/ceremony.mjs";
import { makeChainOps } from "../src/reconcile.mjs";

const provider = (statusOf) => ({
  waitForTransaction: async (hash) => ({ execution_status: statusOf(hash), revert_reason: "policy: gov not open" }),
});

test("a reverted transaction throws with the call's name and the contract's reason", async () => {
  const reverted = provider(() => "REVERTED");
  await assert.rejects(waitSucceeded(reverted, "0x1"), /^Error: transaction 0x1 reverted: policy: gov not open$/);
  await assert.rejects(waitSucceeded(reverted, "0x1", "set_policy"), /^Error: set_policy 0x1 reverted: policy: gov not open$/);
  assert.equal((await waitSucceeded(provider(() => "SUCCEEDED"), "0x1")).execution_status, "SUCCEEDED");
});

test("a receipt that nests its status under value is read the same way", async () => {
  const nested = { waitForTransaction: async () => ({ value: { execution_status: "REVERTED", revert_reason: "commit: policy unmet" } }) };
  await assert.rejects(waitSucceeded(nested, "0x2"), /reverted: commit: policy unmet/);
});

test("the client and fleet subpaths export the same wait", () => {
  assert.equal(fromFleet, waitSucceeded);
  assert.equal(fromClient, waitSucceeded);
});

test("a reverted seed transaction stops the ceremony before renounce", async () => {
  const sent = [];
  const send = (hash) => { sent.push(hash); return Promise.resolve({ transaction_hash: hash }); };
  const contract = {
    set_signer: () => send("0xsigner"),
    set_policy: (prefix) => send(`0xpolicy-${prefix}`),
    renounce_ownership: () => send("0xrenounce"),
  };
  const policy = (prefix) => ({ label: `policy ${prefix}`, prefix, action: "SET_POLICY", policy: {} });
  await assert.rejects(
    runCeremony({
      contract,
      provider: provider((hash) => (hash === "0xpolicy-b" ? "REVERTED" : "SUCCEEDED")),
      signers: [{ address: "0xabc", signer: {} }],
      policies: [policy("a"), policy("b"), policy("c")],
      renounce: true,
    }),
    /policy b 0xpolicy-b reverted: policy: gov not open/,
  );
  assert.deepEqual(sent, ["0xsigner", "0xpolicy-a", "0xpolicy-b"]);
});

test("a ceremony whose transactions all execute renounces last", async () => {
  const sent = [];
  const send = (hash) => { sent.push(hash); return Promise.resolve({ transaction_hash: hash }); };
  await runCeremony({
    contract: { set_signer: () => send("0xsigner"), set_policy: () => send("0xpolicy"), renounce_ownership: () => send("0xrenounce") },
    provider: provider(() => "SUCCEEDED"),
    signers: [{ address: "0xabc", signer: {} }],
    policies: [{ prefix: "a", action: "SET_POLICY", policy: {} }],
    renounce: true,
  });
  assert.deepEqual(sent, ["0xsigner", "0xpolicy", "0xrenounce"]);
});

test("a reverted attestation is not an attestation", async () => {
  const ops = makeChainOps({
    writer: { set_status: async () => ({ transaction_hash: "0x5" }) },
    provider: provider(() => "REVERTED"),
    valueKey: "0x1",
  });
  await assert.rejects(
    ops.setStatus({ observed_revision: 1, applied_hash: "0x0", condition: "SYNCED", reason: "applied" }),
    /set_status 0x5 reverted: policy: gov not open/,
  );
});
