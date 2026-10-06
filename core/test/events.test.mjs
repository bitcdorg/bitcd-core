// Unit tests for the event-stream folds — the ONE derivation every reader
// (indexer, console, product panels) must agree on. Synthetic events use the
// real selectors and the real shortstring encoding; their payload layouts
// mirror contracts/src/events.cairo by hand, so a change there is made here too.
import test from "node:test";
import assert from "node:assert/strict";
import { shortString } from "starknet";
import { deploymentBlock, fetchAllEvents, projectKeys, projectProposals, SELECTORS } from "../src/events.mjs";

const s = (t) => shortString.encodeShortString(t);

const valueChanged = (key, prefix, { digest, version }) => ({
  keys: [SELECTORS.ValueChanged, s(key), s(prefix)],
  data: [digest, s("k8srbac/v1"), s("S3"), String(version)],
});
const statusChanged = (key, prefix, executor, { revision, digest, claimed, sv = 1 }) => ({
  keys: [SELECTORS.StatusChanged, s(key), s(prefix), executor],
  data: [String(revision), digest, s(claimed), String(sv)],
});
const statusAttested = (key, executor, { revision, hash, claimed = "SYNCED" }) => ({
  keys: [SELECTORS.StatusAttested, s(key), executor],
  data: [String(revision), hash, s(claimed)],
});

test("desired + matching observed folds to SYNCED", () => {
  const [k] = projectKeys([
    valueChanged("iam/acct/pset", "iam/acct", { digest: "0xabc", version: 2 }),
    statusChanged("iam/acct/pset", "iam/acct", "0x7", { revision: 2, digest: "0xabc", claimed: "SYNCED" }),
  ]);
  assert.equal(k.state, "SYNCED");
  assert.equal(k.prefix, "iam/acct");
  assert.equal(k.desired.version, 2);
  assert.equal(k.observed.executor, "0x7");
});

test("desired that was never reconciled folds to OUTOFSYNC", () => {
  const [k] = projectKeys([valueChanged("k", "p", { digest: "0x1", version: 1 })]);
  assert.equal(k.state, "OUTOFSYNC");
  assert.equal(k.observed, null);
});

test("a contract-set DISAGREE wins over the derivation", () => {
  const [k] = projectKeys([
    valueChanged("k", "p", { digest: "0x1", version: 1 }),
    statusChanged("k", "p", "0x7", { revision: 1, digest: "0x1", claimed: "DISAGREE" }),
  ]);
  assert.equal(k.state, "DISAGREE");
});

test("k-of-n tally: current-revision votes group by hash; stale votes drop", () => {
  const [k] = projectKeys([
    valueChanged("k", "p", { digest: "0xaa", version: 2 }),
    statusAttested("k", "0x1", { revision: 2, hash: "0xaa" }),
    statusAttested("k", "0x2", { revision: 2, hash: "0xaa" }),
    statusAttested("k", "0x3", { revision: 2, hash: "0xbb" }), // the dissenter
    statusAttested("k", "0x4", { revision: 1, hash: "0xaa" }), // stale — must not count
  ]);
  assert.equal(k.agreement.voters, 3);
  assert.equal(k.agreement.distinct, 2);
  assert.deepEqual(k.agreement.lead, { hash: "0xaa", count: 2 });
});

test("re-attestation is last-write-wins per executor (one executor, one slot)", () => {
  const [k] = projectKeys([
    valueChanged("k", "p", { digest: "0xaa", version: 2 }),
    statusAttested("k", "0x3", { revision: 2, hash: "0xbb" }),
    statusAttested("k", "0x3", { revision: 2, hash: "0xaa" }), // the dissenter converges
  ]);
  assert.equal(k.agreement.voters, 1);
  assert.deepEqual(k.agreement.lead, { hash: "0xaa", count: 1 });
});

test("governance fold: approvers vs intent-signed vs escalation vs committed", () => {
  const A = "0xa1", B = "0xb2", C = "0xc3";
  const props = projectProposals([
    { keys: [SELECTORS.ProposalCreated, "2", A], data: [s("SET_VALUE"), s("k8s/rbac")] },
    { keys: [SELECTORS.ProposalCreated, "1", A], data: [s("SET_POLICY"), s("GLOBAL")] },
    { keys: [SELECTORS.ProposalApproved, "2", A] },
    { keys: [SELECTORS.ProposalApproved, "2", B] },
    { keys: [SELECTORS.ApprovalSigned, "2", B] },
    { keys: [SELECTORS.HumanReviewRequested, "2", C] },
    { keys: [SELECTORS.ProposalCommitted, "2"] },
  ]);
  assert.deepEqual(props.map((p) => p.id), [1, 2], "sorted by id");
  const p2 = props[1];
  assert.equal(p2.action, "SET_VALUE");
  assert.equal(p2.prefix, "k8s/rbac");
  assert.deepEqual([...p2.approvers].sort(), [A, B]);
  assert.deepEqual([...p2.intentSigned], [B], "machine votes = approvers minus intentSigned");
  assert.deepEqual([...p2.escalatedBy], [C]);
  assert.equal(p2.committed, true);
  assert.equal(props[0].committed, false);
});

// A chain whose only interesting event is the constructor's ownership event
// (previous owner 0) at `deployAt`; records every getEvents filter it is asked.
const fakeChain = (latest, deployAt) => {
  const calls = [];
  return {
    calls,
    getBlockNumber: async () => latest,
    getEvents: async (f) => {
      calls.push(f);
      const lo = f.from_block.block_number;
      const hi = f.to_block === "latest" ? latest : f.to_block.block_number;
      const ctor = f.keys?.[1]?.[0] === "0x0";
      const events = ctor && deployAt >= lo && deployAt <= hi ? [{ block_number: deployAt, keys: [], data: [] }] : [];
      return { events, continuation_token: undefined };
    },
  };
};
const span = (f) => [f.from_block.block_number, f.to_block.block_number];

test("deploymentBlock: the constructor's ownership event, searched newest first, then kept", async () => {
  const p = fakeChain(2_500_000, 1_200_000);
  assert.equal(await deploymentBlock(p, "0xa1", { window: 1_000_000 }), 1_200_000);
  assert.deepEqual(p.calls.map(span), [[1_500_001, 2_500_000], [500_001, 1_500_000]]);
  assert.equal(await deploymentBlock(p, "0xa1", { window: 1_000_000 }), 1_200_000);
  assert.equal(p.calls.length, 2, "located once per process");
});

test("deploymentBlock: nothing found, or a node that cannot answer, means genesis", async () => {
  const p = fakeChain(50, -1);
  assert.equal(await deploymentBlock(p, "0xa2", { window: 20 }), 0);
  assert.deepEqual(p.calls.map(span), [[31, 50], [11, 30], [0, 10]]);
  assert.equal(await deploymentBlock({ getEvents: async () => ({ events: [] }) }, "0xa3"), 0, "no getBlockNumber");
});

test("fetchAllEvents scans from the deployment block unless told where to start", async () => {
  const p = fakeChain(100, 42);
  await fetchAllEvents(p, "0xa4");
  assert.equal(p.calls.at(-1).from_block.block_number, 42);
  await fetchAllEvents(p, "0xa4", { fromBlock: 7 });
  assert.equal(p.calls.at(-1).from_block.block_number, 7);
});
