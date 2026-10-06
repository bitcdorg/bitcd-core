// @bitcd/core/events — the event-stream folds behind the materialized view.
//
// The chain is a control plane, NOT a query plane: "is everything Synced?", drift
// dashboards, and governance history are answered from the EVENT STREAM, never by
// per-request on-chain reads. This module folds ValueChanged (desired) +
// StatusChanged/StatusAttested (observed) per value_key and DERIVES
// Synced/OutOfSync/Failed (the contract stays dumb and never computes it), plus the
// per-proposal governance fold (approvals vs SNIP-12 intent-bound votes vs
// escalations). Consumers depend on EVENT NAMES, not the ABI.
import { hash, num, shortString } from "starknet";
import { deriveCondition } from "./reconcile.mjs";

const sel = (name) => "0x" + hash.starknetKeccak(name).toString(16);

export const SELECTORS = {
  ValueChanged: sel("ValueChanged"),
  StatusChanged: sel("StatusChanged"),
  StatusAttested: sel("StatusAttested"),
  ProposalCreated: sel("ProposalCreated"),
  ProposalApproved: sel("ProposalApproved"),
  ApprovalSigned: sel("ApprovalSigned"),
  HumanReviewRequested: sel("HumanReviewRequested"),
  ProposalCommitted: sel("ProposalCommitted"),
};

const SAME = (ev, s) => BigInt(num.toHex(ev.keys[0])) === BigInt(s);
const kindOfEvent = (ev) => {
  for (const [name, s] of Object.entries(SELECTORS)) if (SAME(ev, s)) return name;
  return null;
};

export const decode = (felt) => {
  try {
    return shortString.decodeShortString(num.toHex(felt)) || num.toHex(felt);
  } catch {
    return num.toHex(felt);
  }
};
const hex = (felt) => "0x" + BigInt(felt).toString(16);

/// The block the contract first exists at. The OpenZeppelin ownership event
/// its constructor emits — previous owner 0 — happens exactly once, at deploy,
/// so a scan from there is lossless and short, where one from genesis is what
/// a public node refuses. Located once per process (windowed, newest first)
/// and kept; 0 — the scan from genesis — when nothing is found or the node
/// cannot answer. A deployment record that carries `block` needs no search.
const OWNERSHIP_TRANSFERRED = sel("OwnershipTransferred");
const DEPLOY_BLOCK = new Map();
export async function deploymentBlock(provider, address, { window = 1_000_000 } = {}) {
  const key = BigInt(address).toString(16);
  if (DEPLOY_BLOCK.has(key)) return DEPLOY_BLOCK.get(key);
  let block = 0;
  try {
    let hi = await provider.getBlockNumber();
    for (;;) {
      const lo = Math.max(0, hi - window + 1);
      const page = await provider.getEvents({
        address,
        from_block: { block_number: lo },
        to_block: { block_number: hi },
        keys: [[OWNERSHIP_TRANSFERRED], ["0x0"]],
        chunk_size: 10,
      });
      if (page.events.length > 0) {
        block = Number(page.events[0].block_number);
        break;
      }
      if (lo === 0) break;
      hi = lo - 1;
    }
  } catch {
    block = 0;
  }
  DEPLOY_BLOCK.set(key, block);
  return block;
}

/// Page through the events the folds read (SELECTORS) on `address` (chunked),
/// from `fromBlock` — the deployment block unless given.
export async function fetchAllEvents(provider, address, { fromBlock } = {}) {
  const from = fromBlock ?? await deploymentBlock(provider, address);
  const out = [];
  let token;
  do {
    const page = await provider.getEvents({
      address,
      from_block: { block_number: from },
      to_block: "latest",
      keys: [Object.values(SELECTORS)],
      chunk_size: 100,
      continuation_token: token,
    });
    out.push(...page.events);
    token = page.continuation_token;
  } while (token);
  return out;
}

/// Fold the event stream into a per-key projection: latest desired + latest
/// observed + the k-of-n per-executor vote slots, then derive the authoritative
/// state and the agreement tally. `labelKey(prefix) -> string` is an optional
/// domain labeler (demo grouping); the projection itself stays generic.
export function projectKeys(events, { labelKey } = {}) {
  const keys = new Map();
  const get = (k) => {
    if (!keys.has(k)) keys.set(k, { valueKey: k, desired: null, observed: null, votes: {} });
    return keys.get(k);
  };
  for (const ev of events) {
    const kind = kindOfEvent(ev);
    if (kind === "ValueChanged") {
      // keys: [sel, value_key, prefix]; data: [digest, schema_ref, storage_class, version]
      const r = get(decode(ev.keys[1]));
      r.prefix = decode(ev.keys[2]);
      r.desired = {
        digest: hex(ev.data[0]),
        schema_ref: decode(ev.data[1]),
        storage_class: decode(ev.data[2]),
        version: Number(BigInt(ev.data[3])),
      };
    } else if (kind === "StatusChanged") {
      // keys: [sel, value_key, prefix, executor]
      // data: [observed_revision, observed_digest, condition, status_version]
      const r = get(decode(ev.keys[1]));
      r.observed = {
        revision: Number(BigInt(ev.data[0])),
        digest: hex(ev.data[1]),
        claimed: decode(ev.data[2]),
        status_version: Number(BigInt(ev.data[3])),
        executor: hex(ev.keys[3]),
      };
    } else if (kind === "StatusAttested") {
      // keys: [sel, value_key, executor]; data: [observed_revision, applied_hash, condition]
      // Per-executor vote — last write per executor wins (its current slot).
      const r = get(decode(ev.keys[1]));
      r.votes[hex(ev.keys[2])] = {
        revision: Number(BigInt(ev.data[0])),
        hash: hex(ev.data[1]),
        condition: decode(ev.data[2]),
      };
    }
  }
  // Derive the authoritative state + the k-of-n agreement tally per key.
  return [...keys.values()].map((r) => {
    // Agreement among per-executor votes at the CURRENT desired revision: group by hash.
    const rev = r.desired?.version;
    const tally = {}; // hash -> count, among votes at the current revision
    let voters = 0;
    for (const v of Object.values(r.votes)) {
      if (rev != null && v.revision === rev) {
        voters += 1;
        tally[v.hash] = (tally[v.hash] ?? 0) + 1;
      }
    }
    const groups = Object.entries(tally).sort((a, b) => b[1] - a[1]);
    const lead = groups[0]; // [hash, count] of the largest agreeing group
    const agreement = { voters, distinct: groups.length, lead: lead ? { hash: lead[0], count: lead[1] } : null };

    let state = "NOSTATUS";
    if (r.observed?.claimed === "DISAGREE") {
      state = "DISAGREE"; // contract recorded a contested revision
    } else if (r.desired && r.observed) {
      state = deriveCondition({
        desiredVersion: r.desired.version,
        desiredDigest: r.desired.digest,
        observedRevision: r.observed.revision,
        observedDigest: r.observed.digest,
        claimed: r.observed.claimed,
      });
    } else if (r.desired) {
      state = "OUTOFSYNC"; // desired exists, never reconciled
    }
    const kind = labelKey ? labelKey(r.prefix) : undefined;
    return { ...r, ...(kind !== undefined ? { kind } : {}), state, agreement };
  });
}

/// Fold the governance events into a per-proposal view. `approvers`
/// is the full roster; `intentSigned` are the SNIP-12 intent-bound votes — the only
/// ones that count toward min_humans on-chain; `escalatedBy` are human-review demands.
export function projectProposals(events) {
  const props = new Map();
  const get = (id) => {
    if (!props.has(id)) {
      props.set(id, { id, action: null, prefix: null, approvers: new Set(), intentSigned: new Set(), escalatedBy: new Set(), committed: false });
    }
    return props.get(id);
  };
  for (const ev of events) {
    const kind = kindOfEvent(ev);
    if (kind === "ProposalCreated") {
      // keys: [sel, proposal_id, proposer]; data: [action, prefix_hash]
      const r = get(Number(BigInt(ev.keys[1])));
      r.action = decode(ev.data[0]);
      r.prefix = decode(ev.data[1]);
      r.proposer = hex(ev.keys[2]);
    } else if (kind === "ProposalApproved") {
      // keys: [sel, proposal_id, approver]
      get(Number(BigInt(ev.keys[1]))).approvers.add(hex(ev.keys[2]));
    } else if (kind === "ApprovalSigned") {
      get(Number(BigInt(ev.keys[1]))).intentSigned.add(hex(ev.keys[2]));
    } else if (kind === "HumanReviewRequested") {
      // keys: [sel, proposal_id, requester] — a per-proposal escalation.
      get(Number(BigInt(ev.keys[1]))).escalatedBy.add(hex(ev.keys[2]));
    } else if (kind === "ProposalCommitted") {
      get(Number(BigInt(ev.keys[1]))).committed = true;
    }
  }
  return [...props.values()].sort((a, b) => a.id - b.id);
}
