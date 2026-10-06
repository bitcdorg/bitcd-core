// @bitcd/core/fleet — the predicate-voter engine + the fleet-daemon shell,
// shared by agent fleets and pre-flight notaries.
//
// A voter is a non-human Signer whose vote is a REPRODUCIBLE PREDICATE over the
// proposal's immutable state — never a judgment (LLM agents stay out of this
// path entirely: they may propose and page, never vote). The reference daemons
// (agentgate's fleet peers and notaries) differ only in which predicate they
// carry — the decision core is this one `decide`, so it lives in the library
// once and packages never import each other.
//
// The skill/predicate interface (pure, deterministic, reproducible):
//   {
//     name, role, operatorId, address,
//     appliesTo(proposal) -> bool,
//     check(proposal, ctx) -> { pass, reason, evidence }   // a predicate, NOT a judgment
//   }
// `ctx` (from the injected `fetchCtx`) is the immutable proposal state +
// independently-verifiable sources ONLY (a signed allowlist, the blob digest,
// on-chain params) — never attacker-authored free text fed to a model. A
// consumer that injects its own skill must keep model clients out of it:
// agentgate ships the CI tripwire (`.tools/lint-no-model-clients.mjs`, takes
// explicit roots) — the discipline follows the skill, not the repo.
import { num, shortString } from "starknet";
import { fetchAllEvents, projectProposals } from "./events.mjs";
import { assertRoundTrip } from "./snip12.mjs";
import { str } from "./protocol.mjs";
import { pendingParamsKey } from "./pending.mjs";

/// Vote outcomes. WITHHOLD (predicate ran and failed) is deliberately distinct
/// from ABSTAIN (not my prefix / not eligible): a WITHHOLD is the FAIL-beat
/// evidence record; an ABSTAIN is silence.
export const VOTE = {
  APPROVE: "APPROVE",
  WITHHOLD: "WITHHOLD",
  ABSTAIN: "ABSTAIN",
};

const decodeFelt = (felt) => {
  try {
    return shortString.decodeShortString(num.toHex(felt)) || num.toHex(felt);
  } catch {
    return num.toHex(felt);
  }
};

/// The pure decision core: decide does NO IO
/// of its own — `getSigner`/`fetchCtx` are injected, so this is unit-testable
/// with plain objects, no chain (the reconcileOnce pattern).
export async function decide(proposal, { getSigner, fetchCtx, skill }) {
  if (!skill.appliesTo(proposal)) return { vote: VOTE.ABSTAIN };
  const me = await getSigner(skill.address);
  if (!me.active || me.role !== skill.role) {
    return { vote: VOTE.ABSTAIN, reason: "ineligible" };
  }
  const { pass, reason, evidence } = await skill.check(proposal, await fetchCtx(proposal));
  return { vote: pass ? VOTE.APPROVE : VOTE.WITHHOLD, reason, evidence };
}

/// Conjoin predicates into one skill `check`: every predicate must pass; the
/// first failure short-circuits into a WITHHOLD with THAT predicate's reason
/// (the evidence log then records exactly which gate refused). Evidence from
/// the predicates that ran is merged, keyed by predicate name.
export function composePredicates(predicates) {
  return async (proposal, ctx) => {
    const evidence = {};
    for (const pred of predicates) {
      const r = await pred.check(proposal, ctx);
      evidence[pred.name] = r.evidence ?? null;
      if (!r.pass) return { pass: false, reason: `${pred.name}: ${r.reason}`, evidence };
    }
    return { pass: true, reason: "all predicates passed", evidence };
  };
}

/// The proposal-params side channel. The contract stores a proposal's params
/// immutably but exposes no getter (only the SNIP-12 `approval_digest` view
/// recomputes over them), so the proposer publishes the CLAIMED params as a
/// blob at this conventional key — and every voter VERIFIES the claim against
/// the chain before predicating on it (verifiedParams below). Untrusted
/// storage, verify-on-read: the untrusted-storage boundary, applied to params.
export const proposalParamsKey = pendingParamsKey;

/// Fetch the claimed params for a folded proposal and PROVE they are the real
/// ones: the off-chain SNIP-12 hash over the claim must equal the contract's
/// `approval_digest(id, approver)`, which is computed from immutable stored
/// state. A swapped/forged side-channel blob throws here — a predicate never
/// sees unverified params.
export async function verifiedParams({ view, store, chainId, contractAddress, proposal, approver }) {
  const raw = await store.getText(proposalParamsKey(proposal.prefix, proposal.id));
  const params = JSON.parse(raw).params;
  await assertRoundTrip(
    view,
    {
      verifyingContract: contractAddress,
      chainId,
      proposalId: proposal.id,
      action: str(proposal.action),
      prefix: str(proposal.prefix),
      params,
    },
    approver,
  );
  return params;
}

/// Chain IO for one voter identity — the reconcile engine's makeChainOps analog.
///   view    read-only Contract (bitcd ABI on a provider)
///   writer  Contract connected to the voter's account
///   provider RpcProvider (awaits the vote tx)
/// Wait for a transaction and fail unless it executed: a node reports a
/// reverted transaction as accepted, and a reverted vote must not count as cast.
export async function waitSucceeded(provider, transactionHash) {
  const r = await provider.waitForTransaction(transactionHash);
  const status = r?.execution_status ?? r?.value?.execution_status;
  if (status === "REVERTED") throw new Error(`transaction ${transactionHash} reverted: ${r?.revert_reason ?? r?.value?.revert_reason ?? "no reason given"}`);
  return r;
}

export function makeVoterOps({ view, writer, provider }) {
  return {
    getSigner: async (address) => {
      const s = await view.get_signer(address);
      return {
        active: Boolean(s.active),
        is_human: Boolean(s.is_human),
        operator_id: decodeFelt(s.operator_id),
        role: decodeFelt(s.role),
      };
    },
    approve: async (proposalId) => {
      const { transaction_hash } = await writer.approve(proposalId);
      await waitSucceeded(provider, transaction_hash);
      return transaction_hash;
    },
    requestHumanReview: async (proposalId) => {
      const { transaction_hash } = await writer.request_human_review(proposalId);
      await waitSucceeded(provider, transaction_hash);
      return transaction_hash;
    },
  };
}

/// One poll pass for a voter daemon: fold the proposal stream, decide every
/// open proposal this identity has not voted on, cast APPROVE votes on-chain,
/// and append every non-ABSTAIN decision to the tamper-evident evidence log.
/// Level-triggered and idempotent: each pass decides from the current fold, so
/// a proposal a reorg dropped is simply gone from it. A decision is remembered
/// in `seen`, though: a vote a reorg removed is cast again only by a pass that
/// starts with a fresh `seen` (a restarted daemon).
/// Returns the decisions taken this pass: [{ id, vote, reason, escalated }],
/// plus { failed: true } for a proposal whose votes didn't land this pass.
///
/// `seen` (caller-held Set, per daemon process) dedups WITHHOLD/escalation
/// records across passes — an APPROVE dedups itself via the on-chain approver
/// set, but a withheld vote leaves no chain trace, so without `seen` every poll
/// would re-append the same evidence line. A proposal enters `seen` only once
/// its transactions have landed: a failed approve or escalation is retried on
/// the next pass, and an agent that already approved but whose escalation
/// never landed asks for it again. `proposals` (already folded) skips the
/// event fetch. `held` (a caller-held Set) gets each proposal whose votes
/// failed the moment they fail, and loses it once they land or the chain
/// shows them — so a caller relaying commits can hold those back. A decision
/// that throws holds its proposal too, and the round goes on. `owed` (a
/// caller-held Set) remembers escalations this agent decided on: each is sent
/// again every round until the chain shows it, and nothing decided later
/// cancels it.
export async function voteOnce({
  provider, address, self, ops, skill, fetchCtx, evidence, log,
  seen = new Set(),
  escalate, // optional: (proposal, decision) -> bool — demand a human reviewer on doubt
  proposals,
  held, // optional Set: proposals whose vote or escalation hasn't landed, kept up to date as it goes
  owed = new Set(), // caller-held Set: escalations this agent decided on that haven't landed yet
}) {
  const folded = proposals ?? projectProposals(await fetchAllEvents(provider, address));
  const me = BigInt(self);
  const isMe = (a) => BigInt(a) === me;
  const out = [];
  const fail = (p, vote, e) => {
    // Not marked seen: the next pass tries again. Held, so a caller that
    // relays commits keeps this proposal back until its votes land.
    log?.(`[${skill.operatorId}] proposal ${p.id}: vote not recorded (${(e?.message ?? String(e)).slice(0, 120)}) — retrying next pass`);
    held?.add(p.id);
    out.push({ id: p.id, vote, reason: e?.message ?? String(e), escalated: false, failed: true });
  };
  const release = (id) => { if (!owed.has(id)) held?.delete(id); };
  for (const p of folded) {
    if (p.committed) continue;
    const approved = [...p.approvers].some(isMe);
    let escalatedByMe = [...(p.escalatedBy ?? [])].some(isMe);
    // An escalation this agent owes is sent again until the chain shows it;
    // no later decision (a WITHHOLD on missing context, say) can cancel it.
    if (owed.has(p.id)) {
      if (!escalatedByMe) {
        try { await ops.requestHumanReview(p.id); } catch (e) { fail(p, null, e); continue; }
        escalatedByMe = true;
      }
      owed.delete(p.id);
    }
    // Skipped (decided before, or not decidable yet): its hold, if any, stays.
    if (seen.has(p.id)) continue;
    if (approved && (!escalate || escalatedByMe)) { release(p.id); continue; } // nothing left for this agent to do
    let decision;
    try {
      decision = await decide(p, { getSigner: ops.getSigner, fetchCtx, skill });
    } catch (e) { fail(p, null, e); continue; }
    if (decision.vote === VOTE.ABSTAIN) { seen.add(p.id); release(p.id); continue; }
    let escalated = false;
    try {
      // Escalate BEFORE approving: once the demand for a human has landed,
      // no commit can skip it, so an approval that completes the machine
      // quorum can't be committed around a failed escalation. The obligation
      // is recorded before it is sent.
      if (escalate && !escalatedByMe && (await escalate(p, decision))) {
        owed.add(p.id);
        await ops.requestHumanReview(p.id);
        owed.delete(p.id);
        escalated = true;
      }
      if (decision.vote === VOTE.APPROVE && !approved) await ops.approve(p.id);
    } catch (e) { fail(p, decision.vote, e); continue; }
    release(p.id);
    seen.add(p.id);
    // An agent that had already approved (a restart, or a retried escalation)
    // records only what it did now.
    if (approved && !escalated) continue;
    evidence?.append({
      actor: skill.operatorId,
      skill: skill.name,
      proposalId: p.id,
      action: p.action,
      prefix: p.prefix,
      verdict: decision.vote,
      reason: decision.reason ?? null,
      evidence: decision.evidence ?? null,
      ...(escalated ? { escalated: true } : {}),
    });
    log?.(`[${skill.operatorId}] proposal ${p.id} (${p.action} ${p.prefix}): ${decision.vote}${decision.reason ? ` — ${decision.reason}` : ""}${escalated ? " [escalated to human]" : ""}`);
    out.push({ id: p.id, vote: decision.vote, reason: decision.reason, escalated });
  }
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/// The contract's revert reason in an error message — a Cairo short string
/// such as 'proposal: executed' — or null when the failure didn't come from the
/// contract (network, timeout, nonce).
export function contractReason(message) {
  const m = String(message).match(/'([a-z_]+: [^']{1,56})'/i) ?? String(message).match(/\('([^']{1,31})'\)/);
  return m ? m[1] : null;
}

/// Is the proposal's params side channel published yet? The DEFAULT decidability
/// test (see makeFleetPeer's `isDecidable`).
export function paramsPublished(store) {
  return async (proposal) => {
    try {
      await store.getText(proposalParamsKey(proposal.prefix, proposal.id));
      return true;
    } catch {
      return false;
    }
  };
}

/// Build a fleet peer daemon — the reusable daemon SHELL (poll -> decide ->
/// escalate -> vote -> append evidence -> relay commit). A peer daemon is this
/// shell plus the CONFIGURATION it carries (which identity, which prefix, which
/// skill, which ctx); the shell is the same for every fleet, so a second fleet
/// is a configuration, never a copied loop. Returns { pass, watch, status }.
///
///   contractAddress, self:{address, operator}   identity
///   prefixStr, skill, fetchCtx, escalate        the fleet's configuration
///   view, writer, provider, store               chain/blob IO
///   evidence, log                               observability
///   hooks: { beforePass, afterPass }            optional (a startup/liveness gate,
///                                               a post-settle publish step, …)
///   isDecidable(proposal) -> bool               optional; default paramsPublished
///   paramsGraceMs                               how long a not-yet-decidable proposal
///                                               is WAITED for before being decided
///   now                                         injectable clock (tests)
export function makeFleetPeer({
  contractAddress, self,
  prefixStr, skill, fetchCtx, escalate,
  view, writer, provider, store,
  evidence, log = () => {},
  hooks = {},
  isDecidable,
  paramsGraceMs = 60_000,
  now = () => Date.now(),
}) {
  const ops = makeVoterOps({ view, writer, provider });
  const decidable = isDecidable ?? paramsPublished(store);

  const decided = new Set();     // proposals this process has voted on (engine `seen`)
  const firstSeenAt = new Map(); // proposal id -> when this daemon first observed it
  const commitRefused = new Set();
  const heldBack = new Set();    // proposals whose vote or escalation hasn't landed yet
  const escalationsOwed = new Set(); // escalations decided on but not yet on chain

  const mine = (p) => p.prefix === prefixStr;

  /// A proposal is not fully published until BOTH its tx and its claimed params
  /// exist — `propose` confirms first, the side-channel PUT lands after. A peer
  /// polling in that window cannot verify the claim. A predicate that answered
  /// that with a WITHHOLD would be final: the engine's `seen` set is a ONE-WAY
  /// DOOR, a decided proposal is never re-decided, so a LEGITIMATE proposal
  /// would stay WITHHELD for the life of the process.
  ///
  /// So "not yet decidable" must be expressed by SKIPPING, never by deciding —
  /// bounded by paramsGraceMs, after which it is decided normally and thus still
  /// fails closed. (A `seen` object, so the engine has no notion of readiness.)
  async function seenFor(proposals) {
    const notReady = new Set();
    for (const p of proposals) {
      if (p.committed || !mine(p) || decided.has(p.id)) continue;
      const first = firstSeenAt.get(p.id) ?? now();
      firstSeenAt.set(p.id, first);
      if (now() - first > paramsGraceMs) continue; // grace spent -> decide (fails closed)
      if (!(await decidable(p))) {
        notReady.add(p.id);
        log(`proposal ${p.id}: on chain, its request document not yet published — waiting`);
      }
    }
    return {
      has: (id) => decided.has(id) || notReady.has(id),
      add: (id) => decided.add(id),
    };
  }

  /// Relay commit for this prefix's open proposals — commit is permissionless.
  /// 'policy unmet' is the quiet steady state (the quorum isn't there yet — retry
  /// next pass). Any OTHER contract guard is a PERMANENT refusal: log it once.
  /// An error that carries no contract reason (the RPC timed out, a nonce
  /// race) is transient and retried next pass.
  async function relayCommits(proposals) {
    for (const p of proposals) {
      if (p.committed || !mine(p) || commitRefused.has(p.id)) continue;
      try {
        const { transaction_hash } = await writer.commit(p.id);
        await waitSucceeded(provider, transaction_hash);
        log(`proposal ${p.id} committed`);
        p.committed = true; // so this pass's afterPass hook sees it settled
      } catch (e) {
        const m = e?.message ?? String(e);
        if (/policy unmet/.test(m)) continue;
        const reason = contractReason(m);
        if (reason === null) {
          log(`proposal ${p.id} commit failed (${m.slice(0, 120)}) — retrying next pass`);
          continue;
        }
        // 'proposal: executed' is the race every peer but one loses: another
        // peer's commit landed first, which is the outcome this pass wanted.
        log(reason === "proposal: executed"
          ? `proposal ${p.id} already committed by a peer`
          : `proposal ${p.id} commit refused: ${reason} — not retrying`);
        commitRefused.add(p.id);
      }
    }
  }

  /// One poll pass. Level-triggered and idempotent. A proposal whose vote or
  /// escalation failed isn't committed by this peer until a later vote lands:
  /// otherwise earlier approvals could carry it past a human the peer meant
  /// to summon.
  async function pass() {
    await hooks.beforePass?.();
    const proposals = projectProposals(await fetchAllEvents(provider, contractAddress));
    // heldBack is updated as each vote fails or lands, and survives a round
    // that skips the proposal (say, its params are unreadable); owed keeps an
    // escalation this peer decided on until the chain shows it.
    const decisions = await voteOnce({
      provider, address: contractAddress, self: self.address, ops, skill, fetchCtx,
      evidence, log, escalate, proposals, held: heldBack, owed: escalationsOwed,
      seen: await seenFor(proposals),
    });
    await relayCommits(proposals.filter((p) => !heldBack.has(p.id)));
    await hooks.afterPass?.(proposals);
    return decisions;
  }

  async function watch({ intervalMs = 5000 } = {}) {
    log(`peer ${self.operator} watching ${contractAddress} prefix=${prefixStr} (@${intervalMs / 1000}s)`);
    // eslint-disable-next-line no-constant-condition
    while (true) {
      // A hook may deliberately terminate the process (e.g. a capability gate
      // that fails closed); everything else — RPC blips, blob-store hiccups — is
      // caught and retried on the next tick.
      try { await pass(); } catch (e) { console.error(`loop error: ${e?.message ?? e}`); }
      await sleep(intervalMs);
    }
  }

  async function status() {
    const proposals = projectProposals(await fetchAllEvents(provider, contractAddress));
    return proposals.filter(mine).map((x) => ({
      ...x,
      approvers: [...x.approvers],
      intentSigned: [...x.intentSigned],
      escalatedBy: [...x.escalatedBy],
    }));
  }

  return { pass, watch, status };
}
