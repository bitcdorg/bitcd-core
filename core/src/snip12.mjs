// Shared SNIP-12 (typed-data) helpers for intent-bound human approvals.
//
// A human approves *readable intent*, not raw calldata: a wallet renders this typed
// data and the human signs it; an UNTRUSTED relayer submits the collected signatures
// via `approve_sigs`. The typed-data hash MUST equal the contract's `approval_digest`
// — `assertRoundTrip()` proves it. This is the SNIP-12-rev1 encoding fragility point:
// the Cairo `snip12.cairo` constants are set to match exactly what starknet.js
// produces here (notably `version`/`revision` are the felt 1, and action/prefix are
// passed as their already-encoded felt so rev-1's `getHex` passes them through).
//
// This module is PURE (depends only on starknet) so it can be shared verbatim by
// the e2e rig, the product daemons, and the console — the typed-data encoding lives in ONE
// place. The orchestration wrapper `approveWithSigs` lives in client.mjs.
import { hash, num, shortString, stark, typedData as td } from "starknet";

// Must match contracts/src/snip12.cairo PARAMS_HASH_TAG ('bitcd:params:v1').
const PARAMS_HASH_TAG = shortString.encodeShortString("bitcd:params:v1");

/// poseidon_hash_span([TAG, len, ...params]) — matches Cairo snip12::params_hash over
/// the proposal's IMMUTABLE stored params (length-prefixed + domain-tagged).
export function paramsHash(params) {
  const els = [PARAMS_HASH_TAG, num.toHex(params.length), ...params.map((x) => num.toHex(x))];
  return num.toHex(hash.computePoseidonHashOnElements(els));
}

/// The SNIP-12 typed data a human signs to approve a proposal. `action`/`prefix` are
/// the already-encoded short-string felts (e.g. ACTION.FORCE_UNLOCK); the wallet shows
/// them as the intent. `chainId` is the provider's chain id (felt hex). The contract
/// recomputes the identical hash from immutable stored state in `approve_sigs`.
export function approvalTypedData({ verifyingContract, chainId, proposalId, action, prefix, params }) {
  return {
    types: {
      StarknetDomain: [
        { name: "name", type: "shortstring" },
        { name: "version", type: "shortstring" },
        { name: "chainId", type: "shortstring" },
        { name: "revision", type: "shortstring" },
      ],
      Approval: [
        { name: "verifyingContract", type: "felt" },
        { name: "proposalId", type: "felt" },
        { name: "action", type: "shortstring" },
        { name: "prefix", type: "shortstring" },
        { name: "paramsHash", type: "felt" },
      ],
    },
    primaryType: "Approval",
    // version/revision are "1" -> rev-1 getHex maps them to felt 1 (matches Cairo).
    domain: { name: "bitcd", version: "1", chainId, revision: "1" },
    message: {
      verifyingContract: num.toHex(verifyingContract),
      proposalId: num.toHex(proposalId),
      action: num.toHex(action),
      prefix: num.toHex(prefix),
      paramsHash: paramsHash(params),
    },
  };
}

/// The off-chain message hash for `(args, approver)` — must equal `approval_digest`.
export function approvalMessageHash(args, approver) {
  return td.getMessageHash(approvalTypedData(args), approver);
}

/// Sign the typed data with the approver account (the realistic wallet flow:
/// `signMessage` renders+hashes+signs). Returns a contract `SignedApproval`.
export async function signApproval(acct, args) {
  const sig = await acct.signMessage(approvalTypedData(args), acct.address);
  return { approver: acct.address, signature: stark.formatSignature(sig) };
}

/// Prove the off-chain typed-data hash equals the on-chain `approval_digest` for
/// `(proposalId, approver)`. Throws on mismatch (the round-trip the audit requires).
/// `view` is any Contract with the bitcd ABI attached to a provider.
export async function assertRoundTrip(view, args, approver) {
  const offchain = BigInt(approvalMessageHash(args, approver));
  const onchain = BigInt(await view.approval_digest(args.proposalId, approver));
  if (offchain !== onchain) {
    throw new Error(
      `SNIP-12 round-trip mismatch for ${approver}: offchain ${num.toHex(offchain)} != onchain ${num.toHex(onchain)}`,
    );
  }
}
