// @bitcd/core/reconcile — the executor engine: the reconcile STEP,
// the drift pass, the authoritative-condition derivation, and the chain+blob `ops`
// wiring every executor daemon shares.
//
// The control-plane loop, one pass: watch (caller) -> fetch -> verify -> apply ->
// ack. All IO is INJECTED via `ops`, so `reconcileOnce`/`driftCheckOnce` import
// nothing and are shared verbatim by the deterministic e2e beats, the chainops
// daemon, the in-cluster k8s-rbac bridge, and the console scenarios. The contract
// guarantees who decided + that bytes are unaltered; this code drives the untrusted
// provider toward desired and ATTESTS what it actually observed.
//
// `ops` (all async unless noted):
//   getValue()            -> { digest, schema_ref, storage_class, version, tombstoned }  (felts as hex strings)
//   getStatus()           -> { observed_revision, observed_digest, condition, status_version, exists }
//   getSpecBlob()         -> string  (the desired bytes from storage — S3)
//   getLiveBlob()         -> string  (re-read the live provider surface; throws if missing)
//   applyToProvider(text) -> actuate the verified desired config onto the live provider
//   setStatus({ observed_revision, applied_hash, condition, reason })   (the attestation)
//   digestOf(text)        -> "0x..."  (starknetKeccak — NOT async)
//   log?(msg)             -> optional progress sink
//
// An executor ATTESTS its apply OUTCOME — `SYNCED` (applied/observed this
// live hash) or `FAILED` (apply errored). It does NOT attest `OUTOFSYNC`: drift
// (agreed hash != desired digest) is DERIVED by the reader (indexer/UI). The contract
// promotes the aggregate only on k-of-n agreement on the same (revision, hash).
import { num, shortString } from "starknet";
import { digestOf } from "./protocol.mjs";
import { waitSucceeded } from "./tx.mjs";

/// Observed-state conditions AS STRINGS (what `ops.setStatus` receives and the
/// folds compare). The felt map the contract takes is CONDITION_FELT in ./protocol.
export const CONDITION = {
  SYNCED: "SYNCED",
  OUTOFSYNC: "OUTOFSYNC",
  FAILED: "FAILED",
  PROGRESSING: "PROGRESSING",
};

/// Canonical serialization so a digest is stable regardless of key order or
/// whitespace (the executor and whoever proposed the spec MUST agree byte-for-byte,
/// or verify-on-read would spuriously fail). Sorts object keys recursively.
export function renderConfig(config) {
  return JSON.stringify(sortDeep(config));
}

function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    return Object.fromEntries(
      Object.keys(v).sort().map((k) => [k, sortDeep(v[k])]),
    );
  }
  return v;
}

/// The AUTHORITATIVE condition — DERIVED, never blindly trusted from the executor's
/// self-report (a compromised single executor that writes condition=SYNCED with a
/// stale digest is caught here; k-of-n attestation removes the rest of that trust).
///
///   SYNCED    <=> the observed revision has caught up to desired AND the observed
///                 (live) digest equals the desired digest
///   FAILED    <=> not provably synced AND the executor reported an apply failure
///   OutOfSync <=> otherwise (drift: digests differ; or lag: observed_revision <
///                 desired_version because a new desired revision is not yet applied)
export function deriveCondition({
  desiredVersion,
  desiredDigest,
  observedRevision,
  observedDigest,
  claimed,
}) {
  const caughtUp = Number(observedRevision) >= Number(desiredVersion);
  const matches = digestEq(observedDigest, desiredDigest);
  if (caughtUp && matches) return CONDITION.SYNCED;
  if (claimed === CONDITION.FAILED) return CONDITION.FAILED;
  return CONDITION.OUTOFSYNC;
}

/// One full reconcile pass. A missing or tampered document, an apply that
/// throws, or `opts.failApply` (which simulates one) is reported FAILED
/// (desired is never rewritten; rollback is a new governed revision) and
/// returned as { condition, reason, version, error? }; `opts.reportFailure:
/// false` skips the report. Otherwise returns { condition, observedDigest,
/// desiredDigest, present, version }.
export async function reconcileOnce(ops, opts = {}) {
  const v = await ops.getValue();
  if (v.tombstoned) {
    ops.log?.("desired is tombstoned — nothing to reconcile");
    return { condition: "TOMBSTONED", version: Number(v.version) };
  }

  // verify-on-read (the untrusted-storage boundary): the spec blob in
  // storage MUST hash to the on-chain digest, or the executor refuses to apply a
  // swapped/corrupted desired and reports FAILED.
  let spec;
  try {
    spec = await ops.getSpecBlob();
  } catch (e) {
    return ackFailure(ops, v, "spec-missing", opts);
  }
  if (!digestEq(ops.digestOf(spec), v.digest)) {
    ops.log?.("verify-on-read FAILED — spec blob does not match on-chain digest");
    return ackFailure(ops, v, "spec-tamper", opts);
  }

  if (opts.failApply) {
    ops.log?.("apply failed (simulated) — reporting FAILED, desired untouched");
    return ackFailure(ops, v, "apply-error", opts);
  }

  // apply: drive the live provider to the verified desired config. A provider
  // that throws is reported FAILED (apply-error) rather than left looking like
  // the previous state.
  try {
    await ops.applyToProvider(spec);
  } catch (e) {
    const error = e?.message ?? String(e);
    ops.log?.(`apply failed — ${error}`);
    return { ...(await ackFailure(ops, v, "apply-error", opts)), error };
  }
  return ackObserve(ops, v, "applied");
}

/// Drift pass: re-read the LIVE provider (no apply) and re-attest. This is what
/// makes it a reconciler — an out-of-band edit surfaces as OutOfSync with the
/// on-chain desired unchanged.
export async function driftCheckOnce(ops) {
  const v = await ops.getValue();
  if (v.tombstoned) return { condition: "TOMBSTONED", version: Number(v.version) };
  return ackObserve(ops, v, "drift-scan");
}

// Re-read live and attest SYNCED with the observed hash at this revision;
// whether that is Synced or OutOfSync is the reader's derivation.
async function ackObserve(ops, v, reason) {
  let observedDigest;
  let present = true;
  try {
    const live = await ops.getLiveBlob();
    observedDigest = ops.digestOf(live);
  } catch (e) {
    // The provider object is gone — attest the sentinel; the reader treats hash 0 as
    // "no live state" (a kind of drift). Apply itself succeeded, so condition SYNCED.
    observedDigest = "0x0";
    present = false;
  }
  // Attest the apply OUTCOME (SYNCED) + the observed hash. Drift/Synced is
  // the reader's derivation (hash vs desired digest); k-of-n agreement is on the hash.
  await ops.setStatus({
    observed_revision: v.version,
    applied_hash: observedDigest,
    condition: CONDITION.SYNCED,
    reason,
  });
  return { condition: CONDITION.SYNCED, observedDigest, desiredDigest: v.digest, present, version: Number(v.version) };
}

// Apply failed — attest FAILED with the sentinel hash (0). Desired is never
// touched. `reportFailure: false` (a caller that already reported this
// revision's failure) skips the attestation and keeps the result.
async function ackFailure(ops, v, reason, opts = {}) {
  if (opts.reportFailure === false) return { condition: CONDITION.FAILED, reason, version: Number(v.version), reported: false };
  await ops.setStatus({
    observed_revision: Number(v.version),
    applied_hash: "0x0",
    condition: CONDITION.FAILED,
    reason,
  });
  return { condition: CONDITION.FAILED, reason, version: Number(v.version) };
}

function digestEq(a, b) {
  try {
    return BigInt(a) === BigInt(b);
  } catch {
    return String(a) === String(b);
  }
}

// --------------------------------------------------------------------------------
// makeChainOps — the chain+blob `ops` wiring shared by every executor daemon
// (chainops daemon, e2e beat, k8s-rbac bridge, console scenario). The default
// provider surface is a blob store ("live" object = the actuated state); a real
// provider (k8s API, AWS IAM) swaps `getLiveBlob`/`applyToProvider` via the
// overrides — the provider adapter seam.
// --------------------------------------------------------------------------------

const str = (s) => shortString.encodeShortString(s);
const decodeFelt = (felt) => {
  try {
    return shortString.decodeShortString(num.toHex(felt)) || num.toHex(felt);
  } catch {
    return num.toHex(felt);
  }
};

/// Build the injected-IO `ops` object for `reconcileOnce`/`driftCheckOnce`.
///   view     read-only Contract (bitcd ABI on a provider)
///   writer   Contract connected to the EXECUTOR account (SET_STATUS role)
///   provider RpcProvider (awaits the attest tx)
///   valueKey the value's felt key (already-encoded shortstring)
///   store    s3Store() handle (or any {getText, putText})
///   specKey  blob key of the governed desired bytes
///   liveKey  blob key of the live provider surface (default store-backed provider)
///   getLiveBlob/applyToProvider  optional real-provider overrides (k8s, IAM, ...)
export function makeChainOps({
  view, writer, provider, valueKey, store, specKey, liveKey,
  getLiveBlob, applyToProvider, log,
}) {
  return {
    getValue: async () => {
      const v = await view.get_value(valueKey);
      return {
        digest: "0x" + v.digest.toString(16),
        schema_ref: v.schema_ref,
        storage_class: v.storage_class,
        version: Number(v.version),
        tombstoned: Boolean(v.tombstoned),
      };
    },
    getStatus: async () => {
      const s = await view.get_status(valueKey);
      return {
        observed_revision: Number(s.observed_revision),
        observed_digest: "0x" + s.observed_digest.toString(16),
        condition: decodeFelt(s.condition),
        status_version: Number(s.status_version),
        exists: Boolean(s.exists),
      };
    },
    getSpecBlob: () => store.getText(specKey),
    getLiveBlob: getLiveBlob ?? (() => store.getText(liveKey)),
    applyToProvider: applyToProvider ?? ((text) => store.putText(liveKey, text)),
    digestOf,
    setStatus: async ({ observed_revision, applied_hash, condition, reason }) => {
      const { transaction_hash } = await writer.set_status(
        valueKey, observed_revision, applied_hash, str(condition), str(String(reason).slice(0, 31)),
      );
      // A reverted attestation is not an attestation: the caller must not
      // go on as if the chain recorded it.
      await waitSucceeded(provider, transaction_hash, "set_status");
    },
    log,
  };
}
