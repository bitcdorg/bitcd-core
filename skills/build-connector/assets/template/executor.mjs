#!/usr/bin/env node
// executor.mjs — the loop around the reconcile step in @bitcd/core.
//
//   node executor.mjs observe   desired, observed and the derived condition, then exit
//   node executor.mjs once      one pass: gate, then revoke / reconcile / drift check
//   node executor.mjs watch     the pass every BITCD_INTERVAL_MS
//
// Environment:
//   BITCD_RPC                              default http://localhost:5051
//   BITCD_DEPLOYMENT_FILE                  the deployment record
//   BITCD_S3_ENDPOINT, BITCD_S3_BUCKET     the document store (defaults: the dev stack)
//   BITCD_EXECUTOR_ADDRESS, BITCD_EXECUTOR_PK   this connector's executor account
//   BITCD_VALUE_KEY                        the governed key, default iam/acct/pset (the rig's)
//   BITCD_SPEC_KEY                         the document's key in the store, default iam/acct/spec
//   BITCD_MANIFEST_KEY                     default sys/manifest
//   BITCD_LIVE_FILE                        the stand-in provider's file, default ./live/state.json
//   BITCD_INTERVAL_MS, BITCD_GRACE_MS      default 5000 / 30000
import { pathToFileURL } from "node:url";
import { account, applyNoProxy, bitcdContract, loadDeployment, provider, str } from "@bitcd/core/client";
import { deriveCondition, driftCheckOnce, makeChainOps, reconcileOnce } from "@bitcd/core/reconcile";
import { s3Store } from "@bitcd/core/store";
import { loadOrgManifest, makeGate } from "@bitcd/core/org/loader";
import { DEFAULT_MANIFEST_KEY, manifestSpecKey } from "@bitcd/core/org/manifest";
import { makeProvider } from "./provider.mjs";

applyNoProxy();
const env = (k, d) => process.env[k] ?? d;

// Everything the pass needs, from the environment.
export function wire({ log = console.log } = {}) {
  const p = provider();
  const dep = loadDeployment();
  const view = bitcdContract(dep.address, p);
  const executor = { address: env("BITCD_EXECUTOR_ADDRESS"), pk: env("BITCD_EXECUTOR_PK") };
  if (!executor.address || !executor.pk) throw new Error("BITCD_EXECUTOR_ADDRESS and BITCD_EXECUTOR_PK are required");
  const writer = bitcdContract(dep.address, account(executor, p));
  const store = s3Store();
  const valueKeyStr = env("BITCD_VALUE_KEY", "iam/acct/pset");
  const manifestKey = env("BITCD_MANIFEST_KEY", DEFAULT_MANIFEST_KEY);
  const prov = makeProvider({ path: env("BITCD_LIVE_FILE", "./live/state.json"), log });
  const ops = makeChainOps({
    view, writer, provider: p, store,
    valueKey: str(valueKeyStr), specKey: env("BITCD_SPEC_KEY", "iam/acct/spec"),
    getLiveBlob: prov.getLiveBlob, applyToProvider: prov.applyToProvider, log,
  });
  // The organization's definition, by verify-on-read. HALT means apply nothing.
  const gate = makeGate({
    load: () => loadOrgManifest({
      getValue: () => view.get_value(str(manifestKey)),
      getBlob: () => store.getText(manifestSpecKey(manifestKey)),
      valueKeyStr: manifestKey,
    }),
    graceMs: Number(env("BITCD_GRACE_MS", "30000")),
  });
  return { p, dep, view, store, ops, gate, prov, valueKeyStr, log };
}

// What a reader concludes from the chain alone: SYNCED, FAILED or OUTOFSYNC.
export async function derived(ops) {
  const v = await ops.getValue();
  const s = await ops.getStatus();
  const condition = s.exists
    ? deriveCondition({
      desiredVersion: v.version, desiredDigest: v.digest,
      observedRevision: s.observed_revision, observedDigest: s.observed_digest, claimed: s.condition,
    })
    : "OUTOFSYNC";
  return { condition, desired: v, observed: s };
}

// One pass. `state` remembers what this process applied or revoked, so a
// tombstone is revoked once and a failed apply is retried on the next pass.
export async function pass(ctx, state) {
  const { ops, gate, prov, log } = ctx;
  const g = await gate.check();
  if (g.action !== "RUN") {
    log(`${g.action}: ${g.reason}`);
    return { action: g.action, reason: g.reason };
  }
  const v = await ops.getValue();
  if (v.version === 0) return { action: "RUN", outcome: "no value yet" };
  if (v.tombstoned) {
    if (state.revokedAt === v.version) return { action: "RUN", outcome: "revoked", version: v.version };
    await prov.revoke();
    await ops.setStatus({ observed_revision: v.version, applied_hash: "0x0", condition: "SYNCED", reason: "revoked" });
    state.revokedAt = v.version;
    return { action: "RUN", outcome: "revoked", version: v.version };
  }
  if (v.version !== state.applied) {
    const r = await reconcileOnce(ops); // fetch, verify, apply, re-read, attest
    if (r.condition === "SYNCED") state.applied = v.version;
    return { action: "RUN", outcome: r.condition, reason: r.reason, version: v.version };
  }
  const d = await driftCheckOnce(ops); // re-read the system, attest what is there
  if (BigInt(d.observedDigest) !== BigInt(d.desiredDigest)) {
    const r = await reconcileOnce(ops); // drift: put it back
    return { action: "RUN", outcome: `drift repaired: ${r.condition}`, version: v.version };
  }
  return { action: "RUN", outcome: "in sync", version: v.version };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const cmd = process.argv[2] ?? "once";
  const ctx = wire();
  const state = { applied: 0, revokedAt: 0 };
  if (cmd === "observe") {
    console.log(JSON.stringify({ key: ctx.valueKeyStr, ...(await derived(ctx.ops)) }, null, 2));
  } else if (cmd === "once") {
    console.log(JSON.stringify(await pass(ctx, state)));
  } else if (cmd === "watch") {
    const interval = Number(env("BITCD_INTERVAL_MS", "5000"));
    for (;;) {
      console.log(JSON.stringify(await pass(ctx, state)));
      await new Promise((f) => setTimeout(f, interval));
    }
  } else {
    console.error("usage: executor.mjs observe | once | watch");
    process.exit(2);
  }
}
