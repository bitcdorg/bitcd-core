// @bitcd/core/ceremony — declare/deploy and the bootstrap-then-renounce arc.
//
// The ceremony SHAPE is library code; the seed DATA (which signers, which
// policies) is the consumer's — declared in a `bitcd.yaml` and driven through
// the `bitcd` CLI (./cli.mjs), or passed here directly as a reviewed seed table.
//
// After `renounce: true` no single actor remains: the only path to change
// governance is a quorum-approved proposal.
// VERIFY THE SEED BY READING IT BACK before renouncing on anything irreversible.
import { writeFileSync } from "node:fs";
import { artifactSource, casm as embeddedCasm, manifest as bundledManifest, sierra as embeddedSierra } from "./artifacts.mjs";
import { waitSucceeded } from "./tx.mjs";

/// Declare + deploy with `owner` (an Account) as the transient super-admin, and
/// record {address, classHash, owner, rpc} at `deploymentFile` (if given).
/// `rpc` is recorded verbatim (falls back to the account's channel URL if absent).
export async function deployBitcd({ owner, sierra, casm, deploymentFile, rpc, log = () => {} }) {
  const contract = sierra ?? embeddedSierra();
  const compiled = casm ?? embeddedCasm();
  const source = sierra ? "caller" : artifactSource();
  log(`declaring Bitcd from the ${source} class (owner = ${owner.address})`);
  const { declare, deploy } = await owner.declareAndDeploy({
    contract,
    casm: compiled,
    constructorCalldata: [owner.address],
  });
  const classHash = declare?.class_hash ?? deploy.classHash;
  const address = deploy.contract_address ?? deploy.address;
  // The block the contract first exists at: readers scan its events from
  // here, never from genesis (a public node refuses that range).
  let block;
  try {
    const rcpt = await owner.getTransactionReceipt(deploy.transaction_hash);
    block = Number(rcpt.block_number ?? rcpt.value?.block_number);
  } catch {
    block = undefined;
  }
  log(`class hash : ${classHash}`);
  // The bundled class is the one CI builds and checks; say so when this isn't it.
  const pinned = bundledManifest()?.classHash;
  if (pinned && BigInt(classHash) !== BigInt(pinned)) {
    log(`WARNING: this is not the bundled class ${pinned} (MANIFEST.json) — deployed from the ${source} class`);
  }
  log(`deployed at: ${address}`);
  const record = {
    address, classHash, owner: owner.address, rpc: rpc ?? owner.channel?.nodeUrl,
    ...(Number.isFinite(block) ? { block } : {}),
  };
  if (deploymentFile) {
    writeFileSync(deploymentFile, JSON.stringify(record, null, 2));
    log(`wrote ${deploymentFile}`);
  }
  return record;
}

/// Signer struct for `set_signer` from a cast entry ({is_human, operator_id, role}).
export const signerSpec = (a) => ({
  active: true,
  is_human: a.is_human,
  operator_id: a.operator_id,
  role: a.role,
});

/// Policy struct for `set_policy`.
export const policySpec = (threshold, role, min_humans, max_per_operator, allow_open) => ({
  threshold, role, min_humans, max_per_operator, allow_open, exists: true,
});

/// Seed signers + policies through an OWNER-connected contract handle, then
/// optionally renounce. `signers` = [{ label?, address, signer }] (signer =
/// signerSpec(...)); `policies` = [{ label?, prefix, action, policy }].
/// Every tx is awaited (the seed must land in order before renounce), and a
/// reverted one stops the ceremony there: nothing after it is sent.
export async function runCeremony({ contract, provider, signers = [], policies = [], renounce = false, log = () => {} }) {
  async function send(label, call) {
    const { transaction_hash } = await call;
    await waitSucceeded(provider, transaction_hash, label);
    log(`  ok  ${label}  (${transaction_hash.slice(0, 10)})`);
  }
  for (const s of signers) {
    await send(s.label ?? `set_signer ${s.address.slice(0, 10)}`, contract.set_signer(s.address, s.signer));
  }
  for (const p of policies) {
    await send(p.label ?? "set_policy", contract.set_policy(p.prefix, p.action, p.policy));
  }
  if (renounce) {
    log("renouncing ownership (no single actor remains)");
    await send("renounce_ownership", contract.renounce_ownership());
  }
}
