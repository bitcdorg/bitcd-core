// @bitcd/core/client — construct providers/accounts/contract handles and the
// SNIP-12 approve-with-signatures orchestration.
//
// Everything here is chain-generic: no devnet accounts, no demo prefixes. The
// demo cast lives in e2e/scripts/config.mjs; production casts come from the
// consumer (e.g. a BITCD_ACCOUNTS_FILE the e2e rig reads).
import { readFileSync } from "node:fs";
import { Account, Contract, RpcProvider } from "starknet";
import { abi as embeddedAbi } from "./artifacts.mjs";
import { assertRoundTrip, signApproval } from "./snip12.mjs";

export { str } from "./protocol.mjs";

/// Add hosts to NO_PROXY/no_proxy so a corporate/localhost proxy never intercepts
/// RPC. EXPLICIT — importing this module never mutates the environment; call it
/// from your entrypoint (the e2e scripts and daemons do).
export function applyNoProxy(hosts = "localhost,127.0.0.1,0.0.0.0") {
  process.env.NO_PROXY = [process.env.NO_PROXY, hosts].filter(Boolean).join(",");
  process.env.no_proxy = process.env.NO_PROXY;
}

export const RPC_URL = () => process.env.BITCD_RPC ?? "http://localhost:5051";

export function provider(nodeUrl = RPC_URL()) {
  return new RpcProvider({ nodeUrl });
}

/// `spec` = { address, pk } — the shape the e2e cast and BITCD_ACCOUNTS_FILE share.
export function account(spec, p = provider()) {
  return new Account({ provider: p, address: spec.address, signer: spec.pk });
}

/// Contract handle with the bitcd ABI attached (embedded unless `abi` is passed).
export function bitcdContract(addrOrConn, conn, { abi } = {}) {
  const address = typeof addrOrConn === "string" ? addrOrConn : addrOrConn.address;
  return new Contract({ abi: abi ?? embeddedAbi(), address, providerOrAccount: conn });
}

/// Read a deployment record ({address, classHash, owner, rpc}) written by the
/// ceremony's deploy step. Path from BITCD_DEPLOYMENT_FILE unless given.
export function loadDeployment(file = process.env.BITCD_DEPLOYMENT_FILE) {
  if (!file) throw new Error("loadDeployment: set BITCD_DEPLOYMENT_FILE or pass a path");
  return JSON.parse(readFileSync(file, "utf8"));
}

/// Collect intent-bound human signatures (SNIP-12) and submit them via
/// `approve_sigs`, relayed by `relayer` (any account — a human need not send a
/// tx; it defaults to the first signer).
/// Asserts the off-chain↔on-chain hash round-trip on every signer. Returns the tx hash.
export async function approveWithSigs({
  contractAddress, proposalId, action, prefix, params,
  signers, // [{ address, pk }, ...]
  relayer, // signer spec used to submit (gas-payer); defaults to the first signer
  p = provider(),
  abi,
}) {
  const chainId = await p.getChainId();
  const view = bitcdContract(contractAddress, p, { abi });
  const approvals = [];
  for (const s of signers) {
    const args = { verifyingContract: contractAddress, chainId, proposalId, action, prefix, params };
    await assertRoundTrip(view, args, s.address);
    approvals.push(await signApproval(account(s, p), args));
  }
  const c = bitcdContract(contractAddress, account(relayer ?? signers[0], p), { abi });
  const { transaction_hash } = await c.approve_sigs(proposalId, approvals);
  await p.waitForTransaction(transaction_hash);
  return transaction_hash;
}
