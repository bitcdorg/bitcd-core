// Waiting for a transaction. A node reports a reverted transaction as
// accepted, so inclusion alone does not mean the call took effect: a reverted
// vote is not a cast vote, a reverted seed is not a seeded policy, a reverted
// attestation is not an attestation.
//
// Dependency-free, so the pure engines (reconcile, fleet) can wait through it.

/// Wait for a transaction and fail unless it executed, with the contract's
/// revert reason. `what` names the call in the error. Returns the receipt.
export async function waitSucceeded(provider, transactionHash, what = "transaction") {
  const r = await provider.waitForTransaction(transactionHash);
  const status = r?.execution_status ?? r?.value?.execution_status;
  if (status === "REVERTED") throw new Error(`${what} ${transactionHash} reverted: ${r?.revert_reason ?? r?.value?.revert_reason ?? "no reason given"}`);
  return r;
}
