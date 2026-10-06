// Pending documents: where a proposal's blob waits until its commit.
//
// A proposed document must never replace the one readers verify against the
// CURRENT on-chain digest — the executor re-hashes `<value_key>/spec`, and a
// swapped copy there looks exactly like tampering until the proposal lands
// (or forever, if it never does). So a proposer publishes the blob and its
// claimed params beside the proposal, at `<prefix>/proposals/<id>.{blob,json}`
// (the convention `agentgate sign`, the fleet predicates and the ops-console
// already read), and only a COMMITTED digest is ever copied into place.
//
// Two readers of that rule. `promoteCommitted` copies the committed blob into
// place — for a writer that holds the store (the CLI after its own commit,
// the ops-console's repair pass). `locateCommitted` only FINDS it — for a
// reader that must not write (the executor, whose store access is read-only
// in a real deployment): it reads the committed bytes from the proposal's
// side channel instead. Either way nothing is used unless it hashes to the
// digest the quorum committed. Pure over an injected store and digest.

export const pendingBlobKey = (prefixStr, proposalId) => `${prefixStr}/proposals/${proposalId}.blob`;
export const pendingParamsKey = (prefixStr, proposalId) => `${prefixStr}/proposals/${proposalId}.json`;

/// Publish a proposal's blob and claimed params at the pending side channel.
export async function publishPending(store, prefixStr, proposalId, blob, params) {
  await store.putText(pendingBlobKey(prefixStr, proposalId), blob);
  await store.putText(pendingParamsKey(prefixStr, proposalId), JSON.stringify({ params: params.map(String) }));
}

/// Find where the bytes for the committed `digest` can be read: `specKey`
/// when it already verifies, else the first candidate proposal's pending blob
/// that hashes to the digest. Returns { key, proposalId, text } — the bytes
/// that were verified (proposalId null for specKey itself) — or null when nothing matches — the reader then treats the
/// value as unverifiable, never as anything else. Read-only.
export async function locateCommitted({ store, specKey, digest, prefixStr, proposalIds, digestOf }) {
  const matches = (text) => BigInt(digestOf(text)) === BigInt(digest);
  try {
    const text = await store.getText(specKey);
    if (matches(text)) return { key: specKey, proposalId: null, text };
  } catch { /* missing — look for the pending copy */ }
  for (const id of proposalIds) {
    const key = pendingBlobKey(prefixStr, id);
    try {
      const text = await store.getText(key);
      if (matches(text)) return { key, proposalId: id, text };
    } catch { /* no blob for this proposal */ }
  }
  return null;
}

/// Make `specKey` hold the blob for the committed `digest`. Returns
/// "current" when it already verifies, the proposal id it copied from, or
/// null when no candidate proposal's blob hashes to the digest.
export async function promoteCommitted({ store, specKey, digest, prefixStr, proposalIds, digestOf }) {
  const found = await locateCommitted({ store, specKey, digest, prefixStr, proposalIds, digestOf });
  if (found === null) return null;
  if (found.proposalId === null) return "current";
  await store.putText(specKey, found.text);   // the bytes that verified, never a re-read
  return found.proposalId;
}
