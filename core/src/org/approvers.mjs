// Choosing who approves a proposal from a keystore's signers, for the CLI's
// development flows (publish-manifest, propose-changes).
// Pure: `pool` is the keystore's signers as the chain knows them right now —
// [{ name, address, human, operator, role }].

// Pick approvers for `quorum` from `pool`: humans first, at most
// max_per_operator per operator (one over the cap fails the whole set on
// chain). Returns the pick, or null when the pool cannot satisfy it.
export function pickApprovers(pool, quorum) {
  const eligible = pool.filter((s) => s.role === quorum.role);
  const humansFirst = [...eligible].sort((a, b) => Number(b.human) - Number(a.human));
  const picked = [];
  const perOp = new Map();
  for (const s of humansFirst) {
    // Stop only once BOTH the threshold and the human floor are met: a quorum
    // may ask for more humans than its threshold (the contract counts every
    // approver, so extra approvals are fine).
    const humans = picked.filter((x) => x.human).length;
    if (picked.length >= quorum.threshold && humans >= quorum.min_humans) break;
    if (picked.length >= quorum.threshold && !s.human) continue;
    const used = perOp.get(s.operator) ?? 0;
    if (quorum.max_per_operator > 0 && used >= quorum.max_per_operator) continue;
    perOp.set(s.operator, used + 1);
    picked.push(s);
  }
  if (picked.length < quorum.threshold || picked.filter((s) => s.human).length < quorum.min_humans) return null;
  return picked;
}
