// The security lints: the compiler makes envelope violations INEXPRESSIBLE,
// as compile errors tagged with the invariant they enforce. Runs over the
// normalized org model from ./schema.mjs (shape is already valid); returns an
// array of error strings — never throws.
//
// Structurally unexpressible (no lint needed): allow_open anywhere and
// expression forms (the schema rejects them). Open ACQUIRE is expressible
// ONLY as a fleet lease or a lock surface, each pinned to a quorum
// FORCE_UNLOCK by construction — the [lock-recovery] lints below then hold the recovery
// gates to equivalent strength. Open
// SET_VALUE is expressible ONLY as a lock's `value` (the lock IS the write
// capability) and the [single-open-value] lint below holds the org to AT MOST ONE such
// prefix — the envelope's single open-value slot, machine-checked.
import { SHORTSTRING_MAX } from "../protocol.mjs";
import { SEGMENT_RE } from "./keys.mjs";

/// Worst-case rendered length of a key template, provable at compile time —
/// or an error when a referenced param cannot bound it.
export function keyTemplateBound(it, errors) {
  let bound = it.key.length;
  for (const field of it.key_fields) {
    const p = it.params.find((x) => x.name === field);
    const tokenLen = `{${field}}`.length;
    if (!p) { errors.push(`[31-char] ${it.name}: key template references undeclared param "{${field}}"`); continue; }
    if (p.type === "enum") {
      const bad = p.values.filter((v) => !SEGMENT_RE.test(v));
      if (bad.length > 0) errors.push(`[31-char] ${it.name}: enum "${field}" holds non-key-safe values ${JSON.stringify(bad)} used in the key template`);
      bound += Math.max(...p.values.map((v) => v.length)) - tokenLen;
    } else if (p.type === "name") {
      bound += p.max_len - tokenLen;
    } else {
      errors.push(`[31-char] ${it.name}: key template param "{${field}}" must be an enum or a name field (a ${p.type} cannot bound the felt length)`);
    }
    if (p.required === false) errors.push(`[31-char] ${it.name}: key template param "{${field}}" must be required`);
  }
  return bound;
}

// Can this quorum ever be satisfied by the declared cast?
function quorumSatisfiable(q, label, signers, errors) {
  const eligible = signers.filter((s) => s.role === q.role);
  if (eligible.length < q.threshold) {
    errors.push(`[threshold-reachable] ${label}: threshold ${q.threshold} but only ${eligible.length} signer(s) hold role ${q.role}`);
  }
  const humans = eligible.filter((s) => s.human);
  if (humans.length < q.min_humans) {
    errors.push(`[humans-reachable] ${label}: min_humans ${q.min_humans} but only ${humans.length} human signer(s) hold role ${q.role}`);
  }
  if (q.max_per_operator > 0) {
    // What the cap actually leaves usable: each operator contributes at most
    // `max_per_operator` of its own signers (an operator over the cap makes
    // `satisfies` fail outright, so no quorum can lean on its extras). Taking
    // humans first within each operator reaches both maxima at once, so the
    // two sums together decide whether the quorum is satisfiable.
    const byOp = new Map();
    for (const s of eligible) {
      const o = byOp.get(s.operator) ?? { all: 0, humans: 0 };
      o.all += 1;
      if (s.human) o.humans += 1;
      byOp.set(s.operator, o);
    }
    const cap = q.max_per_operator;
    let usable = 0;
    let usableHumans = 0;
    for (const o of byOp.values()) {
      usable += Math.min(o.all, cap);
      usableHumans += Math.min(o.humans, cap);
    }
    if (usable < q.threshold) {
      errors.push(`[operator-diversity] ${label}: max_per_operator ${cap} leaves only ${usable} usable signer(s) across ${byOp.size} operator(s) — cannot reach threshold ${q.threshold}`);
    } else if (usableHumans < q.min_humans) {
      errors.push(`[operator-diversity] ${label}: max_per_operator ${cap} leaves only ${usableHumans} usable human signer(s) — cannot reach min_humans ${q.min_humans}`);
    }
  }
}

// Is `stronger` at least as strong as `base` across every Policy field (the
// comparability rules: role must match — eligibility population is not an
// ordered scale; max_per_operator 0 = unlimited = weakest)? `tag` is the lint
// code the comparison emits ([revoke-not-weaker] revoke-vs-grant, [policy-gate-not-weaker] fleet meta, [lock-recovery]
// lease recovery).
function atLeastAsStrong(stronger, base, label, errors, tag = "revoke-not-weaker") {
  if (stronger.role !== base.role) {
    errors.push(`[${tag}] ${label}: role ${stronger.role} differs from ${base.role} — strength is incomparable across roles; use the same role`);
    return;
  }
  if (stronger.threshold < base.threshold) errors.push(`[${tag}] ${label}: threshold ${stronger.threshold} weakens ${base.threshold} ('commit: weakens threshold')`);
  if (stronger.min_humans < base.min_humans) errors.push(`[${tag}] ${label}: min_humans ${stronger.min_humans} weakens ${base.min_humans} ('commit: weakens min_humans')`);
  if (base.max_per_operator !== 0 && (stronger.max_per_operator === 0 || stronger.max_per_operator > base.max_per_operator)) {
    errors.push(`[${tag}] ${label}: max_per_operator ${stronger.max_per_operator} loosens the finite cap ${base.max_per_operator} ('commit: weakens diversity')`);
  }
}

/// The full lint pass. Returns error strings, [] when clean.
export function checkInvariants(model) {
  const errors = [];
  const {
    signers, connectors, intent_types: intents, reserved_prefixes: reserved, manifest,
    fleets = [], locks = [], values = [],
  } = model;

  // ---- [executor-separation] per-domain executor roles, disjoint from governance and from
  // each other; a role names EXACTLY its connector's executors. ----
  const connectorRoles = new Map(); // role -> connector name
  for (const c of connectors) {
    if (connectorRoles.has(c.role)) {
      errors.push(`[executor-separation] connectors ${connectorRoles.get(c.role)} and ${c.name} share role ${c.role} — a shared role is a cross-domain status-write capability`);
    }
    connectorRoles.set(c.role, c.name);
  }
  const governanceQuorums = [];
  for (const it of intents) {
    governanceQuorums.push([`intent_types.${it.name}.quorum`, it.quorum]);
    if (it.revoke !== "same") governanceQuorums.push([`intent_types.${it.name}.revoke`, it.revoke]);
  }
  for (const val of values) {
    governanceQuorums.push([`values.${val.name}.quorum`, val.quorum]);
    if (val.revoke !== "none" && val.revoke !== "same") governanceQuorums.push([`values.${val.name}.revoke`, val.revoke]);
  }
  for (const f of fleets) {
    governanceQuorums.push([`fleets.${f.name}.quorum`, f.quorum]);
    governanceQuorums.push([`fleets.${f.name}.meta`, f.meta]);
    if (f.lease) governanceQuorums.push([`fleets.${f.name}.lease.recovery`, f.lease.recovery]);
  }
  for (const l of locks) governanceQuorums.push([`locks.${l.name}.recovery`, l.recovery]);
  governanceQuorums.push(["manifest.quorum", manifest.quorum]);
  for (const r of reserved) governanceQuorums.push([`reserved_prefixes ${r.prefix} set_policy`, r.set_policy]);
  for (const [label, q] of governanceQuorums) {
    if (connectorRoles.has(q.role)) {
      errors.push(`[executor-separation] ${label}: role ${q.role} is connector ${connectorRoles.get(q.role)}'s executor role — executors must never be eligible on a governance gate`);
    }
  }
  for (const c of connectors) {
    for (const en of c.executors) {
      const s = signers.find((x) => x.name === en);
      if (s && s.role !== c.role) errors.push(`[executor-separation] connectors.${c.name}: executor ${en} holds role ${s.role}, not the connector's ${c.role}`);
    }
    const strays = signers.filter((s) => s.role === c.role && !c.executors.includes(s.name));
    for (const s of strays) {
      errors.push(`[executor-separation] signer ${s.name} holds executor role ${c.role} but is not in connectors.${c.name}.executors — every holder of a status-write role must be a declared executor`);
    }
  }

  // ---- [person-reachable] a write surface that commits with no person keeps one reachable:
  // summon_human: true, and a human signer of the quorum's role in the cast (a
  // summoned person counts only as a same-role approver, so they must be
  // eligible). ----
  const keepsPersonReachable = (label, q, summonHuman) => {
    if (q.min_humans >= 1) return;
    if (!summonHuman) {
      errors.push(`[person-reachable] ${label}: min_humans 0 needs summon_human: true (voters can then demand a person) or min_humans >= 1`);
    } else if (!signers.some((s) => s.human && s.role === q.role)) {
      errors.push(`[person-reachable] ${label}: summon_human needs a human signer holding role ${q.role} in the cast — the summoned person must be eligible to sign`);
    }
  };
  for (const it of intents) keepsPersonReachable(`intent_types.${it.name}`, it.quorum, it.summon_human);
  for (const val of values) keepsPersonReachable(`values.${val.name}`, val.quorum, val.summon_human);
  for (const f of fleets) keepsPersonReachable(`fleets.${f.name}`, f.quorum, f.summon_human);

  // ---- [policy-gate-not-weaker] a fleet's SET_POLICY meta-gate is never weaker than its value
  // gate — mutual gating cannot be voted away by a weaker quorum. Equal
  // strength passes: a dev org may keep the meta-gate fleet-satisfiable
  // (min_humans 0) while production declares min_humans 1. Do not floor it
  // here — the difference is the org author's explicit act. ----
  for (const f of fleets) atLeastAsStrong(f.meta, f.quorum, `fleets.${f.name}.meta (vs the fleet's value gate)`, errors, "policy-gate-not-weaker");

  // ---- [lock-recovery] every open-ACQUIRE prefix carries an equivalent-strength
  // quorum FORCE_UNLOCK. A fleet's lease recovery is measured against its
  // own value gate; across the org, ALL open prefixes' recovery gates must
  // match each other, so no never-touched lock key can be front-run into a
  // weaker namespace. ----
  const opens = [];
  for (const f of fleets) {
    if (!f.lease) continue;
    opens.push([`fleets.${f.name}.lease`, f.lease.recovery]);
    atLeastAsStrong(f.lease.recovery, f.quorum, `fleets.${f.name}.lease.recovery (vs the fleet's value gate)`, errors, "lock-recovery");
  }
  for (const l of locks) opens.push([`locks.${l.name}`, l.recovery]);
  for (let i = 1; i < opens.length; i++) {
    const [label0, q0] = opens[0];
    const [labelI, qi] = opens[i];
    if (qi.role !== q0.role || qi.threshold !== q0.threshold || qi.min_humans !== q0.min_humans || qi.max_per_operator !== q0.max_per_operator) {
      errors.push(`[lock-recovery] ${labelI} and ${label0}: open-ACQUIRE recovery gates differ — every open prefix carries an equivalent-strength FORCE_UNLOCK`);
    }
  }

  // ---- [single-open-value] at most ONE open-SET_VALUE prefix may exist — a hijacked value
  // key has no governed recovery path (unlike a lock, which a strong
  // FORCE_UNLOCK recovers), so the envelope permits a single lock-scoped
  // open value across the whole org. ----
  const openValues = locks.filter((l) => l.value);
  if (openValues.length > 1) {
    errors.push(`[single-open-value] locks ${openValues.map((l) => l.name).join(", ")} all declare an open value — the envelope permits exactly ONE open-SET_VALUE prefix per deployment (a hijacked value key has no governed recovery path)`);
  }

  // ---- satisfiability of every quorum against the declared cast ----
  for (const [label, q] of governanceQuorums) quorumSatisfiable(q, label, signers, errors);

  // ---- attest.k against the connector's executor roster ----
  for (const it of intents) {
    const c = connectors.find((x) => x.name === it.connector);
    if (!c) continue;
    if (it.attest.k > c.executors.length) {
      errors.push(`[attest-reachable] intent_types.${it.name}: attest.k ${it.attest.k} exceeds connector ${c.name}'s ${c.executors.length} executor(s)`);
    }
    const ops = new Set(c.executors.map((en) => signers.find((s) => s.name === en)?.operator).filter(Boolean));
    if (it.attest.k > 1 && ops.size < it.attest.k) {
      errors.push(`[operator-diversity] intent_types.${it.name}: attest.k ${it.attest.k} needs ${it.attest.k} DISTINCT operators among ${c.name}'s executors (found ${ops.size})`);
    }
  }

  // ---- revoke at least as strong as the grant quorum ----
  for (const it of intents) {
    if (it.revoke !== "same") atLeastAsStrong(it.revoke, it.quorum, `intent_types.${it.name}.revoke`, errors);
  }

  // ---- prefix uniqueness across intent types, the manifest, and reserves ----
  const seen = new Map(); // prefix -> where
  const claim = (prefix, where) => {
    if (seen.has(prefix)) errors.push(`[prefix-owner] prefix "${prefix}" is claimed by both ${seen.get(prefix)} and ${where} — one prefix, one owner`);
    else seen.set(prefix, where);
  };
  for (const it of intents) claim(it.prefix, `intent_types.${it.name}`);
  for (const val of values) claim(val.prefix, `values.${val.name}`);
  for (const f of fleets) {
    claim(f.prefix, `fleets.${f.name}`);
    if (f.lease) claim(f.lease.prefix, `fleets.${f.name}.lease`);
  }
  for (const l of locks) claim(l.prefix, `locks.${l.name}`);
  claim(manifest.prefix, "manifest");
  for (const r of reserved) claim(r.prefix, "reserved_prefixes");

  // ---- 31-char arithmetic over key templates (proven, not discovered) ----
  for (const it of intents) {
    const bound = keyTemplateBound(it, errors);
    if (bound > SHORTSTRING_MAX) {
      errors.push(`[31-char] intent_types.${it.name}: key template worst case is ${bound} chars (> ${SHORTSTRING_MAX}) — shorten the prefix, enum values, or name max_len (hash-of-name naming is designed-for, not yet expressible)`);
    }
  }

  return errors;
}
