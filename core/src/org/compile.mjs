// Normalized org model -> the three compiled artifacts:
//
//   ceremony        the deploy-time seed in @bitcd/core/ceremony's exact
//                   shape: signers ({address, signer}) + policies
//                   ({label, prefix, action, policy}) — names as strings, the
//                   applier felt-encodes at the chain boundary
//   manifest        the orgmanifest/v1 document (a governed value; the form
//                   contract the ops-console renders and the executor's map)
//   executorConfigs one runtime config per connector (public settings + the
//                   env-var NAMES the operator must fill — never material)
//
// Ceremony completeness is a compile GUARANTEE, not a convention: every
// intent-type prefix gets its quartet (SET_VALUE / TOMBSTONE_VALUE /
// SET_STATUS / SET_POLICY-iff-mutable), every value surface its
// SET_VALUE (+ TOMBSTONE iff a revoke gate is declared, + SET_POLICY iff
// mutable), every fleet its value gate + EXPLICIT meta-gate + the lease
// pair (open ACQUIRE + quorum FORCE_UNLOCK), every lock its lease pair
// (+ the ONE open SET_VALUE iff it declares `value`; + SET_POLICY iff
// mutable), the manifest prefix gets SET_VALUE + TOMBSTONE_VALUE + SET_POLICY,
// the GLOBAL gates (SET_ROLE + SET_POLICY) keep day-2 signer management
// reachable, and every reserved prefix gets its SET_POLICY-only meta-policy
// — because after renounce, no policy can ever be created on an unseeded
// prefix (the envelope is sealed at ceremony).
import { digestOf } from "../protocol.mjs";
import { renderConfig } from "../reconcile.mjs";

export const ORG_SCHEMA = "orgmanifest/v1";

const pol = (q) => ({
  threshold: q.threshold, role: q.role, min_humans: q.min_humans,
  max_per_operator: q.max_per_operator, allow_open: false,
});
const polLabel = (q) => `${q.threshold}-of-${q.role}/h${q.min_humans}`;

// The SET_POLICY meta-policy for a mutable intent-type prefix: the grant
// quorum, floored to at least one human — amending the rules is never weaker
// than writing under them, and never machine-only.
const metaPolicyFor = (q) => ({
  threshold: q.threshold, role: q.role,
  min_humans: Math.max(1, q.min_humans),
  max_per_operator: q.max_per_operator,
});

/// model (from schema.mjs validateOrg, already invariant-checked) ->
/// { ceremony, manifest, executorConfigs }. Pure and deterministic: the same
/// model always compiles to byte-identical artifacts (source_digest included).
export function compileOrg(model, { classHash } = {}) {
  const m = model;

  // ---- ceremony: signers ----
  const signers = m.signers.map((s) => ({
    label: `set_signer ${s.name}`,
    address: s.address,
    signer: { active: true, is_human: s.human, operator_id: s.operator, role: s.role },
  }));

  // ---- ceremony: the policy table ----
  const policies = [];
  const add = (prefix, action, q, label) => policies.push({ label, prefix, action, policy: pol(q) });

  // GLOBAL gates first: signer management (SET_ROLE is GLOBAL-scoped) and
  // its own amendment gate, both at constitution strength.
  add("GLOBAL", "SET_ROLE", m.manifest.quorum, `policy GLOBAL/SET_ROLE=${polLabel(m.manifest.quorum)}`);
  add("GLOBAL", "SET_POLICY", m.manifest.quorum, `policy GLOBAL/SET_POLICY=${polLabel(m.manifest.quorum)}`);

  // The org manifest's own prefix — the constitution (min_humans >= 1 floor
  // is schema-enforced).
  add(m.manifest.prefix, "SET_VALUE", m.manifest.quorum, `policy ${m.manifest.prefix}·SET_VALUE=${polLabel(m.manifest.quorum)}`);
  add(m.manifest.prefix, "TOMBSTONE_VALUE", m.manifest.quorum, `policy ${m.manifest.prefix}·TOMBSTONE_VALUE=${polLabel(m.manifest.quorum)}`);
  add(m.manifest.prefix, "SET_POLICY", m.manifest.quorum, `policy ${m.manifest.prefix}·SET_POLICY=${polLabel(m.manifest.quorum)}`);

  // The intent-type quartets.
  for (const it of m.intent_types) {
    const revoke = it.revoke === "same" ? it.quorum : it.revoke;
    const attest = {
      threshold: it.attest.k,
      role: m.connectors.find((c) => c.name === it.connector).role,
      min_humans: 0,
      max_per_operator: it.attest.k > 1 ? 1 : 0,
    };
    add(it.prefix, "SET_VALUE", it.quorum, `policy ${it.prefix}·SET_VALUE=${polLabel(it.quorum)}`);
    add(it.prefix, "TOMBSTONE_VALUE", revoke, `policy ${it.prefix}·TOMBSTONE_VALUE=${polLabel(revoke)}`);
    add(it.prefix, "SET_STATUS", attest, `policy ${it.prefix}·SET_STATUS=${it.attest.k}-of-${attest.role}`);
    if (it.mutable) {
      const meta = metaPolicyFor(it.quorum);
      add(it.prefix, "SET_POLICY", meta, `policy ${it.prefix}·SET_POLICY=${polLabel(meta)}`);
    }
  }

  // Plain governed values: SET_VALUE, TOMBSTONE only where a revoke gate
  // is declared (rewriting via SET_VALUE is always the recovery path),
  // SET_POLICY iff mutable. No connector, no SET_STATUS — nothing executes
  // these.
  for (const val of m.values ?? []) {
    add(val.prefix, "SET_VALUE", val.quorum, `policy ${val.prefix}·SET_VALUE=${polLabel(val.quorum)}`);
    if (val.revoke !== "none") {
      const rq = val.revoke === "same" ? val.quorum : val.revoke;
      add(val.prefix, "TOMBSTONE_VALUE", rq, `policy ${val.prefix}·TOMBSTONE_VALUE=${polLabel(rq)}`);
    }
    if (val.mutable) {
      const meta = metaPolicyFor(val.quorum);
      add(val.prefix, "SET_POLICY", meta, `policy ${val.prefix}·SET_POLICY=${polLabel(meta)}`);
    }
  }

  // Fleets: the mutual gate + its EXPLICIT meta-gate (the declared
  // dev/production min_humans difference is passed through verbatim, never
  // floored like metaPolicyFor) + the lease pair.
  const openPolicy = () => ({ threshold: 0, role: null, min_humans: 0, max_per_operator: 0, allow_open: true });
  const addOpen = (prefix, label, action = "ACQUIRE") => policies.push({ label, prefix, action, policy: openPolicy() });
  for (const f of m.fleets ?? []) {
    add(f.prefix, "SET_VALUE", f.quorum, `policy ${f.prefix}·SET_VALUE=${polLabel(f.quorum)}`);
    add(f.prefix, "SET_POLICY", f.meta, `policy ${f.prefix}·SET_POLICY=${polLabel(f.meta)}`);
    addOpen(f.lease.prefix, `policy ${f.lease.prefix}·ACQUIRE=open`);
    add(f.lease.prefix, "FORCE_UNLOCK", f.lease.recovery, `policy ${f.lease.prefix}·FORCE_UNLOCK=${polLabel(f.lease.recovery)}`);
  }

  // Standalone lock surfaces (the k8s-lease shape): the lease pair — plus,
  // for the ONE lock that declares `value`, the lock-scoped open SET_VALUE
  // (the lock holder writes single-writer; the [single-open-value] lint holds the org to
  // one such prefix), and SET_POLICY at recovery strength floored to one
  // human iff mutable.
  for (const l of m.locks ?? []) {
    addOpen(l.prefix, `policy ${l.prefix}·ACQUIRE=open`);
    add(l.prefix, "FORCE_UNLOCK", l.recovery, `policy ${l.prefix}·FORCE_UNLOCK=${polLabel(l.recovery)}`);
    if (l.value) addOpen(l.prefix, `policy ${l.prefix}·SET_VALUE=open (lock-scoped)`, "SET_VALUE");
    if (l.mutable) {
      const meta = metaPolicyFor(l.recovery);
      add(l.prefix, "SET_POLICY", meta, `policy ${l.prefix}·SET_POLICY=${polLabel(meta)}`);
    }
  }

  // Reserved prefixes: the day-2 headroom — SET_POLICY only (the quartet is
  // proposed later, through governance, when the prefix is put to use).
  for (const r of m.reserved_prefixes) {
    add(r.prefix, "SET_POLICY", r.set_policy, `policy ${r.prefix}·SET_POLICY=${polLabel(r.set_policy)} (reserved)`);
  }

  // ---- the org manifest document ----
  const manifest = {
    schema: ORG_SCHEMA,
    org: m.org,
    version: m.version,
    naming: m.naming,
    ...(classHash ? { class_hash: classHash } : {}),
    roles: m.roles,
    signers: m.signers.map(({ name, address, human, operator, role }) => ({ name, address, human, operator, role })),
    connectors: m.connectors.map(({ name, type, role, executors, config, credentials }) => ({
      name, type, role, executors, config, credentials,
    })),
    intent_types: m.intent_types.map((it) => ({
      name: it.name, connector: it.connector, prefix: it.prefix, schema: it.schema,
      key: it.key, key_fields: it.key_fields, params: it.params,
      ...(it.ttl ? { ttl: it.ttl } : {}),
      quorum: it.quorum,
      revoke: it.revoke === "same" ? it.quorum : it.revoke,
      attest: it.attest, summon_human: it.summon_human, mutable: it.mutable,
    })),
    // The connector-less surfaces ride only when declared, so an org without
    // them carries none of these keys (digest stability).
    ...(m.fleets?.length > 0 ? {
      fleets: m.fleets.map((f) => ({
        name: f.name, prefix: f.prefix, schema: f.schema, key: f.key,
        quorum: f.quorum, meta: f.meta, summon_human: f.summon_human,
        lease: { prefix: f.lease.prefix, recovery: f.lease.recovery },
      })),
    } : {}),
    // `value` / `mutable` ride only when declared, so a lock without them
    // adds no keys (digest stability).
    ...(m.locks?.length > 0 ? {
      locks: m.locks.map((l) => ({
        name: l.name, prefix: l.prefix, recovery: l.recovery,
        ...(l.value ? { value: l.value } : {}),
        ...(l.mutable ? { mutable: true } : {}),
      })),
    } : {}),
    ...(m.values?.length > 0 ? {
      values: m.values.map((v) => ({
        name: v.name, prefix: v.prefix, schema: v.schema, key: v.key,
        quorum: v.quorum,
        ...(v.revoke !== "none" ? { revoke: v.revoke === "same" ? v.quorum : v.revoke } : {}),
        summon_human: v.summon_human, mutable: v.mutable,
      })),
    } : {}),
    reserved_prefixes: m.reserved_prefixes,
    baseline: m.baseline,
    storage: { ...m.storage, spec_convention: "<value_key>/spec" },
    // The manifest's OWN governance (the loader's key-binding check reads
    // self.key; `bitcd diff` compares `policies` below against get_policy).
    self: { key: m.manifest.key, prefix: m.manifest.prefix, quorum: m.manifest.quorum },
    // The exact policy table the ceremony seeds — declared truth, one row per
    // (prefix, action). The chain stays enforcement truth.
    policies: policies.map((p) => ({ prefix: p.prefix, action: p.action, ...p.policy })),
  };
  // Source digest over the model MINUS empty sections, so an org without
  // fleets/locks/values has a source_digest unaffected by their absence.
  const { fleets, locks, values, ...restModel } = m;
  manifest.source_digest = digestOf(renderConfig({
    model: {
      ...restModel,
      ...(fleets?.length > 0 ? { fleets } : {}),
      ...(locks?.length > 0 ? { locks } : {}),
      ...(values?.length > 0 ? { values } : {}),
    },
  }));

  // ---- per-connector executor runtime configs ----
  const executorConfigs = m.connectors.map((c) => {
    const its = m.intent_types.filter((it) => it.connector === c.name);
    return {
      connector: c.name,
      type: c.type,
      role: c.role,
      intent_types: its.map((it) => it.name),
      prefixes: its.map((it) => it.prefix),
      executors: c.executors.map((en) => {
        const s = m.signers.find((x) => x.name === en);
        return { name: en, address: s.address };
      }),
      config: c.config,
      credentials: c.credentials,
      env: {
        BITCD_CONNECTOR: c.name,
        BITCD_MANIFEST_KEY: m.manifest.key,
        BITCD_S3_BUCKET: m.storage.bucket,
      },
      // Names the operator fills at runtime — never material, never in the
      // manifest blob. These are the variables the executor reads: it finds
      // the store before it can load the manifest, so the endpoint is always
      // BITCD_S3_ENDPOINT, whatever storage.endpoint_env names for the CLI.
      env_required: [
        "BITCD_RPC",
        "BITCD_CONTRACT_ADDRESS",
        "BITCD_S3_ENDPOINT",
        "BITCD_EXECUTOR_ADDRESS",
        "BITCD_EXECUTOR_PK",
        ...Object.values(c.credentials).flat(),
      ],
    };
  });

  return { ceremony: { signers, policies }, manifest, executorConfigs };
}
