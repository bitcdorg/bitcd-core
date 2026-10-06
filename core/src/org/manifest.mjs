// The orgmanifest/v1 envelope: the compiled org definition as a GOVERNED
// VALUE. Published under the org's manifest
// key (default sys/manifest) behind a quorum with min_humans >= 1; executor
// and ops-console load it by verify-on-read with the canonical pin and HALT
// on tamper (./loader.mjs).
//
// The manifest is compiler-produced (./compile.mjs), so validation here is
// the CONSUMER's shield: shape, bounds, felts, the secret lint, and the
// unknown-fields rejection — enough that a tampered-but-digest-matching blob
// is impossible and a maliciously-authored one cannot smuggle expressions or
// material. Chain policy stays enforcement truth; this document is declared
// truth (`bitcd diff` compares the two).
import { renderConfig } from "../reconcile.mjs";
import { SHORTSTRING_MAX, digestOf, str } from "../protocol.mjs";
import { isPlainObject, lintSecrets } from "./lint.mjs";
import { SCHEMA_REF_RE, templateFields } from "./keys.mjs";
import { FIELD_TYPES } from "./schema.mjs";

export const ORG_SCHEMA = "orgmanifest/v1";
export const ORG_SCHEMA_FELT = str(ORG_SCHEMA);
export const DEFAULT_MANIFEST_KEY = "sys/manifest";

export const ACTIONS = ["ACQUIRE", "FORCE_UNLOCK", "SET_POLICY", "SET_ROLE", "SET_VALUE", "TOMBSTONE_VALUE", "SET_STATUS"];

const NAME_RE = /^[A-Za-z0-9_-]+$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{1,64}$/;
const HEX_RE = /^0x[0-9a-fA-F]{1,64}$/;

/// The canonical render — the ONLY bytes anyone digests (shared with the
/// publisher via canonicalOrgManifest and with the loader's canonical pin).
export const canonicalRender = renderConfig;

const feltOk = (s) => typeof s === "string" && s.length > 0 && s.length <= SHORTSTRING_MAX;

function checkKeys(obj, allowed, where, errors) {
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) errors.push(`${where}: unknown field "${k}" (decoration is rejected, not stripped)`);
  }
}

function checkQuorum(q, where, errors) {
  if (!isPlainObject(q)) { errors.push(`${where} must be a quorum`); return; }
  checkKeys(q, new Set(["threshold", "role", "min_humans", "max_per_operator"]), where, errors);
  if (!Number.isSafeInteger(q.threshold) || q.threshold < 1) errors.push(`${where}.threshold must be >= 1`);
  if (!feltOk(q.role)) errors.push(`${where}.role must be a felt-sized role name`);
  if (!Number.isSafeInteger(q.min_humans) || q.min_humans < 0) errors.push(`${where}.min_humans must be >= 0`);
  if (!Number.isSafeInteger(q.max_per_operator) || q.max_per_operator < 0) errors.push(`${where}.max_per_operator must be >= 0`);
}

// A compiled params field spec — the normalized output of schema.mjs's
// validateFieldSpec. Its type and required shape are re-checked so the
// webapp/executor never render or honor an out-of-vocabulary spec; the length
// bounds are enforced by schema.mjs alone.
function checkFieldSpec(f, where, errors) {
  if (!isPlainObject(f)) { errors.push(`${where} must be a field spec`); return; }
  if (!FIELD_TYPES.includes(f.type)) { errors.push(`${where}.type must be one of ${FIELD_TYPES.join("|")}`); return; }
  if (typeof f.name !== "string" || !NAME_RE.test(f.name)) errors.push(`${where}.name must match [A-Za-z0-9_-]+`);
  if (typeof f.label !== "string" || f.label.length === 0) errors.push(`${where}.label must be a non-empty string`);
  if (typeof f.required !== "boolean") errors.push(`${where}.required must be a boolean`);
  if (f.type === "enum" && (!Array.isArray(f.values) || f.values.length === 0)) errors.push(`${where}.values must be non-empty`);
  if (f.type === "name" && (!Number.isSafeInteger(f.max_len) || f.max_len < 1)) errors.push(`${where}.max_len must be >= 1`);
}

const TOP = new Set([
  "schema", "org", "version", "naming", "class_hash", "roles", "signers",
  "connectors", "intent_types", "fleets", "locks", "values",
  "reserved_prefixes", "baseline", "storage",
  "self", "policies", "source_digest",
]);

/// Validate a parsed orgmanifest/v1. Returns { ok, errors } — never throws.
export function validateOrgManifest(m) {
  const errors = [];
  if (!isPlainObject(m)) return { ok: false, errors: ["manifest is not an object"] };
  checkKeys(m, TOP, "manifest", errors);

  if (m.schema !== ORG_SCHEMA) errors.push(`schema must be "${ORG_SCHEMA}", got ${JSON.stringify(m.schema)}`);
  if (typeof m.org !== "string" || !NAME_RE.test(m.org)) errors.push("org must be a [A-Za-z0-9_-]+ name");
  if (!Number.isSafeInteger(m.version) || m.version < 1) errors.push("version must be a positive integer");
  if (m.naming !== "literal") errors.push('naming must be "literal" (hashed is designed-for, not yet expressible)');
  if (m.class_hash !== undefined && !HEX_RE.test(m.class_hash)) errors.push("class_hash must be 0x hex");
  if (m.source_digest !== undefined && !HEX_RE.test(m.source_digest)) errors.push("source_digest must be 0x hex");

  if (!Array.isArray(m.roles) || m.roles.length === 0 || !m.roles.every(feltOk)) errors.push("roles must be a non-empty array of felt-sized names");

  if (!Array.isArray(m.signers) || m.signers.length === 0) errors.push("signers must be a non-empty array");
  else m.signers.forEach((s, i) => {
    const where = `signers[${i}]`;
    if (!isPlainObject(s)) { errors.push(`${where} must be an object`); return; }
    checkKeys(s, new Set(["name", "address", "human", "operator", "role"]), where, errors);
    if (typeof s.name !== "string" || !NAME_RE.test(s.name)) errors.push(`${where}.name invalid`);
    if (typeof s.address !== "string" || !ADDRESS_RE.test(s.address)) errors.push(`${where}.address must be 0x hex`);
    if (typeof s.human !== "boolean") errors.push(`${where}.human must be a boolean`);
    if (!feltOk(s.operator)) errors.push(`${where}.operator must be felt-sized`);
    if (!feltOk(s.role)) errors.push(`${where}.role must be felt-sized`);
  });

  // A fleet-only or value-only org has no executor and no forms: connectors and
  // intent_types may be empty — but the manifest must still declare at least
  // one governed surface (intent_types, fleets, or values).
  if (!Array.isArray(m.connectors)) errors.push("connectors must be an array");
  else m.connectors.forEach((c, i) => {
    const where = `connectors[${i}]`;
    if (!isPlainObject(c)) { errors.push(`${where} must be an object`); return; }
    checkKeys(c, new Set(["name", "type", "role", "executors", "config", "credentials"]), where, errors);
    if (typeof c.name !== "string" || !NAME_RE.test(c.name)) errors.push(`${where}.name invalid`);
    if (typeof c.type !== "string" || !NAME_RE.test(c.type)) errors.push(`${where}.type invalid`);
    if (!feltOk(c.role)) errors.push(`${where}.role must be felt-sized`);
    if (!Array.isArray(c.executors) || c.executors.length === 0) errors.push(`${where}.executors must be non-empty`);
  });

  if (!Array.isArray(m.intent_types)) errors.push("intent_types must be an array");
  else m.intent_types.forEach((it, i) => {
    const where = `intent_types[${i}]`;
    if (!isPlainObject(it)) { errors.push(`${where} must be an object`); return; }
    checkKeys(it, new Set([
      "name", "connector", "prefix", "schema", "key", "key_fields", "params",
      "ttl", "quorum", "revoke", "attest", "summon_human", "mutable",
    ]), where, errors);
    if (typeof it.name !== "string" || !NAME_RE.test(it.name)) errors.push(`${where}.name invalid`);
    if (!feltOk(it.prefix)) errors.push(`${where}.prefix must be felt-sized`);
    if (typeof it.schema !== "string" || !SCHEMA_REF_RE.test(it.schema) || !feltOk(it.schema)) errors.push(`${where}.schema must be a felt-sized <name>/v<N>`);
    if (typeof it.key !== "string" || !it.key.startsWith(`${it.prefix}/`)) errors.push(`${where}.key must sit under its prefix`);
    else if (!Array.isArray(it.key_fields) || JSON.stringify(it.key_fields) !== JSON.stringify(templateFields(it.key))) {
      errors.push(`${where}.key_fields must equal the template's fields`);
    }
    if (!Array.isArray(it.params) || it.params.length === 0) errors.push(`${where}.params must be non-empty`);
    else it.params.forEach((f, j) => checkFieldSpec(f, `${where}.params[${j}]`, errors));
    if (it.ttl !== undefined) {
      if (!isPlainObject(it.ttl)) errors.push(`${where}.ttl must be an object`);
      else {
        checkKeys(it.ttl, new Set(["required", "default_s", "min_s", "max_s"]), `${where}.ttl`, errors);
        if (typeof it.ttl.required !== "boolean") errors.push(`${where}.ttl.required must be a boolean`);
        if (!Number.isSafeInteger(it.ttl.max_s) || it.ttl.max_s <= 0) errors.push(`${where}.ttl.max_s must be > 0`);
      }
    }
    checkQuorum(it.quorum, `${where}.quorum`, errors);
    checkQuorum(it.revoke, `${where}.revoke`, errors);
    if (!isPlainObject(it.attest) || !Number.isSafeInteger(it.attest.k) || it.attest.k < 1) errors.push(`${where}.attest.k must be >= 1`);
    if (typeof it.summon_human !== "boolean") errors.push(`${where}.summon_human must be a boolean`);
    if (typeof it.mutable !== "boolean") errors.push(`${where}.mutable must be a boolean`);
  });

  // ---- the connector-less surfaces (present only when the org declares them) ----
  const checkSurfaceHead = (s, where) => {
    if (!feltOk(s.prefix)) errors.push(`${where}.prefix must be felt-sized`);
    if (typeof s.schema !== "string" || !SCHEMA_REF_RE.test(s.schema) || !feltOk(s.schema)) errors.push(`${where}.schema must be a felt-sized <name>/v<N>`);
    if (typeof s.key !== "string" || !feltOk(s.key) || !s.key.startsWith(`${s.prefix}/`)) errors.push(`${where}.key must be a felt-sized key under its prefix`);
    if (typeof s.name !== "string" || !NAME_RE.test(s.name)) errors.push(`${where}.name invalid`);
  };
  if (m.fleets !== undefined) {
    if (!Array.isArray(m.fleets) || m.fleets.length === 0) errors.push("fleets, when present, must be a non-empty array");
    else m.fleets.forEach((f, i) => {
      const where = `fleets[${i}]`;
      if (!isPlainObject(f)) { errors.push(`${where} must be an object`); return; }
      checkKeys(f, new Set(["name", "prefix", "schema", "key", "quorum", "meta", "summon_human", "lease"]), where, errors);
      checkSurfaceHead(f, where);
      checkQuorum(f.quorum, `${where}.quorum`, errors);
      checkQuorum(f.meta, `${where}.meta`, errors);
      if (typeof f.summon_human !== "boolean") errors.push(`${where}.summon_human must be a boolean`);
      if (!isPlainObject(f.lease)) errors.push(`${where}.lease must carry the lease pair ({prefix, recovery})`);
      else {
        checkKeys(f.lease, new Set(["prefix", "recovery"]), `${where}.lease`, errors);
        if (!feltOk(f.lease.prefix)) errors.push(`${where}.lease.prefix must be felt-sized`);
        checkQuorum(f.lease.recovery, `${where}.lease.recovery`, errors);
      }
    });
  }
  if (m.locks !== undefined) {
    if (!Array.isArray(m.locks) || m.locks.length === 0) errors.push("locks, when present, must be a non-empty array");
    else m.locks.forEach((l, i) => {
      const where = `locks[${i}]`;
      if (!isPlainObject(l)) { errors.push(`${where} must be an object`); return; }
      checkKeys(l, new Set(["name", "prefix", "recovery", "value", "mutable"]), where, errors);
      if (typeof l.name !== "string" || !NAME_RE.test(l.name)) errors.push(`${where}.name invalid`);
      if (!feltOk(l.prefix)) errors.push(`${where}.prefix must be felt-sized`);
      checkQuorum(l.recovery, `${where}.recovery`, errors);
      if (l.value !== undefined) {
        if (!isPlainObject(l.value) || !feltOk(l.value.schema) || !feltOk(l.value.key)) errors.push(`${where}.value must be {schema, key} (felt-sized)`);
        else {
          checkKeys(l.value, new Set(["schema", "key"]), `${where}.value`, errors);
          if (typeof l.prefix === "string" && !l.value.key.startsWith(`${l.prefix}/`)) errors.push(`${where}.value.key must sit under the lock prefix`);
        }
      }
      if (l.mutable !== undefined && l.mutable !== true) errors.push(`${where}.mutable, when present, is true`);
    });
    // At most ONE lock-scoped open value per deployment.
    const openValues = m.locks.filter((l) => isPlainObject(l) && l.value !== undefined);
    if (openValues.length > 1) errors.push("locks: more than one lock declares a value — the envelope permits exactly ONE open-SET_VALUE prefix");
  }
  if (m.values !== undefined) {
    if (!Array.isArray(m.values) || m.values.length === 0) errors.push("values, when present, must be a non-empty array");
    else m.values.forEach((v, i) => {
      const where = `values[${i}]`;
      if (!isPlainObject(v)) { errors.push(`${where} must be an object`); return; }
      checkKeys(v, new Set(["name", "prefix", "schema", "key", "quorum", "revoke", "summon_human", "mutable"]), where, errors);
      checkSurfaceHead(v, where);
      checkQuorum(v.quorum, `${where}.quorum`, errors);
      if (v.revoke !== undefined) checkQuorum(v.revoke, `${where}.revoke`, errors);
      if (typeof v.summon_human !== "boolean") errors.push(`${where}.summon_human must be a boolean`);
      if (typeof v.mutable !== "boolean") errors.push(`${where}.mutable must be a boolean`);
    });
  }
  if ((Array.isArray(m.intent_types) ? m.intent_types.length : 0)
    + (Array.isArray(m.fleets) ? m.fleets.length : 0)
    + (Array.isArray(m.values) ? m.values.length : 0) === 0) {
    errors.push("the manifest declares no governed surface (intent_types, fleets, or values)");
  }

  if (m.reserved_prefixes !== undefined) {
    if (!Array.isArray(m.reserved_prefixes)) errors.push("reserved_prefixes must be an array");
    else m.reserved_prefixes.forEach((r, i) => {
      if (!isPlainObject(r) || !feltOk(r.prefix)) errors.push(`reserved_prefixes[${i}] must be {prefix, set_policy}`);
      else checkQuorum(r.set_policy, `reserved_prefixes[${i}].set_policy`, errors);
    });
  }

  if (!isPlainObject(m.storage) || typeof m.storage.bucket !== "string") errors.push("storage.bucket is required");
  if (!isPlainObject(m.self) || !feltOk(m.self.key) || !feltOk(m.self.prefix)) errors.push("self must carry the manifest's own {key, prefix, quorum}");
  else {
    checkQuorum(m.self.quorum, "self.quorum", errors);
    if (isPlainObject(m.self.quorum) && Number.isSafeInteger(m.self.quorum.min_humans) && m.self.quorum.min_humans < 1) {
      errors.push("self.quorum.min_humans must be >= 1 (the constitution floor)");
    }
  }

  // The open surfaces the DSL emits: the bare ACQUIRE half of a lease pair
  // (fleets/locks), and — for the ONE lock that declares `value` — the
  // lock-scoped open SET_VALUE on that same prefix. Any other decorated open
  // row is refused, not stripped.
  const openValuePrefixes = new Set((Array.isArray(m.locks) ? m.locks : [])
    .filter((l) => isPlainObject(l) && l.value !== undefined).map((l) => l.prefix));
  if (!Array.isArray(m.policies) || m.policies.length === 0) errors.push("policies must be the non-empty seeded table");
  else m.policies.forEach((p, i) => {
    const where = `policies[${i}]`;
    if (!isPlainObject(p)) { errors.push(`${where} must be an object`); return; }
    checkKeys(p, new Set(["prefix", "action", "threshold", "role", "min_humans", "max_per_operator", "allow_open"]), where, errors);
    if (!feltOk(p.prefix) && p.prefix !== "GLOBAL") errors.push(`${where}.prefix must be felt-sized`);
    if (!ACTIONS.includes(p.action)) errors.push(`${where}.action must be one of ${ACTIONS.join("|")}`);
    if (p.allow_open === true) {
      const bare = p.threshold === 0 && p.role === null && p.min_humans === 0 && p.max_per_operator === 0;
      const legal = p.action === "ACQUIRE" || (p.action === "SET_VALUE" && openValuePrefixes.has(p.prefix));
      if (!bare || !legal) {
        errors.push(`${where}: allow_open is only the bare open-ACQUIRE half of a lease pair, or the bare open SET_VALUE of the ONE lock that declares a value (threshold 0, no role)`);
      }
    } else if (p.allow_open !== false) {
      errors.push(`${where}.allow_open must be a boolean (the only open surfaces are a lease ACQUIRE and the one lock-scoped value)`);
    }
  });

  lintSecrets(m, "manifest", errors, new Set(m.connectors?.map?.((c, i) => `manifest.connectors[${i}].credentials`) ?? []));
  return { ok: errors.length === 0, errors };
}

/// Canonicalize for publishing — validates first, throws with every error.
export function canonicalOrgManifest(m) {
  const { ok, errors } = validateOrgManifest(m);
  if (!ok) throw new Error(`invalid ${ORG_SCHEMA}: ${errors.join("; ")}`);
  return renderConfig(m);
}

/// The digest the quorum commits on-chain.
export const orgManifestDigest = (m) => digestOf(canonicalOrgManifest(m));

/// S3 object key for the manifest blob (the `<value_key>/spec` convention).
export const manifestSpecKey = (valueKeyStr) => `${valueKeyStr}/spec`;
