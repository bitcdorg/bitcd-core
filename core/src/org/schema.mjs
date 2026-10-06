// The bitcd/v1 org declaration: structural validation of the parsed yaml
// document into a normalized org model. One document declares the whole
// organization: the cast, the executor-backed surfaces (`connectors` +
// `intent_types`), and the connector-less surfaces — `fleets` (the
// mutual-gating pattern: value gate + explicit SET_POLICY meta-gate + the
// work-lease pair), `locks` (standalone open-ACQUIRE + quorum FORCE_UNLOCK,
// the k8s-lease shape), and `values` (plain governed values). Every section
// is optional; an org must declare at least one governed surface.
//
// Bounded declarative data throughout: closed field sets at every level
// (unknown fields REJECTED, not stripped), closed enums, literal strings,
// durations — never a pattern language, never an expression. The security
// cross-checks live in ./invariants.mjs and run over the normalized model
// this module returns; this module owns shape, types, and per-field bounds.
//
// Pure: takes a PARSED document (the CLI does the yaml parsing), never throws
// — returns { ok, errors, model }.
import { SHORTSTRING_MAX } from "../protocol.mjs";
import { isPlainObject, lintSecrets } from "./lint.mjs";
import { SCHEMA_REF_RE, templateFields } from "./keys.mjs";

export const DSL_SCHEMA = "bitcd/v1";

const NAME_RE = /^[A-Za-z0-9_-]+$/;
const ROLE_RE = /^[A-Z][A-Z0-9_]*$/;          // role felts, by convention upper-case
const OPERATOR_RE = /^[A-Z][A-Z0-9_]*$/;      // operator_id felts
const ENV_VAR_RE = /^[A-Z][A-Z0-9_]*$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{1,64}$/;
const PREFIX_RE = /^[a-z0-9][a-z0-9/._-]*$/;  // chain prefixes / keys (felt-checked for length)
const ENUM_VALUE_RE = /^[A-Za-z0-9_.:-]+$/;
const DURATION_RE = /^([0-9]+)(s|m|h|d)?$/;

export const FIELD_TYPES = ["enum", "name", "subject", "number", "boolean", "duration"];
export const NAME_FORMATS = ["identifier", "key-slug", "email", "hostname", "arn"];
/// Whether a write surface keeps a person reachable: with `summon_human: true`
/// any eligible signer may demand a person's signature on one of its proposals
/// (request_human_review), and once demanded no quorum can commit without it.
/// False when left out.
function parseSummonHuman(o, where, errors) {
  if (o.escalation !== undefined) {
    errors.push(`${where}.escalation is written summon_human: true|false`);
  }
  if (o.summon_human === undefined) return false;
  if (typeof o.summon_human !== "boolean") {
    errors.push(`${where}.summon_human must be true or false`);
    return false;
  }
  return o.summon_human;
}
// A connector's `type` is a free name (the shape check is NAME_RE): the
// executor selects a provider factory by type at runtime and HALTs on one it
// does not know. A type may be executor-less BY DESIGN — it exists so the
// per-domain attest role is declared where every other role is.

const DUR_UNIT = { s: 1, m: 60, h: 3600, d: 86400 };

/// "24h" | "300s" | "30m" | "7d" | 300 -> seconds (or null when unparseable).
export function parseDuration(v) {
  if (Number.isSafeInteger(v) && v >= 0) return v;
  if (typeof v !== "string") return null;
  const m = DURATION_RE.exec(v);
  if (!m) return null;
  return Number(m[1]) * DUR_UNIT[m[2] ?? "s"];
}

const feltLen = (s, where, errors) => {
  if (s.length > SHORTSTRING_MAX) errors.push(`${where}: "${s}" exceeds the ${SHORTSTRING_MAX}-char felt cap`);
};

function checkKeys(obj, allowed, where, errors) {
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) errors.push(`${where}: unknown field "${k}" (decoration is rejected, not stripped)`);
  }
}

function boundedData(v, where, errors, depth = 0) {
  if (depth > 3) { errors.push(`${where} exceeds the bounded nesting depth (3)`); return; }
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return;
  if (Array.isArray(v)) { v.forEach((x, i) => boundedData(x, `${where}[${i}]`, errors, depth + 1)); return; }
  if (isPlainObject(v)) {
    for (const [k, x] of Object.entries(v)) boundedData(x, `${where}.${k}`, errors, depth + 1);
    return;
  }
  errors.push(`${where} holds a non-declarative value (${typeof v})`);
}

// ---------------------------------------------------------------------------
// Quorum blocks — the bounded policy vocabulary. allow_open is NOT expressible
// in a quorum block: the open-value envelope is enforced by construction (open
// ACQUIRE exists only as a fleet lease or a lock, open SET_VALUE only as a
// lock's `value`).
// ---------------------------------------------------------------------------
const QUORUM_KEYS = new Set(["threshold", "role", "min_humans", "max_per_operator"]);

function parseQuorum(q, where, errors) {
  if (!isPlainObject(q)) { errors.push(`${where} must be a quorum block {threshold, role, min_humans, max_per_operator}`); return null; }
  checkKeys(q, QUORUM_KEYS, where, errors);
  const out = {};
  if (!Number.isSafeInteger(q.threshold) || q.threshold < 1) errors.push(`${where}.threshold must be an integer >= 1`);
  else out.threshold = q.threshold;
  if (typeof q.role !== "string" || !ROLE_RE.test(q.role)) errors.push(`${where}.role must be an UPPER_CASE role name`);
  else { out.role = q.role; feltLen(q.role, `${where}.role`, errors); }
  if (!Number.isSafeInteger(q.min_humans) || q.min_humans < 0) errors.push(`${where}.min_humans must be an integer >= 0`);
  else out.min_humans = q.min_humans;
  if (!Number.isSafeInteger(q.max_per_operator) || q.max_per_operator < 0) errors.push(`${where}.max_per_operator must be an integer >= 0 (0 = unlimited)`);
  else out.max_per_operator = q.max_per_operator;
  if ("allow_open" in q) errors.push(`${where}: allow_open is not expressible — open ACQUIRE exists only as a fleet lease or a lock, open SET_VALUE only as a lock's value`);
  return out;
}

// ---------------------------------------------------------------------------
// Params field vocabulary — the webapp's form contract. A new need is a new
// field TYPE added here, never an expression.
// ---------------------------------------------------------------------------
const COMMON_FIELD_KEYS = ["type", "label", "help", "required", "default"];
const FIELD_KEYS = {
  enum: new Set([...COMMON_FIELD_KEYS, "values", "map"]),
  name: new Set([...COMMON_FIELD_KEYS, "max_len", "format"]),
  subject: new Set([...COMMON_FIELD_KEYS, "kinds", "source"]),
  number: new Set([...COMMON_FIELD_KEYS, "min", "max", "integer"]),
  boolean: new Set([...COMMON_FIELD_KEYS]),
  duration: new Set([...COMMON_FIELD_KEYS, "min", "max", "presets"]),
};

export function validateFieldSpec(name, f, where, errors) {
  if (!NAME_RE.test(name)) errors.push(`${where}: param name "${name}" must match [A-Za-z0-9_-]+`);
  if (!isPlainObject(f)) { errors.push(`${where} must be a field spec object`); return null; }
  if (!FIELD_TYPES.includes(f.type)) { errors.push(`${where}.type must be one of ${FIELD_TYPES.join("|")}`); return null; }
  checkKeys(f, FIELD_KEYS[f.type], where, errors);
  if (typeof f.label !== "string" || f.label.length === 0 || f.label.length > 80) errors.push(`${where}.label must be a non-empty string (<= 80 chars)`);
  if (f.help !== undefined && (typeof f.help !== "string" || f.help.length > 400)) errors.push(`${where}.help must be a string (<= 400 chars)`);
  if (f.required !== undefined && typeof f.required !== "boolean") errors.push(`${where}.required must be a boolean`);

  const out = { name, type: f.type, label: f.label, required: f.required ?? true };
  if (f.help !== undefined) out.help = f.help;

  if (f.type === "enum") {
    if (!Array.isArray(f.values) || f.values.length === 0 || f.values.length > 64) {
      errors.push(`${where}.values must be a non-empty array (<= 64 options)`);
    } else {
      for (const v of f.values) {
        if (typeof v !== "string" || !ENUM_VALUE_RE.test(v)) errors.push(`${where}.values: ${JSON.stringify(v)} is not a literal option`);
      }
      out.values = f.values;
    }
    if (f.map !== undefined) {
      if (!isPlainObject(f.map)) errors.push(`${where}.map must map every enum value to bounded provider data`);
      else {
        const values = new Set(f.values ?? []);
        for (const [k, v] of Object.entries(f.map)) {
          if (!values.has(k)) errors.push(`${where}.map has key "${k}" that is not in values`);
          boundedData(v, `${where}.map.${k}`, errors);
        }
        for (const v of values) if (f.map[v] === undefined) errors.push(`${where}.map must cover every value (missing "${v}")`);
        out.map = f.map;
      }
    }
    if (f.default !== undefined && !(f.values ?? []).includes(f.default)) errors.push(`${where}.default must be one of values`);
  } else if (f.type === "name") {
    if (!Number.isSafeInteger(f.max_len) || f.max_len < 1 || f.max_len > 64) errors.push(`${where}.max_len is required (an integer 1..64)`);
    else out.max_len = f.max_len;
    if (f.format !== undefined && !NAME_FORMATS.includes(f.format)) errors.push(`${where}.format must be one of ${NAME_FORMATS.join("|")}`);
    out.format = f.format ?? "identifier";
    if (f.default !== undefined && typeof f.default !== "string") errors.push(`${where}.default must be a string`);
  } else if (f.type === "subject") {
    const hasKinds = f.kinds !== undefined;
    const hasSource = f.source !== undefined;
    if (!hasKinds && !hasSource) errors.push(`${where} needs kinds (provider subject kinds) and/or source: "signers"`);
    if (hasKinds) {
      if (!Array.isArray(f.kinds) || f.kinds.length === 0 || !f.kinds.every((k) => typeof k === "string" && NAME_RE.test(k))) {
        errors.push(`${where}.kinds must be a non-empty array of kind names`);
      } else out.kinds = f.kinds;
    }
    if (hasSource) {
      if (f.source !== "signers") errors.push(`${where}.source must be "signers" (roster-derived — the webapp never invents subjects)`);
      else out.source = f.source;
    }
  } else if (f.type === "number") {
    for (const k of ["min", "max"]) {
      if (f[k] !== undefined) {
        if (typeof f[k] !== "number" || !Number.isFinite(f[k])) errors.push(`${where}.${k} must be a finite number`);
        else out[k] = f[k];
      }
    }
    out.integer = f.integer ?? true;
    if (typeof out.integer !== "boolean") errors.push(`${where}.integer must be a boolean`);
    if (f.default !== undefined && typeof f.default !== "number") errors.push(`${where}.default must be a number`);
    else if (f.default !== undefined && ((out.min !== undefined && f.default < out.min) || (out.max !== undefined && f.default > out.max))) {
      errors.push(`${where}.default must lie within min..max`);
    }
  } else if (f.type === "duration") {
    for (const k of ["min", "max"]) {
      if (f[k] !== undefined) {
        const s = parseDuration(f[k]);
        if (s === null) errors.push(`${where}.${k} must be a duration ("30m", "24h", seconds)`);
        else out[`${k}_s`] = s;
      }
    }
    if (f.presets !== undefined) {
      if (!Array.isArray(f.presets) || f.presets.length === 0 || f.presets.length > 12) errors.push(`${where}.presets must be a non-empty array (<= 12)`);
      else {
        out.presets_s = f.presets.map((v) => parseDuration(v));
        if (out.presets_s.some((s) => s === null)) errors.push(`${where}.presets holds an unparseable duration`);
      }
    }
    if (f.default !== undefined) {
      const s = parseDuration(f.default);
      if (s === null) errors.push(`${where}.default must be a duration`);
      else out.default_s = s;
    }
    if (out.default_s !== undefined && ((out.min_s !== undefined && out.default_s < out.min_s) || (out.max_s !== undefined && out.default_s > out.max_s))) {
      errors.push(`${where}.default must lie within min..max`);
    }
  } else if (f.type === "boolean") {
    if (f.default !== undefined && typeof f.default !== "boolean") errors.push(`${where}.default must be a boolean`);
  }
  if (f.default !== undefined && out.default === undefined && out.default_s === undefined) out.default = f.default;
  return out;
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------
const TOP_KEYS = new Set([
  "schema", "org", "version", "naming", "ceremony",
  "cast", "connectors", "storage", "intent_types",
  "fleets", "locks", "values",
  "reserved_prefixes", "baseline", "manifest",
]);
const SIGNER_KEYS = new Set(["address", "human", "operator", "role"]);
const CONNECTOR_KEYS = new Set(["type", "role", "executors", "config", "credentials"]);
// `escalation` stays a known key only so a file that still uses it gets a
// pointer to summon_human (parseSummonHuman) rather than an unknown-key error.
const INTENT_KEYS = new Set([
  "connector", "prefix", "schema", "key", "params", "ttl", "quorum",
  "revoke", "attest", "escalation", "summon_human", "mutable", "immutable_ack",
]);
const TTL_KEYS = new Set(["required", "default", "min", "max"]);
const VALUE_KEYS = new Set(["prefix", "schema", "key", "quorum", "revoke", "escalation", "summon_human", "mutable", "immutable_ack"]);
const FLEET_KEYS = new Set(["prefix", "schema", "key", "quorum", "meta", "escalation", "summon_human", "lease"]);
const LEASE_KEYS = new Set(["prefix", "recovery"]);
const LOCK_KEYS = new Set(["prefix", "recovery", "value", "mutable"]);
const LOCK_VALUE_KEYS = new Set(["schema", "key"]);

/// Validate a PARSED bitcd/v1 document. Returns { ok, errors,
/// model } — never throws. `model` is the normalized org model
/// ./invariants.mjs and ./compile.mjs consume (present only when ok).
export function validateOrg(doc) {
  const errors = [];
  if (!isPlainObject(doc)) return { ok: false, errors: ["document is not a mapping"] };
  checkKeys(doc, TOP_KEYS, "document", errors);

  if (doc.schema !== DSL_SCHEMA) errors.push(`schema must be "${DSL_SCHEMA}", got ${JSON.stringify(doc.schema)}`);
  if (typeof doc.org !== "string" || !NAME_RE.test(doc.org)) errors.push("org must be a [A-Za-z0-9_-]+ name");
  if (!Number.isSafeInteger(doc.version) || doc.version < 1) errors.push("version must be a positive integer");

  if (doc.naming !== "literal") {
    errors.push(doc.naming === "hashed"
      ? 'naming: "hashed" is designed-for but not yet expressible — use "literal" (every felt <= 31 chars, proven at compile)'
      : 'naming must be "literal"');
  }

  if (!isPlainObject(doc.ceremony) || typeof doc.ceremony.renounce !== "boolean") {
    errors.push("ceremony.renounce must be stated explicitly (true|false) — the prefix envelope is sealed at ceremony");
  } else {
    checkKeys(doc.ceremony, new Set(["renounce"]), "ceremony", errors);
  }

  // ---- cast ----
  const roles = [];
  const signers = [];
  if (!isPlainObject(doc.cast)) errors.push("cast is required ({roles, signers})");
  else {
    checkKeys(doc.cast, new Set(["roles", "signers"]), "cast", errors);
    if (!Array.isArray(doc.cast.roles) || doc.cast.roles.length === 0) errors.push("cast.roles must be a non-empty array of role names");
    else {
      for (const r of doc.cast.roles) {
        if (typeof r !== "string" || !ROLE_RE.test(r)) errors.push(`cast.roles: ${JSON.stringify(r)} must be UPPER_CASE`);
        else { feltLen(r, "cast.roles", errors); roles.push(r); }
      }
      if (new Set(roles).size !== roles.length) errors.push("cast.roles has duplicates");
    }
    if (!isPlainObject(doc.cast.signers) || Object.keys(doc.cast.signers).length === 0) {
      errors.push("cast.signers must be a non-empty map of name -> {address, human, operator, role}");
    } else {
      for (const [name, s] of Object.entries(doc.cast.signers)) {
        const where = `cast.signers.${name}`;
        if (!NAME_RE.test(name)) errors.push(`${where}: signer name must match [A-Za-z0-9_-]+`);
        if (!isPlainObject(s)) { errors.push(`${where} must be an object`); continue; }
        checkKeys(s, SIGNER_KEYS, where, errors);
        if (typeof s.address !== "string" || !ADDRESS_RE.test(s.address)) errors.push(`${where}.address must be a 0x hex address`);
        if (typeof s.human !== "boolean") errors.push(`${where}.human must be a boolean`);
        if (typeof s.operator !== "string" || !OPERATOR_RE.test(s.operator)) errors.push(`${where}.operator must be an UPPER_CASE operator id`);
        else feltLen(s.operator, `${where}.operator`, errors);
        if (typeof s.role !== "string" || !roles.includes(s.role)) errors.push(`${where}.role must be one of cast.roles`);
        signers.push({ name, address: s.address, human: s.human === true, operator: s.operator, role: s.role });
      }
      const addrs = signers.map((s) => { try { return BigInt(s.address).toString(16); } catch { return s.address; } });
      if (new Set(addrs).size !== addrs.length) errors.push("cast.signers has duplicate addresses");
    }
  }

  // ---- connectors (optional — a fleet-only or value-only org has no executor) ----
  const connectors = [];
  const connectorsDoc = isPlainObject(doc.connectors) ? doc.connectors : null;
  if (doc.connectors !== undefined && connectorsDoc === null) {
    errors.push("connectors must be a map");
  }
  {
    for (const [name, c] of Object.entries(connectorsDoc ?? {})) {
      const where = `connectors.${name}`;
      if (!NAME_RE.test(name)) errors.push(`${where}: connector name must match [A-Za-z0-9_-]+`);
      if (!isPlainObject(c)) { errors.push(`${where} must be an object`); continue; }
      checkKeys(c, CONNECTOR_KEYS, where, errors);
      if (typeof c.type !== "string" || !NAME_RE.test(c.type)) errors.push(`${where}.type must be a provider type name`);
      if (typeof c.role !== "string" || !roles.includes(c.role)) errors.push(`${where}.role must be one of cast.roles (the connector's per-domain executor role)`);
      if (!Array.isArray(c.executors) || c.executors.length === 0) errors.push(`${where}.executors must name at least one signer`);
      else for (const e of c.executors) {
        if (!signers.some((s) => s.name === e)) errors.push(`${where}.executors: "${e}" is not in cast.signers`);
      }
      if (c.config !== undefined) {
        if (!isPlainObject(c.config)) errors.push(`${where}.config must be a mapping of NON-secret provider settings`);
        else boundedData(c.config, `${where}.config`, errors);
      }
      if (c.credentials !== undefined) {
        if (!isPlainObject(c.credentials)) errors.push(`${where}.credentials must map credential names to ENV VAR NAMES (never material)`);
        else for (const [k, v] of Object.entries(c.credentials)) {
          const vals = Array.isArray(v) ? v : [v];
          for (const ev of vals) {
            if (typeof ev !== "string" || !ENV_VAR_RE.test(ev)) errors.push(`${where}.credentials.${k}: ${JSON.stringify(ev)} is not an ENV_VAR_NAME (secret material never enters the yaml)`);
          }
        }
      }
      connectors.push({
        name, type: c.type, role: c.role, executors: c.executors ?? [],
        config: c.config ?? {}, credentials: c.credentials ?? {},
      });
    }
  }

  // ---- storage ----
  let storage = null;
  if (!isPlainObject(doc.storage)) errors.push("storage is required ({bucket, endpoint_env?})");
  else {
    checkKeys(doc.storage, new Set(["bucket", "endpoint_env"]), "storage", errors);
    if (typeof doc.storage.bucket !== "string" || doc.storage.bucket.length === 0) errors.push("storage.bucket must be a bucket NAME");
    if (doc.storage.endpoint_env !== undefined && !ENV_VAR_RE.test(doc.storage.endpoint_env)) errors.push("storage.endpoint_env must be an ENV_VAR_NAME");
    storage = { bucket: doc.storage.bucket, endpoint_env: doc.storage.endpoint_env ?? "BITCD_S3_ENDPOINT" };
  }

  // ---- intent types (optional — see the governed-surface floor below) ----
  const intentTypes = [];
  const intentsDoc = isPlainObject(doc.intent_types) ? doc.intent_types : null;
  if (doc.intent_types !== undefined && intentsDoc === null) {
    errors.push("intent_types must be a map");
  }
  {
    for (const [name, it] of Object.entries(intentsDoc ?? {})) {
      const where = `intent_types.${name}`;
      if (!NAME_RE.test(name)) errors.push(`${where}: intent-type name must match [A-Za-z0-9_-]+`);
      if (!isPlainObject(it)) { errors.push(`${where} must be an object`); continue; }
      checkKeys(it, INTENT_KEYS, where, errors);
      if (typeof it.connector !== "string" || !connectors.some((c) => c.name === it.connector)) {
        errors.push(`${where}.connector must name a declared connector`);
      }
      if (typeof it.prefix !== "string" || !PREFIX_RE.test(it.prefix)) errors.push(`${where}.prefix must be a chain prefix`);
      else feltLen(it.prefix, `${where}.prefix`, errors);
      if (typeof it.schema !== "string" || !SCHEMA_REF_RE.test(it.schema)) errors.push(`${where}.schema must look like <name>/v<N> (the grant-envelope schema ref)`);
      else feltLen(it.schema, `${where}.schema`, errors);
      if (typeof it.key !== "string" || it.key.length === 0) errors.push(`${where}.key is required (the value-key template)`);
      else if (typeof it.prefix === "string" && !it.key.startsWith(`${it.prefix}/`)) errors.push(`${where}.key must start with "${it.prefix}/" (the key is scoped to its prefix)`);

      const params = [];
      if (!isPlainObject(it.params) || Object.keys(it.params).length === 0) errors.push(`${where}.params must be a non-empty map of field specs`);
      else for (const [pn, pf] of Object.entries(it.params)) {
        const spec = validateFieldSpec(pn, pf, `${where}.params.${pn}`, errors);
        if (spec) params.push(spec);
      }

      let ttl = null;
      if (it.ttl !== undefined) {
        if (!isPlainObject(it.ttl)) errors.push(`${where}.ttl must be {required?, default?, min?, max}`);
        else {
          checkKeys(it.ttl, TTL_KEYS, `${where}.ttl`, errors);
          const maxS = parseDuration(it.ttl.max);
          if (maxS === null || maxS <= 0) errors.push(`${where}.ttl.max is required (a positive duration — the longest grant this type can commit)`);
          const defS = it.ttl.default !== undefined ? parseDuration(it.ttl.default) : undefined;
          if (it.ttl.default !== undefined && defS === null) errors.push(`${where}.ttl.default must be a duration`);
          const minS = it.ttl.min !== undefined ? parseDuration(it.ttl.min) : undefined;
          if (it.ttl.min !== undefined && minS === null) errors.push(`${where}.ttl.min must be a duration`);
          if (it.ttl.required !== undefined && typeof it.ttl.required !== "boolean") errors.push(`${where}.ttl.required must be a boolean`);
          ttl = { required: it.ttl.required ?? false, max_s: maxS ?? 0 };
          if (defS !== undefined && defS !== null) ttl.default_s = defS;
          if (minS !== undefined && minS !== null) ttl.min_s = minS;
          if (ttl.default_s !== undefined && ttl.default_s > ttl.max_s) errors.push(`${where}.ttl.default exceeds ttl.max`);
          if (ttl.min_s !== undefined && ttl.min_s > ttl.max_s) errors.push(`${where}.ttl.min exceeds ttl.max`);
        }
      }

      const quorum = parseQuorum(it.quorum, `${where}.quorum`, errors);
      let revoke = "same";
      if (it.revoke !== undefined && it.revoke !== "same") {
        const rq = parseQuorum(it.revoke, `${where}.revoke`, errors);
        if (rq) revoke = rq;
      }
      let attest = { k: 1 };
      if (it.attest !== undefined) {
        if (!isPlainObject(it.attest) || !Number.isSafeInteger(it.attest.k) || it.attest.k < 1) {
          errors.push(`${where}.attest must be {k: <integer >= 1>}`);
        } else {
          checkKeys(it.attest, new Set(["k"]), `${where}.attest`, errors);
          attest = { k: it.attest.k };
        }
      }
      const summon_human = parseSummonHuman(it, where, errors);
      if (typeof it.mutable !== "boolean") errors.push(`${where}.mutable must be stated explicitly (the prefix envelope is sealed at ceremony)`);
      if (it.mutable === false && it.immutable_ack !== true) {
        errors.push(`${where}: mutable: false makes "${it.prefix}" PERMANENTLY immutable after renounce — acknowledge with immutable_ack: true`);
      }
      if (it.mutable === true && it.immutable_ack !== undefined) errors.push(`${where}.immutable_ack only accompanies mutable: false`);

      intentTypes.push({
        name, connector: it.connector, prefix: it.prefix, schema: it.schema,
        key: it.key, key_fields: typeof it.key === "string" ? templateFields(it.key) : [],
        params, ttl, quorum, revoke, attest, summon_human, mutable: it.mutable === true,
      });
    }
  }

  // ---- the connector-less surfaces: values / fleets / locks ----
  // Shared field parsing for a governed-value surface head ({prefix, schema,
  // key} with the prefix scope binding and the 31-char proof on the STATIC key).
  const parseSurfaceHead = (s, where) => {
    const out = {};
    if (typeof s.prefix !== "string" || !PREFIX_RE.test(s.prefix)) errors.push(`${where}.prefix must be a chain prefix`);
    else { feltLen(s.prefix, `${where}.prefix`, errors); out.prefix = s.prefix; }
    if (typeof s.schema !== "string" || !SCHEMA_REF_RE.test(s.schema)) errors.push(`${where}.schema must look like <name>/v<N> (the governed value's schema ref)`);
    else { feltLen(s.schema, `${where}.schema`, errors); out.schema = s.schema; }
    if (typeof s.key !== "string" || !PREFIX_RE.test(s.key)) errors.push(`${where}.key must be a chain key (the ONE governed value key — no template)`);
    else {
      feltLen(s.key, `${where}.key`, errors);
      if (typeof s.prefix === "string" && !s.key.startsWith(`${s.prefix}/`)) errors.push(`${where}.key must start with "${s.prefix}/" (the key is scoped to its prefix)`);
      out.key = s.key;
    }
    return out;
  };

  // values: plain governed values — a quorum-gated config with no connector
  // and no executor. TOMBSTONE is seeded only when a revoke gate is
  // declared; rewriting through SET_VALUE is always the recovery path.
  const values = [];
  if (doc.values !== undefined) {
    if (!isPlainObject(doc.values)) errors.push("values must be a map of name -> {prefix, schema, key, quorum, mutable}");
    else for (const [name, val] of Object.entries(doc.values)) {
      const where = `values.${name}`;
      if (!NAME_RE.test(name)) errors.push(`${where}: value name must match [A-Za-z0-9_-]+`);
      if (!isPlainObject(val)) { errors.push(`${where} must be an object`); continue; }
      checkKeys(val, VALUE_KEYS, where, errors);
      const head = parseSurfaceHead(val, where);
      const quorum = parseQuorum(val.quorum, `${where}.quorum`, errors);
      let revoke = "none";
      if (val.revoke !== undefined) {
        if (val.revoke === "same") revoke = "same";
        else { const rq = parseQuorum(val.revoke, `${where}.revoke`, errors); if (rq) revoke = rq; }
      }
      const summon_human = parseSummonHuman(val, where, errors);
      if (typeof val.mutable !== "boolean") errors.push(`${where}.mutable must be stated explicitly (the prefix envelope is sealed at ceremony)`);
      if (val.mutable === false && val.immutable_ack !== true) {
        errors.push(`${where}: mutable: false makes "${val.prefix}" PERMANENTLY immutable after renounce — acknowledge with immutable_ack: true`);
      }
      if (val.mutable === true && val.immutable_ack !== undefined) errors.push(`${where}.immutable_ack only accompanies mutable: false`);
      values.push({ name, ...head, quorum, revoke, summon_human, mutable: val.mutable === true });
    }
  }

  // fleets: the agentgate mutual-gating pattern — the value gate, an EXPLICIT
  // SET_POLICY meta-gate (the dev/production min_humans difference is
  // declared, never derived), and the work-lease pair (open ACQUIRE + quorum
  // FORCE_UNLOCK).
  const fleets = [];
  if (doc.fleets !== undefined) {
    if (!isPlainObject(doc.fleets)) errors.push("fleets must be a map of name -> {prefix, schema, key, quorum, meta, lease}");
    else for (const [name, f] of Object.entries(doc.fleets)) {
      const where = `fleets.${name}`;
      if (!NAME_RE.test(name)) errors.push(`${where}: fleet name must match [A-Za-z0-9_-]+`);
      if (!isPlainObject(f)) { errors.push(`${where} must be an object`); continue; }
      checkKeys(f, FLEET_KEYS, where, errors);
      const head = parseSurfaceHead(f, where);
      const quorum = parseQuorum(f.quorum, `${where}.quorum`, errors);
      const meta = parseQuorum(f.meta, `${where}.meta (the fleet's SET_POLICY gate — required, never derived)`, errors);
      const summon_human = parseSummonHuman(f, where, errors);
      let lease = null;
      if (!isPlainObject(f.lease)) {
        errors.push(`${where}.lease is required ({prefix, recovery}) — the work-lease is part of the fleet pattern`);
      } else {
        checkKeys(f.lease, LEASE_KEYS, `${where}.lease`, errors);
        if (typeof f.lease.prefix !== "string" || !PREFIX_RE.test(f.lease.prefix)) errors.push(`${where}.lease.prefix must be a chain prefix`);
        else feltLen(f.lease.prefix, `${where}.lease.prefix`, errors);
        const recovery = parseQuorum(f.lease.recovery, `${where}.lease.recovery`, errors);
        lease = { prefix: f.lease.prefix, recovery };
      }
      fleets.push({ name, ...head, quorum, meta, summon_human, lease });
    }
  }

  // locks: standalone open-ACQUIRE lock surfaces (the k8s-lease shape) — the
  // lock keys are dynamic under the prefix; the recovery gate is the whole
  // declaration. A lock MAY additionally carry `value` — the ONE lock-scoped
  // open SET_VALUE the envelope permits (the lock IS the write capability —
  // the terraform-state shape); the [single-open-value] lint holds the org to at most one
  // such prefix. `mutable: true` seeds the lock prefix's SET_POLICY at
  // recovery strength (floored to one human).
  const locks = [];
  if (doc.locks !== undefined) {
    if (!isPlainObject(doc.locks)) errors.push("locks must be a map of name -> {prefix, recovery, value?, mutable?}");
    else for (const [name, l] of Object.entries(doc.locks)) {
      const where = `locks.${name}`;
      if (!NAME_RE.test(name)) errors.push(`${where}: lock name must match [A-Za-z0-9_-]+`);
      if (!isPlainObject(l)) { errors.push(`${where} must be an object`); continue; }
      checkKeys(l, LOCK_KEYS, where, errors);
      if (typeof l.prefix !== "string" || !PREFIX_RE.test(l.prefix)) errors.push(`${where}.prefix must be a chain prefix`);
      else feltLen(l.prefix, `${where}.prefix`, errors);
      const recovery = parseQuorum(l.recovery, `${where}.recovery`, errors);
      let value = null;
      if (l.value !== undefined) {
        if (!isPlainObject(l.value)) errors.push(`${where}.value must be {schema, key} — the lock-scoped open value (the lock holder writes it single-writer)`);
        else {
          checkKeys(l.value, LOCK_VALUE_KEYS, `${where}.value`, errors);
          const v = {};
          if (typeof l.value.schema !== "string" || !SCHEMA_REF_RE.test(l.value.schema)) errors.push(`${where}.value.schema must look like <name>/v<N> (the value's schema ref)`);
          else { feltLen(l.value.schema, `${where}.value.schema`, errors); v.schema = l.value.schema; }
          if (typeof l.value.key !== "string" || !PREFIX_RE.test(l.value.key)) errors.push(`${where}.value.key must be a chain key`);
          else {
            feltLen(l.value.key, `${where}.value.key`, errors);
            if (typeof l.prefix === "string" && !l.value.key.startsWith(`${l.prefix}/`)) errors.push(`${where}.value.key must start with "${l.prefix}/" (the key is scoped to its prefix)`);
            v.key = l.value.key;
          }
          value = v;
        }
      }
      if (l.mutable !== undefined && typeof l.mutable !== "boolean") errors.push(`${where}.mutable must be a boolean`);
      locks.push({ name, prefix: l.prefix, recovery, value, mutable: l.mutable === true });
    }
  }

  // The governed-surface floor: an org with nothing to govern is a mistake.
  const declared = (x) => (isPlainObject(x) ? Object.keys(x).length : 0);
  if (declared(doc.intent_types) + declared(doc.fleets) + declared(doc.values) === 0) {
    errors.push("an org must declare at least one governed surface (intent_types, fleets, or values)");
  }

  // ---- reserved prefixes ----
  const reserved = [];
  if (doc.reserved_prefixes !== undefined) {
    if (!Array.isArray(doc.reserved_prefixes)) errors.push("reserved_prefixes must be an array");
    else doc.reserved_prefixes.forEach((r, i) => {
      const where = `reserved_prefixes[${i}]`;
      if (!isPlainObject(r)) { errors.push(`${where} must be {prefix, set_policy}`); return; }
      checkKeys(r, new Set(["prefix", "set_policy"]), where, errors);
      if (typeof r.prefix !== "string" || !PREFIX_RE.test(r.prefix)) errors.push(`${where}.prefix must be a chain prefix`);
      else feltLen(r.prefix, `${where}.prefix`, errors);
      const sp = parseQuorum(r.set_policy, `${where}.set_policy`, errors);
      if (sp) reserved.push({ prefix: r.prefix, set_policy: sp });
    });
  }

  // ---- baseline ----
  let baseline = { unmanaged: "untouched", drift_scope: "managed-keys" };
  if (doc.baseline !== undefined) {
    if (!isPlainObject(doc.baseline)) errors.push("baseline must be a mapping");
    else {
      checkKeys(doc.baseline, new Set(["unmanaged", "drift_scope"]), "baseline", errors);
      if (doc.baseline.unmanaged !== undefined && doc.baseline.unmanaged !== "untouched") {
        errors.push('baseline.unmanaged: only "untouched" is expressible (the executor never reads or writes outside managed keys)');
      }
      if (doc.baseline.drift_scope !== undefined && doc.baseline.drift_scope !== "managed-keys") {
        errors.push('baseline.drift_scope: only "managed-keys" is expressible');
      }
    }
  }

  // ---- the org manifest's own governance ----
  let manifest = null;
  if (!isPlainObject(doc.manifest)) errors.push("manifest is required ({key, quorum}) — the compiled definition is itself a governed value");
  else {
    checkKeys(doc.manifest, new Set(["key", "prefix", "quorum"]), "manifest", errors);
    if (typeof doc.manifest.key !== "string" || !PREFIX_RE.test(doc.manifest.key) || !doc.manifest.key.includes("/")) {
      errors.push("manifest.key must be a chain key (e.g. sys/manifest)");
    } else feltLen(doc.manifest.key, "manifest.key", errors);
    const prefix = doc.manifest.prefix ?? (typeof doc.manifest.key === "string" ? doc.manifest.key.split("/")[0] : null);
    if (typeof prefix !== "string" || !PREFIX_RE.test(prefix)) errors.push("manifest.prefix must be a chain prefix");
    else if (typeof doc.manifest.key === "string" && !doc.manifest.key.startsWith(`${prefix}/`)) errors.push(`manifest.key must sit under manifest.prefix "${prefix}"`);
    const mq = parseQuorum(doc.manifest.quorum, "manifest.quorum", errors);
    if (mq && mq.min_humans < 1) {
      errors.push("manifest.quorum.min_humans must be >= 1 — the org's constitution is never rewritten machine-only");
    }
    manifest = { key: doc.manifest.key, prefix, quorum: mq };
  }

  // ---- the secret lint over the whole document ----
  // Credentials sections carry secret NAME references and are exempt from the
  // field-name check (values are still linted).
  const allow = new Set(Object.keys(doc.connectors ?? {}).map((n) => `document.connectors.${n}.credentials`));
  lintSecrets(doc, "document", errors, allow);

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    errors: [],
    model: {
      org: doc.org, version: doc.version, naming: doc.naming,
      ceremony: { renounce: doc.ceremony.renounce },
      roles, signers, connectors, storage,
      intent_types: intentTypes,
      fleets, locks, values,
      reserved_prefixes: reserved,
      baseline, manifest,
    },
  };
}
