// Key and schema-ref grammar shared by the org declaration and everything
// that writes under it: the `<name>/v<N>` schema ref a governed value
// carries, the `{param}` key template an intent type declares, and the store
// key a value's document lives at. The compiler proves statically
// (./invariants.mjs) what `expandKey` enforces on each request.
import { assertShortString } from "../protocol.mjs";

/// Schema refs look like `k8srbacgrant/v1` — a felt, so <= 31 chars.
export const SCHEMA_REF_RE = /^[a-z0-9-]+\/v[0-9]+$/;

// ------------------------------------------------------------------------
// Key templates — "k8s/rbac/{ns}/{name}" -> a felt-checked value key.
// ------------------------------------------------------------------------

export const KEY_TOKEN_RE = /\{([A-Za-z0-9_]+)\}/g;
/// A substituted segment must stay key-safe: no '/', no braces, no whitespace.
export const SEGMENT_RE = /^[A-Za-z0-9_.-]+$/;

/// Expand a key template with param values. Throws on a missing param, an
/// unsafe segment, or a result past the 31-char felt cap — the same check the
/// compiler proves statically via each field's max_len arithmetic.
export function expandKey(template, params) {
  const key = template.replace(KEY_TOKEN_RE, (_, field) => {
    const v = params?.[field];
    if (v === undefined || v === null) throw new Error(`key template ${template}: missing param "${field}"`);
    const s = String(v);
    if (!SEGMENT_RE.test(s)) throw new Error(`key template ${template}: param "${field}" value ${JSON.stringify(s)} is not key-safe`);
    return s;
  });
  if (key.includes("{") || key.includes("}")) throw new Error(`key template ${template}: unresolved token`);
  return assertShortString(key, "value key");
}

/// The template's referenced field names, in order (for the compiler's
/// max_len arithmetic and the webapp's form wiring).
export function templateFields(template) {
  return [...template.matchAll(KEY_TOKEN_RE)].map((m) => m[1]);
}

/// The S3 object key for a value's spec blob (the `<value_key>/spec`
/// convention — a store key, not a felt, so no 31-char limit).
export const specKeyFor = (valueKeyStr) => `${valueKeyStr}/spec`;
