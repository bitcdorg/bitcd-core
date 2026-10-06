// The secret-material lint, shared by the grant envelope, the org schema,
// and the org manifest. Secret-shaped FIELD NAMES are refused anywhere (yaml and
// manifests reference secret NAMES under credential sections only), and
// secret-shaped VALUES are refused everywhere.
//
// capability-ledger's manifest lint follows the same discipline as a pattern
// copy, not an import: it versions its lint with its own schema.

export const SECRET_FIELD_RE = /(api[_-]?key|secret|token|password|credential|private[_-]?key)$/i;
export const SECRET_VALUE_RE = /^(sk-|ghp_|gho_|xox[baprs]-|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}|-----BEGIN )/;

export const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/// Walk a parsed document and push an error for every secret-shaped field
/// name or value. `allowFields` is a Set of exact key paths (e.g.
/// "connectors.prod.credentials") whose CHILDREN are secret NAME references
/// and therefore exempt from the field-name check (values are still linted).
export function lintSecrets(v, where, errors, allowFields = new Set()) {
  if (typeof v === "string") {
    if (SECRET_VALUE_RE.test(v)) {
      errors.push(`${where} looks like secret material (value prefix) — reference a secret NAME instead`);
    }
    return;
  }
  if (Array.isArray(v)) {
    v.forEach((x, i) => lintSecrets(x, `${where}[${i}]`, errors, allowFields));
    return;
  }
  if (isPlainObject(v)) {
    for (const [k, x] of Object.entries(v)) {
      if (SECRET_FIELD_RE.test(k) && !allowFields.has(where)) {
        errors.push(`${where}.${k}: secret-shaped field name — secret references belong under a credentials section (names only)`);
      }
      lintSecrets(x, `${where}.${k}`, errors, allowFields);
    }
  }
}
