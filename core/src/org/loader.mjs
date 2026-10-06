// Verify-on-read loading of the org manifest with the fail-safe: HALT on any
// terminal failure, a bounded grace window (<= one poll interval) for
// transient ones. Pure with injected IO; loadOrgManifest never throws — it
// classifies, and makeGate decides RUN / HOLD / HALT. The process kill (or
// the ops-console's full-page refusal) belongs to the host, never to this
// module.
//
// The ladder mirrors the capability-ledger loader, specialized to
// orgmanifest/v1 (a deliberate pattern copy, not an import).
import { digestOf as defaultDigestOf } from "../protocol.mjs";
import { ORG_SCHEMA, ORG_SCHEMA_FELT, canonicalRender, validateOrgManifest } from "./manifest.mjs";

const terminal = (reason, version) => ({ ok: false, class: "terminal", reason, ...(version !== undefined && { version }) });
const transient = (reason, version) => ({ ok: false, class: "transient", reason, ...(version !== undefined && { version }) });

/// Read + verify the governed org manifest. Never throws — returns
///   { ok: true,  manifest, version, digest }
///   { ok: false, class: "transient", reason }   chain / blob store unreachable
///   { ok: false, class: "terminal",  reason }   everything a HALT must follow:
///     missing on chain, tombstoned, wrong schema_ref, digest mismatch
///     (TAMPERED), not JSON, non-canonical bytes, invalid manifest,
///     key-binding mismatch.
export async function loadOrgManifest({
  getValue,
  getBlob,
  digestOf = defaultDigestOf,
  valueKeyStr,
}) {
  let v;
  try {
    v = await getValue();
  } catch (e) {
    return transient(`chain read failed: ${e?.message ?? e}`);
  }
  const version = Number(v.version);
  if (version === 0) return terminal("no org manifest on chain (bitcd publish-manifest first)");
  if (Boolean(v.tombstoned)) return terminal("org manifest TOMBSTONED (governed revoke)", version);
  if (v.schema_ref !== undefined && v.schema_ref !== null && BigInt(v.schema_ref) !== BigInt(ORG_SCHEMA_FELT)) {
    return terminal(`on-chain schema_ref is not ${ORG_SCHEMA}`, version);
  }
  const digest = "0x" + BigInt(v.digest).toString(16);

  let blob;
  try {
    blob = await getBlob();
  } catch (e) {
    return transient(`manifest blob missing/unreadable: ${e?.name ?? e?.message ?? e}`, version);
  }
  if (BigInt(digestOf(blob)) !== BigInt(digest)) {
    return terminal("manifest blob digest != on-chain digest (TAMPERED)", version);
  }

  let manifest;
  try {
    manifest = JSON.parse(blob);
  } catch {
    return terminal("manifest blob is not JSON", version);
  }
  if (canonicalRender(manifest) !== blob) {
    return terminal("blob is not the canonical projection (non-canonical or decorated manifest)", version);
  }
  const { ok, errors } = validateOrgManifest(manifest);
  if (!ok) return terminal(`invalid ${ORG_SCHEMA}: ${errors.join("; ")}`, version);

  if (valueKeyStr !== undefined && manifest.self.key !== valueKeyStr) {
    return terminal(`manifest is bound to ${manifest.self.key}, loaded from ${valueKeyStr} (key-binding mismatch)`, version);
  }

  return { ok: true, manifest, version, digest };
}

/// The fail-safe gate. Wraps a load() thunk and
/// answers, per poll:
///   RUN  { manifest, version, digest, stale:false }  fresh verified load
///   RUN  { …, stale:true }   transient failure, last verified manifest still
///                            inside the grace window (<= one poll interval)
///   HOLD { reason }          transient at startup — nothing verified yet
///   HALT { reason }          any terminal failure (zero grace), or a
///                            transient one beyond the grace window
/// Never fail-open: nothing unverified ever reaches RUN.
export function makeGate({ load, graceMs = 0, now = Date.now }) {
  let lastGood = null;
  const startedAt = now();
  return {
    async check() {
      const r = await load();
      if (r.ok) {
        lastGood = { manifest: r.manifest, version: r.version, digest: r.digest, at: now() };
        return { action: "RUN", manifest: r.manifest, version: r.version, digest: r.digest, stale: false };
      }
      if (r.class === "terminal") return { action: "HALT", reason: r.reason };
      if (lastGood && now() - lastGood.at <= graceMs) {
        return { action: "RUN", manifest: lastGood.manifest, version: lastGood.version, digest: lastGood.digest, stale: true, reason: r.reason };
      }
      if (!lastGood && now() - startedAt <= graceMs) {
        return { action: "HOLD", reason: r.reason };
      }
      return { action: "HALT", reason: `${r.reason} (transient, grace window exhausted)` };
    },
  };
}
