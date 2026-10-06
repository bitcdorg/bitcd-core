// @bitcd/core/protocol — the on-chain protocol vocabulary, as felts.
//
// These short-strings are the contract's action tags / condition labels / reserved
// scope (contracts/src/lib.cairo `actions`/`conditions`/`scopes`). They are protocol
// identity, not demo fixtures: every consumer (the e2e rig, examples, third parties)
// must encode the exact same felts the contract compares against.
import { hash, shortString } from "starknet";

/// Encode a JS string as a Cairo short-string felt (max 31 chars — see
/// SHORTSTRING_MAX / assertShortString below).
export const str = (s) => shortString.encodeShortString(s);

/// The digest the contract commits and verify-on-read recomputes (starknetKeccak).
export const digestOf = (text) => "0x" + hash.starknetKeccak(text).toString(16);

/// Action tags dispatched by `commit` / gated by per-(prefix, action) policies.
export const ACTION = {
  ACQUIRE: str("ACQUIRE"),
  SET_VALUE: str("SET_VALUE"),
  TOMBSTONE_VALUE: str("TOMBSTONE_VALUE"),
  SET_STATUS: str("SET_STATUS"),
  FORCE_UNLOCK: str("FORCE_UNLOCK"),
  SET_POLICY: str("SET_POLICY"),
  SET_ROLE: str("SET_ROLE"),
};

/// Observed-state conditions the executor self-reports, AS FELTS — what
/// `set_status` takes on-chain. The reconcile engine's string map is
/// `CONDITION` in ./reconcile.mjs; keep the two distinct (felt vs string).
export const CONDITION_FELT = {
  SYNCED: str("SYNCED"),
  OUTOFSYNC: str("OUTOFSYNC"),
  FAILED: str("FAILED"),
  PROGRESSING: str("PROGRESSING"),
};

/// Reserved GLOBAL scope — SET_ROLE mutates global signer identity, so its policy
/// lives here, never under a per-prefix keyspace (the confused-deputy guard).
export const GLOBAL = str("GLOBAL");

/// Storage-class hints for the on-chain value commitment. The chain stores
/// only {digest, schema_ref, storage_class}; bytes live where the class says.
export const STORAGE_CLASS = {
  S3: str("S3"),
};

/// Cairo short-string capacity. Every key (lock_key, value_key, prefix, schema_ref)
/// is one felt: **31 ASCII chars max**. Real-world names blow this fast — a
/// hash-of-name scheme on top is the production direction.
export const SHORTSTRING_MAX = 31;

/// Throw an actionable error before the encoder's less helpful one.
export function assertShortString(s, what = "key") {
  if (typeof s !== "string" || s.length === 0 || s.length > SHORTSTRING_MAX) {
    throw new Error(
      `${what} must be a 1..${SHORTSTRING_MAX}-char string (Cairo shortstring), got ${JSON.stringify(s)} (${s?.length ?? 0} chars). ` +
      `Longer names need a hash-of-name scheme.`,
    );
  }
  return s;
}
