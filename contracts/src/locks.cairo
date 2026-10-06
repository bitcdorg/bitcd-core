//! Lock logic — lease + compare-and-set.
//!
//! Pure helpers only — storage access lives in the contract module (lib.cairo).
//! A lease is expired when it has a non-zero ttl and `now - acquired_at >= ttl`
//! (time always from get_block_timestamp). A `ttl == 0` lease never expires
//! and must be released explicitly or force-unlocked via governance.

/// True when the lease has elapsed. `ttl == 0` means "no expiry".
///
/// Compared as `now - acquired_at >= ttl` rather than `now >= acquired_at + ttl`
/// so a caller-supplied `ttl` near u64::MAX cannot overflow-panic the add and
/// brick `acquire`. `acquired_at` is a past block timestamp, so it is always
/// `<= now`; the explicit guard keeps the subtraction safe regardless.
pub fn is_expired(now: u64, acquired_at: u64, ttl: u64) -> bool {
    ttl != 0 && now >= acquired_at && now - acquired_at >= ttl
}

/// A slot is free to acquire when nobody holds it, it was tombstoned, or its
/// lease expired. `held` is false for an empty/tombstoned slot.
pub fn is_acquirable(held: bool, now: u64, acquired_at: u64, ttl: u64) -> bool {
    !held || is_expired(now, acquired_at, ttl)
}
