//! Policy evaluation — bounded, declarative, NO scripting.
//!
//! `satisfies` checks an approval set against a Policy with a fixed loop over the
//! approvers — never a predicate interpreter. Four orthogonal gates, all must hold:
//!   - threshold:        count(eligible approvers) >= threshold
//!   - role (M-of-role): every counted approver has signer.role == policy.role,
//!                       unless policy.role == 0 (any role)
//!   - min_humans:       count(is_human among counted) >= min_humans
//!   - max_per_operator: no single operator_id contributes more than the cap
//!                       (0 == unlimited)
//!
//! `allow_open == true` short-circuits to permit (used for ungoverned prefixes).
//! Only `active` signers count. Diversity uses on-chain Signer attributes.

use super::{Policy, Signer};

/// Evaluate `approvers` against `policy`. `approvers` must already be deduplicated
//  by account (governance records one approval per account).
pub fn satisfies(policy: Policy, approvers: Span<Signer>) -> bool {
    if policy.allow_open {
        return true;
    }

    let mut eligible: u32 = 0;
    let mut humans: u32 = 0;

    let mut i: u32 = 0;
    let len = approvers.len();
    while i != len {
        let s = *approvers.at(i);
        if s.active && role_ok(policy.role, s.role) {
            eligible += 1;
            if s.is_human {
                humans += 1;
            }
            if policy.max_per_operator != 0
                && operator_count(approvers, policy.role, s.operator_id) > policy.max_per_operator {
                return false;
            }
        }
        i += 1;
    }

    // Floor: a non-open policy always needs at least one eligible approver, so a
    // mis-seeded `threshold == 0` can never rubber-stamp an empty approval set
    // (defense-in-depth behind the write-time governance floor).
    eligible >= 1 && eligible >= policy.threshold && humans >= policy.min_humans
}

/// role == 0 means "any role accepted".
fn role_ok(required: felt252, actual: felt252) -> bool {
    required == 0 || required == actual
}

/// Count the ELIGIBLE approvers (active && role_ok) sharing `operator_id`. The
/// diversity cap must measure only signers who actually count toward the quorum;
/// counting active-but-wrong-role signers would overcount and spuriously reject.
fn operator_count(approvers: Span<Signer>, required_role: felt252, operator_id: felt252) -> u32 {
    let mut n: u32 = 0;
    let mut i: u32 = 0;
    let len = approvers.len();
    while i != len {
        let s = *approvers.at(i);
        if s.active && role_ok(required_role, s.role) && s.operator_id == operator_id {
            n += 1;
        }
        i += 1;
    }
    n
}
