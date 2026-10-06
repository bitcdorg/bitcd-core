//! Governance pipeline param decoders — fixed-arity, bounded.
//!
//! Proposal params are a flat `Span<felt252>` decoded by the target action's
//! fixed-arity handler — never a variadic script. Each decoder asserts exact
//! arity so a malformed proposal can never commit. felt→bool is `!= 0`;
//! felt→u32/u64/ContractAddress go through TryInto and panic on overflow.

use starknet::ContractAddress;
use super::{Policy, Signer};

fn as_bool(v: felt252) -> bool {
    v != 0
}

fn as_u32(v: felt252) -> u32 {
    v.try_into().expect('param: u32 overflow')
}

fn as_u64(v: felt252) -> u64 {
    v.try_into().expect('param: u64 overflow')
}

fn as_address(v: felt252) -> ContractAddress {
    v.try_into().expect('param: bad address')
}

/// FORCE_UNLOCK: [lock_key]
pub fn decode_force_unlock(params: Span<felt252>) -> felt252 {
    assert(params.len() == 1, 'force_unlock: arity 1');
    *params.at(0)
}

/// SET_POLICY: [target_prefix, target_action, threshold, role, min_humans,
///              max_per_operator, allow_open, exists]
pub fn decode_policy(params: Span<felt252>) -> (felt252, felt252, Policy) {
    assert(params.len() == 8, 'set_policy: arity 8');
    let target_prefix = *params.at(0);
    let target_action = *params.at(1);
    let policy = Policy {
        threshold: as_u32(*params.at(2)),
        role: *params.at(3),
        min_humans: as_u32(*params.at(4)),
        max_per_operator: as_u32(*params.at(5)),
        allow_open: as_bool(*params.at(6)),
        exists: as_bool(*params.at(7)),
    };
    (target_prefix, target_action, policy)
}

/// SET_VALUE (governed prefix): [value_key, digest, schema_ref, storage_class,
/// expected_version]. Mirrors the open `set_value` args minus `lock_key` — a
/// governed value write is authorized by a quorum on `(prefix, SET_VALUE)`, not
/// by holding a lock, so it moves the first-touch prefix binding off the open path.
pub fn decode_value(params: Span<felt252>) -> (felt252, felt252, felt252, felt252, u64) {
    assert(params.len() == 5, 'set_value: arity 5');
    (*params.at(0), *params.at(1), *params.at(2), *params.at(3), as_u64(*params.at(4)))
}

/// TOMBSTONE_VALUE (governed prefix): [value_key, expected_version]. A governed
/// value has no lock holder to use the open `tombstone_value` path, so its logical
/// delete is itself a quorum action.
pub fn decode_tombstone_value(params: Span<felt252>) -> (felt252, u64) {
    assert(params.len() == 2, 'tombstone_value: arity 2');
    (*params.at(0), as_u64(*params.at(1)))
}

/// SET_ROLE: [account, active, is_human, operator_id, role]
pub fn decode_signer(params: Span<felt252>) -> (ContractAddress, Signer) {
    assert(params.len() == 5, 'set_role: arity 5');
    let account = as_address(*params.at(0));
    let signer = Signer {
        active: as_bool(*params.at(1)),
        is_human: as_bool(*params.at(2)),
        operator_id: *params.at(3),
        role: *params.at(4),
    };
    (account, signer)
}
