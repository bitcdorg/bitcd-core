//! Event payload structs — bitcd's `watch` mechanism.
//! Emit on EVERY state transition. The #[event] enum lives in the contract
//! module (lib.cairo) and references these payloads.

use starknet::ContractAddress;

#[derive(Drop, starknet::Event)]
pub struct LockAcquired {
    #[key]
    pub lock_key: felt252,
    #[key]
    pub holder: ContractAddress,
    pub operation_id: felt252,
    pub version: u64,
    pub acquired_at: u64,
    pub ttl: u64,
}

#[derive(Drop, starknet::Event)]
pub struct LockReleased {
    #[key]
    pub lock_key: felt252,
    #[key]
    pub holder: ContractAddress,
    pub version: u64,
}

#[derive(Drop, starknet::Event)]
pub struct LockForceUnlocked {
    #[key]
    pub lock_key: felt252,
    #[key]
    pub previous_holder: ContractAddress,
    pub version: u64,
}

#[derive(Drop, starknet::Event)]
pub struct ProposalCreated {
    #[key]
    pub proposal_id: u64,
    pub action: felt252,
    pub prefix_hash: felt252,
    #[key]
    pub proposer: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct ProposalApproved {
    #[key]
    pub proposal_id: u64,
    #[key]
    pub approver: ContractAddress,
}

/// A human intent-bound approval landed via `approve_sigs`. Emitted
/// IN ADDITION to `ProposalApproved` for the same approval, so the indexer can tell an
/// intent-bound SNIP-12 vote (counts toward `min_humans`) from a raw `approve()` vote
/// (counts toward threshold only). The approver signed *readable intent* off-chain; an
/// untrusted relayer submitted the signature.
#[derive(Drop, starknet::Event)]
pub struct ApprovalSigned {
    #[key]
    pub proposal_id: u64,
    #[key]
    pub approver: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct ProposalCommitted {
    #[key]
    pub proposal_id: u64,
    pub action: felt252,
}

/// An eligible signer demanded a human reviewer on a proposal whose static policy
/// would otherwise permit an agent-only quorum (`min_humans == 0`) — e.g. a
/// predicate-agent in doubt asking for human intervention. Dynamic,
/// one-directional escalation (the strengthen-only ratchet, per-proposal): `commit`
/// then reads the effective floor `max(policy.min_humans, 1)`, so the proposal
/// requires >= 1 *intent-bound* human. It can only ever RAISE the floor —
/// there is no path to clear it — and it is checked at commit, not counted as a
/// vote, so a confident sub-quorum cannot route around it. The indexer surfaces
/// "escalated to human" per proposal.
#[derive(Drop, starknet::Event)]
pub struct HumanReviewRequested {
    #[key]
    pub proposal_id: u64,
    #[key]
    pub requester: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct PolicyChanged {
    #[key]
    pub prefix_hash: felt252,
    #[key]
    pub action: felt252,
    pub threshold: u32,
    pub role: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct RoleChanged {
    #[key]
    pub account: ContractAddress,
    pub active: bool,
    pub role: felt252,
}

/// A governed value commitment changed. The chain records WHO decided
/// and that the off-chain bytes are unaltered — `digest` is the content address
/// of the blob (in `storage_class`, e.g. S3); the bytes themselves never live
/// on-chain. `version` is monotonic.
#[derive(Drop, starknet::Event)]
pub struct ValueChanged {
    #[key]
    pub value_key: felt252,
    #[key]
    pub prefix: felt252,
    pub digest: felt252,
    pub schema_ref: felt252,
    pub storage_class: felt252,
    pub version: u64,
}

/// Observed/actuation state changed — the executor's attestation of what
/// it re-read from the live provider. `observed_revision` echoes the spec `version`
/// the executor reconciled against; `observed_digest` is the digest of the live
/// state (drift = it differs from the on-chain `ValueChanged.digest` at that
/// revision). The contract stays the data plane's witness, never its store.
/// The indexer joins this with `ValueChanged` by `value_key` to derive Synced /
/// OutOfSync. `status_version` is the monotonic status CAS line.
#[derive(Drop, starknet::Event)]
pub struct StatusChanged {
    #[key]
    pub value_key: felt252,
    #[key]
    pub prefix: felt252,
    pub observed_revision: u64,
    pub observed_digest: felt252,
    pub condition: felt252,
    pub status_version: u64,
    #[key]
    pub executor: ContractAddress,
}

/// One executor's vote — emitted on EVERY `set_status`, before any
/// aggregation. The indexer folds these per `(value_key, observed_revision)` into the
/// agreement tally ("3/5 agree on hash X, 1 says Y, 1 Failed") and derives the
/// authoritative state, including DISAGREE. The aggregate promotion (k-of-n reached)
/// is the separate `StatusChanged`. `applied_hash` is the live-state digest the
/// executor observed (0 = apply failed); only digests on-chain.
#[derive(Drop, starknet::Event)]
pub struct StatusAttested {
    #[key]
    pub value_key: felt252,
    #[key]
    pub executor: ContractAddress,
    pub observed_revision: u64,
    pub applied_hash: felt252,
    pub condition: felt252,
}
