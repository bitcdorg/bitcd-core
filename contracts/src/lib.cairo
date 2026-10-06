//! bitcd — a governed `etcd` on Starknet.
//!
//! The contract STORES and GATES; it never computes business logic. Writes are
//! gated by on-chain multisig policy (bounded, declarative: threshold + human
//! floor + approver diversity — never a scripting language).
//!
//! Module layout (one contract, several modules):
//!   - lib.cairo        shared types, interface, the #[starknet::contract]
//!   - policy.cairo     bounded declarative policy evaluation (`satisfies`)
//!   - locks.cairo      lease + CAS lock logic (acquire / release / force)
//!   - governance.cairo propose / approve / commit param decoders
//!   - events.cairo     event payload structs (the `watch` mechanism)
//!   - snip12.cairo     SNIP-12 typed-data hashing for intent-bound approvals

pub mod events;
pub mod governance;
pub mod locks;
pub mod policy;
pub mod snip12;

use starknet::ContractAddress;

// ---------------------------------------------------------------------------
// Shared value types (assembled for the ABI; stored flattened, one map per field)
// ---------------------------------------------------------------------------

/// A lock slot. `version` is monotonic (the CAS line); `tombstoned` is the
/// append-only logical delete — never a physical erase.
#[derive(Drop, Serde, Copy, starknet::Store)]
pub struct LockRecord {
    pub holder: ContractAddress,
    pub acquired_at: u64,
    pub ttl: u64,
    pub operation_id: felt252,
    pub version: u64,
    pub tombstoned: bool,
}

/// Bounded, declarative policy — a struct of knobs, never a scripting language.
#[derive(Drop, Serde, Copy, starknet::Store)]
pub struct Policy {
    pub threshold: u32,
    pub role: felt252,
    pub min_humans: u32,
    pub max_per_operator: u32,
    pub allow_open: bool,
    pub exists: bool,
}

/// On-chain signer identity used for M-of-role and operator diversity.
#[derive(Drop, Serde, Copy, starknet::Store)]
pub struct Signer {
    pub active: bool,
    pub is_human: bool,
    pub operator_id: felt252,
    pub role: felt252,
}

/// A governed value commitment. The chain stores only the content `digest` of
/// an off-chain blob plus a `storage_class` hint (no backend URL — S3→OCI stays
/// a config swap); the bytes never live on-chain. `version` is monotonic for
/// CAS; `tombstoned` is a logical-delete marker — no physical erase and the
/// version line is never reset. It is NOT a permanent gravestone: a subsequent
/// write (`set_value` / governed `SET_VALUE`) may recreate the key, clearing
/// `tombstoned` while bumping `version` — etcd put-after-delete / Terraform
/// destroy→apply semantics. `prefix` is the governing namespace, pinned
/// write-once on first write.
#[derive(Drop, Serde, Copy, starknet::Store)]
pub struct ValueRecord {
    pub digest: felt252,
    pub schema_ref: felt252,
    pub storage_class: felt252,
    pub version: u64,
    pub prefix: felt252,
    pub exists: bool,
    pub tombstoned: bool,
}

/// Observed/actuation state for a reconciled key. The `ValueRecord` is the
/// *desired* state (consensus-written); this is the *observed* state the executor
/// re-read and attested (executor-written). The two are DISJOINT write surfaces:
/// `set_status` never touches a `value_*` map and no spec path touches a `status_*`
/// map — which is the structural reason a failed apply can never rewrite desired
/// (it can only report `condition = FAILED`). The contract stays dumb: it records
/// what the executor observed (`observed_revision`, `observed_digest`, a verbatim
/// `condition`) and gates WHO may write it; `Synced`/`OutOfSync` is DERIVED
/// off-chain (indexer/UI) by comparing observed to desired. `observed_digest` is a
/// digest of the live provider state, never the bytes. `status_version` is a
/// monotonic line, separate from the spec `version`.
///
/// This is the **aggregate** record — the k-of-n-agreed view. It is
/// *promoted* only when a `(prefix, SET_STATUS)` policy quorum of executors agrees on
/// the same `(observed_revision, observed_digest, condition)` (see `AttestationRecord`
/// for the per-executor votes). `condition == DISAGREE` records a contested revision
/// (executors split across hashes). `executor` is the attester that tipped promotion.
/// Single-writer status is the k=1 special case.
#[derive(Drop, Serde, Copy, starknet::Store)]
pub struct StatusRecord {
    pub observed_revision: u64,
    pub observed_digest: felt252,
    pub condition: felt252,
    pub reason: felt252,
    pub attestation: felt252,
    pub status_version: u64,
    pub executor: ContractAddress,
    pub exists: bool,
}

/// A single executor's vote. Each executor writes ONLY its own slot
/// (single-writer per slot — no cross-executor CAS). The aggregate `StatusRecord` is
/// promoted when a policy quorum of these agree on `(observed_revision, applied_hash,
/// condition)`. `seen` marks a slot ever written (roster membership). `applied_hash`
/// is the live-state digest the executor observed (0 = apply failed); `condition` is
/// its apply outcome (`SYNCED`/`FAILED`). `observed_revision` is monotonic per slot.
#[derive(Drop, Serde, Copy, starknet::Store)]
pub struct AttestationRecord {
    pub observed_revision: u64,
    pub applied_hash: felt252,
    pub condition: felt252,
    pub seen: bool,
}

// Action tags — policy is keyed by (prefix_hash, action_tag).
pub mod actions {
    pub const ACQUIRE: felt252 = 'ACQUIRE';
    pub const FORCE_UNLOCK: felt252 = 'FORCE_UNLOCK';
    pub const SET_POLICY: felt252 = 'SET_POLICY';
    pub const SET_ROLE: felt252 = 'SET_ROLE';
    // Value commitment. DUAL-MODE, keyed on the prefix's `(prefix, SET_VALUE)`
    // policy: when `allow_open` it is the single-writer open fast path (the lock
    // holder writes the digest, no quorum); when NOT `allow_open` it is a
    // governed write committed through propose/approve/commit (the quorum IS the
    // write capability). Because of the open variant it must stay ABSENT from
    // `is_governance_action` (whose floor forbids `allow_open`); the runtime
    // `satisfies()` floor still guards the governed variant. The two modes are
    // mutually exclusive — the open entrypoints reject a governed prefix
    // (`'value: governed'`) and the governed commit arm rejects an open one
    // (`'commit: value is open'`).
    pub const SET_VALUE: felt252 = 'SET_VALUE';
    // Governed logical-delete of a value commitment. Unlike SET_VALUE there is NO
    // open variant: a governed value has no lock holder to use the open
    // `tombstone_value` path, so its delete is always a quorum — and therefore IS
    // a governance action (floor + ratchet protected). The open `tombstone_value`
    // entrypoint is gated by the prefix's SET_VALUE policy, not this tag.
    pub const TOMBSTONE_VALUE: felt252 = 'TOMBSTONE_VALUE';
    // Observed-state attestation. A FAST PATH like ACQUIRE
    // and open SET_VALUE — so it stays ABSENT from `is_governance_action` (drift
    // re-attests are frequent; the heavy quorum pipeline is not on this hot path).
    // Its capability is neither a lock nor a quorum: the caller must be an active
    // Signer whose `role` matches the prefix's `(prefix, SET_STATUS)` policy role —
    // the consensus-assigned executor for that namespace (`SET_ROLE` decides who).
    // The SAME policy (threshold/diversity) scales from one executor to k-of-n
    // executor agreement without reshaping the record.
    pub const SET_STATUS: felt252 = 'SET_STATUS';
}

// Observed-state condition the executor self-reports. Stored VERBATIM,
// like `storage_class` — the contract never interprets it (dumb-contract rule). The
// off-chain reader derives the authoritative `Synced`/`OutOfSync` from observed vs
// desired revision+digest; `condition` carries the executor's own signal (notably
// `FAILED`, which observed/desired comparison alone cannot express).
pub mod conditions {
    // Executor-attested apply outcomes (the agreement key co-label):
    pub const SYNCED: felt252 = 'SYNCED'; // applied; here is the observed live hash
    pub const FAILED: felt252 = 'FAILED'; // apply errored (applied_hash sentinel 0)
    pub const PROGRESSING: felt252 = 'PROGRESSING';
    // CONTRACT-set: eligible executors attested >=2 distinct hashes for the
    // same revision — no k-of-n agreement; promotion is blocked until they converge.
    pub const DISAGREE: felt252 = 'DISAGREE';
    // OUTOFSYNC is NOT an on-chain condition: drift (agreed hash != desired digest) is
    // DERIVED off-chain (indexer/UI), like Synced. Kept only as a reader label.
    pub const OUTOFSYNC: felt252 = 'OUTOFSYNC';
}

// Storage-class hint stored beside a value digest (a bounded enum, never a
// backend URL). The contract does NOT interpret these — it
// stores the felt verbatim, like `operation_id`; the consts document the off-chain
// contract. `INLINE` (0) is the sentinel for "no external blob".
pub mod storage_class {
    pub const INLINE: felt252 = 0;
    pub const S3: felt252 = 'S3';
    pub const OCI: felt252 = 'OCI';
}

// Reserved scopes. `SET_ROLE` mutates GLOBAL signer identity,
// not a per-prefix keyspace — so its proposals must be scoped to GLOBAL and gated
// by the single (GLOBAL, SET_ROLE) policy, never by a per-prefix policy that a
// weak-prefix quorum could satisfy (the confused-deputy trap).
pub mod scopes {
    pub const GLOBAL: felt252 = 'GLOBAL';
}

/// True for actions whose policy is consensus-gated governance (never `allow_open`,
/// always `threshold >= 1`). `ACQUIRE` and open-mode `SET_VALUE` are the only
/// ungoverned fast paths; dual-mode `SET_VALUE` and `SET_STATUS` are not in this set.
pub fn is_governance_action(action: felt252) -> bool {
    action == actions::FORCE_UNLOCK
        || action == actions::SET_POLICY
        || action == actions::SET_ROLE
        || action == actions::TOMBSTONE_VALUE
}

/// One human's intent-bound approval, collected off-chain and submitted by the
/// (untrusted) relayer via `approve_sigs`. `signature` is the SNIP-12
/// signature over the `approval_digest` for `(proposal_id, approver)`; the relayer
/// supplies nothing that enters the signed message except `approver` itself.
#[derive(Drop, Serde)]
pub struct SignedApproval {
    pub approver: ContractAddress,
    pub signature: Array<felt252>,
}

/// Minimal SRC6 surface — just enough to verify an approver account's signature over
/// the SNIP-12 message hash (account-abstraction-correct: the account decides what a
/// valid signature is). Returns the short string `'VALID'` iff the signature is valid.
#[starknet::interface]
pub trait ISRC6<TState> {
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
}

#[starknet::interface]
pub trait IBitcd<TContractState> {
    // --- locks (single-writer fast path) ---
    fn acquire_lock(ref self: TContractState, lock_key: felt252, prefix_hash: felt252, operation_id: felt252, ttl: u64);
    fn release_lock(ref self: TContractState, lock_key: felt252, expected_version: u64);
    fn get_lock(self: @TContractState, lock_key: felt252) -> LockRecord;

    // --- governed values (single-writer commitment, gated by lock ownership) ---
    fn set_value(ref self: TContractState, value_key: felt252, lock_key: felt252, digest: felt252, schema_ref: felt252, storage_class: felt252, expected_version: u64);
    fn tombstone_value(ref self: TContractState, value_key: felt252, lock_key: felt252, expected_version: u64);
    fn get_value(self: @TContractState, value_key: felt252) -> ValueRecord;

    // --- observed status (executor-role-gated) ---
    // Each executor ATTESTS (observed_revision, applied_hash, condition); the
    // aggregate status is promoted by the contract when a (prefix, SET_STATUS) policy
    // quorum of executors agree. No caller-supplied version (per-executor slots are
    // single-writer); the aggregate status_version is bumped on promotion.
    fn set_status(ref self: TContractState, value_key: felt252, observed_revision: u64, applied_hash: felt252, condition: felt252, reason: felt252);
    fn get_status(self: @TContractState, value_key: felt252) -> StatusRecord;
    fn get_attestation(self: @TContractState, value_key: felt252, executor: ContractAddress) -> AttestationRecord;

    // --- governance pipeline (consensus-gated) ---
    fn propose(ref self: TContractState, action: felt252, prefix_hash: felt252, params: Array<felt252>) -> u64;
    fn approve(ref self: TContractState, proposal_id: u64);
    // Relayed, intent-bound human approvals: each approver signs the
    // SNIP-12 `approval_digest` off-chain; an untrusted relayer batches them here.
    fn approve_sigs(ref self: TContractState, proposal_id: u64, approvals: Array<SignedApproval>);
    // The SNIP-12 message hash a human signs to approve `(proposal_id, approver)`.
    // The off-chain signer must produce a signature over exactly this felt.
    fn approval_digest(self: @TContractState, proposal_id: u64, approver: ContractAddress) -> felt252;
    // Dynamic escalation: an eligible signer (an approver in this proposal's
    // scope — e.g. a predicate-agent in doubt) demands a human reviewer on THIS
    // proposal, raising the effective `min_humans` floor to >= 1 at commit even when
    // the static policy is 0. Strengthen-only — cannot be cleared or out-voted.
    fn request_human_review(ref self: TContractState, proposal_id: u64);
    fn commit(ref self: TContractState, proposal_id: u64);

    // --- policy / signer seeding (owner-only; governed changes go through `commit`) + views ---
    fn set_policy(ref self: TContractState, prefix_hash: felt252, action: felt252, policy: Policy);
    fn set_signer(ref self: TContractState, account: ContractAddress, signer: Signer);
    fn get_policy(self: @TContractState, prefix_hash: felt252, action: felt252) -> Policy;
    fn get_signer(self: @TContractState, account: ContractAddress) -> Signer;
}

#[starknet::contract]
pub mod Bitcd {
    use core::num::traits::Zero;
    use openzeppelin_access::ownable::OwnableComponent;
    use starknet::storage::*;
    use starknet::{
        ContractAddress, get_block_timestamp, get_caller_address, get_contract_address, get_tx_info,
    };
    use super::events::{
        ApprovalSigned, HumanReviewRequested, LockAcquired, LockForceUnlocked, LockReleased,
        PolicyChanged, ProposalApproved, ProposalCommitted, ProposalCreated, RoleChanged,
        StatusAttested, StatusChanged, ValueChanged,
    };
    use super::{
        AttestationRecord, IBitcd, ISRC6Dispatcher, ISRC6DispatcherTrait, LockRecord, Policy,
        Signer, SignedApproval, StatusRecord, ValueRecord, actions, conditions, governance,
        is_governance_action, locks, policy as policy_mod, scopes, snip12,
    };

    // SRC6 magic return value for a valid signature.
    const VALID_SIGNATURE: felt252 = 'VALID';
    // Hard cap on a single `approve_sigs` batch (DoS bound — the relayer can make
    // multiple calls, which accrue additively). The effective max is the signer
    // count; this is a generous constant because signers aren't enumerable on-chain.
    const MAX_SIGS_PER_CALL: u32 = 64;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    pub struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        // --- locks (flattened) ---
        lock_held: Map<felt252, bool>,
        lock_holder: Map<felt252, ContractAddress>,
        lock_acquired_at: Map<felt252, u64>,
        lock_ttl: Map<felt252, u64>,
        lock_operation_id: Map<felt252, felt252>,
        lock_version: Map<felt252, u64>,
        lock_tombstoned: Map<felt252, bool>,
        key_prefix: Map<felt252, felt252>, // lock_key -> prefix_hash (write-once)
        // --- governed values (flattened; content-addressed commitment) ---
        value_exists: Map<felt252, bool>,
        value_digest: Map<felt252, felt252>,
        value_schema_ref: Map<felt252, felt252>,
        value_storage_class: Map<felt252, felt252>,
        value_version: Map<felt252, u64>,
        value_tombstoned: Map<felt252, bool>,
        value_prefix: Map<felt252, felt252>, // value_key -> prefix_hash (write-once)
        // --- observed status (flattened; executor-written, disjoint
        //     from the value_* spec maps above; keyed by the same value_key) ---
        status_exists: Map<felt252, bool>,
        status_observed_revision: Map<felt252, u64>,
        status_observed_digest: Map<felt252, felt252>,
        status_condition: Map<felt252, felt252>,
        status_reason: Map<felt252, felt252>,
        status_attestation: Map<felt252, felt252>,
        status_version: Map<felt252, u64>, // monotonic line, separate from spec version
        status_executor: Map<felt252, ContractAddress>,
        // --- per-executor attestation slots (single-writer per slot) ---
        attest_revision: Map<(felt252, ContractAddress), u64>, // (value_key, executor)
        attest_hash: Map<(felt252, ContractAddress), felt252>,
        attest_condition: Map<(felt252, ContractAddress), felt252>,
        attest_seen: Map<(felt252, ContractAddress), bool>, // ever attested (roster dedup)
        // bounded attester roster per value_key (length <= n; iterated like approvers)
        attester_count: Map<felt252, u32>,
        attester_at: Map<(felt252, u32), ContractAddress>, // (value_key, index) -> executor
        // --- policy / signers (struct maps) ---
        policies: Map<(felt252, felt252), Policy>, // (prefix_hash, action) -> Policy
        signers: Map<ContractAddress, Signer>,
        // --- governance proposals (flattened) ---
        next_proposal_id: u64,
        prop_action: Map<u64, felt252>,
        prop_prefix: Map<u64, felt252>,
        prop_proposer: Map<u64, ContractAddress>,
        prop_executed: Map<u64, bool>,
        prop_canceled: Map<u64, bool>,
        prop_param_len: Map<u64, u32>,
        prop_params: Map<(u64, u32), felt252>, // (proposal_id, index) -> param
        prop_approval_count: Map<u64, u32>,
        prop_approved_by: Map<(u64, ContractAddress), bool>, // dedup
        prop_approver_at: Map<(u64, u32), ContractAddress>, // index -> approver
        // Per-(proposal, approver) flag — set ONLY by `approve_sigs`
        // (intent-bound SNIP-12). `_approver_set` masks `is_human` by this, so a human
        // who used raw `approve()` does not count toward `min_humans`.
        prop_intent_signed: Map<(u64, ContractAddress), bool>,
        // Dynamic escalation: set by `request_human_review`, an eligible signer's
        // per-proposal demand for a human reviewer. Write-once-true (monotonic, never
        // cleared). `commit` reads the effective floor `max(policy.min_humans, 1)` when
        // set, so the proposal then needs >= 1 intent-bound human even on a
        // `min_humans == 0` prefix. Strengthen-only and checked at commit (not a vote) —
        // a confident agent sub-quorum cannot out-vote or clear it.
        prop_human_required: Map<u64, bool>,
        // Reentrancy lock spanning `approve_sigs` (which calls relayer-supplied
        // account code via `is_valid_signature`); also blocks reentry into `commit`.
        reentrancy_guard: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        LockAcquired: LockAcquired,
        LockReleased: LockReleased,
        LockForceUnlocked: LockForceUnlocked,
        ProposalCreated: ProposalCreated,
        ProposalApproved: ProposalApproved,
        ApprovalSigned: ApprovalSigned,
        HumanReviewRequested: HumanReviewRequested,
        ProposalCommitted: ProposalCommitted,
        PolicyChanged: PolicyChanged,
        RoleChanged: RoleChanged,
        ValueChanged: ValueChanged,
        StatusChanged: StatusChanged,
        StatusAttested: StatusAttested,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        assert(owner.is_non_zero(), 'owner is zero');
        self.ownable.initializer(owner);
        self.next_proposal_id.write(1);
    }

    #[abi(embed_v0)]
    impl BitcdImpl of IBitcd<ContractState> {
        fn acquire_lock(
            ref self: ContractState,
            lock_key: felt252,
            prefix_hash: felt252,
            operation_id: felt252,
            ttl: u64,
        ) {
            let policy = self.policies.entry((prefix_hash, actions::ACQUIRE)).read();
            assert(policy.exists, 'acquire: no policy');
            assert(policy.allow_open, 'acquire: governed');

            let now = get_block_timestamp();
            let held = self.lock_held.entry(lock_key).read();
            let acquired_at = self.lock_acquired_at.entry(lock_key).read();
            let cur_ttl = self.lock_ttl.entry(lock_key).read();
            assert(locks::is_acquirable(held, now, acquired_at, cur_ttl), 'acquire: held');

            let caller = get_caller_address();
            let version = self.lock_version.entry(lock_key).read() + 1;

            // Scope-binding integrity: a lock_key's governing prefix is pinned
            // on its FIRST governed touch and is immutable thereafter.
            // ACQUIRE is the one open, permissionless fast-path; without this pin it
            // would rewrite key_prefix on every (re)acquire, so the
            // force-unlock scope check (`key_prefix[lock_key] == prop_prefix`) would
            // bind to a HOLDER-chosen scope. A free/expired/tombstoned lock could be
            // re-bound into a foreign namespace with a weaker or absent FORCE_UNLOCK
            // gate — escaping its real quorum, or (with ttl == 0) becoming a
            // permanently un-forceable lock after the owner has renounced. prefix 0
            // is reserved as the "unbound" sentinel, so a real prefix is never 0.
            assert(prefix_hash != 0, 'acquire: zero prefix');
            let bound_prefix = self.key_prefix.entry(lock_key).read();
            if bound_prefix == 0 {
                self.key_prefix.entry(lock_key).write(prefix_hash);
            } else {
                assert(bound_prefix == prefix_hash, 'acquire: prefix rebind');
            }

            self.lock_held.entry(lock_key).write(true);
            self.lock_holder.entry(lock_key).write(caller);
            self.lock_acquired_at.entry(lock_key).write(now);
            self.lock_ttl.entry(lock_key).write(ttl);
            self.lock_operation_id.entry(lock_key).write(operation_id);
            self.lock_version.entry(lock_key).write(version);
            self.lock_tombstoned.entry(lock_key).write(false);

            self
                .emit(
                    LockAcquired {
                        lock_key, holder: caller, operation_id, version, acquired_at: now, ttl,
                    },
                );
        }

        fn release_lock(ref self: ContractState, lock_key: felt252, expected_version: u64) {
            let caller = get_caller_address();
            assert(self.lock_held.entry(lock_key).read(), 'release: not held');
            assert(self.lock_holder.entry(lock_key).read() == caller, 'release: not holder');
            let version = self.lock_version.entry(lock_key).read();
            assert(version == expected_version, 'release: stale version');

            let new_version = version + 1;
            self.lock_held.entry(lock_key).write(false);
            self.lock_tombstoned.entry(lock_key).write(true);
            self.lock_version.entry(lock_key).write(new_version);

            self.emit(LockReleased { lock_key, holder: caller, version: new_version });
        }

        fn get_lock(self: @ContractState, lock_key: felt252) -> LockRecord {
            LockRecord {
                holder: self.lock_holder.entry(lock_key).read(),
                acquired_at: self.lock_acquired_at.entry(lock_key).read(),
                ttl: self.lock_ttl.entry(lock_key).read(),
                operation_id: self.lock_operation_id.entry(lock_key).read(),
                version: self.lock_version.entry(lock_key).read(),
                tombstoned: self.lock_tombstoned.entry(lock_key).read(),
            }
        }

        // Single-writer value commitment. The capability to write a
        // prefix's value digest IS holding that prefix's lock — mirroring etcd's
        // lease semantics and Terraform's acquire→write→release flow. No
        // quorum: SET_VALUE is the open fast path, gated by lock ownership, not by
        // `satisfies()`. The blob lives off-chain; only its digest is here.
        fn set_value(
            ref self: ContractState,
            value_key: felt252,
            lock_key: felt252,
            digest: felt252,
            schema_ref: felt252,
            storage_class: felt252,
            expected_version: u64,
        ) {
            let prefix = self._authorize_value_writer(value_key, lock_key);
            self._apply_value_set(value_key, prefix, digest, schema_ref, storage_class, expected_version);
        }

        // Logical delete of a value commitment: tombstone + bump version,
        // never a physical erase. Same single-writer gate as `set_value`.
        fn tombstone_value(
            ref self: ContractState, value_key: felt252, lock_key: felt252, expected_version: u64,
        ) {
            assert(self.value_exists.entry(value_key).read(), 'value: missing');
            let prefix = self._authorize_value_writer(value_key, lock_key);
            self._apply_value_tombstone(value_key, prefix, expected_version);
        }

        fn get_value(self: @ContractState, value_key: felt252) -> ValueRecord {
            ValueRecord {
                digest: self.value_digest.entry(value_key).read(),
                schema_ref: self.value_schema_ref.entry(value_key).read(),
                storage_class: self.value_storage_class.entry(value_key).read(),
                version: self.value_version.entry(value_key).read(),
                prefix: self.value_prefix.entry(value_key).read(),
                exists: self.value_exists.entry(value_key).read(),
                tombstoned: self.value_tombstoned.entry(value_key).read(),
            }
        }

        // Multi-writer observed-state attestation. Each executor ATTESTS
        // what it re-read live; the contract records that executor's own slot and then
        // GATES promotion of the aggregate StatusRecord on a (prefix, SET_STATUS)
        // policy quorum agreeing on the same (observed_revision, applied_hash,
        // condition) — reusing `policy::satisfies()` verbatim (the decision layer's
        // machinery pointed at the actuators). It still
        // computes NO business logic: it never compares applied_hash to the desired
        // digest (Synced/OutOfSync is DERIVED off-chain); it counts agreement and
        // applies the policy, exactly as `commit()` does. Writes ONLY status_*/attest_*
        // maps — never the spec (a FAILED apply cannot rewrite desired). Single-writer
        // status is the k=1 special case. Only digests on-chain.
        fn set_status(
            ref self: ContractState,
            value_key: felt252,
            observed_revision: u64,
            applied_hash: felt252,
            condition: felt252,
            reason: felt252,
        ) {
            // (1) Desired must exist + be scope-bound (the write-once prefix pin is the
            // canonical namespace). (2) Executor eligibility against the value's OWN
            // prefix's SET_STATUS policy (never a foreign prefix). Never open.
            let prefix = self.value_prefix.entry(value_key).read();
            assert(prefix != 0, 'status: value unbound');
            let policy = self.policies.entry((prefix, actions::SET_STATUS)).read();
            assert(policy.exists, 'status: no policy');
            assert(!policy.allow_open, 'status: open');
            let caller = get_caller_address();
            let cs = self.signers.entry(caller).read();
            assert(cs.active, 'status: not executor');
            assert(policy.role == 0 || cs.role == policy.role, 'status: wrong role');
            // DISAGREE is contract-set only — an executor must not be able to "agree on
            // DISAGREE" and promote a contested-looking aggregate with a real hash.
            assert(condition != conditions::DISAGREE, 'status: reserved condition');

            // (3) Per-executor monotonic guards. The vote can never claim a desired
            // revision that does not exist yet, nor roll this executor's slot backward
            // (replay/regression). Each executor writes ONLY its own slot — one vote.
            let value_version = self.value_version.entry(value_key).read();
            assert(observed_revision <= value_version, 'status: future revision');
            let prev = self.attest_revision.entry((value_key, caller)).read();
            assert(observed_revision >= prev, 'status: revision regress');

            self.attest_revision.entry((value_key, caller)).write(observed_revision);
            self.attest_hash.entry((value_key, caller)).write(applied_hash);
            self.attest_condition.entry((value_key, caller)).write(condition);
            // roster membership, write-once per (value_key, executor) — bounds the
            // aggregation loop to n and dedups votes (one slot per executor).
            if !self.attest_seen.entry((value_key, caller)).read() {
                self.attest_seen.entry((value_key, caller)).write(true);
                let n = self.attester_count.entry(value_key).read();
                self.attester_at.entry((value_key, n)).write(caller);
                self.attester_count.entry(value_key).write(n + 1);
            }
            self.emit(StatusAttested { value_key, executor: caller, observed_revision, applied_hash, condition });

            // (4) Aggregate over the roster (<= n): collect the ELIGIBLE executors
            // whose CURRENT slot matches this (revision, hash, condition), and detect a
            // conflicting eligible vote at this revision (a different hash/condition).
            let count = self.attester_count.entry(value_key).read();
            let mut matching: Array<Signer> = array![];
            let mut conflict = false;
            let mut i: u32 = 0;
            while i != count {
                let a = self.attester_at.entry((value_key, i)).read();
                if self.attest_revision.entry((value_key, a)).read() == observed_revision {
                    let sig = self.signers.entry(a).read();
                    if sig.active && (policy.role == 0 || sig.role == policy.role) {
                        let a_hash = self.attest_hash.entry((value_key, a)).read();
                        let a_cond = self.attest_condition.entry((value_key, a)).read();
                        if a_hash == applied_hash && a_cond == condition {
                            matching.append(sig);
                        } else {
                            conflict = true;
                        }
                    }
                }
                i += 1;
            }

            // (5) Promote / contest — only forward (never regress the aggregate
            // revision; a stale-revision agreement from laggards can't overwrite a
            // newer aggregate). Promotion is GATED by the policy evaluator over the
            // agreeing executors (k-of-n + role + operator diversity). A genuine split
            // records DISAGREE (no silent Synced under conflict).
            let agg_rev = self.status_observed_revision.entry(value_key).read();
            let has_status = self.status_exists.entry(value_key).read();
            if !has_status || observed_revision >= agg_rev {
                if policy_mod::satisfies(policy, matching.span()) {
                    self._promote_status(value_key, prefix, observed_revision, applied_hash, condition, reason, caller);
                } else if conflict {
                    self._mark_disagree(value_key, prefix, observed_revision);
                }
            }
        }

        fn get_status(self: @ContractState, value_key: felt252) -> StatusRecord {
            StatusRecord {
                observed_revision: self.status_observed_revision.entry(value_key).read(),
                observed_digest: self.status_observed_digest.entry(value_key).read(),
                condition: self.status_condition.entry(value_key).read(),
                reason: self.status_reason.entry(value_key).read(),
                attestation: self.status_attestation.entry(value_key).read(),
                status_version: self.status_version.entry(value_key).read(),
                executor: self.status_executor.entry(value_key).read(),
                exists: self.status_exists.entry(value_key).read(),
            }
        }

        fn get_attestation(
            self: @ContractState, value_key: felt252, executor: ContractAddress,
        ) -> AttestationRecord {
            AttestationRecord {
                observed_revision: self.attest_revision.entry((value_key, executor)).read(),
                applied_hash: self.attest_hash.entry((value_key, executor)).read(),
                condition: self.attest_condition.entry((value_key, executor)).read(),
                seen: self.attest_seen.entry((value_key, executor)).read(),
            }
        }

        fn propose(
            ref self: ContractState, action: felt252, prefix_hash: felt252, params: Array<felt252>,
        ) -> u64 {
            let caller = get_caller_address();
            assert(self.signers.entry(caller).read().active, 'propose: not a signer');
            assert(action != 0, 'propose: bad action');

            let id = self.next_proposal_id.read();
            self.next_proposal_id.write(id + 1);
            self.prop_action.entry(id).write(action);
            self.prop_prefix.entry(id).write(prefix_hash);
            self.prop_proposer.entry(id).write(caller);

            let len = params.len();
            self.prop_param_len.entry(id).write(len);
            let mut i: u32 = 0;
            while i != len {
                self.prop_params.entry((id, i)).write(*params.at(i));
                i += 1;
            }

            self.emit(ProposalCreated { proposal_id: id, action, prefix_hash, proposer: caller });
            id
        }

        fn approve(ref self: ContractState, proposal_id: u64) {
            // Block reentry from an in-flight `approve_sigs` external call — `approve`
            // is part of the approval surface the guard fences.
            assert(!self.reentrancy_guard.read(), 'approve: reentrant');
            let caller = get_caller_address();
            assert(self.signers.entry(caller).read().active, 'approve: not a signer');
            self._assert_live(proposal_id);
            assert(!self.prop_approved_by.entry((proposal_id, caller)).read(), 'approve: duplicate');

            self.prop_approved_by.entry((proposal_id, caller)).write(true);
            let idx = self.prop_approval_count.entry(proposal_id).read();
            self.prop_approver_at.entry((proposal_id, idx)).write(caller);
            self.prop_approval_count.entry(proposal_id).write(idx + 1);

            self.emit(ProposalApproved { proposal_id, approver: caller });
        }

        // Relayed, intent-bound human approval. A human approves
        // *readable intent*, not raw calldata: off-chain they sign the SNIP-12
        // `approval_digest` (which binds {contract, chain, proposal_id, action, prefix,
        // params_hash}); an UNTRUSTED relayer batches the signatures here. The contract
        // recomputes the message hash from IMMUTABLE stored proposal state — the relayer
        // contributes nothing to the signed content except the approver address — and
        // verifies it against the approver account's own SRC6 `is_valid_signature`. A
        // verified approval is recorded into the SAME storage as `approve()` PLUS the
        // `prop_intent_signed` flag, so it (and only it) counts toward `min_humans`.
        // Permissionless (a human can self-relay — liveness). All-or-nothing:
        // any bad signature panics and reverts the whole batch.
        fn approve_sigs(
            ref self: ContractState, proposal_id: u64, approvals: Array<SignedApproval>,
        ) {
            // Reentrancy guard: `is_valid_signature` calls relayer-supplied (but
            // registered) account code; block reentry into the approval/commit surface
            // for the duration of the batch.
            assert(!self.reentrancy_guard.read(), 'approve_sigs: reentrant');
            self.reentrancy_guard.write(true);

            self._assert_live(proposal_id);
            assert(approvals.len() <= MAX_SIGS_PER_CALL, 'approve_sigs: too many');

            // Bind ONCE from immutable stored proposal state (confused-deputy /
            // scope-binding): action, prefix, and the length-prefixed params
            // hash are all read by `proposal_id`, never taken from `approvals`. The
            // message also pins this contract + chain (no cross-contract / cross-chain
            // replay).
            let action = self.prop_action.entry(proposal_id).read();
            let prefix = self.prop_prefix.entry(proposal_id).read();
            let params_digest = snip12::params_hash(self._params(proposal_id));
            let chain_id = get_tx_info().unbox().chain_id;
            let this = get_contract_address();

            let mut approvals = approvals;
            loop {
                match approvals.pop_front() {
                    Option::Some(item) => {
                        let SignedApproval { approver, signature } = item;
                        assert(self.signers.entry(approver).read().active, 'approve_sigs: not signer');
                        // Reject a true duplicate (already intent-bound), but ALLOW
                        // upgrading a prior raw `approve()` to intent-bound: a human who
                        // voted raw can still bind intent given a valid signature
                        // (robustness/liveness, order-independent). One roster slot
                        // per approver either way.
                        let already = self.prop_approved_by.entry((proposal_id, approver)).read();
                        assert(
                            !(already
                                && self.prop_intent_signed.entry((proposal_id, approver)).read()),
                            'approve_sigs: duplicate',
                        );

                        // EFFECTS before INTERACTION (CEI). All-or-nothing makes this
                        // safe: if the signature below is invalid we panic, reverting
                        // every write in this tx.
                        if !already {
                            self.prop_approved_by.entry((proposal_id, approver)).write(true);
                            let idx = self.prop_approval_count.entry(proposal_id).read();
                            self.prop_approver_at.entry((proposal_id, idx)).write(approver);
                            self.prop_approval_count.entry(proposal_id).write(idx + 1);
                        }
                        self.prop_intent_signed.entry((proposal_id, approver)).write(true);

                        // INTERACTION: the message hash is bound to THIS approver
                        // address, so a signature can never be re-attributed. Require
                        // the exact `'VALID'` magic — anything else (incl. 0) fails.
                        let digest = snip12::approval_message_hash(
                            chain_id, this, approver, proposal_id, action, prefix, params_digest,
                        );
                        let res = ISRC6Dispatcher { contract_address: approver }
                            .is_valid_signature(digest, signature);
                        assert(res == VALID_SIGNATURE, 'approve_sigs: bad signature');

                        // A raw approval already emitted ProposalApproved; only emit it
                        // for a freshly-recorded approver. ApprovalSigned always fires.
                        if !already {
                            self.emit(ProposalApproved { proposal_id, approver });
                        }
                        self.emit(ApprovalSigned { proposal_id, approver });
                    },
                    Option::None => { break; },
                }
            }

            self.reentrancy_guard.write(false);
        }

        fn approval_digest(
            self: @ContractState, proposal_id: u64, approver: ContractAddress,
        ) -> felt252 {
            let action = self.prop_action.entry(proposal_id).read();
            let prefix = self.prop_prefix.entry(proposal_id).read();
            let params_digest = snip12::params_hash(self._params(proposal_id));
            let chain_id = get_tx_info().unbox().chain_id;
            snip12::approval_message_hash(
                chain_id, get_contract_address(), approver, proposal_id, action, prefix, params_digest,
            )
        }

        // Dynamic escalation: an eligible signer demands a human reviewer on THIS
        // proposal, even when the static policy sets `min_humans == 0` — the use case is
        // a predicate-agent (a non-human approver) that is in doubt and wants a human in
        // the loop for this one decision. One-directional: it only ever RAISES the human
        // floor (`commit` reads `max(policy.min_humans, 1)`); there is no entrypoint to
        // clear it — the strengthen-only ratchet at proposal granularity. The
        // demand is enforced at `commit` (not counted as a vote), so a confident agent
        // sub-quorum can never out-vote it. Restricted to the proposal's eligible approver
        // population (active signer + role match) so a random account cannot grief every
        // proposal; a *compromised eligible* signer can still force humans, but that is a
        // liveness annoyance, never an unsafe auto-commit (safety over liveness), and the
        // forced human slot stays intent-bound (the `is_human` masking is unchanged).
        fn request_human_review(ref self: ContractState, proposal_id: u64) {
            // Fence reentry from an in-flight `approve_sigs` external call, like `approve`.
            assert(!self.reentrancy_guard.read(), 'request_human: reentrant');
            self._assert_live(proposal_id);
            let caller = get_caller_address();
            let cs = self.signers.entry(caller).read();
            assert(cs.active, 'request_human: not a signer');
            let prefix = self.prop_prefix.entry(proposal_id).read();
            let action = self.prop_action.entry(proposal_id).read();
            let policy = self.policies.entry((prefix, action)).read();
            assert(policy.exists, 'request_human: no policy');
            assert(policy.role == 0 || cs.role == policy.role, 'request_human: wrong role');
            // Idempotent: set + emit only on the first demand (no event spam, monotonic).
            if !self.prop_human_required.entry(proposal_id).read() {
                self.prop_human_required.entry(proposal_id).write(true);
                self.emit(HumanReviewRequested { proposal_id, requester: caller });
            }
        }

        fn commit(ref self: ContractState, proposal_id: u64) {
            // Block reentry from an in-flight `approve_sigs` external call.
            assert(!self.reentrancy_guard.read(), 'commit: reentrant');
            self._assert_live(proposal_id);
            let action = self.prop_action.entry(proposal_id).read();
            let prefix = self.prop_prefix.entry(proposal_id).read();

            let mut target_policy = self.policies.entry((prefix, action)).read();
            assert(target_policy.exists, 'commit: no policy');
            // Dynamic escalation: a per-proposal demand for a human reviewer raises
            // the effective floor to >= 1, never lowers it. Feeding `satisfies()` a
            // strengthened LOCAL Policy keeps the stored policy and `policy.cairo`
            // unchanged — escalation adds a gate, never relaxes one. With
            // the masking in `_approver_set`, the forced human must be intent-bound.
            if self.prop_human_required.entry(proposal_id).read()
                && target_policy.min_humans < 1 {
                target_policy.min_humans = 1;
            }
            let approvers = self._approver_set(proposal_id);
            assert(policy_mod::satisfies(target_policy, approvers), 'commit: policy unmet');

            // Guard against re-entrant / double commit before dispatch.
            self.prop_executed.entry(proposal_id).write(true);

            // Confused-deputy guard: authorization above gated on (prefix, action),
            // so the operation's REAL target must live in that same scope. Otherwise a
            // quorum on the weakest prefix would be a master key over every keyspace.
            let params = self._params(proposal_id);
            if action == actions::FORCE_UNLOCK {
                let lock_key = governance::decode_force_unlock(params);
                // The lock being force-unlocked must belong to the proposal's prefix.
                assert(self.key_prefix.entry(lock_key).read() == prefix, 'commit: lock out of scope');
                self._force_unlock(lock_key);
            } else if action == actions::SET_POLICY {
                let (tp, ta, pol) = governance::decode_policy(params);
                // The policy being written must live in the proposal's prefix.
                assert(tp == prefix, 'commit: policy out of scope');
                // Self-amend ratchet: when a SET_POLICY quorum amends ANY existing
                // governance meta-policy — its OWN SET_POLICY gate, or a sibling
                // FORCE_UNLOCK / SET_ROLE gate in the same scope — it may only
                // *strengthen* it. A single valid quorum must never lower the bar for,
                // or destroy, a governance gate. Without this, a (GLOBAL,SET_POLICY)
                // quorum could weaken (GLOBAL,SET_ROLE) and forge Sybil signers, or
                // clear a gate (exists=false) — which the write-time floor exempts — into a
                // permanent, unrecoverable lockout (owner already renounced).
                if is_governance_action(ta) {
                    let cur = self.policies.entry((tp, ta)).read();
                    if cur.exists {
                        assert(pol.exists, 'commit: cannot clear gov');
                        // `role` is the eligibility population, not an ordered scale —
                        // changing it (esp. to 0 == any-role) widens who may approve and
                        // is a weakening with no single-step path. Pin it; re-targeting a
                        // gov gate's role needs a fresh ceremony, not a same-tier quorum.
                        assert(pol.role == cur.role, 'commit: changes gov role');
                        assert(pol.threshold >= cur.threshold, 'commit: weakens threshold');
                        assert(pol.min_humans >= cur.min_humans, 'commit: weakens min_humans');
                        // max_per_operator: 0 == unlimited (weakest); a finite cap grows
                        // stronger as it shrinks. Forbid loosening an existing finite cap.
                        if cur.max_per_operator != 0 {
                            assert(
                                pol.max_per_operator != 0
                                    && pol.max_per_operator <= cur.max_per_operator,
                                'commit: weakens diversity',
                            );
                        }
                    }
                }
                self._write_policy(tp, ta, pol);
            } else if action == actions::SET_ROLE {
                // Signers are GLOBAL identity, not per-prefix — only a GLOBAL-scoped
                // quorum may mutate them (closes the cross-prefix signer-forge path).
                assert(prefix == scopes::GLOBAL, 'commit: role not global');
                let (acct, sgnr) = governance::decode_signer(params);
                self._write_signer(acct, sgnr);
            } else if action == actions::SET_VALUE {
                // Governed value write — the quorum on (prefix, SET_VALUE) IS the
                // write capability; there is no lock holder on this path. Mutually
                // exclusive with the open single-writer entrypoint: a SET_VALUE
                // policy is EITHER `allow_open` (lock-holder path only) or governed
                // (this path only). Without this guard a single signer could commit
                // a value to an OPEN prefix via governance (satisfies() short-circuits
                // true on allow_open), bypassing the lock-holder requirement.
                assert(!target_policy.allow_open, 'commit: value is open');
                let (value_key, digest, schema_ref, sc, expected_version) =
                    governance::decode_value(params);
                // Confused-deputy guard + first-touch pin off the open path: the
                // value's governing prefix must equal the proposal's prefix. Pin it
                // write-once on the first governed write — under quorum, not by an
                // open front-runner — and assert it thereafter. prefix 0 is the
                // reserved "unbound" sentinel, so a real value prefix is never 0.
                assert(prefix != 0, 'commit: zero value prefix');
                self._bind_value_prefix(value_key, prefix);
                self._apply_value_set(value_key, prefix, digest, schema_ref, sc, expected_version);
            } else if action == actions::TOMBSTONE_VALUE {
                // Governed logical-delete. The value must already exist and
                // live in the proposal's prefix (scope binding) — a quorum over
                // one prefix can never tombstone another prefix's value.
                let (value_key, expected_version) = governance::decode_tombstone_value(params);
                assert(self.value_exists.entry(value_key).read(), 'commit: value missing');
                assert(
                    self.value_prefix.entry(value_key).read() == prefix, 'commit: value out of scope',
                );
                self._apply_value_tombstone(value_key, prefix, expected_version);
            } else {
                core::panic_with_felt252('commit: unknown action');
            }

            self.emit(ProposalCommitted { proposal_id, action });
        }

        fn set_policy(
            ref self: ContractState, prefix_hash: felt252, action: felt252, policy: Policy,
        ) {
            self.ownable.assert_only_owner();
            self._write_policy(prefix_hash, action, policy);
        }

        fn set_signer(ref self: ContractState, account: ContractAddress, signer: Signer) {
            self.ownable.assert_only_owner();
            self._write_signer(account, signer);
        }

        fn get_policy(self: @ContractState, prefix_hash: felt252, action: felt252) -> Policy {
            self.policies.entry((prefix_hash, action)).read()
        }

        fn get_signer(self: @ContractState, account: ContractAddress) -> Signer {
            self.signers.entry(account).read()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _assert_live(self: @ContractState, proposal_id: u64) {
            assert(self.prop_action.entry(proposal_id).read() != 0, 'proposal: missing');
            assert(!self.prop_executed.entry(proposal_id).read(), 'proposal: executed');
            assert(!self.prop_canceled.entry(proposal_id).read(), 'proposal: canceled');
        }

        fn _params(self: @ContractState, proposal_id: u64) -> Span<felt252> {
            let len = self.prop_param_len.entry(proposal_id).read();
            let mut out = array![];
            let mut i: u32 = 0;
            while i != len {
                out.append(self.prop_params.entry((proposal_id, i)).read());
                i += 1;
            }
            out.span()
        }

        // Reconstruct the approver Signer set for `satisfies()`. Intent binding:
        // a human vote counts toward `min_humans` ONLY if it arrived via the intent-
        // bound SNIP-12 path (`approve_sigs` sets `prop_intent_signed`). So present a
        // raw-`approve()` human as NON-human here — `satisfies()` in `policy.cairo`
        // needs no notion of intent. This masking is governance-only:
        // the k-of-n status path builds its OWN attester set in `set_status` and never
        // reads `prop_intent_signed`, so executor humanity is unaffected.
        fn _approver_set(self: @ContractState, proposal_id: u64) -> Span<Signer> {
            let count = self.prop_approval_count.entry(proposal_id).read();
            let mut out = array![];
            let mut i: u32 = 0;
            while i != count {
                let acct = self.prop_approver_at.entry((proposal_id, i)).read();
                let mut s = self.signers.entry(acct).read();
                s.is_human = s.is_human
                    && self.prop_intent_signed.entry((proposal_id, acct)).read();
                out.append(s);
                i += 1;
            }
            out.span()
        }

        fn _write_policy(
            ref self: ContractState, prefix_hash: felt252, action: felt252, policy: Policy,
        ) {
            // Governance threshold floor: an ACTIVE governance policy is never `allow_open`
            // and always demands a real quorum (>= 1 eligible approver). This holds on
            // BOTH write paths — owner bootstrap and governance commit — so the gate
            // can never be seeded or amended into a no-op. ACQUIRE stays open. A
            // cleared policy (exists == false) is exempt: it gates nothing.
            if is_governance_action(action) && policy.exists {
                assert(!policy.allow_open, 'policy: gov not open');
                assert(policy.threshold >= 1, 'policy: gov needs quorum');
            }
            self.policies.entry((prefix_hash, action)).write(policy);
            self
                .emit(
                    PolicyChanged {
                        prefix_hash, action, threshold: policy.threshold, role: policy.role,
                    },
                );
        }

        // Shared single-writer gate for value commitments. Returns the governing
        // prefix. The capability to write a value is holding the lock that governs
        // its prefix — there is no quorum path here (SET_VALUE is the open fast
        // path). Also pins value_key → prefix on first write, write-once and
        // immutable thereafter (the lock's scope-binding pattern applied to values): a
        // value can never be re-pointed into a foreign namespace.
        fn _authorize_value_writer(
            ref self: ContractState, value_key: felt252, lock_key: felt252,
        ) -> felt252 {
            // The lock's canonical prefix (pinned on first acquire). 0 means the
            // lock_key was never governed-touched, so there is nothing to authorize.
            let prefix = self.key_prefix.entry(lock_key).read();
            assert(prefix != 0, 'value: lock unbound');

            // SET_VALUE must be enabled (allow_open) on this prefix — same shape as
            // the ACQUIRE open check. SET_VALUE is not a governance action, so the
            // governance floor does not forbid allow_open here.
            let policy = self.policies.entry((prefix, actions::SET_VALUE)).read();
            assert(policy.exists, 'value: no policy');
            assert(policy.allow_open, 'value: governed');

            // The caller must currently hold a LIVE lease on lock_key.
            let caller = get_caller_address();
            assert(self.lock_held.entry(lock_key).read(), 'value: not held');
            assert(self.lock_holder.entry(lock_key).read() == caller, 'value: not holder');
            let now = get_block_timestamp();
            let acquired_at = self.lock_acquired_at.entry(lock_key).read();
            let ttl = self.lock_ttl.entry(lock_key).read();
            assert(!locks::is_expired(now, acquired_at, ttl), 'value: lease expired');

            self._bind_value_prefix(value_key, prefix);
            prefix
        }

        // Write-once value_key → prefix pin (the lock's scope-binding pattern
        // applied to values). Bind on first write — on the OPEN path to the
        // lock's prefix, on the GOVERNED commit path to the quorum's prefix — and
        // assert unchanged thereafter so a value can never be re-pointed into a
        // foreign namespace (`'value: prefix rebind'`).
        fn _bind_value_prefix(ref self: ContractState, value_key: felt252, prefix: felt252) {
            let bound = self.value_prefix.entry(value_key).read();
            if bound == 0 {
                self.value_prefix.entry(value_key).write(prefix);
            } else {
                assert(bound == prefix, 'value: prefix rebind');
            }
        }

        // Shared value-commit write (open + governed paths). CAS on the value
        // version (lost-update protection across writers), then commit the
        // content digest + storage hint and emit. The blob lives off-chain.
        // The caller is responsible for authorization and the prefix pin.
        fn _apply_value_set(
            ref self: ContractState,
            value_key: felt252,
            prefix: felt252,
            digest: felt252,
            schema_ref: felt252,
            storage_class: felt252,
            expected_version: u64,
        ) {
            let version = self.value_version.entry(value_key).read();
            assert(version == expected_version, 'set_value: stale version');
            let new_version = version + 1;

            self.value_exists.entry(value_key).write(true);
            self.value_digest.entry(value_key).write(digest);
            self.value_schema_ref.entry(value_key).write(schema_ref);
            self.value_storage_class.entry(value_key).write(storage_class);
            self.value_version.entry(value_key).write(new_version);
            self.value_tombstoned.entry(value_key).write(false);

            self
                .emit(
                    ValueChanged {
                        value_key, prefix, digest, schema_ref, storage_class, version: new_version,
                    },
                );
        }

        // Shared logical-delete (open + governed paths). Tombstone + bump version,
        // never a physical erase. The caller authorizes and confirms the
        // value exists.
        fn _apply_value_tombstone(
            ref self: ContractState, value_key: felt252, prefix: felt252, expected_version: u64,
        ) {
            let version = self.value_version.entry(value_key).read();
            assert(version == expected_version, 'value: stale version');
            let new_version = version + 1;
            self.value_tombstoned.entry(value_key).write(true);
            self.value_version.entry(value_key).write(new_version);

            self
                .emit(
                    ValueChanged {
                        value_key,
                        prefix,
                        digest: self.value_digest.entry(value_key).read(),
                        schema_ref: self.value_schema_ref.entry(value_key).read(),
                        storage_class: self.value_storage_class.entry(value_key).read(),
                        version: new_version,
                    },
                );
        }

        fn _write_signer(ref self: ContractState, account: ContractAddress, signer: Signer) {
            self.signers.entry(account).write(signer);
            self.emit(RoleChanged { account, active: signer.active, role: signer.role });
        }

        fn _force_unlock(ref self: ContractState, lock_key: felt252) {
            assert(self.lock_held.entry(lock_key).read(), 'force: not held');
            let previous_holder = self.lock_holder.entry(lock_key).read();
            let version = self.lock_version.entry(lock_key).read() + 1;
            self.lock_held.entry(lock_key).write(false);
            self.lock_tombstoned.entry(lock_key).write(true);
            self.lock_version.entry(lock_key).write(version);

            self.emit(LockForceUnlocked { lock_key, previous_holder, version });
        }

        // k-of-n agreement reached — promote the aggregate StatusRecord to the agreed
        // (revision, hash, condition) and bump the monotonic status_version. `executor`
        // records the attester that tipped promotion.
        fn _promote_status(
            ref self: ContractState,
            value_key: felt252,
            prefix: felt252,
            observed_revision: u64,
            applied_hash: felt252,
            condition: felt252,
            reason: felt252,
            executor: ContractAddress,
        ) {
            let new_sv = self.status_version.entry(value_key).read() + 1;
            self.status_exists.entry(value_key).write(true);
            self.status_observed_revision.entry(value_key).write(observed_revision);
            self.status_observed_digest.entry(value_key).write(applied_hash);
            self.status_condition.entry(value_key).write(condition);
            self.status_reason.entry(value_key).write(reason);
            self.status_attestation.entry(value_key).write(applied_hash);
            self.status_version.entry(value_key).write(new_sv);
            self.status_executor.entry(value_key).write(executor);

            self
                .emit(
                    StatusChanged {
                        value_key,
                        prefix,
                        observed_revision,
                        observed_digest: applied_hash,
                        condition,
                        status_version: new_sv,
                        executor,
                    },
                );
        }

        // Eligible executors attested >=2 distinct hashes at this revision — record the
        // contested state (no silent promotion under conflict). Idempotent per
        // (revision): only writes/emits when it actually changes the aggregate, so a
        // run of conflicting votes doesn't spam status_version. observed_digest is
        // cleared (0 = no agreed hash); executor 0 (no single promoter).
        fn _mark_disagree(ref self: ContractState, value_key: felt252, prefix: felt252, observed_revision: u64) {
            let already = self.status_condition.entry(value_key).read() == conditions::DISAGREE
                && self.status_observed_revision.entry(value_key).read() == observed_revision;
            if already {
                return;
            }
            let new_sv = self.status_version.entry(value_key).read() + 1;
            let zero: ContractAddress = 0.try_into().unwrap();
            self.status_exists.entry(value_key).write(true);
            self.status_observed_revision.entry(value_key).write(observed_revision);
            self.status_observed_digest.entry(value_key).write(0);
            self.status_condition.entry(value_key).write(conditions::DISAGREE);
            self.status_attestation.entry(value_key).write(0);
            self.status_version.entry(value_key).write(new_sv);
            self.status_executor.entry(value_key).write(zero);

            self
                .emit(
                    StatusChanged {
                        value_key,
                        prefix,
                        observed_revision,
                        observed_digest: 0,
                        condition: conditions::DISAGREE,
                        status_version: new_sv,
                        executor: zero,
                    },
                );
        }
    }
}
