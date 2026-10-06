//! snforge tests for bitcd. The core acceptance list:
//!   acquire-on-empty / fail-while-held / acquire-after-TTL / release-only-holder
//!   / release-CAS-stale / force_unlock quorum + diversity / policy-change top
//!   quorum / version monotonicity / bootstrap leaves no single actor.

use bitcd::{
    IBitcdDispatcher, IBitcdDispatcherTrait, Policy, Signer, SignedApproval, actions, conditions,
    storage_class,
};
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::signature::{KeyPairTrait, SignerTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address, stop_cheat_block_timestamp, stop_cheat_caller_address,
};
use starknet::ContractAddress;

// --- mock SRC6 accounts -----------------------------------------------------
// The intent-bound approval path verifies a SNIP-12 signature against the approver
// account's own `is_valid_signature` (SRC6). Tests use cheat-addresses, so we deploy
// a minimal stark-curve account AT each signer address (`deploy_at`) holding the
// matching public key; approvals are signed with snforge's stark-curve signer.

#[starknet::contract]
pub mod MockAccount {
    use core::ecdsa::check_ecdsa_signature;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        public_key: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.public_key.write(public_key);
    }

    #[abi(embed_v0)]
    impl SRC6Impl of bitcd::ISRC6<ContractState> {
        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            if signature.len() == 2
                && check_ecdsa_signature(
                    hash, self.public_key.read(), *signature.at(0), *signature.at(1),
                ) {
                'VALID'
            } else {
                0
            }
        }
    }
}

// A malicious "account" that reenters `commit` during signature verification — used
// only to prove the `approve_sigs` reentrancy guard.
#[starknet::contract]
pub mod ReentrantAccount {
    use bitcd::{IBitcdDispatcher, IBitcdDispatcherTrait};
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        target: ContractAddress,
        pid: u64,
    }

    #[constructor]
    fn constructor(ref self: ContractState, target: ContractAddress, pid: u64) {
        self.target.write(target);
        self.pid.write(pid);
    }

    #[abi(embed_v0)]
    impl SRC6Impl of bitcd::ISRC6<ContractState> {
        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            // Reenter the governance surface while `approve_sigs` holds the guard.
            IBitcdDispatcher { contract_address: self.target.read() }.commit(self.pid.read());
            'VALID'
        }
    }
}

// Secret keys backing the mock accounts at a1()/a2()/a3().
const SK1: felt252 = 0x1a2b3c4d;
const SK2: felt252 = 0x5e6f7a8b;
const SK3: felt252 = 0x9c0d1e2f;

fn kp(sk: felt252) -> snforge_std::signature::stark_curve::StarkCurveKeyPair {
    KeyPairTrait::from_secret_key(sk)
}

/// One intent-bound SNIP-12 approval: read the contract's `approval_digest` for
/// `(pid, who)` and sign it with `who`'s key. The relayer then submits it.
fn signed(d: IBitcdDispatcher, pid: u64, who: ContractAddress, sk: felt252) -> SignedApproval {
    let digest = d.approval_digest(pid, who);
    let (r, s) = kp(sk).sign(digest).unwrap();
    SignedApproval { approver: who, signature: array![r, s] }
}

// --- fixtures ---------------------------------------------------------------

const PREFIX: felt252 = 'tf/lock';
const GLOBAL: felt252 = 'GLOBAL';
const LOCK: felt252 = 'tf/lock/state';
const ROLE_OP: felt252 = 'OPERATOR';
const OP_A: felt252 = 'OP_A';
const OP_B: felt252 = 'OP_B';

fn owner() -> ContractAddress {
    0x999.try_into().unwrap()
}
fn a1() -> ContractAddress {
    0x1.try_into().unwrap()
}
fn a2() -> ContractAddress {
    0x2.try_into().unwrap()
}
fn a3() -> ContractAddress {
    0x3.try_into().unwrap()
}

fn open_policy() -> Policy {
    Policy {
        threshold: 0, role: 0, min_humans: 0, max_per_operator: 0, allow_open: true, exists: true,
    }
}

fn quorum_policy(threshold: u32, min_humans: u32, max_per_operator: u32) -> Policy {
    Policy {
        threshold, role: ROLE_OP, min_humans, max_per_operator, allow_open: false, exists: true,
    }
}

fn mk_signer(is_human: bool, operator_id: felt252) -> Signer {
    Signer { active: true, is_human, operator_id, role: ROLE_OP }
}

fn deploy() -> (IBitcdDispatcher, ContractAddress) {
    let cls = declare("Bitcd").unwrap().contract_class();
    let (addr, _) = cls.deploy(@array![owner().into()]).unwrap();
    (IBitcdDispatcher { contract_address: addr }, addr)
}

/// Genesis seeding done by the owner: 3 signers (a1/a2 human distinct operators,
/// a3 bot sharing a1's operator), an open ACQUIRE policy, and quorum policies for
/// FORCE_UNLOCK (2-of, ≥1 human, ≤1 per operator) and SET_POLICY (2-of, ≥1 human).
fn deploy_seeded() -> (IBitcdDispatcher, ContractAddress) {
    let (d, addr) = deploy();
    // Deploy a stark-curve SRC6 account AT each signer address so the intent-bound
    // approval path can verify their SNIP-12 signatures.
    let acct = declare("MockAccount").unwrap().contract_class();
    acct.deploy_at(@array![kp(SK1).public_key], a1()).unwrap();
    acct.deploy_at(@array![kp(SK2).public_key], a2()).unwrap();
    acct.deploy_at(@array![kp(SK3).public_key], a3()).unwrap();
    start_cheat_caller_address(addr, owner());
    d.set_signer(a1(), mk_signer(true, OP_A));
    d.set_signer(a2(), mk_signer(true, OP_B));
    d.set_signer(a3(), mk_signer(false, OP_A));
    d.set_policy(PREFIX, actions::ACQUIRE, open_policy());
    // SET_VALUE is the single-writer commitment fast path: open like
    // ACQUIRE — the lock holder writes the digest, no quorum.
    d.set_policy(PREFIX, actions::SET_VALUE, open_policy());
    d.set_policy(PREFIX, actions::FORCE_UNLOCK, quorum_policy(2, 1, 1));
    d.set_policy(PREFIX, actions::SET_POLICY, quorum_policy(2, 1, 2));
    // SET_ROLE is GLOBAL-scoped — signers are global identity, not per-prefix.
    d.set_policy(GLOBAL, actions::SET_ROLE, quorum_policy(2, 1, 1));
    stop_cheat_caller_address(addr);
    (d, addr)
}

fn acquire_as(d: IBitcdDispatcher, addr: ContractAddress, who: ContractAddress, ttl: u64) {
    start_cheat_caller_address(addr, who);
    d.acquire_lock(LOCK, PREFIX, 'op', ttl);
    stop_cheat_caller_address(addr);
}

// --- locks ------------------------------------------------------------------

#[test]
fn test_acquire_on_empty() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    let rec = d.get_lock(LOCK);
    assert(rec.holder == a1(), 'wrong holder');
    assert(rec.version == 1, 'version not 1');
    assert(!rec.tombstoned, 'should be live');
}

#[test]
#[should_panic(expected: 'acquire: held')]
fn test_acquire_fails_while_held() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    acquire_as(d, addr, a2(), 0);
}

#[test]
fn test_acquire_after_ttl_expiry() {
    let (d, addr) = deploy_seeded();
    start_cheat_block_timestamp(addr, 1000);
    acquire_as(d, addr, a1(), 100);
    stop_cheat_block_timestamp(addr);

    // After expiry (t=1100 >= 1000 + 100): a2 takes over.
    start_cheat_block_timestamp(addr, 1100);
    acquire_as(d, addr, a2(), 0);
    stop_cheat_block_timestamp(addr);

    let rec = d.get_lock(LOCK);
    assert(rec.holder == a2(), 'waiter did not take over');
    assert(rec.version == 2, 'version not bumped');
}

#[test]
#[should_panic(expected: 'release: not holder')]
fn test_release_only_holder() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a2());
    d.release_lock(LOCK, 1);
    stop_cheat_caller_address(addr);
}

#[test]
#[should_panic(expected: 'release: stale version')]
fn test_release_cas_rejects_stale() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.release_lock(LOCK, 99);
    stop_cheat_caller_address(addr);
}

#[test]
fn test_version_monotonicity() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    assert(d.get_lock(LOCK).version == 1, 'v1');

    start_cheat_caller_address(addr, a1());
    d.release_lock(LOCK, 1);
    stop_cheat_caller_address(addr);
    assert(d.get_lock(LOCK).version == 2, 'v2');

    acquire_as(d, addr, a1(), 0);
    assert(d.get_lock(LOCK).version == 3, 'v3');
}

// --- governance: force_unlock ----------------------------------------------

#[test]
fn test_force_unlock_quorum_and_diversity() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);

    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::FORCE_UNLOCK, PREFIX, array![LOCK]);
    stop_cheat_caller_address(addr);

    // a1 (OP_A) + a2 (OP_B): 2-of, both human, distinct operators — both via the
    // intent-bound SNIP-12 path so both count toward min_humans.
    approve_2of(d, addr, pid);

    d.commit(pid); // permissionless

    let rec = d.get_lock(LOCK);
    assert(rec.tombstoned, 'lock not freed');
    assert(rec.version == 2, 'version not bumped');
}

#[test]
#[should_panic(expected: 'commit: policy unmet')]
fn test_force_unlock_below_threshold() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);

    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::FORCE_UNLOCK, PREFIX, array![LOCK]);
    d.approve(pid); // only 1 approver, threshold is 2
    stop_cheat_caller_address(addr);

    d.commit(pid);
}

#[test]
#[should_panic(expected: 'commit: policy unmet')]
fn test_force_unlock_fails_diversity() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);

    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::FORCE_UNLOCK, PREFIX, array![LOCK]);
    stop_cheat_caller_address(addr);

    // a1 (OP_A) human via SNIP-12 (min_humans met), a3 (OP_A) bot via raw approve:
    // two eligible from one operator violates max_per_operator = 1 — diversity fails,
    // so the ONLY unmet gate is diversity (not min_humans).
    d.approve_sigs(pid, array![signed(d, pid, a1(), SK1)]);
    start_cheat_caller_address(addr, a3());
    d.approve(pid);
    stop_cheat_caller_address(addr);

    d.commit(pid);
}

// --- governance: policy change ----------------------------------------------

#[test]
fn test_policy_change_top_quorum() {
    let (d, addr) = deploy_seeded();
    // Propose closing the ACQUIRE policy (allow_open -> false, threshold 5).
    let params = array![PREFIX, actions::ACQUIRE, 5, ROLE_OP, 1, 2, 0, 1];

    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    stop_cheat_caller_address(addr);

    approve_2of(d, addr, pid);
    d.commit(pid);

    let p = d.get_policy(PREFIX, actions::ACQUIRE);
    assert(p.threshold == 5, 'threshold not updated');
    assert(!p.allow_open, 'should be closed');
}

#[test]
#[should_panic(expected: 'commit: policy unmet')]
fn test_policy_change_below_quorum() {
    let (d, addr) = deploy_seeded();
    let params = array![PREFIX, actions::ACQUIRE, 5, ROLE_OP, 1, 2, 0, 1];

    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    d.approve(pid); // single approver, threshold is 2
    stop_cheat_caller_address(addr);

    d.commit(pid);
}

// --- bootstrap: no single actor ---------------------------------------------

#[starknet::interface]
trait IOwnableMin<TState> {
    fn renounce_ownership(ref self: TState);
    fn owner(self: @TState) -> ContractAddress;
}

#[test]
fn test_bootstrap_renounce_removes_owner() {
    let (_d, addr) = deploy_seeded();
    let own = IOwnableMinDispatcher { contract_address: addr };
    assert(own.owner() == owner(), 'owner not set');

    start_cheat_caller_address(addr, owner());
    own.renounce_ownership();
    stop_cheat_caller_address(addr);

    assert(own.owner() == 0.try_into().unwrap(), 'owner not renounced');
}

#[test]
#[should_panic(expected: 'Caller is not the owner')]
fn test_bootstrap_no_single_actor_can_change_policy() {
    // After renounce, even the genesis owner cannot directly rewrite policy;
    // the only remaining path is governance, which requires a quorum.
    let (d, addr) = deploy_seeded();
    let own = IOwnableMinDispatcher { contract_address: addr };
    start_cheat_caller_address(addr, owner());
    own.renounce_ownership();
    d.set_policy(PREFIX, actions::ACQUIRE, open_policy());
    stop_cheat_caller_address(addr);
}

// --- regression: confused-deputy scope binding ------------------------------
// Authorization in commit() is gated on policies[(prop_prefix, action)]; these
// lock the invariant that the OPERATION's real target must live in that same
// scope, so a quorum on a weak prefix can never act as a master key elsewhere.

// a1 (OP_A, human) + a2 (OP_B, human) both approve via the intent-bound SNIP-12 path,
// so both count toward `min_humans`. `approve_sigs` is permissionless (relayed),
// so no caller cheat is needed. This is the only way a human-gated quorum
// (min_humans >= 1) can be satisfied — raw `approve()` humans do not count.
fn approve_2of(d: IBitcdDispatcher, _addr: ContractAddress, pid: u64) {
    d.approve_sigs(pid, array![signed(d, pid, a1(), SK1), signed(d, pid, a2(), SK2)]);
}

#[test]
#[should_panic(expected: 'commit: lock out of scope')]
fn test_force_unlock_rejects_cross_prefix() {
    let (d, addr) = deploy_seeded();
    // Attacker controls a *different* prefix's FORCE_UNLOCK policy.
    let weak: felt252 = 'weak';
    start_cheat_caller_address(addr, owner());
    d.set_policy(weak, actions::FORCE_UNLOCK, quorum_policy(2, 1, 1));
    stop_cheat_caller_address(addr);

    // A real lock lives under PREFIX (key_prefix[LOCK] == PREFIX).
    acquire_as(d, addr, a1(), 0);

    // Quorum on `weak` must NOT reach a lock that belongs to PREFIX.
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::FORCE_UNLOCK, weak, array![LOCK]);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
#[should_panic(expected: 'commit: policy out of scope')]
fn test_set_policy_rejects_cross_prefix() {
    let (d, addr) = deploy_seeded();
    // Attacker controls a weak prefix's SET_POLICY policy.
    let weak: felt252 = 'weak';
    start_cheat_caller_address(addr, owner());
    d.set_policy(weak, actions::SET_POLICY, quorum_policy(2, 1, 2));
    stop_cheat_caller_address(addr);

    // Proposal scoped to `weak` tries to rewrite a policy under PREFIX.
    let params = array![PREFIX, actions::ACQUIRE, 0, 0, 0, 0, 1, 1];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, weak, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
#[should_panic(expected: 'commit: role not global')]
fn test_set_role_requires_global_scope() {
    let (d, addr) = deploy_seeded();
    // Even if a per-prefix SET_ROLE policy is seeded (the confused-deputy vector),
    // signer mutation must be GLOBAL-scoped — so this commit is refused.
    start_cheat_caller_address(addr, owner());
    d.set_policy(PREFIX, actions::SET_ROLE, quorum_policy(2, 1, 2));
    stop_cheat_caller_address(addr);

    // [account, active, is_human, operator_id, role]
    let params = array![0xbad, 1, 1, OP_A, ROLE_OP];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_ROLE, PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
fn test_set_role_global_happy_path() {
    let (d, addr) = deploy_seeded();
    let newcomer: ContractAddress = 0x4.try_into().unwrap();
    // [account, active, is_human, operator_id, role]
    let params = array![0x4, 1, 1, OP_B, ROLE_OP];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_ROLE, GLOBAL, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);

    let s = d.get_signer(newcomer);
    assert(s.active, 'signer not active');
    assert(s.role == ROLE_OP, 'role not set');
}

// --- regression: scope-binding integrity ------------------------------------
// The force-unlock scope check trusts key_prefix[lock_key] as the lock's
// canonical, governance-anchored namespace (pinned on first touch).
// acquire_lock — the one open, permissionless fast-path — must therefore pin the
// binding on first touch and refuse any later rebind, or a free lock could be
// re-bound into a foreign prefix with a weaker/absent FORCE_UNLOCK gate (scope
// escape) or, with ttl==0, made permanently un-forceable.

#[test]
#[should_panic(expected: 'acquire: prefix rebind')]
fn test_acquire_cannot_rebind_prefix_on_reacquire() {
    let (d, addr) = deploy_seeded();
    // Seed a second namespace whose ACQUIRE is open (the attacker's prefix).
    let other: felt252 = 'other';
    start_cheat_caller_address(addr, owner());
    d.set_policy(other, actions::ACQUIRE, open_policy());
    stop_cheat_caller_address(addr);

    // LOCK is bound to PREFIX on first touch, then released (free again).
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.release_lock(LOCK, 1);
    stop_cheat_caller_address(addr);

    // Re-acquiring the freed lock under a DIFFERENT prefix must be refused —
    // the prefix is pinned to PREFIX for the life of the key.
    start_cheat_caller_address(addr, a2());
    d.acquire_lock(LOCK, other, 'op', 0);
    stop_cheat_caller_address(addr);
}

#[test]
#[should_panic(expected: 'acquire: prefix rebind')]
fn test_acquire_cannot_rebind_prefix_after_expiry() {
    let (d, addr) = deploy_seeded();
    let other: felt252 = 'other';
    start_cheat_caller_address(addr, owner());
    d.set_policy(other, actions::ACQUIRE, open_policy());
    stop_cheat_caller_address(addr);

    // a1 takes LOCK under PREFIX with a finite ttl, then it expires.
    start_cheat_block_timestamp(addr, 1000);
    acquire_as(d, addr, a1(), 100);
    stop_cheat_block_timestamp(addr);

    // After expiry the slot is acquirable, but the prefix stays pinned to PREFIX,
    // so taking it over under a foreign prefix is still rejected.
    start_cheat_block_timestamp(addr, 1100);
    start_cheat_caller_address(addr, a2());
    d.acquire_lock(LOCK, other, 'op', 0);
    stop_cheat_caller_address(addr);
    stop_cheat_block_timestamp(addr);
}

#[test]
fn test_force_unlock_survives_foreign_prefix_acquire() {
    let (d, addr) = deploy_seeded();
    // A foreign namespace with a deliberately WEAKER force-unlock gate (1-of).
    let weak: felt252 = 'weak';
    start_cheat_caller_address(addr, owner());
    d.set_policy(weak, actions::ACQUIRE, open_policy());
    d.set_policy(weak, actions::FORCE_UNLOCK, quorum_policy(1, 1, 1));
    stop_cheat_caller_address(addr);

    // LOCK is pinned to PREFIX on first touch; an attacker cannot move it to `weak`.
    acquire_as(d, addr, a1(), 0);

    // The canonical PREFIX force-unlock quorum still breaks the lock — the binding
    // was never escapable into the weaker gate.
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::FORCE_UNLOCK, PREFIX, array![LOCK]);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);

    assert(d.get_lock(LOCK).tombstoned, 'canonical unlock failed');
}

#[test]
#[should_panic(expected: 'acquire: zero prefix')]
fn test_acquire_rejects_zero_prefix() {
    // prefix 0 is the reserved "unbound" sentinel; acquiring under it is refused
    // so the first-touch pin can never be defeated by a 0-prefix collision.
    let (d, addr) = deploy_seeded();
    start_cheat_caller_address(addr, owner());
    d.set_policy(0, actions::ACQUIRE, open_policy());
    stop_cheat_caller_address(addr);
    start_cheat_caller_address(addr, a1());
    d.acquire_lock(LOCK, 0, 'op', 0);
    stop_cheat_caller_address(addr);
}

#[test]
fn test_reacquire_same_prefix_still_allowed() {
    // The pin must not break the legitimate release/re-acquire cycle under the
    // SAME prefix (the single-writer fast path).
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.release_lock(LOCK, 1);
    stop_cheat_caller_address(addr);
    acquire_as(d, addr, a2(), 0);
    let rec = d.get_lock(LOCK);
    assert(rec.holder == a2(), 'reacquire failed');
    assert(rec.version == 3, 'version not bumped');
}

// --- regression: self-amend ratchet -----------------------------------------

#[test]
#[should_panic(expected: 'commit: weakens threshold')]
fn test_self_amend_cannot_weaken_threshold() {
    let (d, addr) = deploy_seeded();
    // Target the SET_POLICY meta-policy of PREFIX, lowering threshold 2 -> 1.
    let params = array![PREFIX, actions::SET_POLICY, 1, ROLE_OP, 1, 2, 0, 1];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
#[should_panic(expected: 'commit: weakens min_humans')]
fn test_self_amend_cannot_weaken_min_humans() {
    let (d, addr) = deploy_seeded();
    // Keep threshold but drop min_humans 1 -> 0.
    let params = array![PREFIX, actions::SET_POLICY, 2, ROLE_OP, 0, 2, 0, 1];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
fn test_self_amend_can_strengthen() {
    let (d, addr) = deploy_seeded();
    // Strengthening the meta-policy (threshold 2 -> 3) is allowed.
    let params = array![PREFIX, actions::SET_POLICY, 3, ROLE_OP, 1, 2, 0, 1];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
    assert(d.get_policy(PREFIX, actions::SET_POLICY).threshold == 3, 'not strengthened');
}

// --- regression: generalized self-amend ratchet -----------------------------
// The ratchet must cover EVERY governance meta-policy, not just (prefix,SET_POLICY).
// Otherwise a SET_POLICY quorum can weaken/destroy a sibling gov gate in one step
// — e.g. weaken (GLOBAL,SET_ROLE) to forge signers, or clear a gate into a
// permanent post-renounce lockout (the write-time floor exempts exists==false).

#[test]
#[should_panic(expected: 'commit: weakens threshold')]
fn test_ratchet_blocks_weakening_set_role_policy() {
    let (d, addr) = deploy_seeded();
    // Seed a GLOBAL SET_POLICY meta-policy so a GLOBAL-scoped SET_POLICY quorum
    // exists; it must still not be able to weaken (GLOBAL,SET_ROLE) (2 -> 1).
    start_cheat_caller_address(addr, owner());
    d.set_policy(GLOBAL, actions::SET_POLICY, quorum_policy(2, 1, 2));
    stop_cheat_caller_address(addr);

    let params = array![GLOBAL, actions::SET_ROLE, 1, ROLE_OP, 1, 1, 0, 1];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, GLOBAL, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
#[should_panic(expected: 'commit: cannot clear gov')]
fn test_ratchet_blocks_clearing_gov_policy() {
    let (d, addr) = deploy_seeded();
    // Clear the (PREFIX,SET_POLICY) gate via exists=false while keeping threshold/
    // min_humans unchanged — the write-time floor exempts a cleared policy, so
    // only the ratchet can catch this.
    let params = array![PREFIX, actions::SET_POLICY, 2, ROLE_OP, 1, 2, 0, 0];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
#[should_panic(expected: 'commit: weakens threshold')]
fn test_ratchet_blocks_weakening_force_unlock_policy() {
    let (d, addr) = deploy_seeded();
    // A (PREFIX,SET_POLICY) quorum must not lower (PREFIX,FORCE_UNLOCK) 2 -> 1.
    let params = array![PREFIX, actions::FORCE_UNLOCK, 1, ROLE_OP, 1, 1, 0, 1];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
#[should_panic(expected: 'commit: weakens diversity')]
fn test_ratchet_blocks_loosening_diversity_cap() {
    let (d, addr) = deploy_seeded();
    // (PREFIX,FORCE_UNLOCK) has max_per_operator=1; loosening to 2 weakens the
    // operator-diversity gate and must be rejected.
    let params = array![PREFIX, actions::FORCE_UNLOCK, 2, ROLE_OP, 1, 2, 0, 1];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
#[should_panic(expected: 'commit: changes gov role')]
fn test_ratchet_blocks_widening_gov_role() {
    let (d, addr) = deploy_seeded();
    // Re-target (PREFIX,FORCE_UNLOCK).role from ROLE_OP to 0 (any role) — widening
    // the eligible approver population, a Sybil-enabling weakening. Must be refused.
    let params = array![PREFIX, actions::FORCE_UNLOCK, 2, 0, 1, 1, 0, 1];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
fn test_ratchet_allows_strengthening_sibling_policy() {
    let (d, addr) = deploy_seeded();
    // Tightening a sibling gov gate (PREFIX,FORCE_UNLOCK) 2 -> 3 is allowed.
    let params = array![PREFIX, actions::FORCE_UNLOCK, 3, ROLE_OP, 1, 1, 0, 1];
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_POLICY, PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
    assert(d.get_policy(PREFIX, actions::FORCE_UNLOCK).threshold == 3, 'sibling not strengthened');
}

// --- regression: governance threshold floor ---------------------------------

#[test]
#[should_panic(expected: 'policy: gov not open')]
fn test_governance_policy_cannot_be_open() {
    let (d, addr) = deploy();
    start_cheat_caller_address(addr, owner());
    // An OPEN FORCE_UNLOCK would make force-unlock ungoverned — must be rejected.
    d.set_policy(PREFIX, actions::FORCE_UNLOCK, open_policy());
    stop_cheat_caller_address(addr);
}

#[test]
#[should_panic(expected: 'policy: gov needs quorum')]
fn test_governance_policy_needs_quorum() {
    let (d, addr) = deploy();
    start_cheat_caller_address(addr, owner());
    let p = Policy {
        threshold: 0, role: ROLE_OP, min_humans: 0, max_per_operator: 0, allow_open: false,
        exists: true,
    };
    d.set_policy(PREFIX, actions::SET_POLICY, p);
    stop_cheat_caller_address(addr);
}

// --- regression: ttl overflow safety ----------------------------------------

#[test]
#[should_panic(expected: 'acquire: held')]
fn test_huge_ttl_does_not_overflow() {
    let (d, addr) = deploy_seeded();
    start_cheat_block_timestamp(addr, 1000);
    // A near-u64::MAX ttl must NOT overflow-panic acquired_at + ttl; the second
    // acquire reaches the domain check and is correctly rejected as still-held.
    acquire_as(d, addr, a1(), 0xffffffffffffffff);
    acquire_as(d, addr, a2(), 0);
    stop_cheat_block_timestamp(addr);
}

// --- governed values: single-writer SET_VALUE commitment --------------------
// The capability to write a prefix's value digest IS holding that prefix's lock
// (no quorum). The blob lives off-chain; the chain records who decided and
// that the bytes are unaltered. value_key→prefix is pinned write-once.

const VALUE: felt252 = 'tf/lock/state/value';
const DIGEST_A: felt252 = 0xaaa1;
const DIGEST_B: felt252 = 0xbbb2;

#[test]
fn test_set_value_by_holder() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);

    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0);
    stop_cheat_caller_address(addr);

    let v = d.get_value(VALUE);
    assert(v.exists, 'value not stored');
    assert(v.digest == DIGEST_A, 'wrong digest');
    assert(v.schema_ref == 'tfstate/v4', 'wrong schema');
    assert(v.storage_class == storage_class::S3, 'wrong class');
    assert(v.version == 1, 'version not 1');
    assert(v.prefix == PREFIX, 'prefix not pinned');
    assert(!v.tombstoned, 'should be live');
}

#[test]
#[should_panic(expected: 'value: not holder')]
fn test_set_value_rejects_non_holder() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    // a2 does not hold the lock — it cannot commit the prefix's value.
    start_cheat_caller_address(addr, a2());
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0);
    stop_cheat_caller_address(addr);
}

#[test]
#[should_panic(expected: 'value: not held')]
fn test_set_value_rejects_when_no_lock() {
    let (d, addr) = deploy_seeded();
    // The lock was never acquired, so key_prefix is unbound and nobody holds it.
    // (No acquire ⇒ key_prefix[LOCK] == 0 ⇒ 'value: lock unbound'… but seeding a
    // prefix needs a touch. Acquire then release to bind+free the slot.)
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.release_lock(LOCK, 1);
    // Lock is free; even the prior holder holds nothing.
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0);
    stop_cheat_caller_address(addr);
}

#[test]
#[should_panic(expected: 'value: lock unbound')]
fn test_set_value_rejects_unbound_lock() {
    let (d, addr) = deploy_seeded();
    // A lock_key that was never acquired has key_prefix == 0 (unbound); there is
    // no governing prefix to authorize a value write against.
    let untouched: felt252 = 'never/touched';
    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, untouched, DIGEST_A, 'tfstate/v4', storage_class::S3, 0);
    stop_cheat_caller_address(addr);
}

#[test]
#[should_panic(expected: 'value: lease expired')]
fn test_set_value_rejects_expired_lease() {
    let (d, addr) = deploy_seeded();
    start_cheat_block_timestamp(addr, 1000);
    acquire_as(d, addr, a1(), 100);
    stop_cheat_block_timestamp(addr);

    // After expiry the holder's lease is dead — it cannot write the value
    // (a stale agent must re-acquire, matching the lock's takeover semantics).
    start_cheat_block_timestamp(addr, 1100);
    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0);
    stop_cheat_caller_address(addr);
    stop_cheat_block_timestamp(addr);
}

#[test]
#[should_panic(expected: 'set_value: stale version')]
fn test_set_value_cas_rejects_stale() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0); // -> v1
    // Re-writing with a stale expected_version (0, not 1) is rejected (CAS).
    d.set_value(VALUE, LOCK, DIGEST_B, 'tfstate/v4', storage_class::S3, 0);
    stop_cheat_caller_address(addr);
}

#[test]
fn test_set_value_version_monotonic() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0);
    d.set_value(VALUE, LOCK, DIGEST_B, 'tfstate/v4', storage_class::S3, 1);
    stop_cheat_caller_address(addr);
    let v = d.get_value(VALUE);
    assert(v.version == 2, 'version not 2');
    assert(v.digest == DIGEST_B, 'digest not updated');
}

#[test]
#[should_panic(expected: 'value: prefix rebind')]
fn test_set_value_cannot_rebind_prefix() {
    let (d, addr) = deploy_seeded();
    // Two namespaces, both with open ACQUIRE + SET_VALUE.
    let other: felt252 = 'other';
    start_cheat_caller_address(addr, owner());
    d.set_policy(other, actions::ACQUIRE, open_policy());
    d.set_policy(other, actions::SET_VALUE, open_policy());
    stop_cheat_caller_address(addr);

    // VALUE is pinned to PREFIX via a lock under PREFIX.
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0);
    stop_cheat_caller_address(addr);

    // A different lock under `other` must NOT be able to re-point VALUE into it.
    let other_lock: felt252 = 'other/lock';
    start_cheat_caller_address(addr, a2());
    d.acquire_lock(other_lock, other, 'op', 0);
    d.set_value(VALUE, other_lock, DIGEST_B, 'tfstate/v4', storage_class::S3, 1);
    stop_cheat_caller_address(addr);
}

#[test]
fn test_tombstone_value_keeps_version_line() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0); // v1
    d.tombstone_value(VALUE, LOCK, 1); // v2, logical delete
    stop_cheat_caller_address(addr);
    let v = d.get_value(VALUE);
    assert(v.tombstoned, 'not tombstoned');
    assert(v.version == 2, 'version line broken');
    assert(v.exists, 'record physically erased');
}

#[test]
#[should_panic(expected: 'value: no policy')]
fn test_set_value_requires_policy() {
    let (d, addr) = deploy_seeded();
    // A namespace with an open ACQUIRE but NO SET_VALUE policy: the holder still
    // cannot commit a value there (the write capability must be explicitly granted).
    let bare: felt252 = 'bare';
    start_cheat_caller_address(addr, owner());
    d.set_policy(bare, actions::ACQUIRE, open_policy());
    stop_cheat_caller_address(addr);
    let bare_lock: felt252 = 'bare/lock';
    start_cheat_caller_address(addr, a1());
    d.acquire_lock(bare_lock, bare, 'op', 0);
    d.set_value(VALUE, bare_lock, DIGEST_A, 'tfstate/v4', storage_class::S3, 0);
    stop_cheat_caller_address(addr);
}

// --- governed values: quorum-gated SET_VALUE / TOMBSTONE_VALUE ---------------
// A governed value prefix has `(prefix, SET_VALUE)` NOT `allow_open`: the write
// capability is a QUORUM, not a lock holder. This moves the first-touch
// binding off the open path (value_prefix is pinned write-once under quorum). The
// open and governed modes are mutually exclusive per prefix.

const GOV_PREFIX: felt252 = 'app/config';
const GOV_VALUE: felt252 = 'app/config/v';
const SCHEMA: felt252 = 'appcfg/v1';

/// `deploy_seeded` plus a governed value namespace `GOV_PREFIX`: ACQUIRE stays
/// open (so the open-path-rejection test can take a lock there), but SET_VALUE and
/// TOMBSTONE_VALUE are 2-of-OPERATOR quorums (≥1 human, ≤1 per operator).
fn deploy_seeded_gov() -> (IBitcdDispatcher, ContractAddress) {
    let (d, addr) = deploy_seeded();
    start_cheat_caller_address(addr, owner());
    d.set_policy(GOV_PREFIX, actions::ACQUIRE, open_policy());
    d.set_policy(GOV_PREFIX, actions::SET_VALUE, quorum_policy(2, 1, 1));
    d.set_policy(GOV_PREFIX, actions::TOMBSTONE_VALUE, quorum_policy(2, 1, 1));
    stop_cheat_caller_address(addr);
    (d, addr)
}

/// Drive a proposal to commit with the a1 (OP_A,human) + a2 (OP_B,human) quorum.
fn quorum_commit(d: IBitcdDispatcher, addr: ContractAddress, action: felt252, params: Array<felt252>) {
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(action, GOV_PREFIX, params);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid); // a1 + a2 intent-bound (min_humans >= 1)
    d.commit(pid); // permissionless
}

#[test]
fn test_governed_set_value_by_quorum() {
    let (d, addr) = deploy_seeded_gov();
    // No lock involved — the quorum IS the write capability.
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_A, SCHEMA, storage_class::S3, 0]);

    let v = d.get_value(GOV_VALUE);
    assert(v.exists, 'value not stored');
    assert(v.digest == DIGEST_A, 'wrong digest');
    assert(v.schema_ref == SCHEMA, 'wrong schema');
    assert(v.storage_class == storage_class::S3, 'wrong class');
    assert(v.version == 1, 'version not 1');
    assert(v.prefix == GOV_PREFIX, 'prefix not pinned by quorum');
    assert(!v.tombstoned, 'should be live');
}

#[test]
#[should_panic(expected: 'commit: policy unmet')]
fn test_governed_set_value_below_quorum() {
    let (d, addr) = deploy_seeded_gov();
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_VALUE, GOV_PREFIX, array![GOV_VALUE, DIGEST_A, SCHEMA, storage_class::S3, 0]);
    d.approve(pid); // only 1 of 2
    stop_cheat_caller_address(addr);
    d.commit(pid);
}

#[test]
#[should_panic(expected: 'commit: value is open')]
fn test_governed_commit_rejects_open_prefix() {
    // A SET_VALUE proposal against an OPEN prefix must not commit: the open prefix
    // is written only by the lock holder. Otherwise satisfies() short-circuits true
    // on allow_open and a single signer could write without holding the lock.
    let (d, addr) = deploy_seeded_gov();
    start_cheat_caller_address(addr, a1());
    // PREFIX (not GOV_PREFIX) has an OPEN SET_VALUE policy.
    let pid = d.propose(actions::SET_VALUE, PREFIX, array![VALUE, DIGEST_A, SCHEMA, storage_class::S3, 0]);
    stop_cheat_caller_address(addr);
    d.commit(pid);
}

#[test]
#[should_panic(expected: 'value: governed')]
fn test_open_set_value_rejected_on_governed_prefix() {
    // The lock-holder fast path is refused on a governed SET_VALUE prefix — even a
    // legitimate lock holder must go through the quorum.
    let (d, addr) = deploy_seeded_gov();
    let gov_lock: felt252 = 'app/config/lock';
    start_cheat_caller_address(addr, a1());
    d.acquire_lock(gov_lock, GOV_PREFIX, 'op', 0); // ACQUIRE is open here
    d.set_value(GOV_VALUE, gov_lock, DIGEST_A, SCHEMA, storage_class::S3, 0);
    stop_cheat_caller_address(addr);
}

#[test]
fn test_governed_set_value_cas_and_monotonic() {
    let (d, addr) = deploy_seeded_gov();
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_A, SCHEMA, storage_class::S3, 0]); // v1
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_B, SCHEMA, storage_class::S3, 1]); // v2
    let v = d.get_value(GOV_VALUE);
    assert(v.version == 2, 'version not 2');
    assert(v.digest == DIGEST_B, 'digest not updated');
}

#[test]
#[should_panic(expected: 'set_value: stale version')]
fn test_governed_set_value_cas_rejects_stale() {
    let (d, addr) = deploy_seeded_gov();
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_A, SCHEMA, storage_class::S3, 0]); // v1
    // Re-commit with stale expected_version 0 (current is 1) — CAS rejects.
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_B, SCHEMA, storage_class::S3, 0]);
}

#[test]
#[should_panic(expected: 'value: prefix rebind')]
fn test_governed_value_protected_from_open_capture() {
    // The write-once pin in action: a value first-touched (registered) under the
    // governed prefix cannot then be hijacked by an open-prefix lock holder — the
    // write-once pin asserts on the foreign open prefix.
    let (d, addr) = deploy_seeded_gov();
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_A, SCHEMA, storage_class::S3, 0]);

    // Attacker takes a lock under the OPEN PREFIX and tries to write GOV_VALUE.
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.set_value(GOV_VALUE, LOCK, DIGEST_B, SCHEMA, storage_class::S3, 1);
    stop_cheat_caller_address(addr);
}

#[test]
#[should_panic(expected: 'value: prefix rebind')]
fn test_governed_set_value_cross_prefix_rebind_rejected() {
    // A quorum over a SECOND governed prefix cannot re-point a value already bound
    // to GOV_PREFIX (scope binding, write-once pin).
    let (d, addr) = deploy_seeded_gov();
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_A, SCHEMA, storage_class::S3, 0]);

    let other: felt252 = 'other/cfg';
    start_cheat_caller_address(addr, owner());
    d.set_policy(other, actions::SET_VALUE, quorum_policy(2, 1, 1));
    stop_cheat_caller_address(addr);

    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::SET_VALUE, other, array![GOV_VALUE, DIGEST_B, SCHEMA, storage_class::S3, 1]);
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid);
    d.commit(pid);
}

#[test]
fn test_governed_tombstone_value() {
    let (d, addr) = deploy_seeded_gov();
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_A, SCHEMA, storage_class::S3, 0]); // v1
    quorum_commit(d, addr, actions::TOMBSTONE_VALUE, array![GOV_VALUE, 1]); // v2, logical delete

    let v = d.get_value(GOV_VALUE);
    assert(v.tombstoned, 'not tombstoned');
    assert(v.version == 2, 'version line broken');
    assert(v.exists, 'record physically erased');
}

#[test]
#[should_panic(expected: 'commit: value missing')]
fn test_governed_tombstone_rejects_missing_value() {
    let (d, addr) = deploy_seeded_gov();
    // Tombstoning a never-written value reverts.
    quorum_commit(d, addr, actions::TOMBSTONE_VALUE, array![GOV_VALUE, 0]);
}

// Put-after-delete is INTENDED etcd / Terraform semantics (not an append-only
// violation): `terraform destroy` tombstones the state, a following `terraform
// apply` must recreate it under the same value_key. Append-only means "no
// physical erase + monotonic version", not "permanent gravestone" — resurrection
// keeps the version line and re-emits ValueChanged. These tests pin that.
#[test]
fn test_value_put_after_tombstone_recreates_open() {
    let (d, addr) = deploy_seeded();
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0); // v1
    d.tombstone_value(VALUE, LOCK, 1); // v2, logical delete
    // Recreate under the same key (CAS against the tombstone version) — allowed.
    d.set_value(VALUE, LOCK, DIGEST_B, 'tfstate/v4', storage_class::S3, 2); // v3
    stop_cheat_caller_address(addr);
    let v = d.get_value(VALUE);
    assert(!v.tombstoned, 'should be live again');
    assert(v.version == 3, 'version line not monotonic');
    assert(v.digest == DIGEST_B, 'recreated digest wrong');
}

#[test]
fn test_governed_put_after_tombstone_recreates() {
    let (d, addr) = deploy_seeded_gov();
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_A, SCHEMA, storage_class::S3, 0]); // v1
    quorum_commit(d, addr, actions::TOMBSTONE_VALUE, array![GOV_VALUE, 1]); // v2
    quorum_commit(d, addr, actions::SET_VALUE, array![GOV_VALUE, DIGEST_B, SCHEMA, storage_class::S3, 2]); // v3
    let v = d.get_value(GOV_VALUE);
    assert(!v.tombstoned, 'should be live again');
    assert(v.version == 3, 'version line not monotonic');
    assert(v.digest == DIGEST_B, 'recreated digest wrong');
}

#[test]
#[should_panic(expected: 'policy: gov not open')]
fn test_tombstone_value_policy_cannot_be_open() {
    // TOMBSTONE_VALUE is a governance action — the floor forbids an open policy.
    let (d, addr) = deploy();
    start_cheat_caller_address(addr, owner());
    d.set_policy(GOV_PREFIX, actions::TOMBSTONE_VALUE, open_policy());
    stop_cheat_caller_address(addr);
}

// --- observed status: k-of-n executor attestation ---------------------------
// Desired state (the value) is consensus-/lock-written; OBSERVED state is attested
// by executors (active Signers of the SET_STATUS policy role). Each executor writes
// ONLY its own slot; the contract PROMOTES the aggregate only when a policy quorum
// (k-of-n + operator diversity) agrees on the same (revision, applied_hash,
// condition) — reusing `satisfies()` (the enforcement layer is consensus). A split
// records DISAGREE. The surfaces are disjoint: a status write never rewrites desired.
// The contract computes no Synced/OutOfSync (derived off-chain). k=1 is single-writer.

const ROLE_EXEC: felt252 = 'EXEC_IAM';
const DIGEST_LIVE: felt252 = 0xdead; // a drifted live-state digest != DIGEST_A

fn exec_addr() -> ContractAddress {
    0x9.try_into().unwrap()
}
fn exec2_addr() -> ContractAddress {
    0xa.try_into().unwrap()
}
fn exec3_addr() -> ContractAddress {
    0xb.try_into().unwrap()
}
fn exec_dup_addr() -> ContractAddress {
    0xc.try_into().unwrap() // shares exec_addr's operator_id (diversity test)
}

fn exec_signer(operator_id: felt252) -> Signer {
    Signer { active: true, is_human: false, operator_id, role: ROLE_EXEC }
}

/// `deploy_seeded` plus a single-writer (k=1) SET_STATUS gate on PREFIX + one
/// executor signer — the k=1 case of the aggregation.
fn deploy_seeded_status() -> (IBitcdDispatcher, ContractAddress) {
    let (d, addr) = deploy_seeded();
    start_cheat_caller_address(addr, owner());
    d
        .set_policy(
            PREFIX,
            actions::SET_STATUS,
            Policy {
                threshold: 1, role: ROLE_EXEC, min_humans: 0, max_per_operator: 0,
                allow_open: false, exists: true,
            },
        );
    d.set_signer(exec_addr(), exec_signer('OP_EXEC'));
    stop_cheat_caller_address(addr);
    (d, addr)
}

/// `deploy_seeded` plus a k-of-n SET_STATUS gate (2-of-EXEC, <=1 per operator) and
/// four executor signers: exec1/2/3 on distinct operator_ids + exec_dup sharing
/// exec1's operator (for the diversity test).
fn deploy_seeded_kofn() -> (IBitcdDispatcher, ContractAddress) {
    let (d, addr) = deploy_seeded();
    start_cheat_caller_address(addr, owner());
    d
        .set_policy(
            PREFIX,
            actions::SET_STATUS,
            Policy {
                threshold: 2, role: ROLE_EXEC, min_humans: 0, max_per_operator: 1,
                allow_open: false, exists: true,
            },
        );
    d.set_signer(exec_addr(), exec_signer('OPE1'));
    d.set_signer(exec2_addr(), exec_signer('OPE2'));
    d.set_signer(exec3_addr(), exec_signer('OPE3'));
    d.set_signer(exec_dup_addr(), exec_signer('OPE1'));
    stop_cheat_caller_address(addr);
    (d, addr)
}

/// Acquire LOCK and write the open value once — binds VALUE -> PREFIX at spec v1.
fn bind_value(d: IBitcdDispatcher, addr: ContractAddress) {
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, LOCK, DIGEST_A, 'tfstate/v4', storage_class::S3, 0);
    stop_cheat_caller_address(addr);
}

/// Push the open spec to the next version (a1 holds LOCK from bind_value).
fn bump_value(d: IBitcdDispatcher, addr: ContractAddress, digest: felt252, expected: u64) {
    start_cheat_caller_address(addr, a1());
    d.set_value(VALUE, LOCK, digest, 'tfstate/v4', storage_class::S3, expected);
    stop_cheat_caller_address(addr);
}

fn attest(
    d: IBitcdDispatcher,
    addr: ContractAddress,
    who: ContractAddress,
    obs_rev: u64,
    applied_hash: felt252,
    condition: felt252,
) {
    start_cheat_caller_address(addr, who);
    d.set_status(VALUE, obs_rev, applied_hash, condition, 0);
    stop_cheat_caller_address(addr);
}

#[test]
fn test_set_status_by_executor() {
    // k=1: a single executor's attestation satisfies a threshold-1 policy and is
    // promoted immediately (single-writer behavior).
    let (d, addr) = deploy_seeded_status();
    bind_value(d, addr);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED);

    let st = d.get_status(VALUE);
    assert(st.exists, 'status not stored');
    assert(st.observed_revision == 1, 'wrong observed_revision');
    assert(st.observed_digest == DIGEST_A, 'wrong observed_digest');
    assert(st.condition == conditions::SYNCED, 'wrong condition');
    assert(st.status_version == 1, 'status_version not 1');
    assert(st.executor == exec_addr(), 'wrong executor');
}

#[test]
#[should_panic(expected: 'status: wrong role')]
fn test_set_status_rejects_non_executor() {
    let (d, addr) = deploy_seeded_status();
    bind_value(d, addr);
    attest(d, addr, a1(), 1, DIGEST_A, conditions::SYNCED); // a1 is OPERATOR, not EXEC_IAM
}

#[test]
#[should_panic(expected: 'status: not executor')]
fn test_set_status_rejects_unregistered() {
    let (d, addr) = deploy_seeded_status();
    bind_value(d, addr);
    let stranger: ContractAddress = 0xbad.try_into().unwrap();
    attest(d, addr, stranger, 1, DIGEST_A, conditions::SYNCED);
}

#[test]
#[should_panic(expected: 'status: value unbound')]
fn test_set_status_rejects_unbound_value() {
    let (d, addr) = deploy_seeded_status();
    attest(d, addr, exec_addr(), 0, DIGEST_A, conditions::SYNCED);
}

#[test]
#[should_panic(expected: 'status: no policy')]
fn test_set_status_requires_policy() {
    let (d, addr) = deploy_seeded();
    bind_value(d, addr);
    // No (PREFIX, SET_STATUS) policy is seeded here, and the policy check precedes the signer check.
    attest(d, addr, a1(), 1, DIGEST_A, conditions::SYNCED);
}

#[test]
#[should_panic(expected: 'status: open')]
fn test_set_status_rejects_open_policy() {
    let (d, addr) = deploy_seeded();
    bind_value(d, addr);
    start_cheat_caller_address(addr, owner());
    d.set_policy(PREFIX, actions::SET_STATUS, open_policy());
    stop_cheat_caller_address(addr);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED);
}

#[test]
#[should_panic(expected: 'status: future revision')]
fn test_set_status_rejects_future_revision() {
    let (d, addr) = deploy_seeded_status();
    bind_value(d, addr);
    attest(d, addr, exec_addr(), 2, DIGEST_A, conditions::SYNCED); // spec is at v1
}

#[test]
#[should_panic(expected: 'status: revision regress')]
fn test_set_status_revision_monotonic() {
    let (d, addr) = deploy_seeded_status();
    bind_value(d, addr); // spec v1
    bump_value(d, addr, DIGEST_B, 1); // spec v2
    attest(d, addr, exec_addr(), 2, DIGEST_B, conditions::SYNCED);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED); // roll back this slot
}

#[test]
fn test_set_status_never_rewrites_desired() {
    // Even when the executor observes a hash != desired (drift, derived off-chain),
    // the DESIRED record is untouched — only a governed revision can change it.
    let (d, addr) = deploy_seeded_status();
    bind_value(d, addr); // desired: DIGEST_A @ v1
    attest(d, addr, exec_addr(), 1, DIGEST_LIVE, conditions::SYNCED);

    let v = d.get_value(VALUE);
    assert(v.digest == DIGEST_A, 'desired digest changed');
    assert(v.version == 1, 'desired version changed');
    assert(!v.tombstoned, 'desired tombstoned');
    assert(d.get_status(VALUE).observed_digest == DIGEST_LIVE, 'observed not recorded');
}

#[test]
fn test_status_drift_then_resync_cycle() {
    // k=1 reconcile arc: the observed hash cycles A -> drifted -> A; the aggregate
    // promotes each time (Synced/OutOfSync is the reader's call, off-chain).
    let (d, addr) = deploy_seeded_status();
    bind_value(d, addr);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED); // sv1
    attest(d, addr, exec_addr(), 1, DIGEST_LIVE, conditions::SYNCED); // sv2 (drift)
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED); // sv3 (reconverged)

    let st = d.get_status(VALUE);
    assert(st.observed_digest == DIGEST_A, 'observed not back to desired');
    assert(st.status_version == 3, 'status line not monotonic');
}

// --- k-of-n agreement & disagreement ----------------------------------------

#[test]
fn test_kofn_promotes_only_at_k() {
    let (d, addr) = deploy_seeded_kofn();
    bind_value(d, addr);
    // exec1 alone: below threshold 2 — no promotion.
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED);
    assert(!d.get_status(VALUE).exists, 'promoted below k');
    // exec2 (distinct operator) agrees on the same hash -> 2-of -> promote.
    attest(d, addr, exec2_addr(), 1, DIGEST_A, conditions::SYNCED);
    let st = d.get_status(VALUE);
    assert(st.exists, 'not promoted at k');
    assert(st.condition == conditions::SYNCED, 'wrong condition');
    assert(st.observed_digest == DIGEST_A, 'wrong agreed hash');
    assert(st.observed_revision == 1, 'wrong revision');
    assert(st.status_version == 1, 'promoted more than once');
}

#[test]
fn test_kofn_below_k_pending() {
    let (d, addr) = deploy_seeded_kofn();
    bind_value(d, addr);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED);
    // one honest executor is not enough; the aggregate stays unset.
    let st = d.get_status(VALUE);
    assert(!st.exists, 'promoted with one vote');
    // ...but the vote is recorded as that executor's attestation.
    let a = d.get_attestation(VALUE, exec_addr());
    assert(a.seen && a.applied_hash == DIGEST_A, 'attestation not recorded');
}

#[test]
fn test_kofn_diversity_rejects_same_operator() {
    // Two executors agreeing but sharing one operator_id violate max_per_operator=1,
    // so the quorum is NOT satisfied — one operator can't self-approve k-of-n.
    let (d, addr) = deploy_seeded_kofn();
    bind_value(d, addr);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED); // OPE1
    attest(d, addr, exec_dup_addr(), 1, DIGEST_A, conditions::SYNCED); // OPE1 (same op)
    assert(!d.get_status(VALUE).exists, 'diversity bypassed');
}

#[test]
fn test_kofn_disagree_on_split() {
    // Eligible executors attest DIFFERENT hashes for the same revision -> DISAGREE,
    // no silent Synced.
    let (d, addr) = deploy_seeded_kofn();
    bind_value(d, addr);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED);
    attest(d, addr, exec2_addr(), 1, DIGEST_B, conditions::SYNCED);
    let st = d.get_status(VALUE);
    assert(st.condition == conditions::DISAGREE, 'not contested');
    assert(st.observed_digest == 0, 'disagree has no agreed hash');
}

#[test]
fn test_kofn_byzantine_minority_outvoted() {
    // A lone dishonest executor (different hash) can contest but not block: the
    // honest 2-of agreeing on the true hash still promotes Synced.
    let (d, addr) = deploy_seeded_kofn();
    bind_value(d, addr);
    attest(d, addr, exec3_addr(), 1, DIGEST_B, conditions::SYNCED); // liar
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED); // honest 1 -> DISAGREE
    assert(d.get_status(VALUE).condition == conditions::DISAGREE, 'expected contest');
    attest(d, addr, exec2_addr(), 1, DIGEST_A, conditions::SYNCED); // honest 2 -> promote
    let st = d.get_status(VALUE);
    assert(st.condition == conditions::SYNCED, 'honest quorum did not win');
    assert(st.observed_digest == DIGEST_A, 'wrong agreed hash');
}

#[test]
fn test_kofn_stale_revision_does_not_count() {
    // A vote for an OLD revision never counts toward agreement on the current one.
    let (d, addr) = deploy_seeded_kofn();
    bind_value(d, addr); // v1
    bump_value(d, addr, DIGEST_B, 1); // v2
    attest(d, addr, exec_addr(), 1, DIGEST_B, conditions::SYNCED); // stale (rev 1)
    attest(d, addr, exec2_addr(), 2, DIGEST_B, conditions::SYNCED); // rev 2: only 1 at rev2
    assert(!d.get_status(VALUE).exists, 'stale vote counted');
    attest(d, addr, exec3_addr(), 2, DIGEST_B, conditions::SYNCED); // 2-of at rev2 -> promote
    let st = d.get_status(VALUE);
    assert(st.exists && st.observed_revision == 2, 'not promoted at current rev');
    assert(st.observed_digest == DIGEST_B, 'wrong agreed hash');
}

#[test]
#[should_panic(expected: 'status: reserved condition')]
fn test_kofn_executor_cannot_attest_disagree() {
    // DISAGREE is contract-set only; an executor attesting it is rejected (else two
    // could "agree on DISAGREE" and promote a contested-looking record with a hash).
    let (d, addr) = deploy_seeded_kofn();
    bind_value(d, addr);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::DISAGREE);
}

#[test]
fn test_kofn_one_executor_one_vote() {
    // An executor re-attesting only updates its own slot — it cannot self-satisfy k.
    let (d, addr) = deploy_seeded_kofn();
    bind_value(d, addr);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED);
    attest(d, addr, exec_addr(), 1, DIGEST_A, conditions::SYNCED); // same executor again
    assert(!d.get_status(VALUE).exists, 'double-counted one executor');
    let a = d.get_attestation(VALUE, exec_addr());
    assert(a.observed_revision == 1, 'slot not maintained');
}

// --- SNIP-12 intent-bound human approval -------------------------------------
// A human approves *readable intent*, not raw calldata: they sign the SNIP-12
// `approval_digest` off-chain and an untrusted relayer submits it via `approve_sigs`.
// A human vote counts toward `min_humans` ONLY through this intent-bound path —
// `_approver_set` masks `is_human` for raw `approve()` votes, so `satisfies()`
// needs no notion of intent. The signature binds {contract, chain, proposal_id,
// action, prefix, params_hash} + the approver address (no replay / re-attribution).

/// Acquire LOCK (binds it to PREFIX) and open a FORCE_UNLOCK proposal on PREFIX
/// (policy 2-of, >=1 human, <=1 per operator). Returns the proposal id.
fn propose_fu(d: IBitcdDispatcher, addr: ContractAddress) -> u64 {
    acquire_as(d, addr, a1(), 0);
    start_cheat_caller_address(addr, a1());
    let pid = d.propose(actions::FORCE_UNLOCK, PREFIX, array![LOCK]);
    stop_cheat_caller_address(addr);
    pid
}

#[test]
fn test_intent_signed_human_satisfies_min_humans() {
    // The headline: two humans sign readable intent (SNIP-12) and the relayer submits
    // them — min_humans (1) is met and the quorum commits.
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    d.approve_sigs(pid, array![signed(d, pid, a1(), SK1), signed(d, pid, a2(), SK2)]);
    d.commit(pid);
    assert(d.get_lock(LOCK).tombstoned, 'intent quorum did not commit');
}

#[test]
#[should_panic(expected: 'commit: policy unmet')]
fn test_raw_approve_human_does_not_satisfy_min_humans() {
    // The thesis: a1 and a2 ARE humans, but approving via raw approve() is NOT
    // intent-bound, so neither counts toward min_humans (1). Threshold (2) is met,
    // min_humans is not — the commit is refused. No more rubber-stamping hex.
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    start_cheat_caller_address(addr, a1());
    d.approve(pid);
    stop_cheat_caller_address(addr);
    start_cheat_caller_address(addr, a2());
    d.approve(pid);
    stop_cheat_caller_address(addr);
    d.commit(pid);
}

#[test]
fn test_mixed_intent_and_raw_satisfies() {
    // a1 (OP_A) intent-bound human -> counts toward min_humans; a2 (OP_B) raw approve
    // -> fills threshold only (a bot/automated signer pattern). eligible=2, humans=1,
    // distinct operators -> satisfied.
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    d.approve_sigs(pid, array![signed(d, pid, a1(), SK1)]);
    start_cheat_caller_address(addr, a2());
    d.approve(pid);
    stop_cheat_caller_address(addr);
    d.commit(pid);
    assert(d.get_lock(LOCK).tombstoned, 'mixed quorum did not commit');
}

#[test]
fn test_min_humans_zero_intent_not_required() {
    // Intent binding is load-bearing exactly when min_humans >= 1. With min_humans == 0,
    // the human count cannot fail `satisfies()`, so the masking has no effect and raw
    // approvals suffice (the vacuous case — such a prefix gets no human-intent
    // guarantee, by design).
    let (d, addr) = deploy_seeded();
    let p0: felt252 = 'mh0';
    let lk: felt252 = 'mh0/lock';
    start_cheat_caller_address(addr, owner());
    d.set_policy(p0, actions::ACQUIRE, open_policy());
    d.set_policy(p0, actions::FORCE_UNLOCK, quorum_policy(2, 0, 1)); // min_humans 0
    stop_cheat_caller_address(addr);

    start_cheat_caller_address(addr, a1());
    d.acquire_lock(lk, p0, 'op', 0);
    let pid = d.propose(actions::FORCE_UNLOCK, p0, array![lk]);
    d.approve(pid);
    stop_cheat_caller_address(addr);
    start_cheat_caller_address(addr, a2());
    d.approve(pid);
    stop_cheat_caller_address(addr);
    d.commit(pid);
    assert(d.get_lock(lk).tombstoned, 'min_humans0 needs no intent');
}

// --- dynamic escalation (request_human_review) ------------------------------
// A predicate-agent in doubt can DEMAND a human reviewer on a single proposal, even
// when the static policy sets min_humans == 0. One-directional (can only raise the
// floor to >= 1, never clear it), checked at commit (not counted as a vote, so a
// confident agent sub-quorum cannot route around it), and the forced human must be
// intent-bound (the is_human masking is unchanged).

/// `deploy_seeded` plus an agent-autonomy prefix `mh0`: ACQUIRE open, FORCE_UNLOCK a
/// 2-of-OPERATOR quorum with min_humans == 0 (agents-only by default). Acquires the
/// lock and opens a FORCE_UNLOCK proposal as a1; returns (lock_key, proposal_id).
fn propose_fu_agents_only(d: IBitcdDispatcher, addr: ContractAddress) -> (felt252, u64) {
    let p0: felt252 = 'mh0';
    let lk: felt252 = 'mh0/lock';
    start_cheat_caller_address(addr, owner());
    d.set_policy(p0, actions::ACQUIRE, open_policy());
    d.set_policy(p0, actions::FORCE_UNLOCK, quorum_policy(2, 0, 1)); // min_humans 0
    stop_cheat_caller_address(addr);
    start_cheat_caller_address(addr, a1());
    d.acquire_lock(lk, p0, 'op', 0);
    let pid = d.propose(actions::FORCE_UNLOCK, p0, array![lk]);
    stop_cheat_caller_address(addr);
    (lk, pid)
}

#[test]
#[should_panic(expected: 'commit: policy unmet')]
fn test_request_human_review_blocks_agent_only_commit() {
    // Baseline (test_min_humans_zero_intent_not_required): two raw agent approvals
    // commit on a min_humans==0 prefix. Here both agents vote FIRST, then a doubting
    // eligible agent (a3 — a bot signer) escalates. The vote is already a full quorum,
    // but the demand is enforced at commit, so the confident sub-quorum cannot route
    // around it: effective min_humans=1, no intent-bound human -> unmet.
    let (d, addr) = deploy_seeded();
    let (_lk, pid) = propose_fu_agents_only(d, addr);
    start_cheat_caller_address(addr, a1());
    d.approve(pid);
    stop_cheat_caller_address(addr);
    start_cheat_caller_address(addr, a2());
    d.approve(pid);
    stop_cheat_caller_address(addr);
    // a3: non-human (a predicate-agent), ROLE_OP -> eligible to escalate.
    start_cheat_caller_address(addr, a3());
    d.request_human_review(pid);
    stop_cheat_caller_address(addr);
    d.commit(pid);
}

#[test]
fn test_request_human_review_satisfied_by_intent_human() {
    // After escalation, the demand is met only by a human signing READABLE INTENT
    // (SNIP-12): a1 intent-bound (counts toward the forced min_humans=1) + a2 raw
    // (OP_B, fills threshold). Distinct operators, eligible=2, humans=1 -> commits.
    let (d, addr) = deploy_seeded();
    let (lk, pid) = propose_fu_agents_only(d, addr);
    start_cheat_caller_address(addr, a3());
    d.request_human_review(pid);
    stop_cheat_caller_address(addr);
    d.approve_sigs(pid, array![signed(d, pid, a1(), SK1)]);
    start_cheat_caller_address(addr, a2());
    d.approve(pid);
    stop_cheat_caller_address(addr);
    d.commit(pid);
    assert(d.get_lock(lk).tombstoned, 'escalated quorum did not commit');
}

#[test]
#[should_panic(expected: 'request_human: not a signer')]
fn test_request_human_review_rejects_non_signer() {
    // A random (non-signer) account cannot escalate — escalation is bounded to the
    // proposal's eligible approver population (anti-grief).
    let (d, addr) = deploy_seeded();
    let (_lk, pid) = propose_fu_agents_only(d, addr);
    start_cheat_caller_address(addr, 0x4.try_into().unwrap());
    d.request_human_review(pid);
    stop_cheat_caller_address(addr);
}

#[test]
#[should_panic(expected: 'request_human: wrong role')]
fn test_request_human_review_rejects_wrong_role() {
    // An active signer whose role does not match the proposal's (prefix, action)
    // policy role cannot escalate it — same eligibility filter as `satisfies()`.
    let (d, addr) = deploy_seeded();
    start_cheat_caller_address(addr, owner());
    d.set_signer(a3(), Signer { active: true, is_human: false, operator_id: OP_A, role: 'OTHER' });
    stop_cheat_caller_address(addr);
    let (_lk, pid) = propose_fu_agents_only(d, addr); // FORCE_UNLOCK role ROLE_OP
    start_cheat_caller_address(addr, a3());
    d.request_human_review(pid); // a3 role 'OTHER' != ROLE_OP
    stop_cheat_caller_address(addr);
}

#[test]
fn test_request_human_review_noop_when_already_gated() {
    // On a prefix that already requires a human (min_humans>=1), escalation changes
    // nothing — the normal intent-bound quorum still commits. Calling it twice is a
    // harmless monotonic no-op (strengthen-only, never weakens).
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr); // FORCE_UNLOCK on PREFIX: min_humans already 1
    start_cheat_caller_address(addr, a1());
    d.request_human_review(pid);
    d.request_human_review(pid); // idempotent
    stop_cheat_caller_address(addr);
    approve_2of(d, addr, pid); // a1 + a2 intent-bound
    d.commit(pid);
    assert(d.get_lock(LOCK).tombstoned, 'gated quorum did not commit');
}

#[test]
#[should_panic(expected: 'approve_sigs: bad signature')]
fn test_replay_across_proposal_rejected() {
    // A signature for one proposal cannot be replayed onto another: the digest binds
    // proposal_id (and the recomputed action/prefix/params), so the hash differs.
    let (d, addr) = deploy_seeded();
    let pid1 = propose_fu(d, addr);
    start_cheat_caller_address(addr, a1());
    let pid2 = d
        .propose(
            actions::SET_POLICY, PREFIX, array![PREFIX, actions::SET_POLICY, 3, ROLE_OP, 1, 2, 0, 1],
        );
    stop_cheat_caller_address(addr);
    let (r, s) = kp(SK1).sign(d.approval_digest(pid2, a1())).unwrap();
    d.approve_sigs(pid1, array![SignedApproval { approver: a1(), signature: array![r, s] }]);
}

#[test]
#[should_panic(expected: 'approve_sigs: bad signature')]
fn test_signature_reattribution_rejected() {
    // a1 signs the digest for (pid, a1); the relayer submits it claiming approver=a2.
    // The contract recomputes the hash bound to a2 and checks a2's account — a1's
    // signature is invalid there. A signature is non-transferable between signers.
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    let (r, s) = kp(SK1).sign(d.approval_digest(pid, a1())).unwrap();
    d.approve_sigs(pid, array![SignedApproval { approver: a2(), signature: array![r, s] }]);
}

#[test]
#[should_panic(expected: 'approve_sigs: bad signature')]
fn test_bad_signature_rejected() {
    // A garbage signature makes is_valid_signature return 0 (not 'VALID') — the
    // contract requires the exact magic value, so anything else is rejected.
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    d.approve_sigs(pid, array![SignedApproval { approver: a1(), signature: array![0x1, 0x2] }]);
}

#[test]
#[should_panic(expected: 'approve_sigs: duplicate')]
fn test_approve_sigs_rejects_duplicate() {
    // One approver = one slot: the same approver twice in a batch is rejected once it
    // is already intent-bound (dedup).
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    d.approve_sigs(pid, array![signed(d, pid, a1(), SK1), signed(d, pid, a1(), SK1)]);
}

#[test]
fn test_raw_approve_upgraded_to_intent() {
    // Order-independence: a1 votes raw FIRST (counts threshold, not human),
    // a2 votes raw. Below min_humans -> would not commit. Then a1 upgrades to intent-
    // bound via approve_sigs (no second slot), so a1 then counts toward min_humans and
    // the quorum commits.
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    start_cheat_caller_address(addr, a1());
    d.approve(pid);
    stop_cheat_caller_address(addr);
    start_cheat_caller_address(addr, a2());
    d.approve(pid);
    stop_cheat_caller_address(addr);
    // a1 upgrades its existing raw approval to intent-bound (same slot).
    d.approve_sigs(pid, array![signed(d, pid, a1(), SK1)]);
    d.commit(pid);
    assert(d.get_lock(LOCK).tombstoned, 'upgrade did not satisfy humans');
}

#[test]
#[should_panic(expected: 'approve_sigs: not signer')]
fn test_approve_sigs_rejects_non_signer() {
    // The active-signer check precedes the external call, so an unregistered approver
    // is refused before any account is touched.
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    let stranger: ContractAddress = 0xbad.try_into().unwrap();
    d.approve_sigs(pid, array![SignedApproval { approver: stranger, signature: array![0x1, 0x2] }]);
}

#[test]
#[should_panic(expected: 'approve_sigs: too many')]
fn test_approve_sigs_rejects_oversized_batch() {
    // DoS bound: a batch larger than MAX_SIGS_PER_CALL is rejected up front.
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    let mut batch: Array<SignedApproval> = array![];
    let mut i: u32 = 0;
    while i != 65 {
        batch.append(SignedApproval { approver: a1(), signature: array![] });
        i += 1;
    }
    d.approve_sigs(pid, batch);
}

#[test]
#[should_panic(expected: 'commit: reentrant')]
fn test_approve_sigs_reentrancy_guarded() {
    // A malicious account reenters commit() during signature verification; the guard
    // set by approve_sigs makes that reentrant commit revert. All-or-nothing
    // means the whole batch reverts.
    let (d, addr) = deploy_seeded();
    let pid = propose_fu(d, addr);
    let evil = declare("ReentrantAccount").unwrap().contract_class();
    let evil_addr: ContractAddress = 0xe111.try_into().unwrap();
    evil.deploy_at(@array![addr.into(), pid.into()], evil_addr).unwrap();
    start_cheat_caller_address(addr, owner());
    d.set_signer(evil_addr, mk_signer(true, 'OP_EVIL'));
    stop_cheat_caller_address(addr);
    d.approve_sigs(pid, array![SignedApproval { approver: evil_addr, signature: array![] }]);
}

#[test]
fn test_approval_digest_binds_proposal_and_approver() {
    // The digest distinguishes proposals (different intent) and approvers (non-
    // transferable). Both are the structural basis of the no-replay / no-reattribution
    // guarantees above.
    let (d, addr) = deploy_seeded();
    let pid1 = propose_fu(d, addr);
    start_cheat_caller_address(addr, a1());
    let pid2 = d
        .propose(
            actions::SET_POLICY, PREFIX, array![PREFIX, actions::SET_POLICY, 3, ROLE_OP, 1, 2, 0, 1],
        );
    stop_cheat_caller_address(addr);
    assert(d.approval_digest(pid1, a1()) != d.approval_digest(pid2, a1()), 'digest not bound to prop');
    assert(d.approval_digest(pid1, a1()) != d.approval_digest(pid1, a2()), 'digest not bound to appr');
}
