//! SNIP-12 typed-data hashing for human-intent-bound approvals.
//!
//! A human approves *readable intent*, not raw calldata: they sign a SNIP-12
//! (Starknet's EIP-712 analog) `Approval` message describing the proposal, and the
//! signature is provably bound to the EXACT operation that commits. An untrusted
//! relayer collects and submits the signatures (`approve_sigs`); the contract
//! recomputes this hash from IMMUTABLE stored proposal state and verifies it against
//! the approver account's SRC6 `is_valid_signature`.
//!
//! The binding: the message hash commits to
//!   - `verifying_contract` + `chain_id`  → no cross-contract / cross-chain replay
//!   - `proposal_id`                       → no cross-proposal replay (ids are monotonic)
//!   - `action` + `prefix` + `params_hash` → the human signs the real (action, scope,
//!                                            calldata); a swapped param breaks the hash
//!   - the approver address (mixed in below) → a signature can't be re-attributed
//!
//! These are pure functions (chain_id / contract are passed in) so they are unit-
//! testable and the snforge suite signs the very hash it verifies. The encodeType
//! strings below are the SNIP-12 *revision 1* form; they must match the typed-data
//! the off-chain signer (starknet.js / a wallet) builds — the `approval_digest` view
//! exists so the harness/UI can assert that round-trip.

use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

// SNIP-12 message prefix (revision 1).
const STARKNET_MESSAGE: felt252 = 'StarkNet Message';

// StarknetDomain (revision 1). `name`/`version` are this app's identity; `revision`
// is the felt 1. `chain_id` is supplied per call from the tx context. NOTE: `version`
// and `revision` are the felt `1` (NOT the short-string '1' = 0x31): SNIP-12 rev-1
// encodes a `shortstring`/`felt` field via `getHex`, which maps the off-chain value
// "1" to felt 1 — so these constants must be the number 1 to match a wallet /
// starknet.js typed-data hash. The harness asserts this round-trip.
pub const DOMAIN_NAME: felt252 = 'bitcd';
pub const DOMAIN_VERSION: felt252 = 1;
const DOMAIN_REVISION: felt252 = 1;

// starknet_keccak(encodeType) — the SNIP-12 rev-1 type hashes. `selector!` is exactly
// starknet_keccak of the given string, which is how SNIP-12 derives a type hash.
const STARKNET_DOMAIN_TYPE_HASH: felt252 =
    selector!(
        "\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")",
    );
const APPROVAL_TYPE_HASH: felt252 =
    selector!(
        "\"Approval\"(\"verifyingContract\":\"felt\",\"proposalId\":\"felt\",\"action\":\"shortstring\",\"prefix\":\"shortstring\",\"paramsHash\":\"felt\")",
    );

// Domain-tagged, length-prefixed digest of the proposal params. The tag prevents this
// digest from ever colliding with another Poseidon value used on-chain; the explicit
// length prevents a second-preimage across differently-padded param spans.
const PARAMS_HASH_TAG: felt252 = 'bitcd:params:v1';

/// Hash of the proposal's stored params (length-prefixed + domain-tagged). Computed
/// over the IMMUTABLE `prop_params` span, so it pins the human's signature to the
/// exact calldata that will commit.
pub fn params_hash(params: Span<felt252>) -> felt252 {
    let mut buf = array![PARAMS_HASH_TAG, params.len().into()];
    let mut i: u32 = 0;
    let len = params.len();
    while i != len {
        buf.append(*params.at(i));
        i += 1;
    }
    poseidon_hash_span(buf.span())
}

fn domain_hash(chain_id: felt252) -> felt252 {
    poseidon_hash_span(
        array![STARKNET_DOMAIN_TYPE_HASH, DOMAIN_NAME, DOMAIN_VERSION, chain_id, DOMAIN_REVISION]
            .span(),
    )
}

fn struct_hash(
    verifying_contract: ContractAddress,
    proposal_id: u64,
    action: felt252,
    prefix: felt252,
    params_digest: felt252,
) -> felt252 {
    poseidon_hash_span(
        array![
            APPROVAL_TYPE_HASH,
            verifying_contract.into(),
            proposal_id.into(),
            action,
            prefix,
            params_digest,
        ]
            .span(),
    )
}

/// The SNIP-12 message hash a human signs to approve `proposal_id`, bound to ONE
/// approver account (its address is mixed in, per SNIP-12, so the signature is
/// non-transferable to another signer).
pub fn approval_message_hash(
    chain_id: felt252,
    verifying_contract: ContractAddress,
    approver: ContractAddress,
    proposal_id: u64,
    action: felt252,
    prefix: felt252,
    params_digest: felt252,
) -> felt252 {
    poseidon_hash_span(
        array![
            STARKNET_MESSAGE,
            domain_hash(chain_id),
            approver.into(),
            struct_hash(verifying_contract, proposal_id, action, prefix, params_digest),
        ]
            .span(),
    )
}
