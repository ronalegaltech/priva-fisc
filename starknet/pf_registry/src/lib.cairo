//! PRIVA-FISC registry: the shared state that a proof alone cannot give.
//!
//! Proofs are checked by Garaga-generated verifiers. This contract adds what needs a common ledger:
//!   * an issuer-key list: a proof counts only if the authority key it was checked against is one
//!     the registry owner has listed;
//!   * a nullifier ledger: a presentation is refused if a nullifier it publishes was seen before,
//!     so the same invoices cannot be presented twice in the same context.
//!
//! Three kinds of proof are accepted:
//!   * a batch of 10 invoices (noir/batch_k10), one nullifier per invoice, derived from the
//!     invoice's receipt code;
//!   * 1 to 10 invoices issued to one buyer (noir/debtor_k10), with the same nullifier per invoice
//!     as a batch, so an invoice shown in one of these two kinds is recognised in the other;
//!   * an aggregate of any number of invoices (noir/agg_top), one scope nullifier for the whole
//!     run (taxpayer key, business unit, device, year). The aggregate proof names the leaf, node
//!     and sorted-list circuits it was built from; it is accepted only if those are the circuits
//!     this registry was deployed with.
//! A nullifier per invoice and a scope nullifier cannot be compared with each other, so a context
//! takes proofs with one kind of nullifier only: batches and proofs about one buyer together, or
//! aggregates. The first attestation in a context decides which. (Whoever holds a valid proof of
//! the other kind for that context could send it first; a relying party keeps its context to
//! itself and the taxpayer until the attestation it expects is recorded.)
//! A scope allows ONE aggregate per context: a second one for the same taxpayer key, unit, device
//! and year is refused even if it covers more invoices or other ones.
//! An attestation is never withdrawn here. What a later spot check finds is for the relying
//! party to record.
//!
//! The context is chosen by whoever relies on the attestations and given to the taxpayer. The
//! registry records it; it cannot know which context a relying party issued. A relying party reads
//! only the attestations made in its own context.
//!
//! It records WHAT WAS PROVED, never invoice data. What a proof does not prove (that the authority
//! saw the invoice content, completeness beyond the run) is not cured here either. A scope
//! nullifier rests on unit and device codes the taxpayer wrote: it stops a second presentation of
//! the same run, and a spot check is what confirms the codes. `submitted_by` is the account that
//! sent the transaction, not necessarily the taxpayer: a proof is not bound to its sender.

use starknet::{ClassHash, ContractAddress};

/// Invoices in a batch proof, and its public values in order: threshold, context, year, taxpayer
/// key hash, issuer key hash, starts-at-one, BATCH_SIZE nullifiers, BATCH_SIZE opening commitments.
pub const BATCH_SIZE: u32 = 10;
pub const BATCH_PUBLIC_VALUES: u32 = 26;

/// Public values of an aggregate proof, in order: threshold, context, year, key hashes of the leaf,
/// node and sorted-list circuits, taxpayer key hash, issuer key hash, starts-at-one, number of
/// invoices, root of the opening tree, scope nullifier.
pub const AGGREGATE_PUBLIC_VALUES: u32 = 12;

/// Public values of a proof about one buyer, in order: threshold, context, year, taxpayer key
/// hash, issuer key hash, number of invoices (1 to BATCH_SIZE), buyer tag, BATCH_SIZE nullifiers,
/// BATCH_SIZE opening commitments. Places past the number of invoices hold zero.
pub const ONE_BUYER_PUBLIC_VALUES: u32 = 27;

#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
pub struct Attestation {
    pub context: u256,
    pub taxpayer_key_hash: u256,
    pub issuer_key_hash: u256,
    pub year: u32,
    pub threshold_cents: u64,
    pub invoice_count: u32,
    pub starts_at_one: bool,
    pub aggregated: bool,
    /// Zero unless the statement is about invoices issued to one buyer; then the tag a relying
    /// party recomputes from its context and the buyer's identifier.
    pub buyer_tag: u256,
    pub submitted_by: ContractAddress,
}

#[starknet::interface]
pub trait IPrivaFiscRegistry<TContractState> {
    /// Owner only. Lists or delists an authority key hash.
    fn set_issuer_key(ref self: TContractState, key_hash: u256, active: bool);
    fn is_issuer_key(self: @TContractState, key_hash: u256) -> bool;
    fn is_nullifier_used(self: @TContractState, nullifier: u256) -> bool;
    /// Kind of proof a context holds: 0 none yet, 1 batches and proofs about one buyer,
    /// 2 aggregates.
    fn context_kind(self: @TContractState, context: u256) -> u8;
    /// Verifies a 10-invoice batch proof, checks the issuer key and the nullifiers, records the
    /// attestation and returns its id. Reverts on any failure.
    fn attest_batch(ref self: TContractState, full_proof_with_hints: Span<felt252>) -> u64;
    /// Same for an aggregate proof.
    fn attest_aggregate(ref self: TContractState, full_proof_with_hints: Span<felt252>) -> u64;
    /// Same for a proof about 1 to 10 invoices issued to one buyer.
    fn attest_one_buyer(ref self: TContractState, full_proof_with_hints: Span<felt252>) -> u64;
    fn get_attestation(self: @TContractState, id: u64) -> Attestation;
    fn attestation_count(self: @TContractState) -> u64;
    fn owner(self: @TContractState) -> ContractAddress;
    fn batch_verifier(self: @TContractState) -> ClassHash;
    fn aggregate_verifier(self: @TContractState) -> ClassHash;
    fn one_buyer_verifier(self: @TContractState) -> ClassHash;
    /// Key hashes of the (leaf, node, sorted-list) circuits an aggregate proof must come from.
    fn aggregate_circuits(self: @TContractState) -> (u256, u256, u256);
}

#[starknet::contract]
pub mod PrivaFiscRegistry {
    // The generated verifiers expose the same entry point, so one dispatcher type serves all of
    // them; the class hash decides which verifier runs.
    use pf_batch_k10_verifier::honk_verifier::{
        IUltraKeccakZKHonkVerifierDispatcherTrait, IUltraKeccakZKHonkVerifierLibraryDispatcher,
    };
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ClassHash, ContractAddress, get_caller_address};
    use super::{
        AGGREGATE_PUBLIC_VALUES, Attestation, BATCH_PUBLIC_VALUES, BATCH_SIZE, ONE_BUYER_PUBLIC_VALUES,
    };

    #[storage]
    struct Storage {
        owner: ContractAddress,
        batch_verifier: ClassHash,
        aggregate_verifier: ClassHash,
        one_buyer_verifier: ClassHash,
        leaf_vk_hash: u256,
        node_vk_hash: u256,
        sorted_vk_hash: u256,
        issuer_keys: Map<u256, bool>,
        nullifiers: Map<u256, bool>,
        context_kinds: Map<u256, u8>,
        attestations: Map<u64, Attestation>,
        attestation_count: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        IssuerKeySet: IssuerKeySet,
        BatchAttested: BatchAttested,
        AggregateAttested: AggregateAttested,
        OneBuyerAttested: OneBuyerAttested,
    }

    #[derive(Drop, starknet::Event)]
    pub struct IssuerKeySet {
        #[key]
        pub key_hash: u256,
        pub active: bool,
    }

    #[derive(Drop, starknet::Event)]
    pub struct BatchAttested {
        #[key]
        pub id: u64,
        #[key]
        pub context: u256,
        pub taxpayer_key_hash: u256,
        pub issuer_key_hash: u256,
        pub year: u32,
        pub threshold_cents: u64,
        pub invoice_count: u32,
        pub starts_at_one: bool,
        /// Opening commitments, one per invoice, for later spot checks.
        pub openings: Span<u256>,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AggregateAttested {
        #[key]
        pub id: u64,
        #[key]
        pub context: u256,
        pub taxpayer_key_hash: u256,
        pub issuer_key_hash: u256,
        pub year: u32,
        pub threshold_cents: u64,
        pub invoice_count: u32,
        pub starts_at_one: bool,
        pub opening_root: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OneBuyerAttested {
        #[key]
        pub id: u64,
        #[key]
        pub context: u256,
        pub taxpayer_key_hash: u256,
        pub issuer_key_hash: u256,
        pub year: u32,
        pub threshold_cents: u64,
        pub invoice_count: u32,
        pub buyer_tag: u256,
        /// Opening commitments, one per invoice, for later spot checks.
        pub openings: Span<u256>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        batch_verifier: ClassHash,
        aggregate_verifier: ClassHash,
        leaf_vk_hash: u256,
        node_vk_hash: u256,
        sorted_vk_hash: u256,
        one_buyer_verifier: ClassHash,
    ) {
        self.owner.write(owner);
        self.batch_verifier.write(batch_verifier);
        self.aggregate_verifier.write(aggregate_verifier);
        self.one_buyer_verifier.write(one_buyer_verifier);
        self.leaf_vk_hash.write(leaf_vk_hash);
        self.node_vk_hash.write(node_vk_hash);
        self.sorted_vk_hash.write(sorted_vk_hash);
    }

    #[generate_trait]
    impl Internal of InternalTrait {
        fn verified_values(
            self: @ContractState, verifier: ClassHash, proof: Span<felt252>, expected_len: u32,
        ) -> Span<u256> {
            let result = IUltraKeccakZKHonkVerifierLibraryDispatcher { class_hash: verifier }
                .verify_ultra_keccak_zk_honk_proof(proof);
            assert(result.is_ok(), 'proof invalid');
            let values = result.unwrap();
            assert(values.len() == expected_len, 'unexpected public values');
            values
        }

        fn use_nullifier(ref self: ContractState, nullifier: u256) {
            assert(!self.nullifiers.read(nullifier), 'invoice already presented');
            self.nullifiers.write(nullifier, true);
        }

        /// A context holds proofs with a nullifier per invoice (1: batches and proofs about one
        /// buyer) or aggregates (2), never both.
        fn use_context(ref self: ContractState, context: u256, kind: u8) {
            let held = self.context_kinds.read(context);
            assert(held == 0 || held == kind, 'context holds the other kind');
            if held == 0 {
                self.context_kinds.write(context, kind);
            }
        }

        fn record(ref self: ContractState, attestation: Attestation) -> u64 {
            let id = self.attestation_count.read() + 1;
            self.attestation_count.write(id);
            self.attestations.write(id, attestation);
            id
        }
    }

    #[abi(embed_v0)]
    impl PrivaFiscRegistryImpl of super::IPrivaFiscRegistry<ContractState> {
        fn set_issuer_key(ref self: ContractState, key_hash: u256, active: bool) {
            assert(get_caller_address() == self.owner.read(), 'only owner');
            self.issuer_keys.write(key_hash, active);
            self.emit(IssuerKeySet { key_hash, active });
        }

        fn is_issuer_key(self: @ContractState, key_hash: u256) -> bool {
            self.issuer_keys.read(key_hash)
        }

        fn is_nullifier_used(self: @ContractState, nullifier: u256) -> bool {
            self.nullifiers.read(nullifier)
        }

        fn context_kind(self: @ContractState, context: u256) -> u8 {
            self.context_kinds.read(context)
        }

        fn attest_batch(ref self: ContractState, full_proof_with_hints: Span<felt252>) -> u64 {
            let values = self
                .verified_values(self.batch_verifier.read(), full_proof_with_hints, BATCH_PUBLIC_VALUES);
            let threshold_cents: u64 = (*values.at(0)).try_into().expect('threshold out of range');
            let context = *values.at(1);
            let year: u32 = (*values.at(2)).try_into().expect('year out of range');
            let taxpayer_key_hash = *values.at(3);
            let issuer_key_hash = *values.at(4);
            let starts_at_one = *values.at(5) == 1;

            assert(self.issuer_keys.read(issuer_key_hash), 'issuer key not registered');
            self.use_context(context, 1);
            let mut i: u32 = 0;
            while i != BATCH_SIZE {
                self.use_nullifier(*values.at(6 + i));
                i += 1;
            }

            let id = self
                .record(
                    Attestation {
                        context,
                        taxpayer_key_hash,
                        issuer_key_hash,
                        year,
                        threshold_cents,
                        invoice_count: BATCH_SIZE,
                        starts_at_one,
                        aggregated: false,
                        buyer_tag: 0,
                        submitted_by: get_caller_address(),
                    },
                );
            self
                .emit(
                    BatchAttested {
                        id,
                        context,
                        taxpayer_key_hash,
                        issuer_key_hash,
                        year,
                        threshold_cents,
                        invoice_count: BATCH_SIZE,
                        starts_at_one,
                        openings: values.slice(6 + BATCH_SIZE, BATCH_SIZE),
                    },
                );
            id
        }

        fn attest_aggregate(ref self: ContractState, full_proof_with_hints: Span<felt252>) -> u64 {
            let values = self
                .verified_values(
                    self.aggregate_verifier.read(), full_proof_with_hints, AGGREGATE_PUBLIC_VALUES,
                );
            let threshold_cents: u64 = (*values.at(0)).try_into().expect('threshold out of range');
            let context = *values.at(1);
            let year: u32 = (*values.at(2)).try_into().expect('year out of range');
            let taxpayer_key_hash = *values.at(6);
            let issuer_key_hash = *values.at(7);
            let starts_at_one = *values.at(8) == 1;
            let invoice_count: u32 = (*values.at(9)).try_into().expect('count out of range');
            let opening_root = *values.at(10);
            let scope_nullifier = *values.at(11);

            // The top proof only says "proofs of the circuits with these key hashes verified".
            assert(*values.at(3) == self.leaf_vk_hash.read(), 'unknown leaf circuit');
            assert(*values.at(4) == self.node_vk_hash.read(), 'unknown node circuit');
            assert(*values.at(5) == self.sorted_vk_hash.read(), 'unknown sorted circuit');
            assert(self.issuer_keys.read(issuer_key_hash), 'issuer key not registered');
            self.use_context(context, 2);
            self.use_nullifier(scope_nullifier);

            let id = self
                .record(
                    Attestation {
                        context,
                        taxpayer_key_hash,
                        issuer_key_hash,
                        year,
                        threshold_cents,
                        invoice_count,
                        starts_at_one,
                        aggregated: true,
                        buyer_tag: 0,
                        submitted_by: get_caller_address(),
                    },
                );
            self
                .emit(
                    AggregateAttested {
                        id,
                        context,
                        taxpayer_key_hash,
                        issuer_key_hash,
                        year,
                        threshold_cents,
                        invoice_count,
                        starts_at_one,
                        opening_root,
                    },
                );
            id
        }

        fn attest_one_buyer(ref self: ContractState, full_proof_with_hints: Span<felt252>) -> u64 {
            let values = self
                .verified_values(
                    self.one_buyer_verifier.read(), full_proof_with_hints, ONE_BUYER_PUBLIC_VALUES,
                );
            let threshold_cents: u64 = (*values.at(0)).try_into().expect('threshold out of range');
            let context = *values.at(1);
            let year: u32 = (*values.at(2)).try_into().expect('year out of range');
            let taxpayer_key_hash = *values.at(3);
            let issuer_key_hash = *values.at(4);
            let invoice_count: u32 = (*values.at(5)).try_into().expect('count out of range');
            let buyer_tag = *values.at(6);

            assert(invoice_count != 0 && invoice_count <= BATCH_SIZE, 'count out of range');
            assert(self.issuer_keys.read(issuer_key_hash), 'issuer key not registered');
            // Same nullifiers as a batch, so the two kinds share a context and its ledger.
            self.use_context(context, 1);
            let mut i: u32 = 0;
            while i != invoice_count {
                self.use_nullifier(*values.at(7 + i));
                i += 1;
            }

            let id = self
                .record(
                    Attestation {
                        context,
                        taxpayer_key_hash,
                        issuer_key_hash,
                        year,
                        threshold_cents,
                        invoice_count,
                        starts_at_one: false,
                        aggregated: false,
                        buyer_tag,
                        submitted_by: get_caller_address(),
                    },
                );
            self
                .emit(
                    OneBuyerAttested {
                        id,
                        context,
                        taxpayer_key_hash,
                        issuer_key_hash,
                        year,
                        threshold_cents,
                        invoice_count,
                        buyer_tag,
                        openings: values.slice(7 + BATCH_SIZE, invoice_count),
                    },
                );
            id
        }

        fn get_attestation(self: @ContractState, id: u64) -> Attestation {
            self.attestations.read(id)
        }

        fn attestation_count(self: @ContractState) -> u64 {
            self.attestation_count.read()
        }

        fn owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn batch_verifier(self: @ContractState) -> ClassHash {
            self.batch_verifier.read()
        }

        fn aggregate_verifier(self: @ContractState) -> ClassHash {
            self.aggregate_verifier.read()
        }

        fn one_buyer_verifier(self: @ContractState) -> ClassHash {
            self.one_buyer_verifier.read()
        }

        fn aggregate_circuits(self: @ContractState) -> (u256, u256, u256) {
            (self.leaf_vk_hash.read(), self.node_vk_hash.read(), self.sorted_vk_hash.read())
        }
    }
}
