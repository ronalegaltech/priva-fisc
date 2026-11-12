//! PRIVA-FISC registry - the shared state that a proof alone cannot give.
//!
//! A batch proof (see noir/pf_efi/src/batch.nr) is checked by the Garaga-generated verifier. This
//! contract adds the two things that need a common ledger:
//!   * an issuer-key registry: a proof counts only if the authority key it was checked against is
//!     one the registry owner has listed;
//!   * a nullifier ledger: each invoice in a batch publishes a context-bound nullifier, and a batch
//!     is refused if any of its nullifiers was seen before (the same invoices cannot be presented
//!     twice in the same context).
//!
//! It records WHAT WAS PROVED, never invoice data. What a batch proof does not prove (that the
//! authority saw the invoice content, completeness beyond the batch) is not cured here either.

use starknet::{ClassHash, ContractAddress};

/// Number of invoices in the batch circuit this registry accepts.
pub const BATCH_SIZE: u32 = 10;
/// Public values of the batch circuit, in order: threshold, context, year, taxpayer key hash,
/// issuer key hash, starts-at-one, BATCH_SIZE nullifiers, BATCH_SIZE opening commitments.
pub const PUBLIC_VALUES: u32 = 26;

#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
pub struct Attestation {
    pub context: u256,
    pub taxpayer_key_hash: u256,
    pub issuer_key_hash: u256,
    pub year: u32,
    pub threshold_cents: u64,
    pub invoice_count: u32,
    pub starts_at_one: bool,
    pub submitted_by: ContractAddress,
}

#[starknet::interface]
pub trait IPrivaFiscRegistry<TContractState> {
    /// Owner only. Lists or delists an authority key hash.
    fn set_issuer_key(ref self: TContractState, key_hash: u256, active: bool);
    fn is_issuer_key(self: @TContractState, key_hash: u256) -> bool;
    fn is_nullifier_used(self: @TContractState, nullifier: u256) -> bool;
    /// Verifies a 10-invoice batch proof, checks the issuer key and the nullifiers, records the
    /// attestation and returns its id. Reverts on any failure.
    fn attest_batch(ref self: TContractState, full_proof_with_hints: Span<felt252>) -> u64;
    fn get_attestation(self: @TContractState, id: u64) -> Attestation;
    fn attestation_count(self: @TContractState) -> u64;
    fn owner(self: @TContractState) -> ContractAddress;
    fn verifier_class_hash(self: @TContractState) -> ClassHash;
}

#[starknet::contract]
pub mod PrivaFiscRegistry {
    use pf_batch_k10_verifier::honk_verifier::{
        IUltraKeccakZKHonkVerifierDispatcherTrait, IUltraKeccakZKHonkVerifierLibraryDispatcher,
    };
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ClassHash, ContractAddress, get_caller_address};
    use super::{Attestation, BATCH_SIZE, PUBLIC_VALUES};

    #[storage]
    struct Storage {
        owner: ContractAddress,
        verifier_class_hash: ClassHash,
        issuer_keys: Map<u256, bool>,
        nullifiers: Map<u256, bool>,
        attestations: Map<u64, Attestation>,
        attestation_count: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        IssuerKeySet: IssuerKeySet,
        BatchAttested: BatchAttested,
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

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, verifier_class_hash: ClassHash) {
        self.owner.write(owner);
        self.verifier_class_hash.write(verifier_class_hash);
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

        fn attest_batch(ref self: ContractState, full_proof_with_hints: Span<felt252>) -> u64 {
            // 1. The proof itself.
            let verifier = IUltraKeccakZKHonkVerifierLibraryDispatcher {
                class_hash: self.verifier_class_hash.read(),
            };
            let result = verifier.verify_ultra_keccak_zk_honk_proof(full_proof_with_hints);
            assert(result.is_ok(), 'proof invalid');
            let values = result.unwrap();
            assert(values.len() == PUBLIC_VALUES, 'unexpected public values');

            let threshold_cents: u64 = (*values.at(0)).try_into().expect('threshold out of range');
            let context = *values.at(1);
            let year: u32 = (*values.at(2)).try_into().expect('year out of range');
            let taxpayer_key_hash = *values.at(3);
            let issuer_key_hash = *values.at(4);
            let starts_at_one = *values.at(5) == 1;

            // 2. The authority key must be a listed one.
            assert(self.issuer_keys.read(issuer_key_hash), 'issuer key not registered');

            // 3. No invoice may have been presented before in this context.
            let mut i: u32 = 0;
            while i != BATCH_SIZE {
                let nullifier = *values.at(6 + i);
                assert(!self.nullifiers.read(nullifier), 'invoice already presented');
                self.nullifiers.write(nullifier, true);
                i += 1;
            }

            // 4. Record what was proved.
            let id = self.attestation_count.read() + 1;
            self.attestation_count.write(id);
            self
                .attestations
                .write(
                    id,
                    Attestation {
                        context,
                        taxpayer_key_hash,
                        issuer_key_hash,
                        year,
                        threshold_cents,
                        invoice_count: BATCH_SIZE,
                        starts_at_one,
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

        fn get_attestation(self: @ContractState, id: u64) -> Attestation {
            self.attestations.read(id)
        }

        fn attestation_count(self: @ContractState) -> u64 {
            self.attestation_count.read()
        }

        fn owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn verifier_class_hash(self: @ContractState) -> ClassHash {
            self.verifier_class_hash.read()
        }
    }
}
