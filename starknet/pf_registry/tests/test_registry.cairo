//! Registry tests against real proofs (synthetic invoices): a 10-invoice batch proof and an
//! aggregate proof of 20 invoices (two leaves of 10). Regenerate the fixtures with tools/starknet/refresh_fixture.sh after
//! any circuit change.

use pf_batch_k10_verifier::honk_verifier::{
    IUltraKeccakZKHonkVerifierDispatcherTrait, IUltraKeccakZKHonkVerifierLibraryDispatcher,
};
use pf_registry::{Attestation, IPrivaFiscRegistryDispatcher, IPrivaFiscRegistryDispatcherTrait};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::{ClassHash, ContractAddress};

fn owner() -> ContractAddress {
    0x0a11ce.try_into().unwrap()
}

fn submitter() -> ContractAddress {
    0x0b0b.try_into().unwrap()
}

fn batch_proof() -> Span<felt252> {
    read_txt(@FileTrait::new("tests/proof_calldata.txt")).span()
}

fn aggregate_proof() -> Span<felt252> {
    read_txt(@FileTrait::new("tests/agg_proof_calldata.txt")).span()
}

fn values_of(verifier: ClassHash, proof: Span<felt252>) -> Span<u256> {
    IUltraKeccakZKHonkVerifierLibraryDispatcher { class_hash: verifier }
        .verify_ultra_keccak_zk_honk_proof(proof)
        .unwrap()
}

#[derive(Copy, Drop)]
struct Setup {
    registry: IPrivaFiscRegistryDispatcher,
    batch_values: Span<u256>,
    aggregate_values: Span<u256>,
}

/// Which of the three circuit key hashes the registry is deployed with a wrong value for.
#[derive(Copy, Drop, PartialEq)]
enum Wrong {
    Nothing,
    Leaf,
    Node,
    Sorted,
}

/// Deploys the registry with the circuit key hashes named by the aggregate fixture, except the one
/// selected by `wrong`.
fn setup_with(wrong: Wrong) -> Setup {
    declare("UniversalECIP").unwrap();
    let batch_class = *declare("PfBatchK10Verifier").unwrap().contract_class().class_hash;
    let aggregate_class = *declare("PfAggTopVerifier").unwrap().contract_class().class_hash;
    let batch_values = values_of(batch_class, batch_proof());
    let aggregate_values = values_of(aggregate_class, aggregate_proof());
    let leaf: u256 = if wrong == Wrong::Leaf { 1 } else { *aggregate_values.at(3) };
    let node: u256 = if wrong == Wrong::Node { 1 } else { *aggregate_values.at(4) };
    let sorted: u256 = if wrong == Wrong::Sorted { 1 } else { *aggregate_values.at(5) };

    let registry_class = declare("PrivaFiscRegistry").unwrap().contract_class();
    let mut ctor: Array<felt252> = array![];
    owner().serialize(ref ctor);
    batch_class.serialize(ref ctor);
    aggregate_class.serialize(ref ctor);
    leaf.serialize(ref ctor);
    node.serialize(ref ctor);
    sorted.serialize(ref ctor);
    let (address, _) = registry_class.deploy(@ctor).unwrap();
    Setup { registry: IPrivaFiscRegistryDispatcher { contract_address: address }, batch_values, aggregate_values }
}

fn setup() -> Setup {
    setup_with(Wrong::Nothing)
}

fn list_issuer_key(registry: IPrivaFiscRegistryDispatcher, key_hash: u256) {
    start_cheat_caller_address(registry.contract_address, owner());
    registry.set_issuer_key(key_hash, true);
    stop_cheat_caller_address(registry.contract_address);
}

// --- batch of 10 ---

#[test]
fn test_batch_records_what_was_proved() {
    let s = setup();
    assert(s.batch_values.len() == 26, 'fixture: 26 public values');
    list_issuer_key(s.registry, *s.batch_values.at(4));

    start_cheat_caller_address(s.registry.contract_address, submitter());
    let id = s.registry.attest_batch(batch_proof());
    stop_cheat_caller_address(s.registry.contract_address);

    assert(id == 1, 'first attestation id');
    assert(s.registry.attestation_count() == 1, 'count');
    let a: Attestation = s.registry.get_attestation(1);
    assert(a.invoice_count == 10, 'invoice count');
    assert(!a.aggregated, 'not aggregated');
    assert(a.year == 2026, 'year');
    assert(a.context == *s.batch_values.at(1), 'context');
    assert(a.taxpayer_key_hash == *s.batch_values.at(3), 'taxpayer key');
    assert(a.issuer_key_hash == *s.batch_values.at(4), 'issuer key');
    assert(a.starts_at_one, 'starts at one');
    assert(a.submitted_by == submitter(), 'submitter');
    let mut i: u32 = 0;
    while i != 10 {
        assert(s.registry.is_nullifier_used(*s.batch_values.at(6 + i)), 'nullifier recorded');
        i += 1;
    }
}

#[test]
#[should_panic(expected: 'invoice already presented')]
fn test_batch_cannot_be_presented_twice() {
    let s = setup();
    list_issuer_key(s.registry, *s.batch_values.at(4));
    s.registry.attest_batch(batch_proof());
    s.registry.attest_batch(batch_proof());
}

#[test]
#[should_panic(expected: 'issuer key not registered')]
fn test_batch_with_unlisted_issuer_key_is_refused() {
    let s = setup();
    s.registry.attest_batch(batch_proof());
}

#[test]
#[should_panic(expected: 'issuer key not registered')]
fn test_batch_with_delisted_issuer_key_is_refused() {
    let s = setup();
    let key = *s.batch_values.at(4);
    list_issuer_key(s.registry, key);
    start_cheat_caller_address(s.registry.contract_address, owner());
    s.registry.set_issuer_key(key, false);
    stop_cheat_caller_address(s.registry.contract_address);
    s.registry.attest_batch(batch_proof());
}

#[test]
#[should_panic(expected: 'only owner')]
fn test_only_owner_lists_keys() {
    let s = setup();
    start_cheat_caller_address(s.registry.contract_address, submitter());
    s.registry.set_issuer_key(1, true);
}

#[test]
#[should_panic]
fn test_altered_batch_proof_is_refused() {
    let s = setup();
    list_issuer_key(s.registry, *s.batch_values.at(4));
    // Change one public value inside the calldata (the threshold) and leave the proof as is.
    let original = batch_proof();
    let mut altered: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i != original.len() {
        if i == 1 {
            altered.append(*original.at(i) + 1);
        } else {
            altered.append(*original.at(i));
        }
        i += 1;
    }
    s.registry.attest_batch(altered.span());
}

#[test]
#[should_panic]
fn test_aggregate_proof_is_not_a_batch_proof() {
    let s = setup();
    list_issuer_key(s.registry, *s.aggregate_values.at(7));
    s.registry.attest_batch(aggregate_proof());
}

// --- aggregate ---

#[test]
fn test_aggregate_records_what_was_proved() {
    let s = setup();
    assert(s.aggregate_values.len() == 12, 'fixture: 12 public values');
    list_issuer_key(s.registry, *s.aggregate_values.at(7));

    start_cheat_caller_address(s.registry.contract_address, submitter());
    let id = s.registry.attest_aggregate(aggregate_proof());
    stop_cheat_caller_address(s.registry.contract_address);

    let a: Attestation = s.registry.get_attestation(id);
    assert(a.invoice_count == 20, 'invoice count');
    assert(a.aggregated, 'aggregated');
    assert(a.year == 2026, 'year');
    assert(a.taxpayer_key_hash == *s.aggregate_values.at(6), 'taxpayer key');
    assert(a.issuer_key_hash == *s.aggregate_values.at(7), 'issuer key');
    assert(a.starts_at_one, 'starts at one');
    assert(s.registry.is_nullifier_used(*s.aggregate_values.at(11)), 'scope nullifier recorded');
}

#[test]
#[should_panic(expected: 'invoice already presented')]
fn test_aggregate_cannot_be_presented_twice() {
    let s = setup();
    list_issuer_key(s.registry, *s.aggregate_values.at(7));
    s.registry.attest_aggregate(aggregate_proof());
    s.registry.attest_aggregate(aggregate_proof());
}

#[test]
#[should_panic(expected: 'unknown leaf circuit')]
fn test_aggregate_from_another_leaf_circuit_is_refused() {
    let s = setup_with(Wrong::Leaf);
    list_issuer_key(s.registry, *s.aggregate_values.at(7));
    s.registry.attest_aggregate(aggregate_proof());
}

#[test]
#[should_panic(expected: 'unknown node circuit')]
fn test_aggregate_from_another_node_circuit_is_refused() {
    let s = setup_with(Wrong::Node);
    list_issuer_key(s.registry, *s.aggregate_values.at(7));
    s.registry.attest_aggregate(aggregate_proof());
}

#[test]
#[should_panic(expected: 'unknown sorted circuit')]
fn test_aggregate_from_another_sorted_circuit_is_refused() {
    let s = setup_with(Wrong::Sorted);
    list_issuer_key(s.registry, *s.aggregate_values.at(7));
    s.registry.attest_aggregate(aggregate_proof());
}

#[test]
#[should_panic(expected: 'issuer key not registered')]
fn test_aggregate_with_unlisted_issuer_key_is_refused() {
    let s = setup();
    s.registry.attest_aggregate(aggregate_proof());
}

// --- one kind of proof per context ---
// The two fixtures are made for the same context (see refresh_fixture.sh).

#[test]
fn test_context_remembers_its_kind() {
    let s = setup();
    assert(*s.batch_values.at(1) == *s.aggregate_values.at(1), 'fixtures: same context');
    assert(s.registry.context_kind(*s.batch_values.at(1)) == 0, 'no kind yet');
    list_issuer_key(s.registry, *s.batch_values.at(4));
    s.registry.attest_batch(batch_proof());
    assert(s.registry.context_kind(*s.batch_values.at(1)) == 1, 'holds batches');
}

#[test]
#[should_panic(expected: 'context holds the other kind')]
fn test_aggregate_is_refused_in_a_context_of_batches() {
    let s = setup();
    list_issuer_key(s.registry, *s.batch_values.at(4));
    list_issuer_key(s.registry, *s.aggregate_values.at(7));
    s.registry.attest_batch(batch_proof());
    s.registry.attest_aggregate(aggregate_proof());
}

#[test]
#[should_panic(expected: 'context holds the other kind')]
fn test_batch_is_refused_in_a_context_of_aggregates() {
    let s = setup();
    list_issuer_key(s.registry, *s.batch_values.at(4));
    list_issuer_key(s.registry, *s.aggregate_values.at(7));
    s.registry.attest_aggregate(aggregate_proof());
    s.registry.attest_batch(batch_proof());
}
