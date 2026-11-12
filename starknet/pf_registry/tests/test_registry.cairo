//! Registry tests against a real proof of the 10-invoice batch circuit (synthetic invoices).
//! Regenerate the fixture with tools/starknet/refresh_fixture.sh after any circuit change.

use pf_batch_k10_verifier::honk_verifier::{
    IUltraKeccakZKHonkVerifierDispatcherTrait, IUltraKeccakZKHonkVerifierLibraryDispatcher,
};
use pf_registry::{
    Attestation, IPrivaFiscRegistryDispatcher, IPrivaFiscRegistryDispatcherTrait,
};
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

fn proof() -> Span<felt252> {
    read_txt(@FileTrait::new("tests/proof_calldata.txt")).span()
}

fn setup() -> (IPrivaFiscRegistryDispatcher, ClassHash) {
    declare("UniversalECIP").unwrap();
    let verifier_class = *declare("UltraKeccakZKHonkVerifier").unwrap().contract_class().class_hash;
    let registry_class = declare("PrivaFiscRegistry").unwrap().contract_class();
    let mut ctor: Array<felt252> = array![];
    owner().serialize(ref ctor);
    verifier_class.serialize(ref ctor);
    let (address, _) = registry_class.deploy(@ctor).unwrap();
    (IPrivaFiscRegistryDispatcher { contract_address: address }, verifier_class)
}

/// Public values of the fixture, read through the verifier itself.
fn fixture_values(verifier_class: ClassHash) -> Span<u256> {
    IUltraKeccakZKHonkVerifierLibraryDispatcher { class_hash: verifier_class }
        .verify_ultra_keccak_zk_honk_proof(proof())
        .unwrap()
}

fn list_issuer_key(registry: IPrivaFiscRegistryDispatcher, key_hash: u256) {
    start_cheat_caller_address(registry.contract_address, owner());
    registry.set_issuer_key(key_hash, true);
    stop_cheat_caller_address(registry.contract_address);
}

#[test]
fn test_attest_records_what_was_proved() {
    let (registry, verifier_class) = setup();
    let values = fixture_values(verifier_class);
    assert(values.len() == 26, 'fixture: 26 public values');
    list_issuer_key(registry, *values.at(4));

    start_cheat_caller_address(registry.contract_address, submitter());
    let id = registry.attest_batch(proof());
    stop_cheat_caller_address(registry.contract_address);

    assert(id == 1, 'first attestation id');
    assert(registry.attestation_count() == 1, 'count');
    let a: Attestation = registry.get_attestation(1);
    assert(a.invoice_count == 10, 'invoice count');
    assert(a.year == 2026, 'year');
    assert(a.context == *values.at(1), 'context');
    assert(a.taxpayer_key_hash == *values.at(3), 'taxpayer key');
    assert(a.issuer_key_hash == *values.at(4), 'issuer key');
    assert(a.starts_at_one, 'starts at one');
    assert(a.submitted_by == submitter(), 'submitter');
    let mut i: u32 = 0;
    while i != 10 {
        assert(registry.is_nullifier_used(*values.at(6 + i)), 'nullifier recorded');
        i += 1;
    }
}

#[test]
#[should_panic(expected: 'invoice already presented')]
fn test_same_invoices_cannot_be_presented_twice() {
    let (registry, verifier_class) = setup();
    list_issuer_key(registry, *fixture_values(verifier_class).at(4));
    registry.attest_batch(proof());
    registry.attest_batch(proof());
}

#[test]
#[should_panic(expected: 'issuer key not registered')]
fn test_unlisted_issuer_key_is_refused() {
    let (registry, _) = setup();
    registry.attest_batch(proof());
}

#[test]
#[should_panic(expected: 'issuer key not registered')]
fn test_delisted_issuer_key_is_refused() {
    let (registry, verifier_class) = setup();
    let key = *fixture_values(verifier_class).at(4);
    list_issuer_key(registry, key);
    start_cheat_caller_address(registry.contract_address, owner());
    registry.set_issuer_key(key, false);
    stop_cheat_caller_address(registry.contract_address);
    registry.attest_batch(proof());
}

#[test]
#[should_panic(expected: 'only owner')]
fn test_only_owner_lists_keys() {
    let (registry, _) = setup();
    start_cheat_caller_address(registry.contract_address, submitter());
    registry.set_issuer_key(1, true);
}

#[test]
#[should_panic]
fn test_altered_proof_is_refused() {
    let (registry, verifier_class) = setup();
    list_issuer_key(registry, *fixture_values(verifier_class).at(4));
    // Change one public value inside the calldata (the threshold) and leave the proof as is.
    let original = proof();
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
    registry.attest_batch(altered.span());
}
