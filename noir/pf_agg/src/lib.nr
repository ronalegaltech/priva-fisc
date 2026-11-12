// pf_agg: the proofs above the leaves (see ../pf_efi/src/agg.nr for the method).
//
// Every proof about a run of invoices, leaf or node, has the same public layout:
//     [context, year, gamma, leaf_vk_hash, node_vk_hash, taxpayer key hash, authority key hash,
//      run commitment]
// so a node can take either kind as a child. `leaf_vk_hash` and `node_vk_hash` are the key hashes
// of the leaf circuit and of the node circuit itself. A node verifies each child under one of the
// two, and requires the child to carry the same two values, so they are the same all the way up.
// The verifier of the final proof MUST compare them (and `sorted_vk_hash`) with the key hashes of
// the circuits it trusts: a proof only says "proofs of the circuits with THESE key hashes verified".
//
// Note for testing: inner proofs are checked when the outer circuit is PROVED, not when its witness
// is generated. A test that only executes a node or the top shows nothing about what is inside.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use pf_efi::agg::{Run, gamma_from, join_runs, run_commitment, run_from_fields, sorted_commitment};

/// Verifies one proof about a run (a leaf proof or a node proof) and returns the run.
fn verify_run_proof(
    vk: UltraHonkVerificationKey,
    proof: UltraHonkZKProof,
    is_leaf: bool,
    fields: [Field; 12],
    blind: Field,
    context: Field,
    year: u32,
    gamma: Field,
    leaf_vk_hash: Field,
    node_vk_hash: Field,
    taxpayer_key_hash: Field,
    issuer_key_hash: Field,
) -> Run {
    let run = run_from_fields(fields);
    let key_hash = if is_leaf { leaf_vk_hash } else { node_vk_hash };
    verify_honk_proof(
        vk,
        proof,
        [
            context, year as Field, gamma, leaf_vk_hash, node_vk_hash, taxpayer_key_hash,
            issuer_key_hash, run_commitment(run, blind),
        ],
        key_hash,
    );
    run
}

/// NODE: two adjacent runs become one. Returns (taxpayer key hash, authority key hash, commitment
/// of the joined run).
pub fn prove_node(
    vks: [UltraHonkVerificationKey; 2],
    proofs: [UltraHonkZKProof; 2],
    is_leaf: [bool; 2],
    runs: [[Field; 12]; 2],
    blinds: [Field; 2],
    blind_out: Field,
    taxpayer_key_hash: Field,
    issuer_key_hash: Field,
    context: Field,
    year: u32,
    gamma: Field,
    leaf_vk_hash: Field,
    node_vk_hash: Field,
) -> (Field, Field, Field) {
    let left = verify_run_proof(
        vks[0], proofs[0], is_leaf[0], runs[0], blinds[0], context, year, gamma, leaf_vk_hash,
        node_vk_hash, taxpayer_key_hash, issuer_key_hash,
    );
    let right = verify_run_proof(
        vks[1], proofs[1], is_leaf[1], runs[1], blinds[1], context, year, gamma, leaf_vk_hash,
        node_vk_hash, taxpayer_key_hash, issuer_key_hash,
    );
    (taxpayer_key_hash, issuer_key_hash, run_commitment(join_runs(left, right), blind_out))
}

/// TOP: the proof of the whole run and the proof about the sorted receipt codes together give the
/// statement. Returns (taxpayer key hash, authority key hash, starts at ordinal 1, number of
/// invoices, nullifier-chain root, opening-chain root, scope nullifier).
pub fn prove_top(
    run_vk: UltraHonkVerificationKey,
    run_proof: UltraHonkZKProof,
    run_is_leaf: bool,
    run_fields: [Field; 12],
    run_blind: Field,
    sorted_vk: UltraHonkVerificationKey,
    sorted_proof: UltraHonkZKProof,
    sorted_prod: Field,
    sorted_chain: Field,
    sorted_blind: Field,
    taxpayer_key_hash: Field,
    issuer_key_hash: Field,
    threshold_cents: u64,
    context: Field,
    year: u32,
    leaf_vk_hash: Field,
    node_vk_hash: Field,
    sorted_vk_hash: Field,
) -> (Field, Field, bool, u32, Field, Field, Field) {
    // The challenge is fixed by commitments to both lists.
    let gamma = gamma_from(run_fields[8], sorted_chain);

    let run = verify_run_proof(
        run_vk, run_proof, run_is_leaf, run_fields, run_blind, context, year, gamma, leaf_vk_hash,
        node_vk_hash, taxpayer_key_hash, issuer_key_hash,
    );
    // The sorted list holds exactly as many codes as there are invoices.
    verify_honk_proof(
        sorted_vk,
        sorted_proof,
        [gamma, sorted_commitment(run.count, sorted_prod, sorted_chain, sorted_blind)],
        sorted_vk_hash,
    );
    assert(run.fic_prod == sorted_prod, "top: sorted list does not match the receipts in the leaves");

    run.count.assert_max_bit_size::<32>();
    run.sum_plus.assert_max_bit_size::<96>();
    run.sum_minus.assert_max_bit_size::<96>();
    assert(
        (run.sum_plus as u128) >= (run.sum_minus as u128) + (threshold_cents as u128),
        "top: total is below the threshold",
    );

    (
        taxpayer_key_hash,
        issuer_key_hash,
        run.first_ordinal == 1,
        run.count as u32,
        run.null_chain,
        run.open_chain,
        run.scope,
    )
}
