// pf_agg - the ROOT over B leaf proofs (see ../pf_efi/src/agg.nr for the leaf and the method).
//
// Proved by the root, for N = B*K invoices of one taxpayer key and one authority key:
//   * each of the B leaf proofs verifies under the leaf circuit whose key hash is the public
//     `leaf_vk_hash`, with the same context, year, challenge and key hashes;
//   * leaf b+1 starts at the ordinal right after leaf b ends; same unit and device in all leaves;
//   * no receipt is used twice anywhere in the N invoices;
//   * the grand total (negative totals subtract) >= public `threshold_cents`.
// Published: taxpayer key hash, authority key hash, whether the run starts at ordinal 1, a root of
// the leaves' nullifier chains, a root of their opening-commitment chains, and one scope nullifier.
//
// A verifier MUST compare `leaf_vk_hash` with the key hash of the leaf circuit it trusts: the root
// only says "proofs of the circuit with THIS key hash verified".
// What is not proved is the same as for a single batch (see ../pf_efi/src/batch.nr).
//
// Note for testing: the inner proofs are checked when the root is PROVED, not when its witness is
// generated. A root test that only executes the circuit proves nothing about the leaves.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use pf_efi::agg::{LeafSummary, gamma_from, leaf_commitment, scope_nullifier};
use poseidon::poseidon2::Poseidon2;

pub fn prove_root<let B: u32, let N: u32>(
    leaf_vk: UltraHonkVerificationKey,
    leaf_proofs: [UltraHonkZKProof; B],
    summaries: [[Field; 10]; B],
    blinds: [Field; B],
    sorted_fics: [Field; N],
    taxpayer_key_hash: Field,
    issuer_key_hash: Field,
    threshold_cents: u64,
    context: Field,
    year: u32,
    leaf_vk_hash: Field,
) -> (Field, Field, bool, Field, Field, Field) {
    // 1. The sorted list: 128-bit values, strictly increasing, hence without repeats.
    let mut sorted_prod_inputs_ok = true;
    for j in 0..N {
        sorted_fics[j].assert_max_bit_size::<128>();
        if j > 0 {
            sorted_prod_inputs_ok &= (sorted_fics[j - 1] as u128) < (sorted_fics[j] as u128);
        }
    }
    assert(sorted_prod_inputs_ok, "root: a receipt is used twice (sorted list is not strictly increasing)");

    // 2. The challenge is fixed by commitments to both lists.
    let mut fic_chains: [Field; B] = [0; B];
    for b in 0..B {
        fic_chains[b] = summaries[b][7];
    }
    let gamma = gamma_from(fic_chains, Poseidon2::hash(sorted_fics, N));

    // 3. Each leaf: its proof verifies for exactly this summary; continuity across leaves.
    let mut leaf_prod: Field = 1;
    let mut sum_plus: u128 = 0;
    let mut sum_minus: u128 = 0;
    let mut null_chains: [Field; B] = [0; B];
    let mut open_chains: [Field; B] = [0; B];
    for b in 0..B {
        let s = LeafSummary {
            first_ordinal: summaries[b][0],
            last_ordinal: summaries[b][1],
            unit: summaries[b][2],
            device: summaries[b][3],
            sum_plus: summaries[b][4],
            sum_minus: summaries[b][5],
            fic_prod: summaries[b][6],
            fic_chain: summaries[b][7],
            null_chain: summaries[b][8],
            open_chain: summaries[b][9],
        };
        let commitment = leaf_commitment(s, blinds[b]);
        verify_honk_proof(
            leaf_vk,
            leaf_proofs[b],
            [context, year as Field, gamma, taxpayer_key_hash, issuer_key_hash, commitment],
            leaf_vk_hash,
        );

        if b > 0 {
            assert(s.first_ordinal == summaries[b - 1][1] + 1, "root: ordinals are not consecutive across leaves");
            assert(s.unit == summaries[0][2], "root: mixed business units");
            assert(s.device == summaries[0][3], "root: mixed devices");
        }
        s.sum_plus.assert_max_bit_size::<64>();
        s.sum_minus.assert_max_bit_size::<64>();
        sum_plus += s.sum_plus as u128;
        sum_minus += s.sum_minus as u128;
        leaf_prod *= s.fic_prod;
        null_chains[b] = s.null_chain;
        open_chains[b] = s.open_chain;
    }

    // 4. Same multiset of receipt codes on both sides.
    let mut sorted_prod: Field = 1;
    for j in 0..N {
        sorted_prod *= gamma - sorted_fics[j];
    }
    assert(leaf_prod == sorted_prod, "root: sorted list does not match the receipts in the leaves");

    // 5. Threshold on the grand total.
    assert(sum_plus >= sum_minus + (threshold_cents as u128), "root: total is below the threshold");

    (
        taxpayer_key_hash,
        issuer_key_hash,
        summaries[0][0] == 1,
        Poseidon2::hash(null_chains, B),
        Poseidon2::hash(open_chains, B),
        scope_nullifier(context, taxpayer_key_hash, summaries[0][2], summaries[0][3], year as Field),
    )
}
