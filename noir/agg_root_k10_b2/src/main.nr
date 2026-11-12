// agg_root_k10_b2 - ROOT over 2 leaf proofs of 10 invoice(s) each (20 invoices in one proof).
// Statement: ../pf_agg/src/lib.nr.
//
// Public inputs : threshold_cents, context, year, leaf_vk_hash
// Public outputs: (taxpayer key hash, authority key hash, starts at ordinal 1, nullifier-chain root,
//                 opening-chain root, scope nullifier)

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof};
use pf_agg::prove_root;

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_proofs: [UltraHonkZKProof; 2],
    summaries: [[Field; 10]; 2],
    blinds: [Field; 2],
    sorted_fics: [Field; 20],
    taxpayer_key_hash: Field,
    issuer_key_hash: Field,
    threshold_cents: pub u64,
    context: pub Field,
    year: pub u32,
    leaf_vk_hash: pub Field,
) -> pub (Field, Field, bool, Field, Field, Field) {
    prove_root(
        leaf_vk,
        leaf_proofs,
        summaries,
        blinds,
        sorted_fics,
        taxpayer_key_hash,
        issuer_key_hash,
        threshold_cents,
        context,
        year,
        leaf_vk_hash,
    )
}
