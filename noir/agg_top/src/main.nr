// agg_top: the final proof over any number of leaves. Statement: ../pf_agg/src/lib.nr.
//
// Public inputs : threshold_cents, context, year, leaf_vk_hash, node_vk_hash, sorted_vk_hash
// Public outputs: (taxpayer key hash, authority key hash, starts at ordinal 1, number of invoices,
//                 nullifier-chain root, root of the opening tree, scope nullifier)

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof};
use pf_agg::prove_top;

fn main(
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
    threshold_cents: pub u64,
    context: pub Field,
    year: pub u32,
    leaf_vk_hash: pub Field,
    node_vk_hash: pub Field,
    sorted_vk_hash: pub Field,
) -> pub (Field, Field, bool, u32, Field, Field, Field) {
    prove_top(
        run_vk,
        run_proof,
        run_is_leaf,
        run_fields,
        run_blind,
        sorted_vk,
        sorted_proof,
        sorted_prod,
        sorted_chain,
        sorted_blind,
        taxpayer_key_hash,
        issuer_key_hash,
        threshold_cents,
        context,
        year,
        leaf_vk_hash,
        node_vk_hash,
        sorted_vk_hash,
    )
}
