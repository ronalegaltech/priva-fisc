// agg_node: joins two adjacent runs, each proved by a leaf or by another node.
// Statement: ../pf_agg/src/lib.nr.
//
// Public inputs : context, year, gamma, leaf_vk_hash, node_vk_hash
// Public outputs: (taxpayer key hash, authority key hash, blinded commitment of the joined run)
// Proved with `bb prove -t noir-recursive`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof};
use pf_agg::prove_node;

fn main(
    vks: [UltraHonkVerificationKey; 2],
    proofs: [UltraHonkZKProof; 2],
    is_leaf: [bool; 2],
    runs: [[Field; 11]; 2],
    blinds: [Field; 2],
    blind_out: Field,
    taxpayer_key_hash: Field,
    issuer_key_hash: Field,
    context: pub Field,
    year: pub u32,
    gamma: pub Field,
    leaf_vk_hash: pub Field,
    node_vk_hash: pub Field,
) -> pub (Field, Field, Field) {
    prove_node(
        vks,
        proofs,
        is_leaf,
        runs,
        blinds,
        blind_out,
        taxpayer_key_hash,
        issuer_key_hash,
        context,
        year,
        gamma,
        leaf_vk_hash,
        node_vk_hash,
    )
}
