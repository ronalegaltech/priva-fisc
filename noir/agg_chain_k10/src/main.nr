// agg_chain_k10: Poseidon2 over the 10 slots of one leaf (receipt codes, or opening commitments), as the
// leaf circuit hashes them. Executed only: by the prover to derive the challenge before any leaf
// is proved, and by both sides in a spot check.

use poseidon::poseidon2::Poseidon2;

fn main(values: [Field; 10]) -> pub Field {
    Poseidon2::hash(values, 10)
}
