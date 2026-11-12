// agg_chain_k1: Poseidon2 over the 1 slot of one leaf (receipt codes, or opening commitments), as the
// leaf circuit hashes them. Executed only: by the prover to derive the challenge before any leaf
// is proved, and by both sides in a spot check.

use poseidon::poseidon2::Poseidon2;

fn main(values: [Field; 1]) -> pub Field {
    Poseidon2::hash(values, 1)
}
