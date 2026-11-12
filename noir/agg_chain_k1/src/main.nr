// agg_chain_k1: commitment to the receipt codes of one leaf of 1, as the leaf circuit computes it.
// Executed only, by the prover, to derive the challenge before any leaf is proved.

use poseidon::poseidon2::Poseidon2;

fn main(fics: [Field; 1]) -> pub Field {
    Poseidon2::hash(fics, 1)
}
