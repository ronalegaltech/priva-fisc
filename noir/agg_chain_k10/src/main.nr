// agg_chain_k10: commitment to the receipt codes of one leaf of 10, as the leaf circuit computes it.
// Executed only, by the prover, to derive the challenge before any leaf is proved.

use poseidon::poseidon2::Poseidon2;

fn main(fics: [Field; 10]) -> pub Field {
    Poseidon2::hash(fics, 10)
}
