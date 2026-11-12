// agg_hash3: Poseidon2 over three field elements.
// Executed only, by the prover, to join chains (domain "PF-PAIR001") and to derive the challenge
// (domain "PF-GAMMA01") exactly as the circuits do.

use poseidon::poseidon2::Poseidon2;

fn main(a: Field, b: Field, c: Field) -> pub Field {
    Poseidon2::hash([a, b, c], 3)
}
