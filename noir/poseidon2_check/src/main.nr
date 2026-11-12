// poseidon2_check: Poseidon2 over the first `n` of ten field elements, exactly as the circuits call
// it. Executed only, by tools/efi/test_poseidon2.py, to check that the Python implementation the
// tools use (tools/efi/poseidon2.py) gives the same values as a circuit.

use poseidon::poseidon2::Poseidon2;

fn main(values: [Field; 10], n: u32) -> pub Field {
    Poseidon2::hash(values, n)
}
