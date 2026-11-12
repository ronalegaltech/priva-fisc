// agg_sorted_s4096: up to 4096 receipt codes, sorted strictly increasing, hence without repeats.
// Statement and method: ../pf_efi/src/agg.nr.
//
// Public input : gamma
// Public output: blinded commitment to (number of codes, product of (gamma - code), list hash)
// Proved with `bb prove -t noir-recursive`.

use pf_efi::agg::{check_sorted, sorted_commitment};

fn main(sorted: [Field; 4096], n: u32, blind: Field, gamma: pub Field) -> pub Field {
    let (prod, chain) = check_sorted(sorted, n, gamma);
    sorted_commitment(n as Field, prod, chain, blind)
}
