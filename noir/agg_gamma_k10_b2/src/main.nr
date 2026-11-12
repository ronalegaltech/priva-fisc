// agg_gamma_k10_b2 - the multiset challenge for 2 leaves of 10, computed from the receipt codes.
// Executed only, by the prover, before the leaves are proved.

use pf_efi::agg::gamma_for_codes;

fn main(fics: [[Field; 10]; 2], sorted: [Field; 20]) -> pub Field {
    gamma_for_codes(fics, sorted)
}
