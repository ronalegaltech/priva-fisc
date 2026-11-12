// agg_gamma_k1_b2 - the multiset challenge for 2 leaves of 1, computed from the receipt codes.
// Executed only, by the prover, before the leaves are proved.

use pf_efi::agg::gamma_for_codes;

fn main(fics: [[Field; 1]; 2], sorted: [Field; 2]) -> pub Field {
    gamma_for_codes(fics, sorted)
}
