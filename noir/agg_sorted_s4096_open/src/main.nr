// agg_sorted_s4096_open: the sorted list's product and hash IN THE CLEAR, for the prover's own use.
// Executed only, never proved and never shared.

use pf_efi::agg::check_sorted;

fn main(sorted: [Field; 4096], n: u32, gamma: Field) -> pub (Field, Field) {
    check_sorted(sorted, n, gamma)
}
