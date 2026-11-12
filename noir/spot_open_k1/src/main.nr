// spot_open_k1: where one opened invoice sits under the root of an aggregated proof built from
// leaves of 1 invoice. Statement and method: ../pf_efi/src/spot.nr.
//
// Public inputs : root of the opening tree (as the aggregated proof publishes it), the opened
//                 invoice's commitment and positive total in cents, the verifier's draw r
// Public outputs: (covers the point r stands for, is the first invoice, is the last invoice)
// The leaf and the path to the root are private. Proved with `bb prove -t evm`.

use pf_efi::spot::{locate, MAX_DEPTH};

global K: u32 = 1;

fn main(
    openings: [Field; K],
    plus: [Field; K],
    slot: u32,
    used: [bool; MAX_DEPTH],
    node_is_left: [bool; MAX_DEPTH],
    sibling: [Field; MAX_DEPTH],
    sibling_sum: [Field; MAX_DEPTH],
    root: pub Field,
    commitment: pub Field,
    amount: pub u64,
    r: pub u64,
) -> pub (bool, bool, bool) {
    locate(openings, plus, slot, used, node_is_left, sibling, sibling_sum, root, commitment, amount, r)
}
