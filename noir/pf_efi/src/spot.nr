// Spot check against an aggregated proof, without showing the path.
//
// An aggregated proof publishes one root over the opening commitments of all its invoices. The
// tree under that root carries, at every node, the sum of the positive totals below it (agg.nr).
// This circuit shows that one opening commitment sits in that tree and says where:
//   * whether it is the first invoice, and whether it is the last;
//   * whether it covers the verifier's point. The verifier draws a number r; the point is the
//     fraction r / 2^64 of the sum of all positive totals; an invoice covers it if the point lies
//     between the sum of the positive totals before the invoice and that sum plus its own total.
//
// A verifier who draws points this way opens invoices with probability proportional to their
// amount, as auditors do when they sample by monetary unit: an invoice that carries a large part
// of the total is very likely to be asked for, however many small invoices surround it.
//
// The sibling hashes and sums, the other commitments of the leaf and the total itself stay
// private. The verifier learns the three answers and what the opened invoice itself reveals.

use crate::agg::{openings_join, openings_leaf, openings_root};

/// Longest path this circuit follows: 2^12 leaves.
pub global MAX_DEPTH: u32 = 12;

/// Returns (covers the point, is the first invoice, is the last invoice).
///
/// Private: the leaf (`openings`, `plus`, `slot`) and the path from it to the root; a level that is
/// not `used` is skipped, `node_is_left` says on which side of its sibling the path's node sits.
/// Public: `root` as published by the aggregated proof, the opened invoice's `commitment` and
/// positive total `amount` in cents (zero for a negative total), and the verifier's draw `r`.
pub fn locate<let K: u32>(
    openings: [Field; K],
    plus: [Field; K],
    slot: u32,
    used: [bool; MAX_DEPTH],
    node_is_left: [bool; MAX_DEPTH],
    sibling: [Field; MAX_DEPTH],
    sibling_sum: [Field; MAX_DEPTH],
    root: Field,
    commitment: Field,
    amount: u64,
    r: u64,
) -> (bool, bool, bool) {
    assert(slot < K, "spot: no such slot");
    assert(commitment != 0, "spot: an unused slot cannot be opened");

    // Inside the leaf: the opened slot, what comes before it, and whether anything comes after.
    let mut before: Field = 0;
    let mut sum: Field = 0;
    let mut found = false;
    let mut later_used = false;
    for j in 0..K {
        if j == slot {
            assert(openings[j] == commitment, "spot: this is not the commitment in that slot");
            assert(plus[j] == amount as Field, "spot: this is not the amount in that slot");
            found = true;
        } else if j < slot {
            before += plus[j];
        } else {
            later_used |= openings[j] != 0;
        }
        sum += plus[j];
    }
    assert(found);
    let mut is_first = slot == 0;
    let mut is_last = !later_used;

    // Up the tree: whatever hangs to the left comes before this invoice.
    let mut chain = openings_leaf(openings, plus);
    for level in 0..MAX_DEPTH {
        if used[level] {
            if node_is_left[level] {
                chain = openings_join(chain, sum, sibling[level], sibling_sum[level]);
                is_last = false;
            } else {
                chain = openings_join(sibling[level], sibling_sum[level], chain, sum);
                before += sibling_sum[level];
                is_first = false;
            }
            sum += sibling_sum[level];
        }
    }
    assert(openings_root(chain, sum) == root, "spot: the opening is not under this root");

    // The root binds every sum on the path to what the invoice circuits added up: totals below
    // 10^14 cents each, so nothing here comes near the field size.
    sum.assert_max_bit_size::<96>();
    before.assert_max_bit_size::<96>();

    // point = floor(r * sum / 2^64): the high 12 bytes of the 20-byte product.
    let product: [u8; 20] = ((r as Field) * sum).to_le_bytes();
    let mut point: Field = 0;
    for i in 0..12 {
        point = point * 256 + (product[19 - i] as Field);
    }
    let covers = ((before as u128) <= (point as u128)) & ((point as u128) < (before as u128) + (amount as u128));

    (covers, is_first, is_last)
}

// A tree of two leaves of two slots, built with the same functions the invoice circuits use.
//   left leaf : commitments 11, 12 with totals 300, 100      right leaf: commitment 13 with total 600
// The sum of positive totals is 1000, so the draw r stands for the point floor(r * 1000 / 2^64).
fn test_tree() -> (Field, Field, Field) {
    let left = openings_leaf([11, 12], [300, 100]);
    let right = openings_leaf([13, 0], [600, 0]);
    (left, right, openings_root(openings_join(left, 400, right, 600), 1000))
}

fn path(node_is_left: bool, sibling: Field, sibling_sum: Field) -> ([bool; 12], [bool; 12], [Field; 12], [Field; 12]) {
    let mut used = [false; 12];
    let mut side = [false; 12];
    let mut hashes = [0; 12];
    let mut sums = [0; 12];
    used[0] = true;
    side[0] = node_is_left;
    hashes[0] = sibling;
    sums[0] = sibling_sum;
    (used, side, hashes, sums)
}

// Draws for chosen points of a total of 1000: r = ceil(point * 2^64 / 1000).
global R_POINT_0: u64 = 0;
global R_POINT_299: u64 = 5515576478039155934;
global R_POINT_300: u64 = 5534023222112865485;
global R_POINT_399: u64 = 7360250885410111095;
global R_POINT_400: u64 = 7378697629483820647;
global R_POINT_999: u64 = 18428297329635842065;

#[test]
fn test_first_invoice_covers_the_start() {
    let (_, right, root) = test_tree();
    let (used, side, hashes, sums) = path(true, right, 600);
    let (covers, first, last) = locate([11, 12], [300, 100], 0, used, side, hashes, sums, root, 11, 300, R_POINT_0);
    assert(covers & first & !last);
    let (covers, _, _) = locate([11, 12], [300, 100], 0, used, side, hashes, sums, root, 11, 300, R_POINT_299);
    assert(covers);
    let (covers, _, _) = locate([11, 12], [300, 100], 0, used, side, hashes, sums, root, 11, 300, R_POINT_300);
    assert(!covers);
}

#[test]
fn test_second_invoice_covers_only_its_own_range() {
    let (_, right, root) = test_tree();
    let (used, side, hashes, sums) = path(true, right, 600);
    let (covers, first, last) = locate([11, 12], [300, 100], 1, used, side, hashes, sums, root, 12, 100, R_POINT_300);
    assert(covers & !first & !last);
    let (covers, _, _) = locate([11, 12], [300, 100], 1, used, side, hashes, sums, root, 12, 100, R_POINT_399);
    assert(covers);
    let (covers, _, _) = locate([11, 12], [300, 100], 1, used, side, hashes, sums, root, 12, 100, R_POINT_299);
    assert(!covers);
    let (covers, _, _) = locate([11, 12], [300, 100], 1, used, side, hashes, sums, root, 12, 100, R_POINT_400);
    assert(!covers);
}

#[test]
fn test_last_invoice_in_a_partly_filled_leaf() {
    let (left, _, root) = test_tree();
    let (used, side, hashes, sums) = path(false, left, 400);
    let (covers, first, last) = locate([13, 0], [600, 0], 0, used, side, hashes, sums, root, 13, 600, R_POINT_400);
    assert(covers & !first & last);
    let (covers, _, _) = locate([13, 0], [600, 0], 0, used, side, hashes, sums, root, 13, 600, R_POINT_999);
    assert(covers);
    let (covers, _, _) = locate([13, 0], [600, 0], 0, used, side, hashes, sums, root, 13, 600, R_POINT_399);
    assert(!covers);
}

#[test(should_fail_with = "spot: this is not the amount in that slot")]
fn test_rejects_another_amount() {
    let (_, right, root) = test_tree();
    let (used, side, hashes, sums) = path(true, right, 600);
    let _ = locate([11, 12], [300, 100], 0, used, side, hashes, sums, root, 11, 999, R_POINT_0);
}

#[test(should_fail_with = "spot: the opening is not under this root")]
fn test_rejects_a_smaller_sum_to_the_left() {
    // Claiming less before this invoice would move its range towards the start.
    let (left, _, root) = test_tree();
    let (used, side, hashes, sums) = path(false, left, 100);
    let _ = locate([13, 0], [600, 0], 0, used, side, hashes, sums, root, 13, 600, R_POINT_0);
}

#[test(should_fail_with = "spot: the opening is not under this root")]
fn test_rejects_the_wrong_side() {
    let (left, _, root) = test_tree();
    let (used, side, hashes, sums) = path(true, left, 400);
    let _ = locate([13, 0], [600, 0], 0, used, side, hashes, sums, root, 13, 600, R_POINT_0);
}

#[test(should_fail_with = "spot: an unused slot cannot be opened")]
fn test_rejects_an_unused_slot() {
    let (left, _, root) = test_tree();
    let (used, side, hashes, sums) = path(false, left, 400);
    let _ = locate([13, 0], [600, 0], 1, used, side, hashes, sums, root, 0, 0, R_POINT_0);
}
