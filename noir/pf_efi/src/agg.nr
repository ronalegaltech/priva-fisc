// Aggregation: more invoices than one circuit can hold.
//
// The invoices are cut, in ordinal order, into leaves of up to K. A LEAF proof checks its invoices
// (check_invoices; a leaf may be partly filled, see batch.nr) and publishes only a blinded
// commitment to the summary of that run. A NODE proof
// (../pf_agg) verifies two proofs of adjacent runs, each a leaf or another node, and publishes the
// commitment of the joined run. A TOP proof verifies the proof of the whole run and one proof about
// the sorted list of receipt codes, and states the result.
//
// What only shows across runs is checked when runs are joined: the right run starts at the ordinal
// after the left run ends, and unit and device are the same.
//
// "No receipt is used twice", without any proof revealing a receipt code: the prover also commits
// to the list S of all receipt codes sorted strictly increasing (so S has no repeats). The top
// circuit checks that S and the codes inside the leaves are the same multiset by comparing
//       prod over all invoices of (gamma - fic)   with   prod over S of (gamma - s)
// at a challenge gamma. The prover cannot choose gamma: it is the hash of commitments to both lists
// (the run's fic_chain and the hash of S), recomputed by the top circuit.

use crate::batch::{BatchCore, check_invoices};
use poseidon::poseidon2::Poseidon2;

// Domain separators: ASCII "PF-RUN0001", "PF-PAIR001", "PF-GAMMA01", "PF-SORTED1", "PF-SCOPE01",
// "PF-CODES01", "PF-SUMLEAF", "PF-SUMPAIR", "PF-SUMROOT".
pub global DOMAIN_RUN: Field = 0x50462d52554e30303031;
pub global DOMAIN_PAIR: Field = 0x50462d50414952303031;
pub global DOMAIN_GAMMA: Field = 0x50462d47414d4d413031;
pub global DOMAIN_SORTED: Field = 0x50462d534f5254454431;
pub global DOMAIN_SCOPE: Field = 0x50462d53434f50453031;
pub global DOMAIN_CODES: Field = 0x50462d434f4445533031;
pub global DOMAIN_SUM_LEAF: Field = 0x50462d53554d4c454146;
pub global DOMAIN_SUM_PAIR: Field = 0x50462d53554d50414952;
pub global DOMAIN_SUM_ROOT: Field = 0x50462d53554d524f4f54;

/// Summary of a run of consecutive invoices (one leaf, or several leaves joined). Kept private
/// inside `run_commitment`.
pub struct Run {
    pub count: Field,
    pub first_ordinal: Field,
    pub last_ordinal: Field,
    pub unit: Field,
    pub device: Field,
    pub sum_plus: Field,
    pub sum_minus: Field,
    pub fic_prod: Field, // prod (gamma - fic) over the run
    pub fic_chain: Field, // commitment to the run's receipt codes, in order
    pub null_chain: Field, // commitment to the run's nullifiers, in order
    pub open_chain: Field, // the run's opening commitments and positive totals (see spot.nr)
    pub scope: Field, // scope nullifier of the presentation this run belongs to
}

pub global RUN_FIELDS: u32 = 12;

pub fn run_from_fields(f: [Field; 12]) -> Run {
    Run {
        count: f[0],
        first_ordinal: f[1],
        last_ordinal: f[2],
        unit: f[3],
        device: f[4],
        sum_plus: f[5],
        sum_minus: f[6],
        fic_prod: f[7],
        fic_chain: f[8],
        null_chain: f[9],
        open_chain: f[10],
        scope: f[11],
    }
}

pub fn run_to_fields(r: Run) -> [Field; 12] {
    [
        r.count, r.first_ordinal, r.last_ordinal, r.unit, r.device, r.sum_plus, r.sum_minus,
        r.fic_prod, r.fic_chain, r.null_chain, r.open_chain, r.scope,
    ]
}

pub fn run_commitment(r: Run, blind: Field) -> Field {
    Poseidon2::hash(
        [
            DOMAIN_RUN, r.count, r.first_ordinal, r.last_ordinal, r.unit, r.device, r.sum_plus,
            r.sum_minus, r.fic_prod, r.fic_chain, r.null_chain, r.open_chain, r.scope, blind,
        ],
        14,
    )
}

/// Hash of an ordered pair, used to join the chains of two runs.
pub fn pair_hash(left: Field, right: Field) -> Field {
    Poseidon2::hash([DOMAIN_PAIR, left, right], 3)
}

/// Commitment to the receipt codes of one leaf: how many there are, and the K slots (zero from
/// `count` on).
pub fn codes_commitment<let K: u32>(count: Field, fics: [Field; K]) -> Field {
    Poseidon2::hash([DOMAIN_CODES, count, Poseidon2::hash(fics, K)], 3)
}

// The opening commitments are kept in a tree that also carries amounts, so that a spot check can
// ask for "the invoice that covers this point of the total" (spot.nr). A leaf commits to its
// opening commitments and to its positive totals; a node commits to both children and to the sum
// of positive totals under each; the root adds the grand sum.

/// Commitment to one leaf's opening commitments and positive totals (both zero in unused slots).
pub fn openings_leaf<let K: u32>(openings: [Field; K], plus: [Field; K]) -> Field {
    Poseidon2::hash([DOMAIN_SUM_LEAF, Poseidon2::hash(openings, K), Poseidon2::hash(plus, K)], 3)
}

/// Commitment to two adjacent subtrees and the sum of positive totals under each.
pub fn openings_join(left: Field, left_sum: Field, right: Field, right_sum: Field) -> Field {
    Poseidon2::hash([DOMAIN_SUM_PAIR, left, left_sum, right, right_sum], 5)
}

/// What an aggregated proof publishes: the whole tree and the sum of all positive totals.
pub fn openings_root(chain: Field, sum_plus: Field) -> Field {
    Poseidon2::hash([DOMAIN_SUM_ROOT, chain, sum_plus], 3)
}

/// The run made of the checked invoices of one leaf.
pub fn leaf_run<let K: u32>(c: BatchCore<K>, gamma: Field, context: Field, year: u32) -> Run {
    let mut fic_prod: Field = 1;
    for i in 0..K {
        if i < c.count {
            fic_prod *= gamma - c.fics[i];
        }
    }
    Run {
        count: c.count as Field,
        first_ordinal: c.first_ordinal as Field,
        last_ordinal: c.last_ordinal as Field,
        unit: c.unit,
        device: c.device,
        sum_plus: c.sum_plus as Field,
        sum_minus: c.sum_minus as Field,
        fic_prod,
        fic_chain: codes_commitment(c.count as Field, c.fics),
        null_chain: Poseidon2::hash(c.nullifiers, K),
        open_chain: openings_leaf(c.openings, c.plus),
        scope: scope_nullifier(context, c.taxpayer_key_tag, c.unit, c.device, year as Field),
    }
}

/// Joins two adjacent runs. The right run must continue the left one.
pub fn join_runs(left: Run, right: Run) -> Run {
    assert(right.first_ordinal == left.last_ordinal + 1, "join: ordinals are not consecutive across runs");
    assert(right.unit == left.unit, "join: mixed business units");
    assert(right.device == left.device, "join: mixed devices");
    assert(right.scope == left.scope, "join: runs of different presentations");
    Run {
        count: left.count + right.count,
        first_ordinal: left.first_ordinal,
        last_ordinal: right.last_ordinal,
        unit: left.unit,
        device: left.device,
        sum_plus: left.sum_plus + right.sum_plus,
        sum_minus: left.sum_minus + right.sum_minus,
        fic_prod: left.fic_prod * right.fic_prod,
        fic_chain: pair_hash(left.fic_chain, right.fic_chain),
        null_chain: pair_hash(left.null_chain, right.null_chain),
        open_chain: openings_join(left.open_chain, left.sum_plus, right.open_chain, right.sum_plus),
        scope: left.scope,
    }
}

/// Challenge for the multiset check.
pub fn gamma_from(fic_chain: Field, sorted_chain: Field) -> Field {
    Poseidon2::hash([DOMAIN_GAMMA, fic_chain, sorted_chain], 3)
}

/// What the sorted-list proof publishes: how many codes, their product at gamma, their commitment.
pub fn sorted_commitment(count: Field, prod: Field, chain: Field, blind: Field) -> Field {
    Poseidon2::hash([DOMAIN_SORTED, count, prod, chain, blind], 5)
}

/// Checks a list of receipt codes sorted strictly increasing (the first `n` entries; the rest must
/// be zero) and returns (product of (gamma - s), commitment to the list).
pub fn check_sorted<let S: u32>(sorted: [Field; S], n: u32, gamma: Field) -> (Field, Field) {
    assert(n <= S, "sorted: more codes than this circuit holds");
    let mut prod: Field = 1;
    let mut in_order = true;
    for j in 0..S {
        sorted[j].assert_max_bit_size::<128>();
        if j < n {
            prod *= gamma - sorted[j];
            if j > 0 {
                in_order &= (sorted[j - 1] as u128) < (sorted[j] as u128);
            }
        } else {
            assert(sorted[j] == 0, "sorted: unused entries must be zero");
        }
    }
    assert(in_order, "sorted: a receipt is used twice (list is not strictly increasing)");
    (prod, pair_hash(n as Field, Poseidon2::hash(sorted, S)))
}

/// One nullifier for the whole presentation: this taxpayer, unit, device and year, in this context.
/// The taxpayer enters through the key tag, which is not published: unit and device codes are
/// printed on every invoice, so with the published key hash here any customer could recompute the
/// value and learn which business an attestation belongs to. Unit and device are the taxpayer's
/// word (see batch.nr); a spot check confirms them.
pub fn scope_nullifier(context: Field, taxpayer_key_tag: Field, unit: Field, device: Field, year: Field) -> Field {
    Poseidon2::hash([DOMAIN_SCOPE, context, taxpayer_key_tag, unit, device, year], 6)
}

/// Leaf statement. Public: context, year, gamma, and the key hashes of the leaf and node circuits
/// (carried along so that every proof in a tree has the same public layout; a leaf does not
/// constrain them). Returns (taxpayer key hash, authority key hash, blinded run commitment).
pub fn prove_leaf<let K: u32, let M: u32>(
    request_docs: [[u8; M]; K],
    request_lens: [u32; K],
    request_sigs: [[u128; 18]; K],
    resp_request_uuids: [[u8; 36]; K],
    resp_send_dts: [[u8; 25]; K],
    resp_uuids: [[u8; 36]; K],
    resp_fics: [[u8; 36]; K],
    resp_sigs: [[u128; 18]; K],
    taxpayer_modulus: [u128; 18],
    taxpayer_redc: [u128; 18],
    issuer_modulus: [u128; 18],
    issuer_redc: [u128; 18],
    salts: [Field; K],
    count: u32,
    blind: Field,
    context: Field,
    year: u32,
    gamma: Field,
) -> (Field, Field, Field) {
    let c = check_invoices(
        request_docs,
        request_lens,
        request_sigs,
        resp_request_uuids,
        resp_send_dts,
        resp_uuids,
        resp_fics,
        resp_sigs,
        taxpayer_modulus,
        taxpayer_redc,
        issuer_modulus,
        issuer_redc,
        salts,
        count,
        context,
        year,
    );
    (c.taxpayer_key_hash, c.issuer_key_hash, run_commitment(leaf_run(c, gamma, context, year), blind))
}

/// The same computation as `prove_leaf`, returning the run and the leaf's opening commitments in
/// the clear. For the PROVER's own use (executed, never proved or shared): the next proof up needs
/// the run as private input, and a later spot check needs the opening commitments.
pub fn leaf_run_in_clear<let K: u32, let M: u32>(
    request_docs: [[u8; M]; K],
    request_lens: [u32; K],
    request_sigs: [[u128; 18]; K],
    resp_request_uuids: [[u8; 36]; K],
    resp_send_dts: [[u8; 25]; K],
    resp_uuids: [[u8; 36]; K],
    resp_fics: [[u8; 36]; K],
    resp_sigs: [[u128; 18]; K],
    taxpayer_modulus: [u128; 18],
    taxpayer_redc: [u128; 18],
    issuer_modulus: [u128; 18],
    issuer_redc: [u128; 18],
    salts: [Field; K],
    count: u32,
    context: Field,
    year: u32,
    gamma: Field,
) -> ([Field; 12], [Field; K]) {
    let c = check_invoices(
        request_docs,
        request_lens,
        request_sigs,
        resp_request_uuids,
        resp_send_dts,
        resp_uuids,
        resp_fics,
        resp_sigs,
        taxpayer_modulus,
        taxpayer_redc,
        issuer_modulus,
        issuer_redc,
        salts,
        count,
        context,
        year,
    );
    (run_to_fields(leaf_run(c, gamma, context, year)), c.openings)
}

#[test]
fn test_partly_filled_leaf_counts_only_its_invoices() {
    let gamma = 0x1234567;
    let c: BatchCore<3> = BatchCore {
        count: 2,
        taxpayer_key_hash: 1,
        taxpayer_key_tag: 3,
        issuer_key_hash: 2,
        first_ordinal: 4,
        last_ordinal: 5,
        unit: 7,
        device: 8,
        sum_plus: 300,
        sum_minus: 0,
        fics: [3, 5, 0],
        nullifiers: [11, 12, 0],
        openings: [21, 22, 0],
        plus: [100, 200, 0],
    };
    let r = leaf_run(c, gamma, 99, 2026);
    assert(r.count == 2);
    assert(r.scope == scope_nullifier(99, 3, 7, 8, 2026));
    assert(r.last_ordinal == 5);
    assert(r.fic_prod == (gamma - 3) * (gamma - 5));
    // The same two codes in a full leaf of two give another commitment only through the slots.
    assert(r.fic_chain == codes_commitment(2, [3, 5, 0]));
    assert(r.fic_chain != codes_commitment(3, [3, 5, 0]));
}

#[test]
fn test_multiset_products_agree_only_for_same_codes() {
    let gamma = 0x1234567;
    let a: [Field; 4] = [7, 3, 9, 5];
    let (sorted_prod, _) = check_sorted([3, 5, 7, 9, 0, 0], 4, gamma);
    let (other_prod, _) = check_sorted([3, 5, 7, 8, 0, 0], 4, gamma);
    let mut pa = 1;
    for i in 0..4 {
        pa *= gamma - a[i];
    }
    assert(pa == sorted_prod);
    assert(pa != other_prod);
}

#[test(should_fail_with = "sorted: a receipt is used twice")]
fn test_sorted_list_rejects_repeats() {
    let _ = check_sorted([3, 5, 5, 9], 4, 1);
}

#[test(should_fail_with = "sorted: unused entries must be zero")]
fn test_sorted_list_rejects_hidden_tail() {
    let _ = check_sorted([3, 5, 7, 9], 3, 1);
}

#[test(should_fail_with = "join: ordinals are not consecutive across runs")]
fn test_join_rejects_gap() {
    let l = run_from_fields([10, 1, 10, 7, 8, 100, 0, 2, 3, 4, 5, 9]);
    let r = run_from_fields([10, 12, 21, 7, 8, 100, 0, 2, 3, 4, 5, 9]);
    let _ = join_runs(l, r);
}

#[test]
fn test_join_adds_up() {
    let l = run_from_fields([10, 1, 10, 7, 8, 100, 5, 2, 3, 4, 5, 9]);
    let r = run_from_fields([10, 11, 20, 7, 8, 40, 1, 3, 6, 7, 8, 9]);
    let j = join_runs(l, r);
    assert(j.count == 20);
    assert(j.first_ordinal == 1);
    assert(j.last_ordinal == 20);
    assert(j.sum_plus == 140);
    assert(j.sum_minus == 6);
    assert(j.fic_prod == 6);
    assert(j.fic_chain == pair_hash(3, 6));
}

#[test(should_fail_with = "join: runs of different presentations")]
fn test_join_rejects_other_scope() {
    let l = run_from_fields([10, 1, 10, 7, 8, 100, 0, 2, 3, 4, 5, 9]);
    let r = run_from_fields([10, 11, 20, 7, 8, 100, 0, 2, 3, 4, 5, 10]);
    let _ = join_runs(l, r);
}
