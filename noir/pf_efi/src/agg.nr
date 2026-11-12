// Aggregation: more invoices than one circuit can hold.
//
// The invoices are cut, in ordinal order, into leaves of K. A LEAF proof checks its K invoices
// (check_invoices) and publishes only a blinded commitment to the summary of that run. A NODE proof
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

// Domain separators: ASCII "PF-RUN0001", "PF-PAIR001", "PF-GAMMA01", "PF-SORTED1", "PF-SCOPE01".
pub global DOMAIN_RUN: Field = 0x50462d52554e30303031;
pub global DOMAIN_PAIR: Field = 0x50462d50414952303031;
pub global DOMAIN_GAMMA: Field = 0x50462d47414d4d413031;
pub global DOMAIN_SORTED: Field = 0x50462d534f5254454431;
pub global DOMAIN_SCOPE: Field = 0x50462d53434f50453031;

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
    pub open_chain: Field, // commitment to the run's opening commitments, in order
}

pub global RUN_FIELDS: u32 = 11;

pub fn run_from_fields(f: [Field; 11]) -> Run {
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
    }
}

pub fn run_to_fields(r: Run) -> [Field; 11] {
    [
        r.count, r.first_ordinal, r.last_ordinal, r.unit, r.device, r.sum_plus, r.sum_minus,
        r.fic_prod, r.fic_chain, r.null_chain, r.open_chain,
    ]
}

pub fn run_commitment(r: Run, blind: Field) -> Field {
    Poseidon2::hash(
        [
            DOMAIN_RUN, r.count, r.first_ordinal, r.last_ordinal, r.unit, r.device, r.sum_plus,
            r.sum_minus, r.fic_prod, r.fic_chain, r.null_chain, r.open_chain, blind,
        ],
        13,
    )
}

/// Hash of an ordered pair, used to join the chains of two runs.
pub fn pair_hash(left: Field, right: Field) -> Field {
    Poseidon2::hash([DOMAIN_PAIR, left, right], 3)
}

/// The run made of K checked invoices.
pub fn leaf_run<let K: u32>(c: BatchCore<K>, gamma: Field) -> Run {
    let mut fic_prod: Field = 1;
    for i in 0..K {
        fic_prod *= gamma - c.fics[i];
    }
    Run {
        count: K as Field,
        first_ordinal: c.first_ordinal as Field,
        last_ordinal: c.last_ordinal as Field,
        unit: c.unit,
        device: c.device,
        sum_plus: c.sum_plus as Field,
        sum_minus: c.sum_minus as Field,
        fic_prod,
        fic_chain: Poseidon2::hash(c.fics, K),
        null_chain: Poseidon2::hash(c.nullifiers, K),
        open_chain: Poseidon2::hash(c.openings, K),
    }
}

/// Joins two adjacent runs. The right run must continue the left one.
pub fn join_runs(left: Run, right: Run) -> Run {
    assert(right.first_ordinal == left.last_ordinal + 1, "join: ordinals are not consecutive across runs");
    assert(right.unit == left.unit, "join: mixed business units");
    assert(right.device == left.device, "join: mixed devices");
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
        open_chain: pair_hash(left.open_chain, right.open_chain),
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
pub fn scope_nullifier(context: Field, taxpayer_key_hash: Field, unit: Field, device: Field, year: Field) -> Field {
    Poseidon2::hash([DOMAIN_SCOPE, context, taxpayer_key_hash, unit, device, year], 6)
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
        context,
        year,
    );
    (c.taxpayer_key_hash, c.issuer_key_hash, run_commitment(leaf_run(c, gamma), blind))
}

/// The same computation as `prove_leaf`, returning the run in the clear. For the PROVER's own use
/// (executed, never proved or shared): the next proof up needs these values as private inputs.
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
    context: Field,
    year: u32,
    gamma: Field,
) -> [Field; 11] {
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
        context,
        year,
    );
    run_to_fields(leaf_run(c, gamma))
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
    let l = run_from_fields([10, 1, 10, 7, 8, 100, 0, 2, 3, 4, 5]);
    let r = run_from_fields([10, 12, 21, 7, 8, 100, 0, 2, 3, 4, 5]);
    let _ = join_runs(l, r);
}

#[test]
fn test_join_adds_up() {
    let l = run_from_fields([10, 1, 10, 7, 8, 100, 5, 2, 3, 4, 5]);
    let r = run_from_fields([10, 11, 20, 7, 8, 40, 1, 3, 6, 7, 8]);
    let j = join_runs(l, r);
    assert(j.count == 20);
    assert(j.first_ordinal == 1);
    assert(j.last_ordinal == 20);
    assert(j.sum_plus == 140);
    assert(j.sum_minus == 6);
    assert(j.fic_prod == 6);
    assert(j.fic_chain == pair_hash(3, 6));
}
