// Aggregation: more invoices than one circuit can hold.
//
// The invoices are cut, in ordinal order, into leaves of K. Each LEAF proof checks its K invoices
// (check_invoices) and publishes only a blinded commitment to its summary. A ROOT proof verifies the
// leaf proofs, opens their summaries and checks what only shows across leaves:
//   * leaf b+1 starts at the ordinal after leaf b ends; same unit and device everywhere;
//   * no receipt is used twice ANYWHERE (not just inside one leaf);
//   * the grand total meets the threshold.
//
// "No receipt twice" across leaves, without the root ever seeing a receipt code from inside a proof:
// the prover also hands the root the list S of all receipt codes sorted strictly increasing (so S has
// no repeats), and the root checks that S and the leaves' codes are the same multiset by comparing
//       prod over leaves of prod_i (gamma - fic_i)   with   prod_j (gamma - S_j)
// at a challenge gamma. gamma is not chosen by the prover: it is the hash of commitments to both
// lists (each leaf's fic_chain, and the hash of S), which the root recomputes.

use crate::batch::{BatchCore, check_invoices};
use poseidon::poseidon2::Poseidon2;

// Domain separators: ASCII "PF-LEAF001", "PF-GAMMA01", "PF-SCOPE01".
global DOMAIN_LEAF: Field = 0x50462d4c454146303031;
global DOMAIN_GAMMA: Field = 0x50462d47414d4d413031;
global DOMAIN_SCOPE: Field = 0x50462d53434f50453031;

/// Summary of one leaf, kept private inside `leaf_commitment`.
pub struct LeafSummary {
    pub first_ordinal: Field,
    pub last_ordinal: Field,
    pub unit: Field,
    pub device: Field,
    pub sum_plus: Field,
    pub sum_minus: Field,
    pub fic_prod: Field, // prod_i (gamma - fic_i)
    pub fic_chain: Field, // hash of the leaf's receipt codes, in order
    pub null_chain: Field, // hash of the leaf's nullifiers, in order
    pub open_chain: Field, // hash of the leaf's opening commitments, in order
}

pub fn leaf_commitment(s: LeafSummary, blind: Field) -> Field {
    Poseidon2::hash(
        [
            DOMAIN_LEAF, s.first_ordinal, s.last_ordinal, s.unit, s.device, s.sum_plus, s.sum_minus,
            s.fic_prod, s.fic_chain, s.null_chain, s.open_chain, blind,
        ],
        12,
    )
}

pub fn summarize<let K: u32>(c: BatchCore<K>, gamma: Field) -> LeafSummary {
    let mut fic_prod: Field = 1;
    for i in 0..K {
        fic_prod *= gamma - c.fics[i];
    }
    LeafSummary {
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

/// Challenge for the multiset check: hash of the leaves' receipt-code commitments and of the hash of
/// the sorted list.
pub fn gamma_from<let B: u32>(fic_chains: [Field; B], sorted_hash: Field) -> Field {
    let mut pre: [Field; B + 2] = [0; B + 2];
    pre[0] = DOMAIN_GAMMA;
    for b in 0..B {
        pre[1 + b] = fic_chains[b];
    }
    pre[B + 1] = sorted_hash;
    Poseidon2::hash(pre, B + 2)
}

/// The challenge computed directly from the receipt codes (leaf by leaf, in order) and the sorted
/// list. For the PROVER's own use before any leaf is proved: leaves take gamma as a public input.
pub fn gamma_for_codes<let K: u32, let B: u32, let N: u32>(fics: [[Field; K]; B], sorted: [Field; N]) -> Field {
    let mut chains: [Field; B] = [0; B];
    for b in 0..B {
        chains[b] = Poseidon2::hash(fics[b], K);
    }
    gamma_from(chains, Poseidon2::hash(sorted, N))
}

/// One nullifier for the whole presentation: this taxpayer, unit, device and year, in this context.
pub fn scope_nullifier(context: Field, taxpayer_key_hash: Field, unit: Field, device: Field, year: Field) -> Field {
    Poseidon2::hash([DOMAIN_SCOPE, context, taxpayer_key_hash, unit, device, year], 6)
}

/// Leaf statement. Public: context, year, gamma (inputs); taxpayer key hash, authority key hash and
/// the blinded summary commitment (outputs).
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
    (c.taxpayer_key_hash, c.issuer_key_hash, leaf_commitment(summarize(c, gamma), blind))
}

/// The same computation as `prove_leaf`, returning the summary in the clear. For the PROVER's own
/// use (executed, never proved or shared): the root needs these values as private inputs.
pub fn leaf_summary_in_clear<let K: u32, let M: u32>(
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
) -> [Field; 10] {
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
    let s = summarize(c, gamma);
    [
        s.first_ordinal, s.last_ordinal, s.unit, s.device, s.sum_plus, s.sum_minus, s.fic_prod,
        s.fic_chain, s.null_chain, s.open_chain,
    ]
}

#[test]
fn test_multiset_products_agree_only_for_same_codes() {
    let gamma = 0x1234567;
    let a: [Field; 4] = [7, 3, 9, 5];
    let sorted: [Field; 4] = [3, 5, 7, 9];
    let other: [Field; 4] = [3, 5, 7, 8];
    let mut pa = 1;
    let mut ps = 1;
    let mut po = 1;
    for i in 0..4 {
        pa *= gamma - a[i];
        ps *= gamma - sorted[i];
        po *= gamma - other[i];
    }
    assert(pa == ps);
    assert(pa != po);
}
