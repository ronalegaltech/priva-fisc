// agg_leaf_k10 - aggregation LEAF over 10 invoice(s). Statement and method: ../pf_efi/src/agg.nr.
//
// Public inputs : context, year, gamma
// Public outputs: (taxpayer key hash, authority key hash, blinded summary commitment)
// Proved with `bb prove -t noir-recursive` so that a root circuit can verify it.

use pf_efi::agg::prove_leaf;

global K: u32 = 10;
global M: u32 = 2048;

fn main(
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
    context: pub Field,
    year: pub u32,
    gamma: pub Field,
) -> pub (Field, Field, Field) {
    prove_leaf(
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
        blind,
        context,
        year,
        gamma,
    )
}
