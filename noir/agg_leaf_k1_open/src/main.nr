// agg_leaf_k1_open - the leaf's summary IN THE CLEAR, for the prover's own use.
//
// Executed only (`nargo execute`), never proved and never shared: its output is the private input
// the root needs for this leaf. Same checks as agg_leaf_k1.

use pf_efi::agg::leaf_summary_in_clear;

global K: u32 = 1;
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
    context: Field,
    year: u32,
    gamma: Field,
) -> pub [Field; 10] {
    leaf_summary_in_clear(
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
        gamma,
    )
}
