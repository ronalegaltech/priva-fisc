// batch_k1 - 1 invoice, each with its authority receipt, as one statement.
// The statement, and what it does NOT prove, are documented in ../pf_efi/src/batch.nr.
//
// Public inputs : threshold_cents, context, year
// Public outputs: (taxpayer key hash, authority key hash, starts at ordinal 1, nullifier per invoice,
//                 opening commitment per invoice)

use pf_efi::batch::prove_batch;

global K: u32 = 1; // invoices in the batch
global M: u32 = 2048; // maximum canonical request size in bytes

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
    threshold_cents: pub u64,
    context: pub Field,
    year: pub u32,
) -> pub (Field, Field, bool, [Field; K], [Field; K]) {
    prove_batch(
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
        threshold_cents,
        context,
        year,
    )
}
