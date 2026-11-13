// debtor_k1 - one invoice issued to one buyer, each with its authority receipt, as one
// statement. The statement, and what it does NOT prove, are documented in ../pf_efi/src/debtor.nr.
//
// Public inputs : threshold_cents, context, year
// Public outputs: (taxpayer key hash, authority key hash, number of invoices, buyer tag,
//                 nullifier per slot, opening commitment per slot)

use pf_efi::debtor::prove_debtor;

global K: u32 = 1; // slots
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
    count: u32,
    buyer: Field,
    threshold_cents: pub u64,
    context: pub Field,
    year: pub u32,
) -> pub (Field, Field, u32, Field, [Field; K], [Field; K]) {
    prove_debtor(
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
        buyer,
        threshold_cents,
        context,
        year,
    )
}
