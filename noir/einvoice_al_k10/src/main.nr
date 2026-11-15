// einvoice_al_k10 - up to 10 open e-invoices that one seller issued to one buyer, read from one
// answer of Albania's e-invoice service in which the tax authority signs their amounts, parties
// and status. The statement, what it does NOT prove and what it rests on (the published
// specification only) are documented in ../pf_efi/src/einvoice.nr.
//
// Public inputs : threshold_cents, context
// Public outputs: (authority key hash, number of e-invoices, buyer tag, seller tag, day of the
//                 answer as YYYYMMDD, nullifier per slot)

use pf_efi::einvoice::prove_open_einvoices;
use pf_efi::format::ALBANIA_EINVOICES;

global K: u32 = 10; // slots
global M: u32 = 8192; // maximum size of the canonical answer in bytes

fn main(
    doc: [u8; M],
    doc_len: u32,
    signature: [u128; 18],
    issuer_modulus: [u128; 18],
    issuer_redc: [u128; 18],
    offsets: [u32; K],
    count: u32,
    buyer: Field,
    seller: Field,
    threshold_cents: pub u64,
    context: pub Field,
) -> pub (Field, u32, Field, Field, u32, [Field; K]) {
    prove_open_einvoices(
        ALBANIA_EINVOICES,
        doc,
        doc_len,
        signature,
        issuer_modulus,
        issuer_redc,
        offsets,
        count,
        buyer,
        seller,
        threshold_cents,
        context,
    )
}
