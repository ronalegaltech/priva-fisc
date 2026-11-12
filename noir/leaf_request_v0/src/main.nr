// leaf_request_v0 - one EFI `RegisterInvoiceRequest` on its own: taxpayer XML-DSig checked
// in-circuit and a blinded commitment to the fields read from it.
//
// A component benchmark and test target. The reader and its limits are documented in
// ../pf_efi/src/request.nr; the end-to-end statement lives in ../pf_efi/src/batch.nr.

use pf_efi::request::request_fields_and_digest;
use pf_xmldsig::{assert_rsa_sha256, rsa_key_hash};
use poseidon::poseidon2::Poseidon2;

global MAX_DOC: u32 = 4096;

// Domain separator: ASCII "PF-REQUEST1".
global DOMAIN_REQUEST: Field = 0x50462d5245515545535431;

fn main(
    // --- private witness ---
    doc: [u8; MAX_DOC], // canonical request, enveloped signature removed, zero-padded
    doc_len: u32,
    signature: [u128; 18],
    modulus: [u128; 18],
    redc_param: [u128; 18],
    salt: Field,
) -> pub (Field, Field) {
    let (f, digest) = request_fields_and_digest(doc, doc_len);
    let signer_key_hash = rsa_key_hash(modulus);
    assert_rsa_sha256(digest, signature, modulus, redc_param);

    let request_commitment = Poseidon2::hash(
        [
            DOMAIN_REQUEST,
            f.uuid,
            f.iic,
            f.busin_unit_code,
            f.tcr_code,
            f.ordinal as Field,
            f.issue_local_ts,
            f.issue_tz,
            f.total_negative as Field,
            f.total_cents as Field,
            salt,
        ],
        11,
    );

    (signer_key_hash, request_commitment)
}
