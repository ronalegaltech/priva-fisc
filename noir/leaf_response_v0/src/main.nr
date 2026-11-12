// leaf_response_v0 - one EFI `RegisterInvoiceResponse` receipt on its own: authority XML-DSig
// checked in-circuit and a blinded commitment to the four signed fields.
//
// A component benchmark and test target. The template method and its limits are documented in
// ../pf_efi/src/response.nr; the end-to-end statement lives in ../pf_efi/src/batch.nr.

use pf_efi::response::response_fields_and_digest;
use pf_xmldsig::{assert_rsa_sha256, rsa_key_hash};
use poseidon::poseidon2::Poseidon2;

// Domain separator: ASCII "PF-RECEIPT1".
global DOMAIN_RECEIPT: Field = 0x50462d5245434549505431;

fn main(
    // --- private witness ---
    request_uuid: [u8; 36],
    send_date_time: [u8; 25],
    response_uuid: [u8; 36],
    fic: [u8; 36],
    signature: [u128; 18],
    modulus: [u128; 18],
    redc_param: [u128; 18],
    salt: Field,
) -> pub (Field, Field) {
    let (f, digest) = response_fields_and_digest(request_uuid, send_date_time, response_uuid, fic);
    let issuer_key_hash = rsa_key_hash(modulus);
    assert_rsa_sha256(digest, signature, modulus, redc_param);

    let receipt_commitment = Poseidon2::hash(
        [DOMAIN_RECEIPT, f.request_uuid, f.response_uuid, f.fic, f.send_local_ts, f.send_tz, salt],
        7,
    );

    (issuer_key_hash, receipt_commitment)
}
