// Invoices issued to one buyer, as one statement.
//
// Proved, for one taxpayer key T and one authority key A, for the first `count` of K invoices:
//   * request_i is signed by T, names the buyer B and carries (UUID_i, issue year, total_i), the
//     total not negative;
//   * response_i is signed by A and carries (RequestUUID_i, FIC_i), and RequestUUID_i == UUID_i;
//   * every issue year equals the public `year`, and so does the date the authority put on the
//     receipt;
//   * all FIC_i are different, so these are `count` different invoices;
//   * the totals add up to at least the public `threshold_cents`.
// Published: hash of T, hash of A, `count`, a tag of B bound to the public `context`, and for each
// of the `count` invoices a nullifier bound to the context and a blinded opening commitment (both
// zero in the slots that are not used).
//
// Unlike batch.nr, the invoices need not be consecutive or come from one device: a seller's
// invoices to one buyer are scattered among its other invoices.
//
// The nullifier is the one of batch.nr (receipt code and context), so an invoice shown to a
// verifier in a proof of either kind is recognised when it comes back in the other.
//
// NOT proved (state it wherever this proof is shown):
//   * that the authority saw the CONTENT of a request. Buyer and total are the taxpayer's word
//     until an invoice is opened and compared with the authority's record (see batch.nr); that is
//     why both are in the opening commitment.
//   * that these are ALL the invoices issued to B, or that no credit note to B exists. The
//     statement is a lower bound on what was invoiced to B, nothing more.
//   * secrecy of B towards someone who can guess it. Tax numbers are few: whoever knows the
//     context can test a guess against the tag. The statement is meant for a verifier who already
//     knows the buyer, such as a financier of receivables against that buyer.
//
// As in batch.nr, a circuit with K slots can carry fewer invoices: slots from `count` on must
// still hold well-formed signed pairs that name some buyer (the prover repeats one of its own),
// but nothing read from them reaches any result.

use crate::batch::receipt_in_year;
use crate::buyer::buyer_of_signed_request;
use crate::request::request_fields_and_digest;
use crate::response::response_fields_and_digest;
use pf_xmldsig::{assert_rsa_sha256, rsa_key_hash};
use poseidon::poseidon2::Poseidon2;

// Domain separators: ASCII "PF-NULLIF1" (the value batch.nr uses), "PF-BUYER01", "PF-OPENBUY".
global DOMAIN_NULLIFIER: Field = 0x50462d4e554c4c494631;
global DOMAIN_BUYER: Field = 0x50462d42555945523031;
global DOMAIN_OPENING_BUYER: Field = 0x50462d4f50454e425559;

/// What a verifier who knows the buyer recomputes to recognise it.
pub fn buyer_tag(context: Field, buyer: Field) -> Field {
    Poseidon2::hash([DOMAIN_BUYER, context, buyer], 3)
}

/// Opening commitment of one invoice of this statement. Revealing these ten values lets anyone
/// recompute it.
pub fn opening_commitment_with_buyer(
    iic: Field,
    fic: Field,
    ordinal: Field,
    issue_local_ts: Field,
    issue_tz: Field,
    total_cents: Field,
    unit: Field,
    device: Field,
    buyer: Field,
    salt: Field,
) -> Field {
    Poseidon2::hash(
        [
            DOMAIN_OPENING_BUYER, iic, fic, ordinal, issue_local_ts, issue_tz, total_cents, unit, device,
            buyer, salt,
        ],
        11,
    )
}

pub fn prove_debtor<let K: u32, let M: u32>(
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
    threshold_cents: u64,
    context: Field,
    year: u32,
) -> (Field, Field, u32, Field, [Field; K], [Field; K]) {
    assert(count >= 1, "debtor: no invoices");
    assert(count <= K, "debtor: more invoices than this circuit holds");

    let mut fics: [Field; K] = [0; K];
    let mut nullifiers: [Field; K] = [0; K];
    let mut openings: [Field; K] = [0; K];
    let mut sum: u64 = 0;

    for i in 0..K {
        let (req, req_digest) = request_fields_and_digest(request_docs[i], request_lens[i]);
        assert_rsa_sha256(req_digest, request_sigs[i], taxpayer_modulus, taxpayer_redc);

        let (resp, resp_digest) = response_fields_and_digest(
            resp_request_uuids[i],
            resp_send_dts[i],
            resp_uuids[i],
            resp_fics[i],
        );
        assert_rsa_sha256(resp_digest, resp_sigs[i], issuer_modulus, issuer_redc);

        assert(resp.request_uuid == req.uuid, "debtor: receipt does not belong to this request");
        assert(req.issue_year == year, "debtor: invoice is not from the stated year");
        assert(
            receipt_in_year(resp.send_year, resp.send_month_day, year),
            "debtor: receipt is not from the stated year",
        );
        let named = buyer_of_signed_request(request_docs[i], request_lens[i]);

        if i < count {
            assert(named == buyer, "debtor: invoice names another buyer");
            assert(!req.total_negative, "debtor: negative total");
            sum += req.total_cents;
            fics[i] = resp.fic;
            nullifiers[i] = Poseidon2::hash([DOMAIN_NULLIFIER, context, resp.fic], 3);
            openings[i] = opening_commitment_with_buyer(
                req.iic,
                resp.fic,
                req.ordinal as Field,
                req.issue_local_ts,
                req.issue_tz,
                req.total_cents as Field,
                req.busin_unit_code,
                req.tcr_code,
                buyer,
                salts[i],
            );
        }
    }

    for i in 0..K {
        for j in (i + 1)..K {
            if j < count {
                assert(fics[i] != fics[j], "debtor: a receipt is used twice");
            }
        }
    }
    assert(sum >= threshold_cents, "debtor: total is below the threshold");

    (
        rsa_key_hash(taxpayer_modulus),
        rsa_key_hash(issuer_modulus),
        count,
        buyer_tag(context, buyer),
        nullifiers,
        openings,
    )
}
