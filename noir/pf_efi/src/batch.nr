// K invoices as one statement.
//
// Proved, for one taxpayer key T and one authority key A:
//   for every i in 0..K
//     * request_i is signed by T and carries (UUID_i, unit, device, ordinal_i, issue year, total_i);
//     * response_i is signed by A and carries (RequestUUID_i, FIC_i);
//     * RequestUUID_i == UUID_i                                  (receipt belongs to this request)
//   and across the batch
//     * same business unit and same device for all i;
//     * every issue year equals the public `year`;
//     * ordinal_{i+1} == ordinal_i + 1                           (no gap inside the batch)
//     * all FIC_i are different                                  (no receipt used twice)
//     * sum of totals (negative totals subtract) >= public `threshold_cents`.
// Published: hash of T, hash of A, whether the batch starts at ordinal 1, one nullifier per invoice
// bound to the public `context`, and one blinded opening commitment per invoice.
//
// NOT proved (state it wherever this proof is shown):
//   * that the authority saw the CONTENT of request_i. Its signature covers the UUID and FIC only.
//     A taxpayer who registers cheap invoices and signs different content under the same UUIDs
//     passes this circuit. The defence is outside: after seeing the proof the verifier picks a few
//     invoices at random; for each the prover reveals the preimage of its opening commitment
//     (IIC, FIC, ordinal, issue time, total, salt) and the verifier compares it with what the
//     authority's public invoice-check service returns for that IIC. Unopened invoices stay hidden.
//   * that no invoices exist after the last ordinal, or on other devices of the same taxpayer.
//
// A circuit with K slots can carry fewer than K invoices: `count` says how many slots, from the
// first, are the statement. The remaining slots must still hold well-formed signed pairs (the
// prover repeats one of its own), but nothing read from them reaches any result. The batch
// circuits always use all K; the aggregation leaves (agg.nr) take `count` as an input.

use crate::request::request_fields_and_digest;
use crate::response::response_fields_and_digest;
use pf_xmldsig::{assert_rsa_sha256, rsa_key_hash};
use poseidon::poseidon2::Poseidon2;

// Domain separators: ASCII "PF-NULLIF1", "PF-OPENING".
global DOMAIN_NULLIFIER: Field = 0x50462d4e554c4c494631;
global DOMAIN_OPENING: Field = 0x50462d4f50454e494e47;

/// Opening commitment of one invoice. Revealing these eight values lets anyone recompute it.
pub fn opening_commitment(
    iic: Field,
    fic: Field,
    ordinal: Field,
    issue_local_ts: Field,
    issue_tz: Field,
    total_negative: Field,
    total_cents: Field,
    salt: Field,
) -> Field {
    Poseidon2::hash(
        [DOMAIN_OPENING, iic, fic, ordinal, issue_local_ts, issue_tz, total_negative, total_cents, salt],
        9,
    )
}

/// What the first `count` of K checked invoices amount to. Private: nothing here is published as
/// is. Entries of the three lists from `count` on are zero.
pub struct BatchCore<let K: u32> {
    pub count: u32,
    pub taxpayer_key_hash: Field,
    pub issuer_key_hash: Field,
    pub first_ordinal: u64,
    pub last_ordinal: u64,
    pub unit: Field,
    pub device: Field,
    pub sum_plus: u64,
    pub sum_minus: u64,
    pub fics: [Field; K],
    pub nullifiers: [Field; K],
    pub openings: [Field; K],
}

/// Ordinal, place and amount of one invoice, as read from its signed request.
pub struct Line {
    pub ordinal: u64,
    pub unit: Field,
    pub device: Field,
    pub negative: bool,
    pub cents: u64,
}

/// Across the first `count` lines: same unit and device, consecutive ordinals, and the two sums.
/// Lines from `count` on are ignored. Returns (first ordinal, last ordinal, unit, device, sum of
/// the positive totals, sum of the negative totals).
pub fn summarise<let K: u32>(lines: [Line; K], count: u32) -> (u64, u64, Field, Field, u64, u64) {
    assert(count >= 1, "batch: no invoices");
    assert(count <= K, "batch: more invoices than this circuit holds");
    let first = lines[0];
    let mut last_ordinal = first.ordinal;
    let mut sum_plus: u64 = 0;
    let mut sum_minus: u64 = 0;
    for i in 0..K {
        if i < count {
            if i > 0 {
                assert(lines[i].ordinal == last_ordinal + 1, "batch: ordinals are not consecutive");
                assert(lines[i].unit == first.unit, "batch: mixed business units");
                assert(lines[i].device == first.device, "batch: mixed devices");
            }
            last_ordinal = lines[i].ordinal;
            if lines[i].negative {
                sum_minus += lines[i].cents;
            } else {
                sum_plus += lines[i].cents;
            }
        }
    }
    (first.ordinal, last_ordinal, first.unit, first.device, sum_plus, sum_minus)
}

/// Checks K signed pairs one by one (both signatures, the UUID link, the year) and, across the
/// first `count` of them, the same unit and device and consecutive ordinals. It does NOT check
/// that receipts are distinct and does not apply any threshold: callers do that (see `prove_batch`
/// here and agg.nr).
pub fn check_invoices<let K: u32, let M: u32>(
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
    context: Field,
    year: u32,
) -> BatchCore<K> {
    let taxpayer_key_hash = rsa_key_hash(taxpayer_modulus);
    let issuer_key_hash = rsa_key_hash(issuer_modulus);

    let mut fics: [Field; K] = [0; K];
    let mut nullifiers: [Field; K] = [0; K];
    let mut openings: [Field; K] = [0; K];
    let mut lines: [Line; K] = [Line { ordinal: 0, unit: 0, device: 0, negative: false, cents: 0 }; K];

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

        assert(resp.request_uuid == req.uuid, "batch: receipt does not belong to this request");
        assert(req.issue_year == year, "batch: invoice is not from the stated year");

        lines[i] = Line {
            ordinal: req.ordinal,
            unit: req.busin_unit_code,
            device: req.tcr_code,
            negative: req.total_negative,
            cents: req.total_cents,
        };

        if i < count {
            fics[i] = resp.fic;
            nullifiers[i] = Poseidon2::hash([DOMAIN_NULLIFIER, context, req.iic_signature_hash], 3);
            openings[i] = opening_commitment(
                req.iic,
                resp.fic,
                req.ordinal as Field,
                req.issue_local_ts,
                req.issue_tz,
                req.total_negative as Field,
                req.total_cents as Field,
                salts[i],
            );
        }
    }

    let (first_ordinal, last_ordinal, unit, device, sum_plus, sum_minus) = summarise(lines, count);

    BatchCore {
        count,
        taxpayer_key_hash,
        issuer_key_hash,
        first_ordinal,
        last_ordinal,
        unit,
        device,
        sum_plus,
        sum_minus,
        fics,
        nullifiers,
        openings,
    }
}

pub fn prove_batch<let K: u32, let M: u32>(
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
    threshold_cents: u64,
    context: Field,
    year: u32,
) -> (Field, Field, bool, [Field; K], [Field; K]) {
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
        K,
        context,
        year,
    );

    for i in 0..K {
        for j in (i + 1)..K {
            assert(c.fics[i] != c.fics[j], "batch: a receipt is used twice");
        }
    }
    assert(c.sum_plus >= c.sum_minus + threshold_cents, "batch: total is below the threshold");

    (c.taxpayer_key_hash, c.issuer_key_hash, c.first_ordinal == 1, c.nullifiers, c.openings)
}

#[test]
fn test_summarise_ignores_slots_after_count() {
    let l = |ordinal: u64, cents: u64, negative: bool| Line { ordinal, unit: 7, device: 8, negative, cents };
    // Three invoices; the fourth slot repeats the third, as a prover fills an unused slot.
    let lines = [l(5, 100, false), l(6, 40, true), l(7, 250, false), l(7, 250, false)];
    let (first, last, unit, device, plus, minus) = summarise(lines, 3);
    assert(first == 5);
    assert(last == 7);
    assert(unit == 7);
    assert(device == 8);
    assert(plus == 350);
    assert(minus == 40);
}

#[test]
fn test_summarise_ignores_another_place_after_count() {
    let lines = [
        Line { ordinal: 1, unit: 7, device: 8, negative: false, cents: 10 },
        Line { ordinal: 9, unit: 1, device: 2, negative: false, cents: 99 },
    ];
    let (first, last, _, _, plus, _) = summarise(lines, 1);
    assert(first == 1);
    assert(last == 1);
    assert(plus == 10);
}

#[test(should_fail_with = "batch: ordinals are not consecutive")]
fn test_summarise_counted_slot_must_continue() {
    let l = |ordinal: u64| Line { ordinal, unit: 7, device: 8, negative: false, cents: 1 };
    // Claiming four invoices while the fourth slot only repeats the third.
    let _ = summarise([l(5), l(6), l(7), l(7)], 4);
}

#[test(should_fail_with = "batch: mixed devices")]
fn test_summarise_counted_slot_same_device() {
    let lines = [
        Line { ordinal: 1, unit: 7, device: 8, negative: false, cents: 10 },
        Line { ordinal: 2, unit: 7, device: 9, negative: false, cents: 10 },
    ];
    let _ = summarise(lines, 2);
}

#[test(should_fail_with = "batch: no invoices")]
fn test_summarise_rejects_zero() {
    let _ = summarise([Line { ordinal: 1, unit: 7, device: 8, negative: false, cents: 10 }], 0);
}

#[test(should_fail_with = "batch: more invoices than this circuit holds")]
fn test_summarise_rejects_count_above_capacity() {
    let _ = summarise([Line { ordinal: 1, unit: 7, device: 8, negative: false, cents: 10 }], 2);
}
