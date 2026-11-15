// Open e-invoices to one buyer, as the tax authority states them.
//
// In Albania's e-invoice service a taxpayer's software asks the central system for its e-invoices
// (GetEinvoices) and gets back a list signed by the authority. Unlike the receipt of a
// registration (response.nr), this answer carries CONTENT under the authority's signature: for
// every e-invoice its code (EIC), the document type, the amount, the tax numbers of buyer and
// seller, and its status (accepted, refused, paid, partially paid).
//
// Proved, for one authority key A and one signed answer:
//   * the answer is a GetEinvoices response signed by A, which A dated on the published day;
//   * `count` different e-invoices in it are commercial invoices (type 380) with seller S and buyer
//     B, each with the status ACCEPTED and an amount that is not negative;
//   * their amounts add up to at least the public `threshold_cents`.
// Published: hash of A, `count`, a tag of B and a tag of S bound to the public `context`, the day
// of the answer, and for each counted e-invoice a nullifier bound to the context (zero in the
// slots that are not used).
//
// NOT proved (state it wherever this proof is shown):
//   * that a sale took place. The authority states what is registered and in which status.
//   * that the buyer approved an invoice. ACCEPTED is the status the central system shows, and an
//     invoice may reach it without any act of the buyer. Read it as "not refused and not paid".
//   * anything after the day of the answer: an invoice may have been paid or refused since. The
//     verifier decides how old an answer may be.
//   * that these are all the e-invoices S issued to B.
//   * who presents the proof. Nothing here is signed by the taxpayer: whoever holds the answer
//     can make the proof. (batch.nr and debtor.nr name the taxpayer by its signing key.)
//   * that an invoice was not also presented in a proof made from its registration messages. The
//     nullifier here comes from the e-invoice code, there from the receipt code, and the answer
//     does not link the two.
//
// What this rests on: the published specification only ("Einvoice Service, Technical
// Specification", version 04). No real answer has been seen. Taken from the specification's tables
// and examples, and to be confirmed on a real message: the name of the root element, that the
// list elements carry no prefix, and the attribute names Status, BuyerTin and SellerTin.
//
// How the answer is read without an XML parser:
//   * It must begin with the format's text (format.nr), which names the message and ends with the
//     name of its Header element. The header's start tag is scanned for SendDateTime.
//   * The prover says where each counted <Einvoice ...> element starts. Canonical XML never leaves
//     a raw '<' in text or inside an attribute value, so the bytes `<Einvoice ` can only be the
//     start of such an element, wherever in the answer they are found.
//   * That start tag is scanned once, as <Invoice> is in request.nr: an attribute is recognised
//     only where ` Name="` begins outside any quoted value while the tag is open, and each wanted
//     attribute must occur exactly once. A single quote, a tab or a line break at tag level and a
//     namespace declaration are refused.
//   * The answer must end, at the end of the signed bytes, with the format's closing text.
//
// As in debtor.nr, a circuit with K slots can count fewer e-invoices: slots from `count` on must
// still point at a well-formed element that passes every check (the prover repeats one of the
// counted ones), but nothing read from them reaches any result.
//
// Known liveness limits: an answer of at most M - EINVOICE_TAG - 9 bytes; a start tag of at most
// EINVOICE_TAG - 16 bytes; an amount with two decimals of at most 15 characters; tax numbers of
// the form letter, eight digits, letter.

use crate::debtor::buyer_tag;
use crate::format::{ALBANIA_EINVOICES, EinvoiceFormat};
use pf_xmldsig::{
    assert_rsa_sha256, digit, parse_amount_until_quote, parse_uuid, rsa_key_hash,
    signed_info_digest_response,
};
use poseidon::poseidon2::Poseidon2;

/// Bytes copied for one start tag: all but the last LOOKAHEAD are scanned.
pub global EINVOICE_TAG: u32 = 416;
global HEADER_TAG: u32 = 216;
global LOOKAHEAD: u32 = 16;

// Domain separators: ASCII "PF-NULLEIC", "PF-SELLER1".
global DOMAIN_NULLIFIER_EIC: Field = 0x50462d4e554c4c454943;
global DOMAIN_SELLER: Field = 0x50462d53454c4c455231;
// A tax number enters a tag as the text `NUIS:` followed by its ten characters, packed big-endian:
// the form buyer.nr gives the same buyer read from a registration request.
global NUIS_PREFIX: Field = 0x4e5549533a;

// --- Patterns searched at tag level of an <Einvoice ...> start tag, packed big-endian, with
// their length and 256^(length-1). Six are wanted attributes; ` xmlns` must not occur. ---
global A_AMOUNT: u32 = 0;
global A_BUYER: u32 = 1;
global A_TYPE: u32 = 2;
global A_EIC: u32 = 3;
global A_SELLER: u32 = 4;
global A_STATUS: u32 = 5;
global A_XMLNS: u32 = 6;
global PAT: [Field; 7] = [
    0x20416d6f756e743d22, // ` Amount="`
    0x20427579657254696e3d22, // ` BuyerTin="`
    0x20446f63547970653d22, // ` DocType="`
    0x204549433d22, // ` EIC="`
    0x2053656c6c657254696e3d22, // ` SellerTin="`
    0x205374617475733d22, // ` Status="`
    0x20786d6c6e73, // ` xmlns`
];
global PAT_LEN: [u32; 7] = [9, 11, 10, 6, 12, 9, 6];
global PAT_TOP: [Field; 7] = [
    0x10000000000000000, // 256^8
    0x100000000000000000000, // 256^10
    0x1000000000000000000, // 256^9
    0x10000000000, // 256^5
    0x10000000000000000000000, // 256^11
    0x10000000000000000, // 256^8
    0x10000000000, // 256^5
];

// --- The same for the start tag of the Header element. ---
global H_SENT: u32 = 0;
global H_XMLNS: u32 = 1;
global HPAT: [Field; 2] = [
    0x2053656e644461746554696d653d22, // ` SendDateTime="`
    0x20786d6c6e73, // ` xmlns`
];
global HPAT_LEN: [u32; 2] = [15, 6];
global HPAT_TOP: [Field; 2] = [
    0x10000000000000000000000000000, // 256^14
    0x10000000000, // 256^5
];

/// What the statement uses of one e-invoice in the answer.
pub struct EinvoiceFields {
    pub eic: Field,
    pub buyer: Field,
    pub seller: Field,
    pub negative: bool,
    pub cents: u64,
    /// Index in the answer of the '>' that closes the start tag.
    pub tag_end: u32,
}

fn window<let M: u32, let N: u32>(doc: [u8; M], start: u32) -> [u8; N] {
    let mut out: [u8; N] = [0; N];
    for j in 0..N {
        out[j] = doc[start + j];
    }
    out
}

/// One pass over a start tag. `tag[0]` is the space after the element name; the last LOOKAHEAD
/// bytes are read ahead only. Returns, for each pattern, how many times it begins at tag level and
/// the index of the byte after it (meaningful where the count is 1), plus the index of the '>'
/// that closes the tag.
fn scan_tag<let N: u32, let P: u32>(
    tag: [u8; N],
    pat: [Field; P],
    pat_len: [u32; P],
    pat_top: [Field; P],
) -> ([Field; P], [Field; P], u32) {
    assert(tag[0] == 32, "einvoice: the element name is not followed by an attribute");

    let mut win: [Field; P] = [0; P];
    for a in 0..P {
        let mut v: Field = 0;
        for j in 0..LOOKAHEAD {
            if j < pat_len[a] {
                v = v * 256 + (tag[j] as Field);
            }
        }
        win[a] = v;
    }

    let mut in_quote: Field = 0;
    let mut in_tag: Field = 1;
    let mut count: [Field; P] = [0; P];
    let mut value_at: [Field; P] = [0; P];
    let mut tag_end: Field = 0;
    let mut stray_single_quotes: Field = 0;
    let mut stray_whitespace: Field = 0;

    for k in 0..(N - LOOKAHEAD) {
        let c = tag[k] as Field;
        let outside = in_tag * (1 - in_quote); // 1 iff byte k is tag-level text of the open tag

        for a in 0..P {
            let hit = ((win[a] == pat[a]) as Field) * outside;
            count[a] += hit;
            value_at[a] += hit * ((k + pat_len[a]) as Field);
            win[a] = (win[a] - c * pat_top[a]) * 256 + (tag[k + pat_len[a]] as Field);
        }

        let is_quote = (tag[k] == 34) as Field;
        stray_single_quotes += ((tag[k] == 39) as Field) * outside;
        stray_whitespace += (((tag[k] == 9) | (tag[k] == 10) | (tag[k] == 13)) as Field) * outside;
        let closes = ((tag[k] == 62) as Field) * outside;
        tag_end += closes * (k as Field);
        in_tag -= closes;
        in_quote = in_quote + is_quote - 2 * in_quote * is_quote;
    }

    assert(in_tag == 0, "einvoice: a start tag does not close inside the scan window");
    assert(stray_single_quotes == 0, "einvoice: single quote at tag level");
    assert(stray_whitespace == 0, "einvoice: tab or line break at tag level");
    (count, value_at, tag_end as u32)
}

/// A tax number, letter, eight digits, letter, followed by its closing quote -> `NUIS:` and the
/// ten characters packed big-endian.
fn parse_tax_number(b: [u8; 11]) -> Field {
    let mut acc: Field = NUIS_PREFIX;
    for j in 0..10 {
        let c = b[j];
        if (j == 0) | (j == 9) {
            assert(
                ((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122)),
                "einvoice: a tax number is not letter, eight digits, letter",
            );
        } else {
            assert((c >= 48) & (c <= 57), "einvoice: a tax number is not letter, eight digits, letter");
        }
        acc = acc * 256 + (c as Field);
    }
    assert(b[10] == 34, "einvoice: a tax number is not 10 characters");
    acc
}

/// "YYYY-MM-DDT" -> YYYYMMDD. Whatever follows the 'T' (a local time with its offset, or a UTC time
/// ending in Z) is not read.
fn parse_day(b: [u8; 11]) -> u32 {
    assert((b[4] == 45) & (b[7] == 45) & (b[10] == 84), "einvoice: SendDateTime is not a date and a time");
    let year = digit(b[0]) * 1000 + digit(b[1]) * 100 + digit(b[2]) * 10 + digit(b[3]);
    let month = digit(b[5]) * 10 + digit(b[6]);
    let day = digit(b[8]) * 10 + digit(b[9]);
    assert((month >= 1) & (month <= 12), "einvoice: month out of range");
    assert((day >= 1) & (day <= 31), "einvoice: day out of range");
    (year * 10000 + month * 100 + day) as u32
}

/// The day the authority put on its answer and the index of the '>' that closes the header's
/// start tag. Checks that the answer begins as the format says.
fn read_header<let M: u32, let H: u32, let O: u32, let T: u32>(
    format: EinvoiceFormat<H, O, T>,
    doc: [u8; M],
) -> (u32, u32) {
    for i in 0..H {
        assert(doc[i] == format.head[i], "einvoice: this is not the answer the format describes");
    }
    let tag: [u8; HEADER_TAG] = window(doc, H);
    let (count, at, tag_end) = scan_tag(tag, HPAT, HPAT_LEN, HPAT_TOP);
    assert(count[H_XMLNS] == 0, "einvoice: namespace declaration on the header");
    assert(count[H_SENT] == 1, "einvoice: SendDateTime is missing or repeated");
    (parse_day(window(tag, at[H_SENT] as u32)), H + tag_end)
}

/// The day the authority put on its answer.
pub fn answer_day<let M: u32, let H: u32, let O: u32, let T: u32>(
    format: EinvoiceFormat<H, O, T>,
    doc: [u8; M],
) -> u32 {
    let (day, _) = read_header(format, doc);
    day
}

/// The e-invoice whose element starts at byte `at` of the answer. Refuses anything that is not a
/// commercial invoice with the status ACCEPTED.
pub fn read_einvoice<let M: u32, let H: u32, let O: u32, let T: u32>(
    format: EinvoiceFormat<H, O, T>,
    doc: [u8; M],
    at: u32,
) -> EinvoiceFields {
    assert(at + O - 1 + EINVOICE_TAG <= M, "einvoice: element too close to the end of the array");
    for j in 0..O {
        assert(doc[at + j] == format.open[j], "einvoice: no e-invoice element starts where the prover says");
    }
    let start = at + O - 1; // the space after the element name
    let tag: [u8; EINVOICE_TAG] = window(doc, start);
    let (count, value_at, tag_end) = scan_tag(tag, PAT, PAT_LEN, PAT_TOP);
    for a in 0..7 {
        if a == A_XMLNS {
            assert(count[a] == 0, "einvoice: namespace declaration on an e-invoice element");
        } else {
            assert(count[a] == 1, "einvoice: a required attribute is missing or repeated");
        }
    }

    let (negative, cents) = parse_amount_until_quote(window(tag, value_at[A_AMOUNT] as u32));
    let buyer = parse_tax_number(window(tag, value_at[A_BUYER] as u32));
    let seller = parse_tax_number(window(tag, value_at[A_SELLER] as u32));
    let eic_at = value_at[A_EIC] as u32;
    let eic = parse_uuid(window(tag, eic_at));
    assert(tag[eic_at + 36] == 34, "einvoice: EIC is not 36 characters");

    let kind: [u8; 4] = window(tag, value_at[A_TYPE] as u32);
    assert(kind == DOC_TYPE_INVOICE, "einvoice: not a commercial invoice (type 380)");
    let status: [u8; 9] = window(tag, value_at[A_STATUS] as u32);
    assert(status == STATUS_ACCEPTED, "einvoice: status is not ACCEPTED");

    EinvoiceFields { eic, buyer, seller, negative, cents, tag_end: start + tag_end }
}

global DOC_TYPE_INVOICE: [u8; 4] = "380\"".as_bytes();
global STATUS_ACCEPTED: [u8; 9] = "ACCEPTED\"".as_bytes();

/// What a verifier who knows the seller recomputes to recognise it.
pub fn seller_tag(context: Field, seller: Field) -> Field {
    Poseidon2::hash([DOMAIN_SELLER, context, seller], 3)
}

pub fn prove_open_einvoices<let K: u32, let M: u32, let H: u32, let O: u32, let T: u32>(
    format: EinvoiceFormat<H, O, T>,
    doc: [u8; M],
    doc_len: u32,
    signature: [u128; 18],
    issuer_modulus: [u128; 18],
    issuer_redc: [u128; 18],
    offsets: [u32; K],
    count: u32,
    buyer: Field,
    seller: Field,
    threshold_cents: u64,
    context: Field,
) -> (Field, u32, Field, Field, u32, [Field; K]) {
    assert(count >= 1, "einvoice: no e-invoices");
    assert(count <= K, "einvoice: more e-invoices than this circuit holds");
    assert(doc_len <= M, "einvoice: answer longer than the circuit allows");
    assert(doc_len > H + T, "einvoice: answer shorter than its fixed parts");

    // The authority signed exactly the first `doc_len` bytes.
    let digest = signed_info_digest_response(sha256::sha256_var(doc, doc_len));
    assert_rsa_sha256(digest, signature, issuer_modulus, issuer_redc);

    let (day, header_end) = read_header(format, doc);
    assert(header_end + T < doc_len, "einvoice: header lies outside the signed answer");
    for j in 0..T {
        assert(doc[doc_len - T + j] == format.tail[j], "einvoice: the answer does not end with its closing tags");
    }

    let mut eics: [Field; K] = [0; K];
    let mut nullifiers: [Field; K] = [0; K];
    let mut sum: u64 = 0;
    for i in 0..K {
        let e = read_einvoice(format, doc, offsets[i]);
        // Everything read lies before the closing tags, so inside the signed bytes.
        assert(e.tag_end + T < doc_len, "einvoice: element lies outside the signed answer");
        assert(e.buyer == buyer, "einvoice: an e-invoice names another buyer");
        assert(e.seller == seller, "einvoice: an e-invoice names another seller");
        assert(!e.negative, "einvoice: negative amount");
        if i < count {
            if i > 0 {
                assert(offsets[i] > offsets[i - 1], "einvoice: an e-invoice is counted twice or out of order");
            }
            sum += e.cents;
            eics[i] = e.eic;
            nullifiers[i] = Poseidon2::hash([DOMAIN_NULLIFIER_EIC, context, e.eic], 3);
        }
    }
    for i in 0..K {
        for j in (i + 1)..K {
            if j < count {
                assert(eics[i] != eics[j], "einvoice: an e-invoice code occurs twice");
            }
        }
    }
    assert(sum >= threshold_cents, "einvoice: total is below the threshold");

    (
        rsa_key_hash(issuer_modulus),
        count,
        buyer_tag(context, buyer),
        seller_tag(context, seller),
        day,
        nullifiers,
    )
}

// --- Tests of the readers on hand-written answers (no signature involved) ---
global T_HEADER: str<156> = " RequestUUID=\"00000000-0000-4000-8000-0000000000aa\" SendDateTime=\"2026-11-15T10:20:30Z\" UUID=\"00000000-0000-4000-8000-0000000000bb\"></ns2:Header><Einvoices>";
global T_BUYER: Field = 0x4e5549533a4b303030303030303141; // "NUIS:K00000001A"
global T_SELLER: Field = 0x4e5549533a4c303030303030303242; // "NUIS:L00000002B"

/// Test helper: the format's head, a header, `list` (the e-invoice elements) and the closing tags.
fn answer_with<let A: u32, let B: u32>(header: str<A>, list: str<B>) -> [u8; 2048] {
    let mut out: [u8; 2048] = [0; 2048];
    let mut o: u32 = 0;
    let head = ALBANIA_EINVOICES.head;
    for i in 0..129 {
        out[o + i] = head[i];
    }
    o += 129;
    let h = header.as_bytes();
    for i in 0..A {
        out[o + i] = h[i];
    }
    o += A;
    let l = list.as_bytes();
    for i in 0..B {
        out[o + i] = l[i];
    }
    o += B;
    let tail = ALBANIA_EINVOICES.tail;
    for i in 0..39 {
        out[o + i] = tail[i];
    }
    out
}

fn answer<let B: u32>(list: str<B>) -> [u8; 2048] {
    answer_with(T_HEADER, list)
}

/// Test helper: where the list begins in an answer built with T_HEADER.
global T_LIST: u32 = 285;

#[test]
fn test_reads_an_einvoice() {
    let doc = answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>");
    let e = read_einvoice(ALBANIA_EINVOICES, doc, T_LIST);
    assert(e.eic == 0x0e1f2a3b4c5d4e6f8a9b0c1d2e3f4a5b);
    assert(e.buyer == T_BUYER);
    assert(e.seller == T_SELLER);
    assert(!e.negative);
    assert(e.cents == 125000);
    assert(doc[e.tag_end] == 62);
}

#[test]
fn test_reads_the_second_einvoice() {
    let first = "<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>";
    let doc = answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice><Einvoice Amount=\"7.50\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"11111111-2222-4333-8444-555555555555\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>");
    let e = read_einvoice(ALBANIA_EINVOICES, doc, T_LIST + first.as_bytes().len());
    assert(e.eic == 0x11111111222243338444555555555555);
    assert(e.cents == 750);
}

#[test]
fn test_values_cannot_imitate_attributes() {
    // A document number holding escaped quotes around fake attributes and a '>'.
    let doc = answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"1 > 2 &quot; Amount=&quot;999999.00&quot; Status=&quot;PAID\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>");
    let e = read_einvoice(ALBANIA_EINVOICES, doc, T_LIST);
    assert(e.cents == 125000);
}

#[test(should_fail_with = "einvoice: status is not ACCEPTED")]
fn test_rejects_refused() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"REFUSED\"></Einvoice>"), T_LIST);
}

#[test(should_fail_with = "einvoice: status is not ACCEPTED")]
fn test_rejects_paid() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"PAID\"></Einvoice>"), T_LIST);
}

#[test(should_fail_with = "einvoice: status is not ACCEPTED")]
fn test_rejects_partially_paid() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"PARTIALLY_PAID\"></Einvoice>"), T_LIST);
}

#[test(should_fail_with = "einvoice: status is not ACCEPTED")]
fn test_rejects_status_that_only_begins_with_accepted() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED_LATER\"></Einvoice>"), T_LIST);
}

#[test(should_fail_with = "einvoice: not a commercial invoice (type 380)")]
fn test_rejects_factored_invoice_type() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"393\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>"), T_LIST);
}

#[test(should_fail_with = "einvoice: a required attribute is missing or repeated")]
fn test_rejects_repeated_amount() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\" Amount=\"1.00\"></Einvoice>"), T_LIST);
}

#[test(should_fail_with = "einvoice: a required attribute is missing or repeated")]
fn test_rejects_missing_buyer() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>"), T_LIST);
}

#[test(should_fail_with = "einvoice: no e-invoice element starts where the prover says")]
fn test_rejects_an_offset_inside_an_element() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>"), T_LIST + 1);
}

#[test(should_fail_with = "einvoice: no e-invoice element starts where the prover says")]
fn test_rejects_an_element_of_another_name() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<EinvoiceX Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></EinvoiceX>"), T_LIST);
}

#[test(should_fail_with = "einvoice: a tax number is not letter, eight digits, letter")]
fn test_rejects_malformed_tax_number() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"0720010081\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>"), T_LIST);
}

#[test(should_fail_with = "einvoice: namespace declaration on an e-invoice element")]
fn test_rejects_namespace_declaration() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\" xmlns=\"urn:x\"></Einvoice>"), T_LIST);
}

#[test(should_fail_with = "einvoice: single quote at tag level")]
fn test_rejects_single_quoted_value() {
    let _ = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\" Note='x'></Einvoice>"), T_LIST);
}

#[test]
fn test_reads_negative_amount_as_negative() {
    let e = read_einvoice(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"-3.50\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>"), T_LIST);
    assert(e.negative);
    assert(e.cents == 350);
}

#[test]
fn test_day_of_an_answer_in_utc() {
    assert(answer_day(ALBANIA_EINVOICES, answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>")) == 20261115);
}

#[test]
fn test_day_of_an_answer_with_an_offset() {
    let doc = answer_with(
        " RequestUUID=\"00000000-0000-4000-8000-0000000000aa\" SendDateTime=\"2026-03-01T23:59:59+01:00\" UUID=\"00000000-0000-4000-8000-0000000000bb\"></ns2:Header><Einvoices>",
        "<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>",
    );
    assert(answer_day(ALBANIA_EINVOICES, doc) == 20260301);
}

#[test(should_fail_with = "einvoice: SendDateTime is missing or repeated")]
fn test_rejects_header_without_time() {
    let doc = answer_with(" RequestUUID=\"00000000-0000-4000-8000-0000000000aa\"></ns2:Header><Einvoices>", "<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>");
    let _ = answer_day(ALBANIA_EINVOICES, doc);
}

#[test(should_fail_with = "einvoice: month out of range")]
fn test_rejects_month_13() {
    let doc = answer_with(" SendDateTime=\"2026-13-01T00:00:00Z\"></ns2:Header><Einvoices>", "<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>");
    let _ = answer_day(ALBANIA_EINVOICES, doc);
}

#[test(should_fail_with = "einvoice: this is not the answer the format describes")]
fn test_rejects_another_message() {
    let mut doc = answer("<Einvoice Amount=\"1250.00\" BuyerTin=\"K00000001A\" DocNumber=\"123-2026\" DocType=\"380\" DueDateTime=\"2026-12-10T15:45:24+01:00\" EIC=\"0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\" PartyType=\"SELLER\" RecDateTime=\"2026-11-10T15:45:24+01:00\" SellerTin=\"L00000002B\" Status=\"ACCEPTED\"></Einvoice>");
    // GetEinvoicesResponse -> GetTaxpayersResponse would change the length; one letter is enough here.
    doc[8] = 88;
    let _ = answer_day(ALBANIA_EINVOICES, doc);
}
