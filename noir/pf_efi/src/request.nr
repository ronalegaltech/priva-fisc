// Taxpayer-signed `RegisterInvoiceRequest`.
//
// This is the TAXPAYER's signature. It makes the taxpayer accountable for the content; it does not
// show that the tax authority saw this content. The link to the authority is the header UUID, which
// the authority's signed response repeats (see response.nr).
//
// How fields are read without an XML parser:
//   * The header is matched byte for byte against the only shapes a canonical header can take.
//     It begins with the country's text (format.nr), which ends where the value of SendDateTime
//     begins. Then come the time, 20 characters when it ends in "Z" and 25 with an offset; its
//     closing quote; optionally ` SubseqDelivType="` with one of the five words the schema has;
//     then ` UUID="`, the 36 characters, and `"></Header><Invoice`. Canonical XML writes the
//     attributes of an element in the order of their names with one space before each, so a
//     header with these attributes has no other spelling, and nothing in it is searched for:
//     every byte is either fixed text or a value checked character by character. An attribute
//     written twice, or a word the schema does not have, matches none of the shapes.
//   * The <Invoice> start tag begins where the header ends, which is one of twelve places. Inside
//     that start tag a one-pass scan tracks "inside a quoted value" and "tag still open".
//     An attribute is recognised only where ` Name="` begins outside any quoted value while the tag
//     is open. Canonical XML never leaves a raw '"' inside a value, so text placed in a value cannot
//     imitate an attribute. Each wanted attribute must occur exactly once.
//   * Refused at tag level, because canonical XML never has them there and a parser could read
//     them differently from this scan: a single quote (values are delimited by double quotes
//     only), a tab or line break (attributes are separated by one space), and a namespace
//     declaration (` xmlns`; the element inherits the EFI namespace from the root, a declaration
//     of its own would make it another element).
//   * The document must end with `</Invoice></RegisterInvoiceRequest>`.
//   * The rest of the document (items, taxes, parties) is hashed and otherwise ignored.
//
// Times. SendDateTime and IssueDateTime are read in every spelling the schema allows: UTC as "Z",
// or any offset from -14:00 to +14:00. The issue time is kept as written (its digits and how its
// zone is spelled), because that is what an opened invoice is compared by. The YEAR of an invoice
// is not the four digits written: it is the year of that moment on the country's clock at the
// turn of the year (format.nr). Software that writes UTC puts an invoice issued at half past
// midnight on 1 January under 31 December of the year before; it still belongs to the new year,
// whose numbering it opens.
//
// Known liveness limits: document up to M bytes; <Invoice> start tag up to TAG_WINDOW bytes.
// Read and not used: the late-delivery mark (SubseqDelivType). Not extracted: seller TIN,
// IICSignature, invoice type, corrective references.
//
// The device code (TCRCode) is mandatory in the Montenegrin format. In a format where it is not
// (format.nr), it may occur once or not at all, and an invoice without one has device 0.

use crate::format::{ALBANIA, Format, MONTENEGRO};
use pf_xmldsig::{
    date_on_clock, parse_amount_until_quote, parse_datetime_until_quote, parse_hex32,
    parse_registration_code, parse_uint_until_quote, parse_uuid, signed_info_digest_request,
};

pub global TAG_WINDOW: u32 = 1280;
// The scan looks ahead by the longest pattern it searches for, 16 bytes.
global TAG_READ: u32 = 1296;

// --- Canonical header, after the format's text and the time with its closing quote ---
global HDR_SUBSEQ: [u8; 18] = " SubseqDelivType=\"".as_bytes();
global HDR_UUID: [u8; 7] = " UUID=\"".as_bytes();
global HDR_END: [u8; 19] = "\"></Header><Invoice".as_bytes();
// What may follow the time: the longest late-delivery attribute (33 bytes), then ` UUID="`, the 36
// characters, HDR_END and the space that begins the attributes of <Invoice>.
global HDR_REST: u32 = 96;
// From ` UUID="` to that space.
global HDR_TAIL: u32 = 63;

// The five values of SubseqDelivType, each with the quote that closes it.
global SUBSEQ_WORDS: u32 = 5;
global SUBSEQ_LEN: [u32; 5] = [11, 10, 8, 15, 14];
global SUBSEQ: [[u8; 15]; 5] = [
    fit("NOINTERNET\""),
    fit("BOUNDBOOK\""),
    fit("SERVICE\""),
    fit("TECHNICALERROR\""),
    fit("BUSINESSNEEDS\""),
];

fn fit<let N: u32>(word: str<N>) -> [u8; 15] {
    let mut out: [u8; 15] = [0; 15];
    let b = word.as_bytes();
    for i in 0..N {
        out[i] = b[i];
    }
    out
}

// The last 35 bytes of a canonical request once the enveloped signature is removed.
global DOC_END: [u8; 35] = "</Invoice></RegisterInvoiceRequest>".as_bytes();

// --- Patterns searched at tag level, packed big-endian, with their length and 256^(length-1).
// Six are wanted attributes (` Name="`, exactly once each); ` xmlns` must not occur. ---
global A_BU: u32 = 0;
global A_IIC: u32 = 1;
global A_XMLNS: u32 = 2;
global A_ORD: u32 = 3;
global A_ISSUE: u32 = 4;
global A_TCR: u32 = 5;
global A_TOT: u32 = 6;
global N_ATTR: u32 = 7;
global PAT: [Field; 7] = [
    0x20427573696e556e6974436f64653d22, // ` BusinUnitCode="`
    0x204949433d22, // ` IIC="`
    0x20786d6c6e73, // ` xmlns`
    0x20496e764f72644e756d3d22, // ` InvOrdNum="`
    0x2049737375654461746554696d653d22, // ` IssueDateTime="`
    0x20544352436f64653d22, // ` TCRCode="`
    0x20546f7450726963653d22, // ` TotPrice="`
];
global PAT_LEN: [u32; 7] = [16, 6, 6, 12, 16, 10, 11];
global PAT_TOP: [Field; 7] = [
    0x1000000000000000000000000000000, // 256^15
    0x10000000000, // 256^5
    0x10000000000, // 256^5
    0x10000000000000000000000, // 256^11
    0x1000000000000000000000000000000, // 256^15
    0x1000000000000000000, // 256^9
    0x100000000000000000000, // 256^10
];

pub struct RequestFields {
    pub uuid: Field,
    pub iic: Field,
    pub busin_unit_code: Field,
    /// 0 where the invoice names no device (possible only in a format that allows it).
    pub tcr_code: Field,
    pub ordinal: u64,
    /// The year the issue time falls in on the country's clock (see the note on times above).
    pub issue_year: u32,
    /// IssueDateTime as written: its digits (YYYYMMDDhhmmss) and how its zone is spelled
    /// (pf_xmldsig::DateTime).
    pub issue_ts: Field,
    pub issue_zone: Field,
    pub total_negative: bool,
    pub total_cents: u64,
    /// Index of the '>' closing the <Invoice ...> start tag. Callers must check it is inside the
    /// signed length.
    pub tag_end: u32,
}

fn read<let M: u32, let N: u32>(doc: [u8; M], start: u32) -> [u8; N] {
    let mut out: [u8; N] = [0; N];
    for j in 0..N {
        out[j] = doc[start + j];
    }
    out
}

/// The header, matched against its canonical shapes. Returns the request's UUID and the offset
/// of the space right after `<Invoice`.
fn read_header<let M: u32, let H: u32, let L: u32>(format: Format<H, L>, doc: [u8; M]) -> (Field, u32) {
    for i in 0..H {
        assert(doc[i] == format.request_head[i], "request: header template mismatch");
    }
    // SendDateTime and the quote that closes it.
    let send = parse_datetime_until_quote(read(doc, H));

    // What follows that quote, which sits 20 or 25 bytes after the format's text.
    let short = send.len == 20;
    let mut rest: [u8; HDR_REST] = [0; HDR_REST];
    for j in 0..HDR_REST {
        rest[j] = if short { doc[H + 21 + j] } else { doc[H + 26 + j] };
    }

    // Either the late-delivery mark with one of its five words, or nothing, before ` UUID="`.
    let mut marked = true;
    for j in 0..18 {
        marked &= rest[j] == HDR_SUBSEQ[j];
    }
    let mut words: u32 = 0;
    let mut skip: u32 = 0; // bytes the mark takes
    for w in 0..SUBSEQ_WORDS {
        let mut is_word = marked;
        for j in 0..SUBSEQ_LEN[w] {
            is_word &= rest[18 + j] == SUBSEQ[w][j];
        }
        words += is_word as u32;
        skip += (is_word as u32) * (18 + SUBSEQ_LEN[w]);
    }
    // No word is the beginning of another once its closing quote is counted, so at most one fits.
    assert(!marked | (words == 1), "request: SubseqDelivType is not a word the schema has");

    let mut tail: [u8; HDR_TAIL] = [0; HDR_TAIL];
    for j in 0..HDR_TAIL {
        tail[j] = rest[skip + j];
    }
    for j in 0..7 {
        assert(tail[j] == HDR_UUID[j], "request: header template mismatch");
    }
    let mut uuid_text: [u8; 36] = [0; 36];
    for j in 0..36 {
        uuid_text[j] = tail[7 + j];
    }
    for j in 0..19 {
        assert(tail[43 + j] == HDR_END[j], "request: header template mismatch");
    }
    assert(tail[62] == 32, "request: '<Invoice' is not followed by an attribute");

    (parse_uuid(uuid_text), H + send.len + 1 + skip + 62)
}

/// One pass over the <Invoice ...> start tag, `tag_start` being the space right after `<Invoice`.
/// Returns, for each wanted attribute, the offset of the first byte of its value (the entry at
/// A_XMLNS is unused), the offset of the '>' that closes the tag, and how many times the device
/// code occurs (1, or 0 where the format allows it).
fn scan_invoice_tag<let M: u32, let H: u32, let L: u32>(
    format: Format<H, L>,
    doc: [u8; M],
    tag_start: u32,
) -> ([u32; 7], u32, Field) {
    // The tag begins at one of several places. Its bytes are fetched once; the scan then runs
    // over the copy, at fixed positions.
    let tag: [u8; TAG_READ] = read(doc, tag_start);

    let mut win: [Field; 7] = [0; 7];
    for a in 0..N_ATTR {
        let mut v: Field = 0;
        for j in 0..PAT_LEN[a] {
            v = v * 256 + (tag[j] as Field);
        }
        win[a] = v;
    }

    let mut in_quote: Field = 0;
    let mut in_tag: Field = 1;
    let mut count: [Field; 7] = [0; 7];
    let mut value_at: [Field; 7] = [0; 7]; // counted from tag_start
    let mut tag_end: Field = 0; // counted from tag_start
    let mut stray_single_quotes: Field = 0;
    let mut stray_whitespace: Field = 0;

    for k in 0..TAG_WINDOW {
        let c = tag[k] as Field;
        let outside = in_tag * (1 - in_quote); // 1 iff byte k is tag-level text of the open tag

        for a in 0..N_ATTR {
            let hit = ((win[a] == PAT[a]) as Field) * outside;
            count[a] += hit;
            value_at[a] += hit * ((k + PAT_LEN[a]) as Field);
            win[a] = (win[a] - c * PAT_TOP[a]) * 256 + (tag[k + PAT_LEN[a]] as Field);
        }

        let is_quote = (tag[k] == 34) as Field;
        stray_single_quotes += ((tag[k] == 39) as Field) * outside;
        stray_whitespace += (((tag[k] == 9) | (tag[k] == 10) | (tag[k] == 13)) as Field) * outside;
        let closes = ((tag[k] == 62) as Field) * outside;
        tag_end += closes * (k as Field);
        in_tag -= closes;
        in_quote = in_quote + is_quote - 2 * in_quote * is_quote;
    }

    assert(in_tag == 0, "request: <Invoice> start tag does not close inside the scan window");
    assert(stray_single_quotes == 0, "request: single quote at tag level");
    assert(stray_whitespace == 0, "request: tab or line break at tag level");
    let mut offsets: [u32; 7] = [0; 7];
    for a in 0..N_ATTR {
        if a == A_XMLNS {
            assert(count[a] == 0, "request: namespace declaration on <Invoice>");
        } else if (a == A_TCR) & !format.device_required {
            assert(count[a] * (count[a] - 1) == 0, "request: TCRCode is repeated");
            offsets[a] = tag_start + (value_at[a] as u32);
        } else {
            assert(count[a] == 1, "request: a required attribute is missing or repeated");
            offsets[a] = tag_start + (value_at[a] as u32);
        }
    }
    (offsets, tag_start + (tag_end as u32), count[A_TCR])
}

pub fn extract_request_fields<let M: u32, let H: u32, let L: u32>(
    format: Format<H, L>,
    doc: [u8; M],
) -> RequestFields {
    let (uuid, tag_start) = read_header(format, doc);
    let (at, tag_end, device_count) = scan_invoice_tag(format, doc, tag_start);

    // Fixed-length values must be followed by their closing quote.
    let busin_unit_code = parse_registration_code(read(doc, at[A_BU]));
    assert(doc[at[A_BU] + 10] == 34, "request: BusinUnitCode is not 10 characters");
    // No ten-character code packs to 0, so 0 can stand for "no device".
    let has_device = if format.device_required { true } else { device_count == 1 };
    let mut tcr_code: Field = 0;
    if has_device {
        tcr_code = parse_registration_code(read(doc, at[A_TCR]));
        assert(doc[at[A_TCR] + 10] == 34, "request: TCRCode is not 10 characters");
    }
    let iic = parse_hex32(read(doc, at[A_IIC]));
    assert(doc[at[A_IIC] + 32] == 34, "request: IIC is not 32 characters");
    // The time ends at its closing quote, after 20 or 25 characters.
    let issue = parse_datetime_until_quote(read(doc, at[A_ISSUE]));
    let (issue_year, _) = date_on_clock(issue, format.new_year_clock);

    // Variable-length values end at their closing quote.
    let ordinal = parse_uint_until_quote::<11>(read(doc, at[A_ORD]));
    let (total_negative, total_cents) = parse_amount_until_quote(read(doc, at[A_TOT]));

    RequestFields {
        uuid,
        iic,
        busin_unit_code,
        tcr_code,
        ordinal,
        issue_year,
        issue_ts: issue.written,
        issue_zone: issue.zone,
        total_negative,
        total_cents,
        tag_end,
    }
}

/// Fields of a request plus the digest its XML-DSig signature must cover. `doc` is the canonical
/// request with the enveloped signature removed, zero-padded to M; only `doc_len` bytes are signed.
pub fn request_fields_and_digest<let M: u32, let H: u32, let L: u32>(
    format: Format<H, L>,
    doc: [u8; M],
    doc_len: u32,
) -> (RequestFields, [u8; 32]) {
    assert(doc_len <= M, "request: document longer than the circuit allows");
    let f = extract_request_fields(format, doc);
    // Everything that was read lies before the end of the start tag, which must itself be signed
    // and be followed, at the very end of the signed bytes, by the two closing tags.
    assert(f.tag_end + 35 < doc_len, "request: <Invoice> start tag runs past the signed document");
    for j in 0..35 {
        assert(doc[doc_len - 35 + j] == DOC_END[j], "request: document does not end with its closing tags");
    }
    (f, signed_info_digest_request(sha256::sha256_var(doc, doc_len)))
}

// --- Tests of the field reader on hand-written documents (no signature involved) ---
global T_SIG: str<512> = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
global T_HEAD: str<200> = "<RegisterInvoiceRequest xmlns=\"https://efi.tax.gov.me/fs/schema\" Id=\"Request\" Version=\"1\"><Header SendDateTime=\"2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice";

/// Test helper: head || attrs_before || ` IICSignature="..."` || attrs_after_and_rest, zero-padded.
/// (IICSignature is a real attribute the reader does not use; it sits where real requests have it.)
fn doc_from<let N: u32, let A: u32, let B: u32>(head: str<N>, before: str<A>, after: str<B>) -> [u8; 2048] {
    let mut out: [u8; 2048] = [0; 2048];
    let mut o: u32 = 0;
    let h = head.as_bytes();
    for i in 0..N {
        out[o + i] = h[i];
    }
    o += N;
    let b = before.as_bytes();
    for i in 0..A {
        out[o + i] = b[i];
    }
    o += A;
    let pre = " IICSignature=\"".as_bytes();
    for i in 0..15 {
        out[o + i] = pre[i];
    }
    o += 15;
    let s = T_SIG.as_bytes();
    for i in 0..512 {
        out[o + i] = s[i];
    }
    o += 512;
    out[o] = 34;
    o += 1;
    let a = after.as_bytes();
    for i in 0..B {
        out[o + i] = a[i];
    }
    out
}

/// A request in the Montenegrin format.
fn doc_with<let A: u32, let B: u32>(before: str<A>, after: str<B>) -> [u8; 2048] {
    doc_from(T_HEAD, before, after)
}

#[test]
fn test_reads_plain_invoice() {
    let f = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvNum=\"ab123cd456/7/2026/ef789gh012\" InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1250.00\" TotPriceWoVAT=\"1033.06\"><Items></Items></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.uuid == 0x00000000000040008000_0000000000aa);
    assert(f.iic == 0xff);
    assert(f.ordinal == 7);
    assert(f.issue_year == 2026);
    assert(f.issue_ts == 20260314092653);
    assert(f.issue_zone == 10100);
    assert(!f.total_negative);
    assert(f.total_cents == 125000);
    assert(f.busin_unit_code == 0x61623132336364343536);
    assert(f.tcr_code == 0x65663738396768303132);
}

#[test]
fn test_values_cannot_imitate_attributes() {
    // A free-text value holding '>' and escaped quotes around fake attributes, plus a child element
    // that really has TotPrice and InvOrdNum attributes. Only the start tag's own ones may be read.
    let f = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" Note=\"a > b &quot; TotPrice=&quot;999999.00&quot; InvOrdNum=&quot;1\" TCRCode=\"ef789gh012\" TotPrice=\"-3.50\"><X TotPrice=\"777.00\" InvOrdNum=\"99\"></X></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.ordinal == 7);
    assert(f.total_negative);
    assert(f.total_cents == 350);
}

#[test(should_fail_with = "request: a required attribute is missing or repeated")]
fn test_rejects_repeated_attribute() {
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\" TotPrice=\"1000.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: a required attribute is missing or repeated")]
fn test_rejects_attribute_only_on_child() {
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"><X InvOrdNum=\"7\"></X></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: <Invoice> start tag does not close inside the scan window")]
fn test_rejects_unclosed_tag() {
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\" Note=\"never closed",
    ));
}

#[test(should_fail_with = "request: IIC is not 32 characters")]
fn test_rejects_long_iic() {
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff00\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: single quote at tag level")]
fn test_rejects_single_quoted_value() {
    // A value delimited by single quotes. An XML parser accepts it; canonical XML never writes it.
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" Note='x y' TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test]
fn test_single_quote_inside_a_value_is_fine() {
    let f = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" Note=\"it's fine\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.total_cents == 100);
}

#[test(should_fail_with = "request: header template mismatch")]
fn test_rejects_other_message_type() {
    let mut doc: [u8; 2048] = [0; 2048];
    let s = "<RegisterTCRRequest xmlns=\"https://efi.tax.gov.me/fs/schema\" Id=\"Request\" Version=\"1\"><Header SendDateTime=\"2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><TCR></TCR></RegisterTCRRequest>"
        .as_bytes();
    for i in 0..s.len() {
        doc[i] = s[i];
    }
    let _ = extract_request_fields(MONTENEGRO, doc);
}

#[test(should_fail_with = "request: namespace declaration on <Invoice>")]
fn test_rejects_namespace_declaration() {
    // With a namespace of its own this is no longer the EFI Invoice element.
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\" xmlns=\"urn:x\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: namespace declaration on <Invoice>")]
fn test_rejects_prefixed_namespace_declaration() {
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\" xmlns:p=\"urn:x\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test]
fn test_xmlns_inside_a_value_is_fine() {
    let f = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" Note=\"about xmlns and more\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.ordinal == 7);
}

#[test(should_fail_with = "request: tab or line break at tag level")]
fn test_rejects_tab_separated_attribute() {
    // A second TotPrice after a tab: this scan would not see it, an XML parser would.
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"\tTotPrice=\"999.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: tab or line break at tag level")]
fn test_rejects_line_break_at_tag_level() {
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\"\n TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "integer: leading zero")]
fn test_rejects_ordinal_zero() {
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"0\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

// Signed length of a `doc_with` document: header, attributes before, IICSignature, rest.
fn doc_len_with(before: u32, after: u32) -> u32 {
    200 + before + 15 + 512 + 1 + after
}

#[test]
fn test_document_must_end_with_closing_tags() {
    let before = " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"";
    let after = " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"><Items></Items></Invoice></RegisterInvoiceRequest>";
    let len = doc_len_with(before.as_bytes().len(), after.as_bytes().len());
    let (f, _) = request_fields_and_digest(MONTENEGRO, doc_with(before, after), len);
    assert(f.total_cents == 100);
}

#[test(should_fail_with = "request: document does not end with its closing tags")]
fn test_rejects_signed_length_cut_short() {
    // The same document, signed one byte short of its end.
    let before = " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"";
    let after = " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"><Items></Items></Invoice></RegisterInvoiceRequest>";
    let len = doc_len_with(before.as_bytes().len(), after.as_bytes().len());
    let _ = request_fields_and_digest(MONTENEGRO, doc_with(before, after), len - 1);
}

#[test(should_fail_with = "request: <Invoice> start tag runs past the signed document")]
fn test_rejects_signed_length_ending_at_the_start_tag() {
    // Signed bytes stop right after the '>' of the start tag: no children, no closing tags.
    let before = " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"";
    let after = " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\">";
    let len = doc_len_with(before.as_bytes().len(), after.as_bytes().len());
    let _ = request_fields_and_digest(MONTENEGRO, doc_with(before, after), len);
}

// --- Times in every spelling, and the late-delivery mark ---

// Test helper: a Montenegrin request whose header is given from the value of SendDateTime on
// (the header's length varies, so the pieces are joined at run time) and whose IssueDateTime is
// `issue`. Returns the document and its signed length.
fn doc_with_header<let N: u32, let I: u32>(header_rest: str<N>, issue: str<I>) -> ([u8; 2048], u32) {
    let mut out: [u8; 2048] = [0; 2048];
    let mut o: u32 = 0;
    let head = MONTENEGRO.request_head;
    for i in 0..112 {
        out[i] = head[i];
    }
    o += 112;
    let h = header_rest.as_bytes();
    for i in 0..N {
        out[o + i] = h[i];
    }
    o += N;
    let a = " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\" InvOrdNum=\"7\" IssueDateTime=\""
        .as_bytes();
    for i in 0..a.len() {
        out[o + i] = a[i];
    }
    o += a.len();
    let t = issue.as_bytes();
    for i in 0..I {
        out[o + i] = t[i];
    }
    o += I;
    let b = "\" TCRCode=\"ef789gh012\" TotPrice=\"1250.00\"><Items></Items></Invoice></RegisterInvoiceRequest>"
        .as_bytes();
    for i in 0..b.len() {
        out[o + i] = b[i];
    }
    (out, o + b.len())
}

fn fields_with_header<let N: u32, let I: u32>(header_rest: str<N>, issue: str<I>) -> RequestFields {
    let (doc, len) = doc_with_header(header_rest, issue);
    let (f, _) = request_fields_and_digest(MONTENEGRO, doc, len);
    f
}

#[test]
fn test_reads_times_written_in_utc_with_z() {
    let f = fields_with_header(
        "2026-03-14T08:26:55Z\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T08:26:53Z",
    );
    assert(f.uuid == 0x00000000000040008000_0000000000aa);
    assert(f.ordinal == 7);
    assert(f.issue_year == 2026);
    assert(f.issue_ts == 20260314082653);
    assert(f.issue_zone == 30000);
    assert(f.total_cents == 125000);
    assert(f.tcr_code == 0x65663738396768303132);
}

#[test]
fn test_reads_times_written_with_offset_zero() {
    let f = fields_with_header(
        "2026-03-14T08:26:55+00:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T08:26:53+00:00",
    );
    assert(f.issue_ts == 20260314082653);
    assert(f.issue_zone == 10000);
    assert(f.issue_year == 2026);
}

#[test]
fn test_reads_times_written_west_of_utc() {
    let f = fields_with_header(
        "2026-03-14T03:26:55-05:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T03:56:53-04:30",
    );
    assert(f.issue_ts == 20260314035653);
    assert(f.issue_zone == 20430);
    assert(f.issue_year == 2026);
}

#[test]
fn test_header_and_invoice_may_spell_their_times_differently() {
    let f = fields_with_header(
        "2026-03-14T08:26:55Z\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
    assert(f.issue_zone == 10100);
    let g = fields_with_header(
        "2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T08:26:53Z",
    );
    assert(g.issue_zone == 30000);
    assert(g.uuid == f.uuid);
}

#[test]
fn test_year_is_the_one_on_the_countrys_clock() {
    // Half past midnight on 1 January 2027 in Podgorica, as software that writes UTC puts it.
    let z = fields_with_header(
        "2026-12-31T23:30:02Z\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-12-31T23:30:00Z",
    );
    assert(z.issue_year == 2027);
    assert(z.issue_ts == 20261231233000); // kept as written
    let p = fields_with_header(
        "2026-12-31T23:30:02+00:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-12-31T23:30:00+00:00",
    );
    assert(p.issue_year == 2027);
    // An hour earlier it is still 2026 there.
    let before = fields_with_header(
        "2026-12-31T22:30:02Z\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-12-31T22:30:00Z",
    );
    assert(before.issue_year == 2026);
    // The same moment written on the country's own clock.
    let local = fields_with_header(
        "2027-01-01T00:30:02+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2027-01-01T00:30:00+01:00",
    );
    assert(local.issue_year == 2027);
}

#[test]
fn test_reads_every_late_delivery_word() {
    let a = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"NOINTERNET\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
    let b = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"BOUNDBOOK\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
    let c = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"SERVICE\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
    let d = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"TECHNICALERROR\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
    let e = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"BUSINESSNEEDS\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
    let plain = fields_with_header(
        "2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
    // The mark changes where everything after it sits and nothing that is read.
    for f in [a, b, c, d, e] {
        assert(f.uuid == plain.uuid);
        assert(f.iic == plain.iic);
        assert(f.ordinal == plain.ordinal);
        assert(f.issue_ts == plain.issue_ts);
        assert(f.total_cents == plain.total_cents);
        assert(f.busin_unit_code == plain.busin_unit_code);
        assert(f.tcr_code == plain.tcr_code);
    }
    assert(a.tag_end == plain.tag_end + 29);
    assert(d.tag_end == plain.tag_end + 33);
}

#[test]
fn test_late_delivery_mark_after_a_utc_time() {
    let f = fields_with_header(
        "2026-03-14T08:26:55Z\" SubseqDelivType=\"TECHNICALERROR\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T08:26:53Z",
    );
    assert(f.uuid == 0x00000000000040008000_0000000000aa);
    assert(f.ordinal == 7);
    assert(f.issue_zone == 30000);
}

#[test(should_fail_with = "request: SubseqDelivType is not a word the schema has")]
fn test_rejects_unknown_late_delivery_word() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"POWERCUT\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "request: SubseqDelivType is not a word the schema has")]
fn test_rejects_late_delivery_word_with_a_tail() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"SERVICES\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "request: SubseqDelivType is not a word the schema has")]
fn test_rejects_late_delivery_word_in_lower_case() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"service\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "request: SubseqDelivType is not a word the schema has")]
fn test_rejects_empty_late_delivery_word() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "request: SubseqDelivType is not a word the schema has")]
fn test_late_delivery_value_cannot_carry_a_second_identifier() {
    // Text in the value that looks like the rest of a header, with another UUID.
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"SERVICE&quot; UUID=&quot;11111111-1111-4111-8111-111111111111\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "request: header template mismatch")]
fn test_rejects_late_delivery_mark_written_twice() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" SubseqDelivType=\"SERVICE\" SubseqDelivType=\"SERVICE\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "request: header template mismatch")]
fn test_rejects_identifier_written_twice() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" UUID=\"11111111-1111-4111-8111-111111111111\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "request: header template mismatch")]
fn test_rejects_late_delivery_mark_after_the_identifier() {
    // Not the canonical order of attributes.
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\" SubseqDelivType=\"SERVICE\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "request: header template mismatch")]
fn test_rejects_another_attribute_in_the_header() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" Source=\"x\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "request: header template mismatch")]
fn test_rejects_two_spaces_in_the_header() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\"  UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "datetime: expected '+', '-' or 'Z'")]
fn test_rejects_send_time_without_zone() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "datetime: not closed after 'Z'")]
fn test_rejects_send_time_with_text_after_z() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55Z0\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00",
    );
}

#[test(should_fail_with = "datetime: expected '+', '-' or 'Z'")]
fn test_rejects_issue_time_without_zone() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53",
    );
}

#[test(should_fail_with = "datetime: expected '+', '-' or 'Z'")]
fn test_rejects_issue_time_with_fraction() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53.5+01:00",
    );
}

#[test(should_fail_with = "datetime: not closed after the offset")]
fn test_rejects_issue_time_with_text_after_offset() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+01:00Z",
    );
}

#[test(should_fail_with = "datetime: offset out of range")]
fn test_rejects_issue_time_with_offset_of_15_hours() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14T09:26:53+15:00",
    );
}

#[test(should_fail_with = "datetime: expected 'T'")]
fn test_rejects_issue_time_with_a_space() {
    let _ = fields_with_header(
        "2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice",
        "2026-03-14 09:26:53+01:00",
    );
}

// --- The same reader under another format: Albania, where a non-cash invoice has no device code ---
global T_HEAD_AL: str<230> = "<RegisterInvoiceRequest xmlns=\"https://eFiskalizimi.tatime.gov.al/FiscalizationService/schema\" Id=\"Request\" Version=\"3\"><Header SendDateTime=\"2026-03-14T09:26:55+01:00\" UUID=\"00000000-0000-4000-8000-0000000000aa\"></Header><Invoice";

fn doc_with_al<let A: u32, let B: u32>(before: str<A>, after: str<B>) -> [u8; 2048] {
    doc_from(T_HEAD_AL, before, after)
}

#[test]
fn test_albania_reads_invoice_without_device() {
    let f = extract_request_fields(ALBANIA, doc_with_al(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvNum=\"7/2026\" InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TotPrice=\"1250.00\" TotPriceWoVAT=\"1033.06\"><Items></Items></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.uuid == 0x00000000000040008000_0000000000aa);
    assert(f.iic == 0xff);
    assert(f.ordinal == 7);
    assert(f.issue_year == 2026);
    assert(f.total_cents == 125000);
    assert(f.busin_unit_code == 0x61623132336364343536);
    assert(f.tcr_code == 0);
}

#[test]
fn test_albania_reads_device_when_present() {
    let f = extract_request_fields(ALBANIA, doc_with_al(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvNum=\"7/2026/ef789gh012\" InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1250.00\"><Items></Items></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.ordinal == 7);
    assert(f.tcr_code == 0x65663738396768303132);
}

#[test(should_fail_with = "request: TCRCode is repeated")]
fn test_albania_rejects_repeated_device() {
    let _ = extract_request_fields(ALBANIA, doc_with_al(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TCRCode=\"zz789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test]
fn test_albania_device_on_a_child_is_not_read() {
    // The start tag has no device code; a child element has an attribute of that name.
    let f = extract_request_fields(ALBANIA, doc_with_al(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" Note=\"no TCRCode=&quot;ef789gh012&quot; here\" TotPrice=\"1.00\"><X TCRCode=\"ef789gh012\"></X></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.tcr_code == 0);
    assert(f.total_cents == 100);
}

#[test(should_fail_with = "request: TCRCode is not 10 characters")]
fn test_albania_rejects_long_device() {
    let _ = extract_request_fields(ALBANIA, doc_with_al(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh0123\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: a required attribute is missing or repeated")]
fn test_montenegro_requires_device() {
    let _ = extract_request_fields(MONTENEGRO, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: header template mismatch")]
fn test_albania_rejects_montenegrin_request() {
    let _ = extract_request_fields(ALBANIA, doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: header template mismatch")]
fn test_montenegro_rejects_albanian_request() {
    let _ = extract_request_fields(MONTENEGRO, doc_with_al(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}
