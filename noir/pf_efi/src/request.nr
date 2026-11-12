// Taxpayer-signed `RegisterInvoiceRequest`.
//
// This is the TAXPAYER's signature. It makes the taxpayer accountable for the content; it does not
// show that the tax authority saw this content. The link to the authority is the header UUID, which
// the authority's signed response repeats (see response.nr).
//
// How fields are read without an XML parser:
//   * The header is matched against a fixed canonical template, so UUID sits at a fixed offset and
//     the <Invoice> start tag begins at a fixed offset.
//   * Inside that start tag a one-pass scan tracks "inside a quoted value" and "tag still open".
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
// Known liveness limits: header without SubseqDelivType; SendDateTime/IssueDateTime with the
// offset +01:00 or +02:00; document up to M bytes; <Invoice> start tag up to TAG_WINDOW bytes.
// Not extracted: seller TIN, IICSignature, invoice type, corrective references.

use pf_xmldsig::{
    parse_amount_until_quote, parse_datetime, parse_hex32, parse_registration_code,
    parse_uint_until_quote, parse_uuid, signed_info_digest_request,
};

pub global TAG_WINDOW: u32 = 1280;

// --- Canonical header template ---
global HDR_P0: [u8; 112] = "<RegisterInvoiceRequest xmlns=\"https://efi.tax.gov.me/fs/schema\" Id=\"Request\" Version=\"1\"><Header SendDateTime=\""
    .as_bytes();
global HDR_P1: [u8; 8] = "\" UUID=\"".as_bytes();
global HDR_P2: [u8; 19] = "\"></Header><Invoice".as_bytes();
global OFF_SEND_DT: u32 = 112;
global OFF_HDR_P1: u32 = 137;
global OFF_UUID: u32 = 145;
global OFF_HDR_P2: u32 = 181;
pub global TAG_START: u32 = 200; // the space right after "<Invoice"

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
    pub tcr_code: Field,
    pub ordinal: u64,
    pub issue_year: u32,
    pub issue_local_ts: Field,
    pub issue_tz: Field,
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

/// One pass over the <Invoice ...> start tag. Returns, for each wanted attribute, the offset of the
/// first byte of its value (the entry at A_XMLNS is unused), plus the offset of the '>' that closes
/// the tag.
fn scan_invoice_tag<let M: u32>(doc: [u8; M]) -> ([u32; 7], u32) {
    assert(doc[TAG_START] == 32, "request: '<Invoice' is not followed by an attribute");

    let mut win: [Field; 7] = [0; 7];
    for a in 0..N_ATTR {
        let mut v: Field = 0;
        for j in 0..PAT_LEN[a] {
            v = v * 256 + (doc[TAG_START + j] as Field);
        }
        win[a] = v;
    }

    let mut in_quote: Field = 0;
    let mut in_tag: Field = 1;
    let mut count: [Field; 7] = [0; 7];
    let mut value_at: [Field; 7] = [0; 7];
    let mut tag_end: Field = 0;
    let mut stray_single_quotes: Field = 0;
    let mut stray_whitespace: Field = 0;

    for k in 0..TAG_WINDOW {
        let i = TAG_START + k;
        let c = doc[i] as Field;
        let outside = in_tag * (1 - in_quote); // 1 iff byte i is tag-level text of the open tag

        for a in 0..N_ATTR {
            let hit = ((win[a] == PAT[a]) as Field) * outside;
            count[a] += hit;
            value_at[a] += hit * ((i + PAT_LEN[a]) as Field);
            win[a] = (win[a] - c * PAT_TOP[a]) * 256 + (doc[i + PAT_LEN[a]] as Field);
        }

        let is_quote = (doc[i] == 34) as Field;
        stray_single_quotes += ((doc[i] == 39) as Field) * outside;
        stray_whitespace += (((doc[i] == 9) | (doc[i] == 10) | (doc[i] == 13)) as Field) * outside;
        let closes = ((doc[i] == 62) as Field) * outside;
        tag_end += closes * (i as Field);
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
        } else {
            assert(count[a] == 1, "request: a required attribute is missing or repeated");
            offsets[a] = value_at[a] as u32;
        }
    }
    (offsets, tag_end as u32)
}

pub fn extract_request_fields<let M: u32>(doc: [u8; M]) -> RequestFields {
    // Header: fixed template, so UUID and the start of <Invoice are at fixed offsets.
    for i in 0..112 {
        assert(doc[i] == HDR_P0[i], "request: header template mismatch");
    }
    for i in 0..8 {
        assert(doc[OFF_HDR_P1 + i] == HDR_P1[i], "request: header template mismatch");
    }
    for i in 0..19 {
        assert(doc[OFF_HDR_P2 + i] == HDR_P2[i], "request: header template mismatch");
    }
    let _ = parse_datetime(read(doc, OFF_SEND_DT)); // constrains the 25 SendDateTime characters
    let uuid = parse_uuid(read(doc, OFF_UUID));

    let (at, tag_end) = scan_invoice_tag(doc);

    // Fixed-length values must be followed by their closing quote.
    let busin_unit_code = parse_registration_code(read(doc, at[A_BU]));
    assert(doc[at[A_BU] + 10] == 34, "request: BusinUnitCode is not 10 characters");
    let tcr_code = parse_registration_code(read(doc, at[A_TCR]));
    assert(doc[at[A_TCR] + 10] == 34, "request: TCRCode is not 10 characters");
    let iic = parse_hex32(read(doc, at[A_IIC]));
    assert(doc[at[A_IIC] + 32] == 34, "request: IIC is not 32 characters");
    let issue: [u8; 25] = read(doc, at[A_ISSUE]);
    let (issue_local_ts, issue_tz) = parse_datetime(issue);
    assert(doc[at[A_ISSUE] + 25] == 34, "request: IssueDateTime is not 25 characters");
    // The four year characters were constrained to digits by parse_datetime.
    let issue_year = ((issue[0] - 48) as u32) * 1000
        + ((issue[1] - 48) as u32) * 100
        + ((issue[2] - 48) as u32) * 10
        + ((issue[3] - 48) as u32);

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
        issue_local_ts,
        issue_tz,
        total_negative,
        total_cents,
        tag_end,
    }
}

/// Fields of a request plus the digest its XML-DSig signature must cover. `doc` is the canonical
/// request with the enveloped signature removed, zero-padded to M; only `doc_len` bytes are signed.
pub fn request_fields_and_digest<let M: u32>(doc: [u8; M], doc_len: u32) -> (RequestFields, [u8; 32]) {
    assert(doc_len <= M, "request: document longer than the circuit allows");
    let f = extract_request_fields(doc);
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

/// Test helper: header || attrs_before || ` IICSignature="..."` || attrs_after_and_rest, zero-padded.
/// (IICSignature is a real attribute the reader does not use; it sits where real requests have it.)
fn doc_with<let A: u32, let B: u32>(before: str<A>, after: str<B>) -> [u8; 2048] {
    let mut out: [u8; 2048] = [0; 2048];
    let mut o: u32 = 0;
    let head = T_HEAD.as_bytes();
    for i in 0..200 {
        out[o + i] = head[i];
    }
    o += 200;
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

#[test]
fn test_reads_plain_invoice() {
    let f = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvNum=\"ab123cd456/7/2026/ef789gh012\" InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1250.00\" TotPriceWoVAT=\"1033.06\"><Items></Items></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.uuid == 0x00000000000040008000_0000000000aa);
    assert(f.iic == 0xff);
    assert(f.ordinal == 7);
    assert(f.issue_year == 2026);
    assert(f.issue_local_ts == 20260314092653);
    assert(f.issue_tz == 10100);
    assert(!f.total_negative);
    assert(f.total_cents == 125000);
    assert(f.busin_unit_code == 0x61623132336364343536);
    assert(f.tcr_code == 0x65663738396768303132);
}

#[test]
fn test_values_cannot_imitate_attributes() {
    // A free-text value holding '>' and escaped quotes around fake attributes, plus a child element
    // that really has TotPrice and InvOrdNum attributes. Only the start tag's own ones may be read.
    let f = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" Note=\"a > b &quot; TotPrice=&quot;999999.00&quot; InvOrdNum=&quot;1\" TCRCode=\"ef789gh012\" TotPrice=\"-3.50\"><X TotPrice=\"777.00\" InvOrdNum=\"99\"></X></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.ordinal == 7);
    assert(f.total_negative);
    assert(f.total_cents == 350);
}

#[test(should_fail_with = "request: a required attribute is missing or repeated")]
fn test_rejects_repeated_attribute() {
    let _ = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\" TotPrice=\"1000.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: a required attribute is missing or repeated")]
fn test_rejects_attribute_only_on_child() {
    let _ = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"><X InvOrdNum=\"7\"></X></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: <Invoice> start tag does not close inside the scan window")]
fn test_rejects_unclosed_tag() {
    let _ = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\" Note=\"never closed",
    ));
}

#[test(should_fail_with = "request: IIC is not 32 characters")]
fn test_rejects_long_iic() {
    let _ = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff00\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: single quote at tag level")]
fn test_rejects_single_quoted_value() {
    // A value delimited by single quotes. An XML parser accepts it; canonical XML never writes it.
    let _ = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" Note='x y' TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test]
fn test_single_quote_inside_a_value_is_fine() {
    let f = extract_request_fields(doc_with(
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
    let _ = extract_request_fields(doc);
}

#[test(should_fail_with = "request: namespace declaration on <Invoice>")]
fn test_rejects_namespace_declaration() {
    // With a namespace of its own this is no longer the EFI Invoice element.
    let _ = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\" xmlns=\"urn:x\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: namespace declaration on <Invoice>")]
fn test_rejects_prefixed_namespace_declaration() {
    let _ = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\" xmlns:p=\"urn:x\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test]
fn test_xmlns_inside_a_value_is_fine() {
    let f = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" Note=\"about xmlns and more\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.ordinal == 7);
}

#[test(should_fail_with = "request: tab or line break at tag level")]
fn test_rejects_tab_separated_attribute() {
    // A second TotPrice after a tab: this scan would not see it, an XML parser would.
    let _ = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"\tTotPrice=\"999.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "request: tab or line break at tag level")]
fn test_rejects_line_break_at_tag_level() {
    let _ = extract_request_fields(doc_with(
        " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"",
        " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\"\n TotPrice=\"1.00\"></Invoice></RegisterInvoiceRequest>",
    ));
}

#[test(should_fail_with = "integer: leading zero")]
fn test_rejects_ordinal_zero() {
    let _ = extract_request_fields(doc_with(
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
    let (f, _) = request_fields_and_digest(doc_with(before, after), len);
    assert(f.total_cents == 100);
}

#[test(should_fail_with = "request: document does not end with its closing tags")]
fn test_rejects_signed_length_cut_short() {
    // The same document, signed one byte short of its end.
    let before = " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"";
    let after = " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\"><Items></Items></Invoice></RegisterInvoiceRequest>";
    let len = doc_len_with(before.as_bytes().len(), after.as_bytes().len());
    let _ = request_fields_and_digest(doc_with(before, after), len - 1);
}

#[test(should_fail_with = "request: <Invoice> start tag runs past the signed document")]
fn test_rejects_signed_length_ending_at_the_start_tag() {
    // Signed bytes stop right after the '>' of the start tag: no children, no closing tags.
    let before = " BusinUnitCode=\"ab123cd456\" IIC=\"000000000000000000000000000000ff\"";
    let after = " InvOrdNum=\"7\" IssueDateTime=\"2026-03-14T09:26:53+01:00\" TCRCode=\"ef789gh012\" TotPrice=\"1.00\">";
    let len = doc_len_with(before.as_bytes().len(), after.as_bytes().len());
    let _ = request_fields_and_digest(doc_with(before, after), len);
}
