// The buyer named in a taxpayer-signed `RegisterInvoiceRequest`.
//
// Like everything read from the request, this is the TAXPAYER's word. The authority's receipt does
// not repeat it, and the taxpayer can sign a second request under the same UUID naming another
// buyer. A statement built on it is worth as much as the comparison of opened invoices with what
// the authority has on record (see spot.nr and tools/efi/opening.py).
//
// How the identifier is read without an XML parser:
//   * The seven bytes `<Buyer ` must occur exactly once in the whole byte array. Canonical XML
//     never leaves a raw '<' inside a value or in text, so they can only start an element.
//   * Inside that start tag the same one-pass scan as for <Invoice> (request.nr): ` IDNum="` and
//     ` IDType="` are recognised only outside quoted values while the tag is open, exactly once
//     each. A single quote, a tab or a line break at tag level is refused.
//   * IDType is 2 to 4 capital letters, IDNum is 1 to 20 characters of 0-9, A-Z, a-z.
//   * The caller checks that the start tag closes inside the signed length.
//
// The identifier is the text `IDType:IDNum` packed big-endian into one field element, at most 25
// bytes. ':' occurs in neither part and the first byte is a letter, so two different pairs never
// pack to the same value.
//
// Known liveness limits: the <Buyer> start tag up to BUYER_WINDOW bytes and beginning at least
// BUYER_WINDOW + 9 bytes before the end of the array; an invoice without a <Buyer> element (retail
// sales) is refused by this reader, a statement about buyers has to leave such invoices out.

pub global BUYER_WINDOW: u32 = 400;

global OPEN: Field = 0x3c427579657220; // `<Buyer `
global OPEN_TOP: Field = 0x1000000000000; // 256^6
global P_NUM: Field = 0x2049444e756d3d22; // ` IDNum="`
global P_NUM_TOP: Field = 0x100000000000000; // 256^7
global P_TYPE: Field = 0x204944547970653d22; // ` IDType="`
global P_TYPE_TOP: Field = 0x10000000000000000; // 256^8

pub struct BuyerFields {
    /// `IDType:IDNum`, packed big-endian.
    pub id: Field,
    /// Index of the '>' closing the <Buyer ...> start tag. Callers must check it is inside the
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

/// Index of the space that ends the one `<Buyer ` in `doc`.
fn find_buyer_tag<let M: u32>(doc: [u8; M]) -> u32 {
    let mut win: Field = 0;
    for j in 0..7 {
        win = win * 256 + (doc[j] as Field);
    }
    let mut count: Field = 0;
    let mut at: Field = 0;
    for i in 0..(M - 7) {
        let hit = (win == OPEN) as Field;
        count += hit;
        at += hit * ((i + 6) as Field);
        win = (win - (doc[i] as Field) * OPEN_TOP) * 256 + (doc[i + 7] as Field);
    }
    let hit = (win == OPEN) as Field;
    count += hit;
    at += hit * ((M - 1) as Field);
    assert(count == 1, "buyer: <Buyer> is missing or repeated");
    at as u32
}

/// One pass over the <Buyer ...> start tag, `start` being the space after `<Buyer`. Returns the
/// offsets of the first byte of the IDNum and IDType values and of the '>' that closes the tag.
fn scan_buyer_tag<let M: u32>(doc: [u8; M], start: u32) -> (u32, u32, u32) {
    let mut win_num: Field = 0;
    for j in 0..8 {
        win_num = win_num * 256 + (doc[start + j] as Field);
    }
    let mut win_type: Field = 0;
    for j in 0..9 {
        win_type = win_type * 256 + (doc[start + j] as Field);
    }

    let mut in_quote: Field = 0;
    let mut in_tag: Field = 1;
    let mut n_num: Field = 0;
    let mut n_type: Field = 0;
    let mut num_at: Field = 0;
    let mut type_at: Field = 0;
    let mut tag_end: Field = 0;
    let mut stray_single_quotes: Field = 0;
    let mut stray_whitespace: Field = 0;

    for k in 0..BUYER_WINDOW {
        let i = start + k;
        let b = doc[i];
        let c = b as Field;
        let outside = in_tag * (1 - in_quote); // 1 iff byte i is tag-level text of the open tag

        let hit_num = ((win_num == P_NUM) as Field) * outside;
        n_num += hit_num;
        num_at += hit_num * ((i + 8) as Field);
        win_num = (win_num - c * P_NUM_TOP) * 256 + (doc[i + 8] as Field);

        let hit_type = ((win_type == P_TYPE) as Field) * outside;
        n_type += hit_type;
        type_at += hit_type * ((i + 9) as Field);
        win_type = (win_type - c * P_TYPE_TOP) * 256 + (doc[i + 9] as Field);

        let is_quote = (b == 34) as Field;
        stray_single_quotes += ((b == 39) as Field) * outside;
        stray_whitespace += (((b == 9) | (b == 10) | (b == 13)) as Field) * outside;
        let closes = ((b == 62) as Field) * outside;
        tag_end += closes * (i as Field);
        in_tag -= closes;
        in_quote = in_quote + is_quote - 2 * in_quote * is_quote;
    }

    assert(in_tag == 0, "buyer: <Buyer> start tag does not close inside the scan window");
    assert(stray_single_quotes == 0, "buyer: single quote at tag level");
    assert(stray_whitespace == 0, "buyer: tab or line break at tag level");
    assert(n_num == 1, "buyer: IDNum is missing or repeated");
    assert(n_type == 1, "buyer: IDType is missing or repeated");
    (num_at as u32, type_at as u32, tag_end as u32)
}

/// IDType: 2 to 4 capital letters terminated by '"' -> the letters packed big-endian.
fn pack_id_type(b: [u8; 5]) -> Field {
    let mut acc: Field = 0;
    let mut len: u32 = 0;
    let mut done = false;
    for j in 0..5 {
        if !done {
            if b[j] == 34 {
                done = true;
            } else {
                assert((b[j] >= 65) & (b[j] <= 90), "buyer: IDType is not 2 to 4 capital letters");
                acc = acc * 256 + (b[j] as Field);
                len += 1;
            }
        }
    }
    assert(done & (len >= 2), "buyer: IDType is not 2 to 4 capital letters");
    acc
}

/// IDNum: 1 to 20 characters of 0-9, A-Z, a-z terminated by '"' -> (the characters packed
/// big-endian, 256^(their number)).
fn pack_id_num(b: [u8; 21]) -> (Field, Field) {
    let mut acc: Field = 0;
    let mut pow: Field = 1;
    let mut len: u32 = 0;
    let mut done = false;
    for j in 0..21 {
        if !done {
            if b[j] == 34 {
                done = true;
            } else {
                let c = b[j];
                let ok = ((c >= 48) & (c <= 57)) | ((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122));
                assert(ok, "buyer: IDNum has a character outside 0-9, A-Z, a-z");
                acc = acc * 256 + (c as Field);
                pow = pow * 256;
                len += 1;
            }
        }
    }
    assert(done & (len >= 1), "buyer: IDNum is empty or longer than 20 characters");
    (acc, pow)
}

pub fn extract_buyer<let M: u32>(doc: [u8; M]) -> BuyerFields {
    let start = find_buyer_tag(doc);
    let (num_at, type_at, tag_end) = scan_buyer_tag(doc, start);
    let kind = pack_id_type(read(doc, type_at));
    let (num, pow) = pack_id_num(read(doc, num_at));
    BuyerFields { id: (kind * 256 + 58) * pow + num, tag_end }
}

/// The buyer identifier of a request whose first `doc_len` bytes are the signed ones. The whole
/// <Buyer ...> start tag must lie before the two closing tags that end the signed document.
pub fn buyer_of_signed_request<let M: u32>(doc: [u8; M], doc_len: u32) -> Field {
    assert(doc_len <= M, "buyer: document longer than the circuit allows");
    let f = extract_buyer(doc);
    assert(f.tag_end + 35 < doc_len, "buyer: <Buyer> lies outside the signed document");
    f.id
}

// --- Tests on hand-written documents (no signature involved) ---

fn doc_of<let A: u32>(s: str<A>) -> [u8; 1024] {
    let mut out: [u8; 1024] = [0; 1024];
    let b = s.as_bytes();
    for i in 0..A {
        out[i] = b[i];
    }
    out
}

global TIN_12345678: Field = 0x54494e3a3132333435363738; // "TIN:12345678"

#[test]
fn test_reads_the_buyer_and_not_the_seller() {
    let f = extract_buyer(doc_of(
        "<Invoice TotPrice=\"10.00\"><Seller IDNum=\"71508534\" IDType=\"TIN\" Name=\"S\"></Seller><Buyer IDNum=\"12345678\" IDType=\"TIN\" Name=\"Kupac d.o.o.\"></Buyer><Items></Items></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.id == TIN_12345678);
    assert(f.tag_end == 138);
}

#[test]
fn test_values_cannot_imitate_the_identifier() {
    // Attributes that sort before IDNum, one of them a free text holding '>' and escaped quotes
    // around a fake IDNum; a leading zero in the real one is kept.
    let f = extract_buyer(doc_of(
        "<Invoice><Buyer Address=\"a > b &quot; IDNum=&quot;999&quot; IDType=&quot;VAT\" Country=\"MNE\" IDNum=\"02345678\" IDType=\"TIN\" Name=\"N\" Town=\"T\"></Buyer></Invoice></RegisterInvoiceRequest>",
    ));
    assert(f.id == 0x54494e3a3032333435363738); // "TIN:02345678"
}

#[test]
fn test_type_is_part_of_the_identifier() {
    let vat = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"12345678\" IDType=\"VAT\"></Buyer></Invoice>"));
    assert(vat.id == 0x5641543a3132333435363738); // "VAT:12345678"
    assert(vat.id != TIN_12345678);
    let id = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"AB12cd\" IDType=\"ID\"></Buyer></Invoice>"));
    assert(id.id == 0x49443a414231326364); // "ID:AB12cd"
}

#[test]
fn test_similar_element_names_do_not_count() {
    let f = extract_buyer(doc_of(
        "<Invoice><Buyers IDNum=\"1\" IDType=\"TIN\"></Buyers><Buyer IDNum=\"12345678\" IDType=\"TIN\"></Buyer><BuyerX IDNum=\"2\" IDType=\"TIN\"></BuyerX></Invoice>",
    ));
    assert(f.id == TIN_12345678);
}

#[test(should_fail_with = "buyer: <Buyer> is missing or repeated")]
fn test_rejects_invoice_without_buyer() {
    let _ = extract_buyer(doc_of("<Invoice><Seller IDNum=\"71508534\" IDType=\"TIN\"></Seller><Items></Items></Invoice>"));
}

#[test(should_fail_with = "buyer: <Buyer> is missing or repeated")]
fn test_rejects_two_buyers() {
    let _ = extract_buyer(doc_of(
        "<Invoice><Buyer IDNum=\"12345678\" IDType=\"TIN\"></Buyer><Buyer IDNum=\"87654321\" IDType=\"TIN\"></Buyer></Invoice>",
    ));
}

#[test(should_fail_with = "buyer: IDNum is missing or repeated")]
fn test_rejects_repeated_number() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"12345678\" IDNum=\"87654321\" IDType=\"TIN\"></Buyer></Invoice>"));
}

#[test(should_fail_with = "buyer: IDNum is missing or repeated")]
fn test_rejects_number_only_on_a_child() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDType=\"TIN\" Name=\"N\"><X IDNum=\"12345678\"></X></Buyer></Invoice>"));
}

#[test(should_fail_with = "buyer: IDType is missing or repeated")]
fn test_rejects_missing_type() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"12345678\" Name=\"N\"></Buyer></Invoice>"));
}

#[test(should_fail_with = "buyer: IDNum has a character outside 0-9, A-Z, a-z")]
fn test_rejects_punctuation_in_number() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"1234-5678\" IDType=\"TIN\"></Buyer></Invoice>"));
}

#[test(should_fail_with = "buyer: IDNum is empty or longer than 20 characters")]
fn test_rejects_empty_number() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"\" IDType=\"TIN\"></Buyer></Invoice>"));
}

#[test(should_fail_with = "buyer: IDNum is empty or longer than 20 characters")]
fn test_rejects_long_number() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"123456789012345678901\" IDType=\"TIN\"></Buyer></Invoice>"));
}

#[test(should_fail_with = "buyer: IDType is not 2 to 4 capital letters")]
fn test_rejects_lower_case_type() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"12345678\" IDType=\"tin\"></Buyer></Invoice>"));
}

#[test(should_fail_with = "buyer: IDType is not 2 to 4 capital letters")]
fn test_rejects_long_type() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"12345678\" IDType=\"TINXX\"></Buyer></Invoice>"));
}

#[test(should_fail_with = "buyer: single quote at tag level")]
fn test_rejects_single_quoted_value() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"12345678\" IDType=\"TIN\" Name='N'></Buyer></Invoice>"));
}

#[test(should_fail_with = "buyer: <Buyer> start tag does not close inside the scan window")]
fn test_rejects_unclosed_tag() {
    let _ = extract_buyer(doc_of("<Invoice><Buyer IDNum=\"12345678\" IDType=\"TIN\" Name=\"never closed"));
}

#[test]
fn test_buyer_inside_the_signed_part() {
    // 104 bytes; the start tag closes at index 45.
    let doc = doc_of(
        "<Invoice><Buyer IDNum=\"12345678\" IDType=\"TIN\"></Buyer><Items></Items></Invoice></RegisterInvoiceRequest>",
    );
    assert(buyer_of_signed_request(doc, 104) == TIN_12345678);
}

#[test(should_fail_with = "buyer: <Buyer> lies outside the signed document")]
fn test_rejects_buyer_after_the_signed_bytes() {
    // The element sits in the padding after the 40 signed bytes.
    let doc = doc_of(
        "<Invoice></Invoice></RegisterInvoiceReq><Buyer IDNum=\"12345678\" IDType=\"TIN\"></Buyer>",
    );
    let _ = buyer_of_signed_request(doc, 40);
}
