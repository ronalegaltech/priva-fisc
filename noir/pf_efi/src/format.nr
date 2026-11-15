// Country formats.
//
// The fiscalization systems read here (Montenegro, Albania) exchange the same two signed messages
// and sign them the same way. What differs from one country to the other is fixed text (the address
// of the schema, the version, how the response is spelled) and which invoice attributes are
// mandatory. A `Format` holds exactly that and nothing else.
//
// A circuit is built for one format: the value is a compile-time constant, so each format gives
// its own circuit and its own verification key. A proof made for one format does not verify under
// the key of another.
//
//   MONTENEGRO  written against the published schema and against real messages of the tax
//               administration's test environment.
//   ALBANIA     written against the published specification only ("Fiscalization Service,
//               Technical Specification", version 09, tatime.gov.al). No real signed message has
//               been seen. In particular the response is spelled as in the specification's example,
//               with the prefix `ns2`; a service that spells it otherwise needs another template.
//               A non-cash invoice carries no device code there, so the code is optional.

pub struct Format<let H: u32, let L: u32> {
    /// The canonical request from its first byte up to the value of SendDateTime.
    pub request_head: [u8; H],
    /// The canonical response, with zeros where its four signed values go.
    pub response: [u8; L],
    /// Where in `response` the four values start: RequestUUID (36 bytes), SendDateTime (25),
    /// UUID (36), FIC (36).
    pub at_request_uuid: u32,
    pub at_send_date_time: u32,
    pub at_response_uuid: u32,
    pub at_fic: u32,
    /// Whether every invoice names the device that issued it (TCRCode). Where it does not, an
    /// invoice without one has device 0.
    pub device_required: bool,
}

pub global MONTENEGRO: Format<112, 318> = Format {
    request_head: "<RegisterInvoiceRequest xmlns=\"https://efi.tax.gov.me/fs/schema\" Id=\"Request\" Version=\"1\"><Header SendDateTime=\""
        .as_bytes(),
    response: "<RegisterInvoiceResponse xmlns=\"https://efi.tax.gov.me/fs/schema\" Id=\"Response\" Version=\"1\"><Header RequestUUID=\"00000000-0000-0000-0000-000000000000\" SendDateTime=\"0000-00-00T00:00:00+00:00\" UUID=\"00000000-0000-0000-0000-000000000000\"></Header><FIC>00000000-0000-0000-0000-000000000000</FIC></RegisterInvoiceResponse>"
        .as_bytes(),
    at_request_uuid: 113,
    at_send_date_time: 165,
    at_response_uuid: 198,
    at_fic: 250,
    device_required: true,
};

pub global ALBANIA: Format<142, 376> = Format {
    request_head: "<RegisterInvoiceRequest xmlns=\"https://eFiskalizimi.tatime.gov.al/FiscalizationService/schema\" Id=\"Request\" Version=\"3\"><Header SendDateTime=\""
        .as_bytes(),
    response: "<ns2:RegisterInvoiceResponse xmlns:ns2=\"https://eFiskalizimi.tatime.gov.al/FiscalizationService/schema\" Id=\"Response\" Version=\"3\"><ns2:Header RequestUUID=\"00000000-0000-0000-0000-000000000000\" SendDateTime=\"0000-00-00T00:00:00+00:00\" UUID=\"00000000-0000-0000-0000-000000000000\"></ns2:Header><ns2:FIC>00000000-0000-0000-0000-000000000000</ns2:FIC></ns2:RegisterInvoiceResponse>"
        .as_bytes(),
    at_request_uuid: 155,
    at_send_date_time: 207,
    at_response_uuid: 240,
    at_fic: 300,
    device_required: false,
};

// The placeholders in a response template, as written above.
global ZERO_UUID: [u8; 36] = "00000000-0000-0000-0000-000000000000".as_bytes();
global ZERO_TIME: [u8; 25] = "0000-00-00T00:00:00+00:00".as_bytes();

/// The four values sit where the offsets say, each between the characters that delimit it.
fn layout_is_consistent<let H: u32, let L: u32>(f: Format<H, L>) {
    for i in 0..36 {
        assert(f.response[f.at_request_uuid + i] == ZERO_UUID[i]);
        assert(f.response[f.at_response_uuid + i] == ZERO_UUID[i]);
        assert(f.response[f.at_fic + i] == ZERO_UUID[i]);
    }
    for i in 0..25 {
        assert(f.response[f.at_send_date_time + i] == ZERO_TIME[i]);
    }
    // Attribute values end at a double quote, the FIC text at the '<' of its closing tag.
    assert(f.response[f.at_request_uuid - 1] == 34);
    assert(f.response[f.at_request_uuid + 36] == 34);
    assert(f.response[f.at_send_date_time - 1] == 34);
    assert(f.response[f.at_send_date_time + 25] == 34);
    assert(f.response[f.at_response_uuid - 1] == 34);
    assert(f.response[f.at_response_uuid + 36] == 34);
    assert(f.response[f.at_fic - 1] == 62);
    assert(f.response[f.at_fic + 36] == 60);
    // In order, without overlap.
    assert(f.at_request_uuid + 36 < f.at_send_date_time);
    assert(f.at_send_date_time + 25 < f.at_response_uuid);
    assert(f.at_response_uuid + 36 < f.at_fic);
    assert(f.at_fic + 36 < L);
    // The request head ends where the SendDateTime value begins.
    assert(f.request_head[H - 1] == 34);
}

#[test]
fn test_montenegro_layout() {
    layout_is_consistent(MONTENEGRO);
}

#[test]
fn test_albania_layout() {
    layout_is_consistent(ALBANIA);
}
