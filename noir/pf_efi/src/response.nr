// Authority-signed `RegisterInvoiceResponse`.
//
// What the authority's signature binds is ONLY (RequestUUID, SendDateTime, UUID, FIC). It does not
// bind invoice content, the taxpayer, or the ordinal - those are in the taxpayer-signed request.
//
// The canonical response has a fixed layout (318 bytes), so no document bytes are accepted: the
// only byte string hashed is built here from the template plus four character-class-checked fields.
// Canonicalization done outside the circuit can therefore affect liveness only, never soundness.
//
// Known liveness limit: SendDateTime with a numeric offset (25 chars; the schema also allows "Z").

use pf_xmldsig::{parse_datetime, parse_uuid, signed_info_digest_response};

global DOC_P0: [u8; 113] = "<RegisterInvoiceResponse xmlns=\"https://efi.tax.gov.me/fs/schema\" Id=\"Response\" Version=\"1\"><Header RequestUUID=\""
    .as_bytes();
global DOC_P1: [u8; 16] = "\" SendDateTime=\"".as_bytes();
global DOC_P2: [u8; 8] = "\" UUID=\"".as_bytes();
global DOC_P3: [u8; 16] = "\"></Header><FIC>".as_bytes();
global DOC_P4: [u8; 32] = "</FIC></RegisterInvoiceResponse>".as_bytes();

global DOC_LEN: u32 = 318;
global OFF_REQ_UUID: u32 = 113;
global OFF_P1: u32 = 149;
global OFF_DT: u32 = 165;
global OFF_P2: u32 = 190;
global OFF_UUID: u32 = 198;
global OFF_P3: u32 = 234;
global OFF_FIC: u32 = 250;
global OFF_P4: u32 = 286;

pub struct ResponseFields {
    pub request_uuid: Field,
    pub response_uuid: Field,
    pub fic: Field,
    pub send_local_ts: Field,
    pub send_tz: Field,
}

/// Fields of a response plus the digest its XML-DSig signature must cover.
pub fn response_fields_and_digest(
    request_uuid: [u8; 36],
    send_date_time: [u8; 25],
    response_uuid: [u8; 36],
    fic: [u8; 36],
) -> (ResponseFields, [u8; 32]) {
    // Field syntax first: after this the document below has exactly one XML reading.
    let (send_local_ts, send_tz) = parse_datetime(send_date_time);
    let fields = ResponseFields {
        request_uuid: parse_uuid(request_uuid),
        response_uuid: parse_uuid(response_uuid),
        fic: parse_uuid(fic),
        send_local_ts,
        send_tz,
    };

    let mut doc: [u8; DOC_LEN] = [0; DOC_LEN];
    for i in 0..113 {
        doc[i] = DOC_P0[i];
    }
    for i in 0..36 {
        doc[OFF_REQ_UUID + i] = request_uuid[i];
    }
    for i in 0..16 {
        doc[OFF_P1 + i] = DOC_P1[i];
    }
    for i in 0..25 {
        doc[OFF_DT + i] = send_date_time[i];
    }
    for i in 0..8 {
        doc[OFF_P2 + i] = DOC_P2[i];
    }
    for i in 0..36 {
        doc[OFF_UUID + i] = response_uuid[i];
    }
    for i in 0..16 {
        doc[OFF_P3 + i] = DOC_P3[i];
    }
    for i in 0..36 {
        doc[OFF_FIC + i] = fic[i];
    }
    for i in 0..32 {
        doc[OFF_P4 + i] = DOC_P4[i];
    }
    (fields, signed_info_digest_response(sha256::digest(doc)))
}
