// Authority-signed `RegisterInvoiceResponse`.
//
// What the authority's signature binds is ONLY (RequestUUID, SendDateTime, UUID, FIC). It does not
// bind invoice content, the taxpayer, or the ordinal - those are in the taxpayer-signed request.
//
// The canonical response has a fixed layout (318 bytes in the Montenegrin format), so no document
// bytes are accepted: the only byte string hashed is built here from the format's template
// (format.nr) plus four character-class-checked fields.
// Canonicalization done outside the circuit can therefore affect liveness only, never soundness.
//
// Known liveness limit: SendDateTime with a numeric offset (25 chars; the schema also allows "Z").

use crate::format::Format;
use pf_xmldsig::{parse_datetime, parse_uuid, signed_info_digest_response};

pub struct ResponseFields {
    pub request_uuid: Field,
    pub response_uuid: Field,
    pub fic: Field,
    pub send_local_ts: Field,
    pub send_tz: Field,
    /// Year, and month * 100 + day, of SendDateTime: the only date in the whole record that the
    /// authority itself signed.
    pub send_year: u32,
    pub send_month_day: u32,
}

/// Fields of a response plus the digest its XML-DSig signature must cover.
pub fn response_fields_and_digest<let H: u32, let L: u32>(
    format: Format<H, L>,
    request_uuid: [u8; 36],
    send_date_time: [u8; 25],
    response_uuid: [u8; 36],
    fic: [u8; 36],
) -> (ResponseFields, [u8; 32]) {
    // Field syntax first: after this the document below has exactly one XML reading.
    let (send_local_ts, send_tz) = parse_datetime(send_date_time);
    // parse_datetime constrained these characters to digits.
    let d = |i: u32| (send_date_time[i] - 48) as u32;
    let fields = ResponseFields {
        request_uuid: parse_uuid(request_uuid),
        response_uuid: parse_uuid(response_uuid),
        fic: parse_uuid(fic),
        send_local_ts,
        send_tz,
        send_year: d(0) * 1000 + d(1) * 100 + d(2) * 10 + d(3),
        send_month_day: (d(5) * 10 + d(6)) * 100 + d(8) * 10 + d(9),
    };

    let mut doc = format.response;
    for i in 0..36 {
        doc[format.at_request_uuid + i] = request_uuid[i];
    }
    for i in 0..25 {
        doc[format.at_send_date_time + i] = send_date_time[i];
    }
    for i in 0..36 {
        doc[format.at_response_uuid + i] = response_uuid[i];
    }
    for i in 0..36 {
        doc[format.at_fic + i] = fic[i];
    }
    (fields, signed_info_digest_response(sha256::digest(doc)))
}
