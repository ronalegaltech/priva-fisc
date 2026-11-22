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
// Known liveness limit: SendDateTime written with an offset (25 characters, any offset). The schema
// also allows "Z", which would make the response five bytes shorter; the one real response seen
// carries an offset.

use crate::format::Format;
use pf_xmldsig::{date_on_clock, parse_datetime, parse_uuid, signed_info_digest_response};

pub struct ResponseFields {
    pub request_uuid: Field,
    pub response_uuid: Field,
    pub fic: Field,
    /// SendDateTime as written: its digits (YYYYMMDDhhmmss) and how its zone is written.
    pub send_ts: Field,
    pub send_zone: Field,
    /// Year, and month * 100 + day, of SendDateTime on the country's clock (format.nr): the only
    /// date in the whole record that the authority itself signed.
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
    let send = parse_datetime(send_date_time);
    let (send_year, send_month_day) = date_on_clock(send, format.new_year_clock);
    let fields = ResponseFields {
        request_uuid: parse_uuid(request_uuid),
        response_uuid: parse_uuid(response_uuid),
        fic: parse_uuid(fic),
        send_ts: send.written,
        send_zone: send.zone,
        send_year,
        send_month_day,
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
