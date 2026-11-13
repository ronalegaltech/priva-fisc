// buyer_check: the buyer identifier of one request, as pf_efi::buyer reads it. Executed only, by
// tools/efi/test_buyer.py, on whole requests of real shape, to check the reader against the Python
// reference the tools use (tools/efi/buyer.py). No signature is checked here.

use pf_efi::buyer::buyer_of_signed_request;

global M: u32 = 2048; // maximum canonical request size in bytes, as in the batch circuits

fn main(doc: [u8; M], doc_len: u32) -> pub Field {
    buyer_of_signed_request(doc, doc_len)
}
