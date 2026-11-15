// pf_efi - Montenegro EFI (law 46/2019) message layer on top of pf_xmldsig, and the same layer for
// other countries whose fiscalization exchanges the same signed messages.
//
//   format    what differs from one country to another (fixed text, mandatory attributes)
//   request   taxpayer-signed RegisterInvoiceRequest  -> invoice facts
//   buyer     the buyer named in that request
//   response  authority-signed RegisterInvoiceResponse -> receipt facts
//   batch     K invoices, each with its receipt, as one statement
//   debtor    invoices issued to one buyer, as one statement
//   agg       leaves of K invoices and a root over them, for more than one circuit can hold
//   spot      where one opened invoice sits under the root of an aggregated proof
pub mod format;
pub mod request;
pub mod buyer;
pub mod response;
pub mod batch;
pub mod debtor;
pub mod agg;
pub mod spot;
