// pf_efi - Montenegro EFI (law 46/2019) message layer on top of pf_xmldsig.
//
//   request   taxpayer-signed RegisterInvoiceRequest  -> invoice facts
//   response  authority-signed RegisterInvoiceResponse -> receipt facts
//   batch     K invoices, each with its receipt, as one statement
//   agg       leaves of K invoices and a root over them, for more than one circuit can hold
pub mod request;
pub mod response;
pub mod batch;
pub mod agg;
