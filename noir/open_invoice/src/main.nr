// open_invoice - recompute one invoice's opening commitment from its revealed values.
//
// Used by a verifier during a spot check: execute (no proof needed) and compare the output with
// the opening commitment published by the batch proof. See ../pf_efi/src/batch.nr.

use pf_efi::batch::opening_commitment;

fn main(
    iic: Field,
    fic: Field,
    ordinal: Field,
    issue_local_ts: Field,
    issue_tz: Field,
    total_negative: Field,
    total_cents: Field,
    salt: Field,
) -> pub Field {
    opening_commitment(iic, fic, ordinal, issue_local_ts, issue_tz, total_negative, total_cents, salt)
}
