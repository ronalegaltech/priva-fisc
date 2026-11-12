// open_invoice - one invoice's opening commitment from its revealed values, in circuit form.
//
// Executed only (no proof). tools/efi/opening.py computes the same value in Python during a spot
// check; tools/efi/test_poseidon2.py checks that the two agree. See ../pf_efi/src/batch.nr.

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
