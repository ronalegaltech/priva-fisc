#!/usr/bin/env python3
"""The whole story on invented invoices: an honest taxpayer, then one who inflates an invoice.

  python3 tools/demo.py              # 25 invoices in leaves of up to 10 (about 5 minutes)
  python3 tools/demo.py --quick      # 4 invoices in leaves of 1 (about 2 minutes)

Part 1. A taxpayer proves that its invoices of the year, numbered without a gap, add up to at
least a threshold. The verifier checks the proof, asks for the first invoice and for three
invoices by amount, and compares each opening with what the tax authority has on record.

Part 2. The same invoices are registered, but the taxpayer has signed one of them again showing
500,000.00 more before tax, and claims a threshold the registered invoices do not reach. The proof
is valid: the authority signs only identifiers, so no circuit can see the difference. The
verifier's draws by amount ask for the inflated invoice, and the comparison with the authority's
record shows it.

Everything here is invented: throw-away keys, made-up identifiers, and a made-up authority record
that stands in for the authority's public invoice lookup. Run `. tools/toolchain.env` first.
Exit status 0 if both parts end as described.
"""
import argparse
import os
import secrets
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "efi"))
import agg  # noqa: E402
import batch_inputs  # noqa: E402
import opening  # noqa: E402

DRAWS = 3


def euros(cents):
    return f"{cents // 100:,}.{cents % 100:02d} EUR"


def registered_total(invoices):
    return sum(int(i["authority"]["total"].replace(".", "")) for i in invoices)


def presentation(k, n, inflate):
    """One taxpayer, one proof, one verifier. Returns (every opening accepted, number of openings
    that differ from the authority's record)."""
    invoices, tmod, imod, _, _, year = batch_inputs.synthetic(n, None, 1, None, inflate=inflate)
    true_total = registered_total(invoices)
    if inflate is None:
        threshold = true_total * 8 // 10 // 100 * 100
    else:
        threshold = (true_total + 40_000_000) // 100 * 100
    context = secrets.randbits(120)  # issued by the verifier for this presentation
    on_record = {i["authority"]["iic"].lower(): i["authority"] for i in invoices}

    print(f"  registered with the authority : {n} invoices, {euros(true_total)} in all")
    print(f"  the taxpayer claims           : at least {euros(threshold)}")
    with tempfile.TemporaryDirectory() as work:
        proof_dir, record = os.path.join(work, "proof"), os.path.join(work, "record.json")
        started = time.time()
        agg.make_proof(k, invoices, tmod, imod, threshold, context, year, proof_dir, keep=record)
        ok, st, problems, _ = agg.verify(proof_dir)
        if not ok or int(st["context"], 16) != context:
            print("  the proof was NOT accepted: " + "; ".join(problems))
            return False, 0
        print(f"  proof made in {time.time() - started:.0f} s and accepted: {st['invoice_count']} invoices of {st['year']}, "
              f"numbered without a gap from 1,")
        print(f"                                  no receipt used twice, total at least {euros(st['threshold_cents'])}")

        asked = [("the first invoice", {"index": 0}, {"edge": "first"})]
        for _ in range(DRAWS):
            draw = secrets.randbits(64)
            asked.append(("an invoice by amount", {"point": draw}, {"point": draw}))
        accepted, differing = True, 0
        for what, reveal, check in asked:
            o = opening.reveal_from_record(record, **reveal)
            good = opening.check_against_proof(o, proof_dir, **check)
            differences = opening.differences(o, on_record.get(o["iic"].lower(), {}))
            accepted &= good
            differing += bool(differences)
            verdict = "agrees with the authority's record" if not differences else \
                "DIFFERS from the authority's record in: " + ", ".join(differences)
            print(f"  verifier asks for {what:20s} -> invoice no. {o['ordinal']:<3d} opened, "
                  f"{'belongs to the proof' if good else 'NOT part of the proof'}, {verdict}")
    return accepted, differing


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="4 invoices in leaves of 1")
    a = ap.parse_args()
    k, n = (1, 4) if a.quick else (10, 25)

    try:
        print("PART 1: an honest taxpayer")
        accepted, differing = presentation(k, n, None)
        honest = accepted and differing == 0
        print("  result: " + ("nothing to object to" if honest else "UNEXPECTED"))

        print()
        print("PART 2: one invoice signed again with 500,000.00 more before tax")
        accepted, differing = presentation(k, n, n * 2 // 3)
        caught = accepted and differing > 0
        print(f"  result: " + (f"caught, {differing} of {DRAWS + 1} openings differ from the authority's record" if caught
                               else "NOT caught in this run"))
        print(f"  (asking for {DRAWS} invoices by number instead would have found it with probability {DRAWS}/{n})")
    except agg.StepFailed as e:
        print(f"FAILED - {e}")
        return 1
    return 0 if honest and caught else 1


if __name__ == "__main__":
    sys.exit(main())
