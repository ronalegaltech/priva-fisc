#!/usr/bin/env python3
"""Accept/reject tests for the aggregation tree, all the way through PROVING.

  python3 tools/efi/test_agg.py            # leaves of 1 invoice (fast)
  python3 tools/efi/test_agg.py --k 10     # leaves of up to 10: full and partly filled leaves

The proofs inside a node or the top proof are only checked when that proof is made, so every case
here runs the prover. A case counts as "refused" when a circuit rejects its inputs or no valid proof
comes out. After some accepted proofs a spot check is played out: the opening of an invoice must
lead to the root the proof publishes, and an edited or misplaced opening must not.
"""
import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agg  # noqa: E402
import batch_inputs  # noqa: E402
import opening  # noqa: E402


def fake_sorted(invoices):
    """Strictly increasing, right length, but not the leaves' codes (hides a reused receipt)."""
    codes = sorted({agg.fic_int(i) for i in invoices})
    while len(codes) < len(invoices):
        codes.append(codes[-1] + 1)
    return codes


def bump_first_run(items):
    items[0]["run"][5] += 10**8  # sum_plus of the first leaf


def skip_four(invoices, k):
    """First leaf: only 6 of the first 10 invoices. Second leaf: invoices 11 to 20. Four left out."""
    first = invoices[:6]
    return [(first + [first[-1]] * (k - 6), 6), (invoices[10:20], 10)]


def spot_check(record, proof_dir, positions):
    """Yields (label, passed) for a spot check of the given invoice positions."""
    openings = [opening.reveal_from_record(record, i) for i in positions]
    for i, o in zip(positions, openings):
        good = opening.check_against_proof(o, proof_dir) and o["ordinal"] == i + 1
        yield f"spot check: invoice {i + 1} opens", good
    o = dict(openings[0])
    cents = int(o["total"].replace(".", "")) + 1
    o["total"] = f"{cents // 100}.{cents % 100:02d}"
    yield "spot check: amount raised by one cent", not opening.check_against_proof(o, proof_dir)
    if len(openings) > 1:
        o = dict(openings[0])
        o["path"] = openings[1]["path"]
        yield "spot check: opening under another path", not opening.check_against_proof(o, proof_dir)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=1, choices=agg.LEAF_SIZES)
    a = ap.parse_args()
    k = a.k
    failed = 0

    def case(label, n, tamper=None, hooks=None, expect=None, spot=None):
        """n invoices. expect=None: must be accepted. Otherwise: must be refused, with `expect` in
        the reason. spot: invoice positions to open after an accepted proof."""
        nonlocal failed
        invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(n, tamper, 1, None)
        checks = []
        with tempfile.TemporaryDirectory() as out:
            record = os.path.join(out, "record.json") if spot else None
            proof_dir = os.path.join(out, "proof")
            try:
                st = agg.make_proof(k, invoices, tmod, imod, threshold, context, year, proof_dir, hooks=hooks, keep=record)
                ok, _, problems, _ = agg.verify(proof_dir)
                counted = st["invoice_count"] == n
                outcome, reason = ("accepted", "") if ok and counted else ("refused", "; ".join(problems) or "wrong invoice count")
                if ok and counted and spot:
                    checks = list(spot_check(record, proof_dir, spot))
            except agg.StepFailed as e:
                outcome, reason = "refused", str(e)
        good = (outcome == "accepted") if expect is None else (outcome == "refused" and expect in reason)
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label:38s} {outcome}" + (f" [{reason[-72:]}]" if reason else ""), flush=True)
        for what, passed in checks:
            failed += not passed
            print(f"{'PASS' if passed else 'FAIL'}  {what:38s} {'as required' if passed else 'WRONG'}", flush=True)

    if k == 1:
        case("valid, 1 leaf (no node)", 1)
        case("valid, 2 leaves", 2)
        case("valid, 3 leaves (node over node+leaf)", 3, spot=[2, 0])
        case("receipt reused across leaves", 2, tamper="reused-receipt", expect="a receipt is used twice")
        case("...hidden behind a fake sorted list", 2, tamper="reused-receipt", hooks={"sorted": fake_sorted},
             expect="sorted list does not match")
        case("gap between leaves", 2, tamper="gap", expect="ordinals are not consecutive across runs")
        case("another device in second leaf", 2, tamper="mixed-device", expect="mixed devices")
        case("total below threshold", 2, tamper="below-threshold", expect="total is below the threshold")
        case("leaf proved with another challenge", 2, hooks={"leaf_gamma": 12345}, expect="proving agg_node")
        case("run edited after proving", 2, hooks={"runs": bump_first_run}, expect="proving agg_node")
        case("wrong leaf circuit key hash", 2, hooks={"leaf_vk_hash": 1}, expect="proving agg_node")
        case("leaf passed off as a node", 2, hooks={"is_leaf": lambda item: False}, expect="proving agg_node")
        case("leaf said to hold two invoices", 1, hooks={"count": lambda index, c: 2}, expect="more invoices than this circuit holds")
    else:
        case("valid, 20 invoices (2 full leaves)", 20)
        case("valid, 23 invoices (10 + 10 + 3)", 23, spot=[22, 4])
        case("valid, 7 invoices (one leaf, no node)", 7, spot=[6])
        case("unused slot counted as an invoice", 7, hooks={"count": lambda index, c: c + 1},
             expect="ordinals are not consecutive")
        case("leaf said to hold no invoice", 7, hooks={"count": lambda index, c: 0}, expect="no invoices")
        case("leaf said to hold 11 invoices", 7, hooks={"count": lambda index, c: 11},
             expect="more invoices than this circuit holds")
        case("four invoices left out between leaves", 20, hooks={"cut": skip_four},
             expect="ordinals are not consecutive across runs")
        case("receipt reused across leaves", 20, tamper="reused-receipt", hooks={"sorted": fake_sorted},
             expect="sorted list does not match")
    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
