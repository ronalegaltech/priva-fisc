#!/usr/bin/env python3
"""Accept/reject tests for the aggregation tree, all the way through PROVING.

  python3 tools/efi/test_agg.py            # leaves of 1 invoice (fast)
  python3 tools/efi/test_agg.py --k 10     # leaves of 10: 20 and 30 invoices, and one attack

The proofs inside a node or the top proof are only checked when that proof is made, so every case
here runs the prover. A case counts as "refused" when a circuit rejects its inputs or no valid proof
comes out.
"""
import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agg  # noqa: E402
import batch_inputs  # noqa: E402


def fake_sorted(invoices):
    """Strictly increasing, right length, but not the leaves' codes (hides a reused receipt)."""
    codes = sorted({agg.fic_int(i) for i in invoices})
    while len(codes) < len(invoices):
        codes.append(codes[-1] + 1)
    return codes


def bump_first_run(items):
    items[0]["run"][5] += 10**8  # sum_plus of the first leaf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=1, choices=agg.LEAF_SIZES)
    a = ap.parse_args()
    k = a.k
    failed = 0

    def case(label, leaves, tamper=None, hooks=None, expect=None):
        """expect=None: must be accepted. Otherwise: must be refused, with `expect` in the reason."""
        nonlocal failed
        invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(leaves * k, tamper, 1, None)
        with tempfile.TemporaryDirectory() as out:
            try:
                st = agg.make_proof(k, invoices, tmod, imod, threshold, context, year, out, hooks=hooks)
                ok, _, problems, _ = agg.verify(out)
                ok = ok and st["invoice_count"] == leaves * k
                outcome, reason = ("accepted", "") if ok else ("refused", "; ".join(problems) or "wrong invoice count")
            except agg.StepFailed as e:
                outcome, reason = "refused", str(e)
        good = (outcome == "accepted") if expect is None else (outcome == "refused" and expect in reason)
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label:36s} {outcome}" + (f" [{reason[-74:]}]" if reason else ""), flush=True)

    if k == 1:
        case("valid, 1 leaf (no node)", 1)
        case("valid, 2 leaves", 2)
        case("valid, 3 leaves (node over node+leaf)", 3)
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
    else:
        case(f"valid, 2 leaves ({2 * k} invoices)", 2)
        case(f"valid, 3 leaves ({3 * k} invoices)", 3)
        case("receipt reused across leaves", 2, tamper="reused-receipt", hooks={"sorted": fake_sorted},
             expect="sorted list does not match")
    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
