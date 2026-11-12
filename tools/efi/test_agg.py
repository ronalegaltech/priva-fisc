#!/usr/bin/env python3
"""Accept/reject tests for the aggregation (2 leaves -> 1 root), all the way through PROVING.

  python3 tools/efi/test_agg.py            # leaves of 1 invoice (fast)
  python3 tools/efi/test_agg.py --k 10     # leaves of 10 invoices: valid case and two attacks

The inner proofs are only checked when the root is proved, so every case here runs the prover; a
case counts as "refused" when either a circuit rejects its inputs or no valid root proof comes out.
"""
import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agg  # noqa: E402
import batch_inputs  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=1, choices=(1, 10))
    a = ap.parse_args()
    k, n = a.k, 2 * a.k
    failed = 0

    def case(label, tamper=None, hooks=None, expect=None):
        """expect=None: must be accepted. Otherwise: must be refused, with `expect` in the reason."""
        nonlocal failed
        invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(n, tamper, 1, None)
        with tempfile.TemporaryDirectory() as out:
            try:
                h = hooks(invoices) if callable(hooks) else hooks
                agg.prove(k, invoices, tmod, imod, threshold, context, year, out, hooks=h)
                ok, _, problems = agg.verify(k, out)
                outcome, reason = ("accepted", "") if ok else ("refused", "; ".join(problems))
            except agg.StepFailed as e:
                outcome, reason = "refused", str(e)
        good = (outcome == "accepted") if expect is None else (outcome == "refused" and expect in reason)
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label:34s} {outcome}" + (f" [{reason[-78:]}]" if reason else ""))

    case("valid")
    case("receipt reused across leaves", tamper="reused-receipt", expect="a receipt is used twice")
    case("...hidden behind a fake sorted list", tamper="reused-receipt",
         hooks=lambda inv: {"sorted": sorted({agg.fic_int(i) for i in inv} | {max(agg.fic_int(i) for i in inv) + 1})[:len(inv)]},
         expect="sorted list does not match")
    if k == 1:
        case("gap between leaves", tamper="gap", expect="ordinals are not consecutive across leaves")
        case("another device in second leaf", tamper="mixed-device", expect="mixed devices")
        case("total below threshold", tamper="below-threshold", expect="total is below the threshold")
        # A leaf proved under another challenge carries another product, so the multiset check
        # already fails when the root's witness is built.
        case("leaf proved with another challenge", hooks={"leaf_gamma": 12345}, expect="sorted list does not match")
        case("summary edited after proving", hooks={"summaries": lambda s: [[*s[0][:4], s[0][4] + 10**8, *s[0][5:]], s[1]]},
             expect="proving the root")
        case("wrong leaf circuit key hash", hooks={"leaf_vk_hash": 1}, expect="proving the root")
    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
