#!/usr/bin/env python3
"""Accept/reject tests for the debtor circuits: invoices one seller issued to one buyer.

  python3 tools/efi/test_debtor.py            # 1-invoice circuit (fast)
  python3 tools/efi/test_debtor.py --k 10     # 10-invoice circuit

A valid set must execute and publish what a verifier can recompute: the number of invoices, the
buyer tag, each nullifier (the same value the batch circuits give that invoice) and each opening
commitment. Every tampered set must be refused by the circuit.
"""
import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agg  # noqa: E402
import debtor_inputs  # noqa: E402
import opening  # noqa: E402
import poseidon2  # noqa: E402

DOMAIN_NULLIFIER = int.from_bytes(b"PF-NULLIF1", "big")
DOMAIN_BUYER = int.from_bytes(b"PF-BUYER01", "big")
DOMAIN_OPENING_BUYER = int.from_bytes(b"PF-OPENBUY", "big")


def expected(s, k):
    """What the circuit must publish after the two key hashes: count, tag, nullifiers, openings."""
    nullifiers, openings = [0] * k, [0] * k
    for i, inv in enumerate(s["invoices"][:s["count"]]):
        v = opening.field_values(opening.opening_of(inv["doc"], inv["resp"][3], hex(inv["salt"])))
        fic = int(v["fic"], 0)
        nullifiers[i] = poseidon2.hash([DOMAIN_NULLIFIER, s["context"], fic])
        openings[i] = poseidon2.hash([DOMAIN_OPENING_BUYER] + [int(v[name], 0) for name in (
            "iic", "fic", "ordinal", "issue_local_ts", "issue_tz", "total_cents", "unit", "device")] + [s["buyer"], inv["salt"]])
    return [s["count"], poseidon2.hash([DOMAIN_BUYER, s["context"], s["buyer"]])] + nullifiers + openings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=1)
    a = ap.parse_args()
    name, k = f"debtor_k{a.k}", a.k
    failed = 0

    def report(label, good, detail=""):
        nonlocal failed
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label:28s} {detail}", flush=True)

    def run(s):
        """(accepted, published values after the key hashes, reason of refusal)."""
        agg.compiled(name)
        path = os.path.join(agg.pkg(name), "ProverTest.toml")
        with open(path, "w") as f:
            f.write(debtor_inputs.prover_toml(s))
        try:
            r = subprocess.run(["nargo", "execute", "-p", "ProverTest", "witness_test"], cwd=agg.pkg(name),
                               capture_output=True, text=True)
        finally:
            os.remove(path)
        text = r.stdout + r.stderr
        if r.returncode != 0:
            if not any(mark in text for mark in ("Failed constraint", "Assertion failed", "Failed to solve")):
                raise RuntimeError(f"nargo failed for a reason other than a circuit constraint:\n{text[-600:]}")
            reason = next((l.strip() for l in text.splitlines() if "ssert" in l or "Failed" in l), "")
            return False, None, reason[-70:]
        # The count is printed in decimal, everything else in hexadecimal.
        values = [int(v, 0) for v in re.findall(r"0x[0-9a-f]+|\b\d+\b", re.search(r"Circuit output: (.*)", text).group(1))]
        return True, values[2:], ""

    s = debtor_inputs.synthetic(k)
    accepted, published, why = run(s)
    report("all slots to one buyer", accepted and published == expected(s, k),
           f"accepted, {s['count']} invoice(s), published values recomputed" if accepted else f"rejected [{why}]")

    if k > 1:
        s = debtor_inputs.synthetic(k, count=3)
        accepted, published, why = run(s)
        good = accepted and published == expected(s, k) and published[0] == 3
        report("3 invoices, filler after", good,
               "accepted, later slots (other buyers, a credit note) left no trace" if accepted else f"rejected [{why}]")

        at_most = dict(s, threshold=s["total"])
        report("threshold equal to the sum", run(at_most)[0], "accepted")

    for t in debtor_inputs.TAMPERS:
        if k == 1 and t in debtor_inputs.NEEDS_TWO:
            continue
        accepted, _, why = run(debtor_inputs.synthetic(k, t))
        report(t, not accepted, "accepted" if accepted else f"rejected [{why}]")

    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
