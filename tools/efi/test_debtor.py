#!/usr/bin/env python3
"""Accept/reject tests for the debtor circuits: invoices one seller issued to one buyer.

  python3 tools/efi/test_debtor.py                  # 1-invoice circuit (fast)
  python3 tools/efi/test_debtor.py --k 10           # 10-invoice circuit
  python3 tools/efi/test_debtor.py --format al      # the same for the Albanian format
  python3 tools/efi/test_debtor.py --long           # the circuits for longer requests: 7 invoices
                                                    # of up to 4,096 bytes, 4 of up to 8,192, 2 of
                                                    # up to 16,384 (Montenegrin format only; there
                                                    # are none for Albanian files)
  python3 tools/efi/test_debtor.py --longest        # the circuit for 1 request of up to 32,768
                                                    # bytes, apart because compiling it needs room
                                                    # (see tools/test.sh)

A valid set must execute and publish what a verifier can recompute: the number of invoices, the
buyer tag, each nullifier (the same value the batch circuits give that invoice) and each opening
commitment. Every tampered set must be refused by the circuit.

The circuits for longer requests are the same statement over the same reader with other sizes, so
--long runs fewer cases on each: requests near the longest the circuit reads, short and long
requests together with unused slots, and a handful of the refusals.
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
import formats  # noqa: E402
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
            "iic", "fic", "ordinal", "issue_ts", "issue_zone", "total_cents", "unit", "device")] + [s["buyer"], inv["salt"]])
    return [s["count"], poseidon2.hash([DOMAIN_BUYER, s["context"], s["buyer"]])] + nullifiers + openings


# Lines of an invented invoice, by the longest request a circuit reads: one whose request nearly
# fills the circuit, and one that is just too long for the circuit of the next shorter length.
NEARLY_FULL = {4096: 15, 8192: 40, 16384: 90, 32768: 200}
TOO_LONG_FOR_SHORTER = {4096: 6, 8192: 20, 16384: 60, 32768: 120}
LONGEST = 32768


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=1)
    ap.add_argument("--format", default="me", choices=[f.name for f in formats.ALL])
    ap.add_argument("--long", action="store_true", help="the circuits for requests of up to 4,096, 8,192 and 16,384 bytes")
    ap.add_argument("--longest", action="store_true", help="the circuit for one request of up to 32,768 bytes")
    a = ap.parse_args()
    fmt = formats.by_name(a.format)
    failed = 0

    def report(label, good, detail=""):
        nonlocal failed
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label:28s} {detail}", flush=True)

    def runner(name, longest):
        def run(s):
            """(accepted, published values after the key hashes, reason of refusal)."""
            agg.compiled(name)
            path = os.path.join(agg.pkg(name), "ProverTest.toml")
            with open(path, "w") as f:
                f.write(debtor_inputs.prover_toml(s, longest))
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
        return run

    if a.long or a.longest:
        if all(longest <= 2048 for _, longest, _ in fmt.one_buyer_circuits):
            print(f"no circuits for longer requests in the format of {fmt.country}")
            return 1
        for k, longest, name in fmt.one_buyer_circuits:
            if longest <= 2048 or not (a.longest if longest == LONGEST else a.long):
                continue
            run = runner(name, longest)
            print(f"{name}: up to {k} invoice(s), requests of up to {longest} bytes", flush=True)
            s = debtor_inputs.synthetic(k, fmt=fmt, lines=NEARLY_FULL[longest])
            sizes = [len(i["doc"]) for i in s["invoices"]]
            accepted, published, why = run(s)
            report("requests near the limit", accepted and published == expected(s, k) and max(sizes) > longest * 3 // 4,
                   f"accepted, {k} invoice(s) of {min(sizes)} to {max(sizes)} bytes, published values recomputed"
                   if accepted else f"rejected [{why}]")
            if k > 1:
                # A long request first, short ones after it, and slots left over for the prover's filler.
                count = k - 1
                s = debtor_inputs.synthetic(k, count=count, fmt=fmt, lines={0: TOO_LONG_FOR_SHORTER[longest]})
                accepted, published, why = run(s)
                report("long and short, a slot unused", accepted and published == expected(s, k) and published[0] == count,
                       f"accepted, {count} invoice(s), the unused slot left no trace" if accepted else f"rejected [{why}]")
            for t in ("other-buyer", "no-buyer", "credit-note", "below-threshold", "old-receipt", "other-format"):
                accepted, _, why = run(debtor_inputs.synthetic(k, t, fmt=fmt, lines=TOO_LONG_FOR_SHORTER[longest]))
                report(t, not accepted, "accepted" if accepted else f"rejected [{why}]")
        print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
        return 1 if failed else 0

    name, k = fmt.one_buyer_circuit(a.k), a.k
    run = runner(name, 2048)

    s = debtor_inputs.synthetic(k, fmt=fmt)
    accepted, published, why = run(s)
    report("all slots to one buyer", accepted and published == expected(s, k),
           f"accepted, {s['count']} invoice(s), published values recomputed" if accepted else f"rejected [{why}]")

    # Requests in the other shapes the schema allows: times in UTC or with another offset, the
    # late-delivery mark. What is published is recomputed from the files, so this also compares
    # how the tools and the circuit take a time written each way.
    for shape in (("utc-z", "offset-minus-zero", "west-of-utc", "late-businessneeds", "late-utc-z", "zero-total-plain")
                  if k == 1 else ("mixed",)):
        s = debtor_inputs.synthetic(k, fmt=fmt, shape=shape)
        accepted, published, why = run(s)
        report("shape " + shape, accepted and published == expected(s, k),
               "accepted, published values recomputed" if accepted else f"rejected [{why}]")

    s = debtor_inputs.synthetic(k, fmt=fmt)
    if k > 1:
        s = debtor_inputs.synthetic(k, count=3, fmt=fmt)
        accepted, published, why = run(s)
        good = accepted and published == expected(s, k) and published[0] == 3
        report("3 invoices, filler after", good,
               "accepted, later slots (other buyers, a credit note) left no trace" if accepted else f"rejected [{why}]")

        at_most = dict(s, threshold=s["total"])
        report("threshold equal to the sum", run(at_most)[0], "accepted")

    if not fmt.device_required:
        # In this format an invoice may carry no device code; its opening then has device 0.
        without = [opening.opening_of(inv["doc"], inv["resp"][3], hex(inv["salt"]))["device"] is None
                   for inv in s["invoices"][:s["count"]]]
        report("invoices without a device code", any(without) and (k == 1 or not all(without)),
               f"{sum(without)} of {len(without)} invoice(s) in the accepted set had none")

    for t in debtor_inputs.tampers(fmt):
        if k == 1 and t in debtor_inputs.NEEDS_TWO:
            continue
        accepted, _, why = run(debtor_inputs.synthetic(k, t, fmt=fmt))
        report(t, not accepted, "accepted" if accepted else f"rejected [{why}]")

    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
