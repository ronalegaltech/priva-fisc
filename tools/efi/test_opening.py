#!/usr/bin/env python3
"""Spot-check round trip on the 1-invoice circuit: the opening of the invoice must match the
commitment the circuit publishes, and an edited opening must not. Then the comparison of an
opening with the authority's record.

Run from anywhere:  python3 tools/efi/test_opening.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.normpath(os.path.join(HERE, "..", "..", "noir", "batch_k1"))


def sh(*cmd, cwd=None, check=True):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check)


def main():
    prover = os.path.join(PKG, "ProverOpenTest.toml")
    sh(sys.executable, os.path.join(HERE, "batch_inputs.py"), "synthetic", "--k", "1", "--out", prover)
    r = sh("nargo", "execute", "-p", "ProverOpenTest", "witness_test", cwd=PKG)
    # (taxpayer key hash, authority key hash, starts-at-one, [nullifiers], [opening commitments])
    commitment = re.findall(r"0x[0-9a-f]+", re.search(r"Circuit output: (.*)", r.stdout + r.stderr).group(1))[-1]
    failed = 0
    with tempfile.TemporaryDirectory() as d:
        opening = os.path.join(d, "opening.json")
        sh(sys.executable, os.path.join(HERE, "opening.py"), "reveal", "--prover", prover, "--index", "0", "--out", opening)
        os.remove(prover)

        def check(label, want):
            nonlocal failed
            r = sh(sys.executable, os.path.join(HERE, "opening.py"), "check", "--opening", opening, "--commitment", commitment, check=False)
            got = r.stdout.strip()
            ok = got == want
            failed += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {label:28s} {got}")

        check("true opening", "MATCH")
        o = json.load(open(opening))
        for label, edit in (
            ("amount raised by one cent", lambda o: o.update(total=f"{(int(o['total'].replace('.', '')) + 1) // 100}.{(int(o['total'].replace('.', '')) + 1) % 100:02d}")),
            ("another ordinal", lambda o: o.update(ordinal=o["ordinal"] + 1)),
            ("another receipt code", lambda o: o.update(fic=("0" if o["fic"][0] != "0" else "1") + o["fic"][1:])),
        ):
            e = dict(o)
            edit(e)
            json.dump(e, open(opening, "w"))
            check(label, "NO MATCH")
        # Comparing an opening with what the authority has on record for that invoice.
        sys.path.insert(0, HERE)
        import opening as tool

        def compare(label, lookup, want):
            nonlocal failed
            got = tool.differences(o, lookup)
            ok = got == want
            failed += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {label:28s} {'agrees' if not got else 'differs in ' + ', '.join(got)}")

        record = {name: o[name] for name in tool.COMPARED}
        shifted = o["total"].replace(".", "")
        shifted = shifted[:-1] + "." + shifted[-1]  # the same digits, ten times the amount
        compare("record equal to the opening", record, [])
        compare("same codes in capitals", dict(record, iic=o["iic"].upper(), fic=o["fic"].upper()), [])
        compare("total written as a number", dict(record, total=float(o["total"])), [])
        compare("record with another total", dict(record, total="0.01"), ["total"])
        compare("same digits, decimal point moved", dict(record, total=shifted), ["total"])
        compare("total with three decimals", dict(record, total=o["total"] + "0"), ["total"])
        compare("record of another device", dict(record, device="zz999zz999", ordinal=o["ordinal"] + 1), ["ordinal", "device"])
        compare("no record found", {}, list(tool.COMPARED))

        def seller(label, lookup, subject, want):
            nonlocal failed
            got = tool.differences(o, lookup, subject)
            ok = got == want
            failed += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {label:28s} {'agrees' if not got else 'differs in ' + ', '.join(got)}")

        subject = "CN=Invented Company,2.5.4.97=VATME-12345678,C=ME"
        seller("seller is the certificate's", dict(record, seller_tin="12345678"), subject, [])
        seller("seller is someone else", dict(record, seller_tin="87654321"), subject, ["seller"])
        seller("record names no seller", record, subject, ["seller"])

        r = sh(sys.executable, os.path.join(HERE, "opening.py"), "check", "--opening", opening, "--commitment", commitment, "--first", check=False)
        ok = r.returncode != 0 and "MATCH" not in r.stdout
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {'--first without the proof':28s} {'refused' if ok else 'ACCEPTED'}")
    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
