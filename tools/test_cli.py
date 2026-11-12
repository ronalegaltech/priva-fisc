#!/usr/bin/env python3
"""The command line on signed files, as a taxpayer and a verifier would use it.

  python3 tools/test_cli.py

Writes an invented signed request and receipt to disk, proves from the files, and checks what
`pf.py verify` prints and returns: for the right and for another context, with the taxpayer's
certificate and with someone else's, for an altered public value, and when the claim is false.
One invoice, so only the 1-invoice circuit is used.
"""
import os
import random
import secrets
import subprocess
import sys
import tempfile
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "efi"))
from efi_common import new_key  # noqa: E402
from leaf_request_inputs import build_request, core_fields, signed_xml  # noqa: E402
from leaf_response_inputs import synthetic_soap  # noqa: E402

PF = os.path.join(HERE, "pf.py")


def pf(*args):
    r = subprocess.run([sys.executable, PF, *args], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    rng = random.Random(secrets.randbits(64))
    taxpayer, stranger, authority = new_key(), new_key(), new_key()
    c = core_fields(rng)
    c["ordinal"] = 1
    failed = 0

    def report(label, good, detail=""):
        nonlocal failed
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not good else ""), flush=True)

    with tempfile.TemporaryDirectory() as d:
        request, receipt, other = (os.path.join(d, n) for n in ("request.xml", "receipt.xml", "other.xml"))
        with open(request, "wb") as f:
            f.write(signed_xml(taxpayer, build_request(taxpayer, c, tricky=False)))
        with open(other, "wb") as f:
            f.write(signed_xml(stranger, build_request(stranger, c, tricky=False)))
        fields = (c["uuid"].encode(), c["issue"].encode(), str(uuid.uuid4()).encode(), str(uuid.uuid4()).encode())
        with open(receipt, "wb") as f:
            f.write(synthetic_soap(authority, fields))
        total = f"{c['total'] // 100}.{c['total'] % 100:02d}"
        above = f"{c['total'] // 100 + 1}.00"
        proof = os.path.join(d, "proof")
        common = ("--year", str(c["year"]), "--context", "0x33", request, receipt)

        code, out = pf("prove", "--out", proof, "--threshold", total, *common)
        report("proof from the signed files", code == 0 and os.path.exists(os.path.join(proof, "proof")), out[-200:])

        code, out = pf("verify", proof, "--context", "0x33")
        report("verify: valid, authority key not listed (exit 2)", code == 2 and "PROOF VALID" in out and "NOT IN registry" in out, out[-200:])
        code, out = pf("verify", proof, "--context", "0x34")
        report("verify: made for another context (exit 4)", code == 4 and "NOT the expected one" in out, out[-200:])
        code, out = pf("verify", proof, "--context", "0x33", "--taxpayer-cert", request)
        report("verify: the taxpayer's certificate matches", code == 2 and "key matches the certificate" in out, out[-200:])
        code, out = pf("verify", proof, "--context", "0x33", "--taxpayer-cert", other)
        report("verify: someone else's certificate (exit 3)", code == 3 and "NOT the key of the proof" in out, out[-200:])

        ledger = os.path.join(d, "ledger.json")
        code, out = pf("verify", proof, "--context", "0x33", "--ledger", ledger)
        report("verify with a ledger: first presentation", code == 2 and "presented before       : no" in out, out[-300:])
        code, out = pf("verify", proof, "--context", "0x33", "--ledger", ledger)
        report("verify with a ledger: the same proof again (exit 5)", code == 5 and "presented before       : YES" in out, out[-300:])
        code, out = pf("verify", proof, "--context", "not-hex")
        report("verify: a mistyped context prints no verdict", code != 0 and "PROOF VALID" not in out, out[-200:])

        # A directory with no proof in it, named after the words a careless check would look for.
        trap = os.path.join(d, "Proof verified successfully")
        os.makedirs(trap)
        with open(os.path.join(trap, "public_inputs"), "wb") as f:
            f.write(open(os.path.join(proof, "public_inputs"), "rb").read())
        code, out = pf("verify", trap, "--context", "0x33")
        report("verify: a directory without a proof (exit 1)", code == 1 and "PROOF INVALID" in out and "PROOF VALID" not in out, out[-200:])

        path = os.path.join(proof, "public_inputs")
        data = bytearray(open(path, "rb").read())
        data[31] ^= 1  # the threshold, by one cent
        with open(path, "wb") as f:
            f.write(data)
        code, out = pf("verify", proof, "--context", "0x33")
        report("verify: a public value altered (exit 1)", code == 1 and "PROOF INVALID" in out, out[-200:])

        refused = os.path.join(d, "refused")
        code, out = pf("prove", "--out", refused, "--threshold", above, *common)
        report("prove: threshold above the total is refused", code != 0 and not os.path.exists(os.path.join(refused, "proof")), out[-200:])
        code, out = pf("prove", "--out", refused, "--threshold", total, "--year", str(c["year"] + 1), "--context", "0x33", request, receipt)
        report("prove: another year is refused", code != 0 and not os.path.exists(os.path.join(refused, "proof")), out[-200:])
        code, out = pf("prove", "--out", refused, "--threshold", total, "--year", str(c["year"]), request, receipt)
        report("prove: real files need the verifier's context", code != 0 and not os.path.exists(os.path.join(refused, "proof")), out[-200:])
        code, out = pf("prove", "--out", refused, "--threshold", total, "--year", str(c["year"]), "--context", "0x33", other, receipt)
        report("prove: a receipt with someone else's request still proves (the receipt names no taxpayer)",
               code == 0, out[-200:])

    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
