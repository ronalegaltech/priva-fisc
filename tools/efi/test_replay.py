#!/usr/bin/env python3
"""What a taxpayer can and cannot change by signing the same invoice again.

  python3 tools/efi/test_replay.py

The receipt of the tax authority names only the request UUID and the receipt code, so the taxpayer
can sign other bytes under the same UUID and reuse the receipt. This test signs one invoice four
ways, runs the 1-invoice circuit on each with the same context and salt, and compares what the
circuit publishes:

  * the nullifier must stay the same whatever the taxpayer rewrites (it comes from the receipt
    code), so a second presentation in the same context is caught;
  * the opening commitment must change when business unit, device or amount change, so a spot
    check against the authority's record exposes the rewrite.
"""
import os
import random
import re
import secrets
import subprocess
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import batch_inputs  # noqa: E402
from efi_common import modulus_of, new_key  # noqa: E402
from leaf_request_inputs import EFI, build_request, core_fields, ingest_xml as ingest_request, signed_xml  # noqa: E402
from leaf_response_inputs import ingest_xml as ingest_response, synthetic_soap  # noqa: E402

PKG = os.path.normpath(os.path.join(HERE, "..", "..", "noir", "batch_k1"))


def main():
    rng = random.Random(secrets.randbits(64))
    taxpayer, authority = new_key(), new_key()
    c = core_fields(rng)
    c["ordinal"] = 1
    context, salt = secrets.randbits(120), secrets.randbits(248)

    def receipt():
        fields = (c["uuid"].encode(), c["issue"].encode(), str(uuid.uuid4()).encode(), str(uuid.uuid4()).encode())
        got, sig, _ = ingest_response(synthetic_soap(authority, fields))
        return got, sig

    def published(edit, resp, resp_sig):
        """(nullifier, opening commitment) the circuit publishes for this invoice signed after `edit`."""
        request = build_request(taxpayer, c, tricky=False)
        edit(request.find(EFI + "Invoice"))
        doc, req_sig, _ = ingest_request(signed_xml(taxpayer, request))
        invoice = {"doc": doc, "req_sig": req_sig, "resp": resp, "resp_sig": resp_sig, "salt": salt}
        path = os.path.join(PKG, "ProverReplay.toml")
        batch_inputs.write_prover(path, [invoice], modulus_of(taxpayer), modulus_of(authority), 0, context, c["year"])
        try:
            r = subprocess.run(["nargo", "execute", "-p", "ProverReplay", "witness_replay"], cwd=PKG, capture_output=True, text=True)
        finally:
            os.remove(path)
        m = re.search(r"Circuit output: (.*)", r.stdout + r.stderr)
        if r.returncode != 0 or m is None:
            raise RuntimeError("the circuit refused an invoice this test expects it to accept:\n" + r.stderr.strip()[-400:])
        values = re.findall(r"0x[0-9a-f]+", m.group(1))
        return values[-2], values[-1]

    def other_signature(inv):
        s = inv.get("IICSignature")
        inv.set("IICSignature", ("1" if s[0] != "1" else "2") + s[1:])

    def other_device(inv):
        code = inv.get("TCRCode")
        inv.set("TCRCode", code[:-1] + ("0" if code[-1] != "0" else "1"))

    def other_amount(inv):
        inv.set("TotPrice", "999999.00")

    resp, resp_sig = receipt()
    base = published(lambda inv: None, resp, resp_sig)
    failed = 0

    def report(label, good):
        nonlocal failed
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label}", flush=True)

    got = published(other_signature, resp, resp_sig)
    report("signed again with another IICSignature: same nullifier", got[0] == base[0])
    got = published(other_device, resp, resp_sig)
    report("signed again for another device: same nullifier", got[0] == base[0])
    report("signed again for another device: another opening commitment", got[1] != base[1])
    got = published(other_amount, resp, resp_sig)
    report("signed again with another amount: same nullifier", got[0] == base[0])
    report("signed again with another amount: another opening commitment", got[1] != base[1])
    resp2, resp_sig2 = receipt()
    got = published(lambda inv: None, resp2, resp_sig2)
    report("another receipt for the same request UUID: another nullifier", got[0] != base[0])

    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
