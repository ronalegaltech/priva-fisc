#!/usr/bin/env python3
"""One real invoice from the test service, end to end.

  python3 tools/efi/test_real_pair.py [--notebook FILE]

A request and its receipt, as registered with the Montenegrin tax administration's TEST service
on 13 Oct 2021, are recorded in the outputs of a public notebook: `Fiskalizacija.ipynb` in
https://github.com/djordjen/ElektronskaFiskalizacijaPython. The notebook is not kept in this
repository: name it with --notebook or in PF_EFI_REAL_NOTEBOOK. Without it the test is skipped and
exits with 0.

What the pair is: the receipt is signed by the administration's test signer, the key listed in
registry/issuer_keys.json as me-efi-test-2020. The request is signed with a test certificate whose
private key is public (it lies in the same repository), so the pair says nothing about any
taxpayer. It is one invoice; it follows the schema in force today.

Checked:
  * digest and signature of the request and of the receipt (efi_common.ingest_signed);
  * the key that signed the receipt has the key hash of the registry's entry;
  * `pf.py prove` makes a batch proof and a proof about the buyer from the two files;
  * `pf.py verify` accepts both with exit status 2 (valid, authority key not a production key),
    refuses the batch proof under another context (4) and the buyer proof for another buyer (6).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from efi_common import ingest_signed  # noqa: E402
import keyhash  # noqa: E402

ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
PF = os.path.join(ROOT, "tools", "pf.py")
REGISTRY_ID = "me-efi-test-2020"
CONTEXT = "0x2a"


def outputs(notebook_path):
    """Text outputs of the notebook's code cells."""
    with open(notebook_path, encoding="utf-8") as f:
        notebook = json.load(f)
    for cell in notebook["cells"]:
        for o in cell.get("outputs", []):
            text = o.get("text") or o.get("data", {}).get("text/plain") or ""
            yield "".join(text)


def the_pair(notebook_path):
    request = receipt = None
    for text in outputs(notebook_path):
        if "Envelope" in text and "<RegisterInvoiceRequest" in text:
            request = text.strip()
        if "Envelope" in text and "RegisterInvoiceResponse" in text and "<FIC" in text:
            receipt = text.strip()
    return request, receipt


def pf(*args):
    return subprocess.run([sys.executable, PF, *args], capture_output=True, text=True).returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--notebook", default=os.environ.get("PF_EFI_REAL_NOTEBOOK"))
    a = ap.parse_args()
    if not a.notebook:
        print("skipped: no notebook (see the top of tools/efi/test_real_pair.py)")
        return 0
    failed = 0

    def report(label, good, detail=""):
        nonlocal failed
        failed += not good
        print(f"{'ok  ' if good else 'FAIL'} {label}" + (f": {detail}" if detail else ""))

    request, receipt = the_pair(a.notebook)
    if request is None or receipt is None:
        print("FAIL: the notebook does not hold a request and a receipt in its outputs")
        return 1

    try:
        doc, _, _ = ingest_signed(request.encode("utf-8"), "RegisterInvoiceRequest", b"Request")
        report("request: digest and signature", True, f"{len(doc)} canonical bytes")
    except Exception as e:  # noqa: BLE001
        report("request: digest and signature", False, str(e)[:120])
    try:
        _, _, modulus = ingest_signed(receipt.encode("utf-8"), "RegisterInvoiceResponse", b"Response")
        report("receipt: digest and signature", True)
    except Exception as e:  # noqa: BLE001
        report("receipt: digest and signature", False, str(e)[:120])
        modulus = None

    with open(os.path.join(ROOT, "registry", "issuer_keys.json"), encoding="utf-8") as f:
        entry = next(k for k in json.load(f)["keys"] if k["id"] == REGISTRY_ID)
    if modulus is not None:
        report(f"receipt signed with the key listed as {REGISTRY_ID}", keyhash.key_hash(modulus) == int(entry["key_hash"], 16))

    amount = re.search(r' TotPrice="([0-9]+\.[0-9]{2})"', request).group(1)
    year = re.search(r' IssueDateTime="([0-9]{4})-', request).group(1)
    buyer = re.search(r'<Buyer [^>]*IDType="([A-Z]+)"[^>]*IDNum="([^"]+)"', request)
    buyer = f"{buyer.group(1)}:{buyer.group(2)}"
    other_buyer = buyer[:-1] + ("0" if buyer[-1] != "0" else "1")

    with tempfile.TemporaryDirectory() as tmp:
        req_path, rec_path = os.path.join(tmp, "request.xml"), os.path.join(tmp, "receipt.xml")
        with open(req_path, "w", encoding="utf-8") as f:
            f.write(request)
        with open(rec_path, "w", encoding="utf-8") as f:
            f.write(receipt)
        common = ("--threshold", amount, "--year", year, "--context", CONTEXT, req_path, rec_path)

        batch = os.path.join(tmp, "batch")
        report("batch proof from the two files", pf("prove", "--out", batch, *common) == 0)
        code = pf("verify", batch, "--context", CONTEXT)
        report("verified: valid, authority key not a production key", code == 2, f"exit status {code}")
        code = pf("verify", batch, "--context", "0x2b")
        report("refused under another context", code == 4, f"exit status {code}")

        one = os.path.join(tmp, "one_buyer")
        report("proof about the buyer from the two files", pf("prove", "--out", one, "--buyer", buyer, *common) == 0)
        code = pf("verify", one, "--context", CONTEXT, "--buyer", buyer)
        report("verified for that buyer", code == 2, f"exit status {code}")
        code = pf("verify", one, "--context", CONTEXT, "--buyer", other_buyer)
        report("refused for another buyer", code == 6, f"exit status {code}")

    print("the real pair behaves as required" if not failed else f"{failed} check(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
