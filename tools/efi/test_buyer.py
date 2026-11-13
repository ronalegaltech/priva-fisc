#!/usr/bin/env python3
"""The buyer field: the circuit reader and the Python reference must agree on whole requests.

  python3 tools/efi/test_buyer.py

Requests are invented ones of real shape (tools/efi/batch_inputs.py), then altered byte by byte.
No signature is involved: this checks only how the buyer is read.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agg  # noqa: E402
import batch_inputs  # noqa: E402
import buyer  # noqa: E402
from efi_common import toml_bytes  # noqa: E402


def in_circuit(doc, doc_len=None):
    """The identifier the circuit returns, or None if it refuses the request."""
    padded = doc + bytes(buyer.SIZE - len(doc))
    toml = toml_bytes("doc", padded) + f"doc_len = {len(doc) if doc_len is None else doc_len}\n"
    try:
        return agg.execute("buyer_check", toml, want_output=True)[1][0]
    except agg.StepFailed:
        return None


def in_python(doc, doc_len=None):
    try:
        return buyer.buyer_id(doc, doc_len)
    except buyer.BuyerError:
        return None


def main():
    failed = 0

    def report(label, good):
        nonlocal failed
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label}", flush=True)

    invoices = batch_inputs.synthetic(1, None, 1, None)[0]
    doc = bytes(invoices[0]["doc"])
    tag = doc[doc.index(b"<Buyer "):doc.index(b"</Buyer>") + 8]
    want = buyer.pack("TIN", "12345678")

    report("an invented request names the buyer once", doc.count(b"<Buyer ") == 1 and b'IDNum="12345678"' in tag)
    report("reference reads TIN:12345678", in_python(doc) == want and buyer.unpack(want) == "TIN:12345678")
    report("circuit reads the same", in_circuit(doc) == want)

    # Each entry: label, altered request, signed length (None = all of it), expected identifier (None = refused).
    after_buyer = doc.index(b"</Buyer>") + 8
    cases = [
        ("free text with '>' before the number", doc.replace(b"<Buyer IDNum=", b'<Buyer Address="a > b" Country="MNE" IDNum='), None, want),
        ("another kind of identifier", doc.replace(b'IDType="TIN" Name', b'IDType="VAT" Name'), None, buyer.pack("VAT", "12345678")),
        ("letters in the number", doc.replace(b'<Buyer IDNum="12345678"', b'<Buyer IDNum="ME02abc9"'), None, buyer.pack("TIN", "ME02abc9")),
        ("no buyer (retail sale)", doc.replace(tag, b""), None, None),
        ("two buyers", doc.replace(tag, tag + tag.replace(b"12345678", b"87654321")), None, None),
        ("number repeated in the tag", doc.replace(b'<Buyer IDNum="12345678"', b'<Buyer IDNum="12345678" IDNum="87654321"'), None, None),
        ("dash in the number", doc.replace(b'<Buyer IDNum="12345678"', b'<Buyer IDNum="1234-5678"'), None, None),
        ("number of 21 characters", doc.replace(b'<Buyer IDNum="12345678"', b'<Buyer IDNum="123456789012345678901"'), None, None),
        ("type in lower case", doc.replace(b'IDType="TIN" Name', b'IDType="tin" Name'), None, None),
        ("single-quoted value in the tag", tag and doc.replace(b'IDType="TIN" Name', b"IDType=\"TIN\" X='y' Name"), None, None),
        ("signature ends before the buyer", doc, doc.index(b"<Buyer "), None),
        ("signature ends right after the buyer", doc, after_buyer, None),
    ]
    for label, altered, signed, expected in cases:
        py, circuit = in_python(altered, signed), in_circuit(altered, signed)
        verdict = "refused" if expected is None else buyer.unpack(expected)
        report(f"{label}: {verdict}, by both", py == expected and circuit == expected)

    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
