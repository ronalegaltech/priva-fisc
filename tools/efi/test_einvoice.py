#!/usr/bin/env python3
"""Accept/reject tests for noir/einvoice_al_k10: open e-invoices to one buyer, read from one signed
answer of the e-invoice service.

  python3 tools/efi/test_einvoice.py

A valid selection must execute and publish what a verifier can recompute: the number of
e-invoices, the buyer tag, the seller tag, the day of the answer and each nullifier. Every other
case must be refused by the circuit. Answers are invented and signed by throw-away keys.
"""
import os
import random
import re
import secrets
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agg  # noqa: E402
import einvoice as ei  # noqa: E402
from efi_common import ingest_signed, modulus_of, new_key  # noqa: E402

NAME = ei.CIRCUIT


def base(rng, n=3, others=5, edit=None, root="GetEinvoicesResponse"):
    """A signed invented answer and the honest selection for its buyer."""
    key = new_key()
    seller, buyer = ei.tax_number(rng), ei.tax_number(rng)
    mixed, total = ei.invented_list(rng, n, others, seller, buyer)
    if edit:
        edit(mixed, seller, buyer)
    xml = ei.signed_answer(key, mixed, root=root)
    doc, signature, modulus = ingest_signed(xml, root, b"Response", namespaces=(ei.NAMESPACE,))
    doc = bytes(doc)
    s = {"doc": doc, "doc_len": None, "signature": signature, "modulus": modulus, "buyer": buyer, "seller": seller,
         "context": secrets.randbits(120), "total": total, "answer": None, "counted": [], "day": None}
    if root == "GetEinvoicesResponse":
        s["answer"] = ei.read_answer(doc)
        s["counted"], _ = ei.countable(s["answer"], buyer)
        s["day"] = s["answer"]["day"]
    s["offsets"] = [e["offset"] for e in s["counted"]]
    s["count"] = len(s["offsets"])
    s["threshold"] = total // 2
    return s


def other_element(s, why):
    """Offset of an element of the answer that the reader refuses for the reason `why`, or that
    belongs to another buyer when `why` is None."""
    for e in s["answer"]["einvoices"]:
        if why is None and "refused" not in e and e["buyer"] != s["buyer"]:
            return e["offset"]
        if why is not None and e.get("refused") == why:
            return e["offset"]
    raise RuntimeError(f"the invented answer has no element refused for: {why}")


def main():
    rng = random.Random(secrets.randbits(64))
    failed = 0

    def report(label, good, detail=""):
        nonlocal failed
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label:34s} {detail}", flush=True)

    def run(s):
        """(accepted, published values after the key hash, reason of refusal)."""
        agg.compiled(NAME)
        path = os.path.join(agg.pkg(NAME), "ProverTest.toml")
        with open(path, "w") as f:
            f.write(ei.prover_toml(s["doc"], s["signature"], s["modulus"], s["offsets"], s["count"],
                                   ei.party_id(s["buyer"]), ei.party_id(s["seller"]), s["threshold"], s["context"],
                                   doc_len=s["doc_len"]))
        try:
            r = subprocess.run(["nargo", "execute", "-p", "ProverTest", "witness_test"], cwd=agg.pkg(NAME),
                               capture_output=True, text=True)
        finally:
            os.remove(path)
        text = r.stdout + r.stderr
        if r.returncode != 0:
            if not any(mark in text for mark in ("Failed constraint", "Assertion failed", "Failed to solve", "Index out of bounds")):
                raise RuntimeError(f"nargo failed for a reason other than a circuit constraint:\n{text[-600:]}")
            reason = next((l.strip() for l in text.splitlines() if "ssert" in l or "Failed" in l or "out of bounds" in l), "")
            return False, None, reason[-72:]
        values = [int(v, 0) for v in re.findall(r"0x[0-9a-f]+|\b\d+\b", re.search(r"Circuit output: (.*)", text).group(1))]
        return True, values[1:], ""

    def expected(s):
        return ei.published(s["counted"], s["day"], s["buyer"], s["seller"], s["context"])

    def accept(label, s, note):
        accepted, values, why = run(s)
        report(label, accepted and values == expected(s), note if accepted else f"rejected [{why}]")

    def refuse(label, s):
        accepted, _, why = run(s)
        report(label, not accepted, "accepted" if accepted else f"rejected [{why}]")

    # --- valid selections ---
    s = base(rng)
    accept("3 open invoices among 8", s, "accepted, published values recomputed")
    accept("threshold equal to the sum", dict(s, threshold=s["total"]), "accepted")
    accept("1 invoice", base(rng, n=1, others=2), "accepted")
    accept("10 invoices among 15", base(rng, n=10, others=5), "accepted")

    def tricky(mixed, seller, buyer):
        for e in mixed:
            e["DocNumber"] = '1 > 2 " Amount="999999.00" Status="PAID" BuyerTin="X00000000X'
    accept("values that look like attributes", base(rng, edit=tricky), "accepted, amounts and status unaffected")

    # --- an element that must not be counted is put among the counted ---
    for label, why in (("an invoice to another buyer", None), ("a refused invoice", "status is not ACCEPTED"),
                       ("an invoice of another type", "not a commercial invoice (type 380)"),
                       ("an invoice with a negative amount", "negative amount")):
        s = base(rng)
        s["offsets"] = sorted(s["offsets"] + [other_element(s, why)])
        s["count"] += 1
        refuse(label, s)

    def paid_only(mixed, seller, buyer):
        for e in mixed:
            if e["Status"] == "REFUSED":
                e["Status"] = "PAID"
    s = base(rng, edit=paid_only)
    s["offsets"] = sorted(s["offsets"] + [other_element(s, "status is not ACCEPTED")])
    s["count"] += 1
    refuse("a paid invoice", s)

    def second_seller(mixed, seller, buyer):
        next(e for e in mixed if e["BuyerTin"] == buyer and e["Status"] == "ACCEPTED" and e["DocType"] == "380"
             and not e["Amount"].startswith("-"))["SellerTin"] = "M00000001Z"
    s = base(rng, edit=second_seller)
    stranger = next(e["offset"] for e in s["answer"]["einvoices"] if e.get("seller") == "M00000001Z")
    s["seller"] = next(e["seller"] for e in s["answer"]["einvoices"] if e.get("seller") not in (None, "M00000001Z"))
    s["offsets"] = sorted(set(s["offsets"]) | {stranger})
    s["count"] = len(s["offsets"])
    refuse("an invoice of another seller", s)

    # --- the selection itself ---
    s = base(rng)
    refuse("an invoice counted twice", dict(s, offsets=[s["offsets"][0]] + s["offsets"], count=s["count"] + 1))
    refuse("invoices out of order", dict(s, offsets=s["offsets"][::-1]))
    refuse("an offset inside an element", dict(s, offsets=[s["offsets"][0] + 1] + s["offsets"][1:]))
    refuse("an offset at the list element", dict(s, offsets=[s["doc"].index(b"<Einvoices>")] + s["offsets"][1:]))
    refuse("no invoices", dict(s, count=0))
    refuse("more invoices than slots", dict(s, count=ei.K + 1))
    refuse("threshold above the sum", dict(s, threshold=s["total"] + 1))
    refuse("another buyer claimed", dict(s, buyer=ei.tax_number(rng)))
    refuse("another seller claimed", dict(s, seller=ei.tax_number(rng)))

    # --- the answer and its signature ---
    refuse("signature altered", dict(s, signature=s["signature"] ^ (1 << 7)))
    refuse("signed by another key", dict(s, modulus=modulus_of(new_key())))
    m = re.search(rb' Amount="(\d)', s["doc"][s["offsets"][0]:])
    at = s["offsets"][0] + m.start(1)
    edited = s["doc"][:at] + (b"9" if s["doc"][at:at + 1] != b"9" else b"8") + s["doc"][at + 1:]
    refuse("an amount changed after signing", dict(s, doc=edited))
    refuse("signed bytes cut short", dict(s, doc_len=len(s["doc"]) - 1))
    other = base(rng, root="GetTaxpayersResponse")
    listed = [h.start() for h in re.finditer(re.escape(ei.OPEN), other["doc"])]
    refuse("another message of the same service",
           dict(other, offsets=listed[:1], count=1, buyer=other["buyer"], seller=other["seller"], threshold=0))

    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
