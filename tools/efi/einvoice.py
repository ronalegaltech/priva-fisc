#!/usr/bin/env python3
"""Open e-invoices to one buyer, read from an answer of Albania's e-invoice service.

  einvoice.py synth --out ANSWER.xml [--n N] [--others M]    an invented signed answer, for demos and tests
  einvoice.py show ANSWER.xml                                what the tool reads from an answer (counts only)

In that service a taxpayer's software asks the central system for its e-invoices (GetEinvoices)
and gets back a list signed by the tax authority. Each e-invoice in it carries its code (EIC), the
document type, the amount, the tax numbers of buyer and seller and its status. The circuit
noir/einvoice_al_k10 (statement and limits in noir/pf_efi/src/einvoice.nr) proves that up to ten
e-invoices of one answer were issued by one seller to one buyer, are commercial invoices with the
status ACCEPTED, and add up to at least a threshold. `pf.py prove --einvoices ANSWER.xml` makes
such a proof.

This module is the Python side: the fixed text of the answer (it must stay byte-identical to
ALBANIA_EINVOICES in noir/pf_efi/src/format.nr), a reader that mirrors the circuit's, the inputs
of the circuit, and invented answers signed by a throw-away key.

What it rests on: the published specification only ("Einvoice Service, Technical Specification",
version 04). No real answer has been seen. The name of the root element, the list elements being
written without a prefix, and the attribute names Status, BuyerTin and SellerTin are taken from the
specification's tables and examples and have to be confirmed on a real message.

Privacy: prints counts and totals of invented data only; `show` prints counts, never codes,
amounts or tax numbers.
"""
import argparse
import datetime
import json
import random
import re
import secrets
import sys
import uuid

from lxml import etree

import buyer as buyer_reader
import poseidon2
from efi_common import canonical_without_signature, ingest_signed, modulus_of, new_key, redc_param, \
    signature_element, toml_limbs

NAMESPACE = "https://Einvoice.tatime.gov.al/EinvoiceService/schema"
# Must stay byte-identical to ALBANIA_EINVOICES in noir/pf_efi/src/format.nr.
HEAD = f'<ns2:GetEinvoicesResponse xmlns:ns2="{NAMESPACE}" Id="Response" Version="1"><ns2:Header'.encode()
OPEN = b"<Einvoice "
TAIL = b"</Einvoices></ns2:GetEinvoicesResponse>"

CIRCUIT = "einvoice_al_k10"
K = 10                 # slots of the circuit
M = 8192               # bytes the circuit reserves for the canonical answer
EINVOICE_TAG = 416     # bytes the circuit copies for one start tag; all but the last 16 are scanned
HEADER_TAG = 216
PUBLIC_VALUES = 7 + K  # threshold, context, authority key hash, count, buyer tag, seller tag, day, K nullifiers

DOMAIN_NULLIFIER_EIC = int.from_bytes(b"PF-NULLEIC", "big")
DOMAIN_BUYER = int.from_bytes(b"PF-BUYER01", "big")
DOMAIN_SELLER = int.from_bytes(b"PF-SELLER1", "big")

TAX_NUMBER = re.compile(r"[A-Za-z][0-9]{8}[A-Za-z]")
AMOUNT = re.compile(r"-?([1-9][0-9]*|0)\.[0-9]{2}")
EIC = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
PARTY = re.compile(r"NUIS:[A-Za-z][0-9]{8}[A-Za-z]")


class Refused(ValueError):
    """The reader, like the circuit, refuses this answer or this e-invoice."""


def party_id(tax_number: str) -> int:
    """A tax number as the circuits tag it: the text NUIS:<number>, the form a buyer has in a
    registration request (buyer.py)."""
    return buyer_reader.pack("NUIS", tax_number)


def _start_tag(doc: bytes, start: int, window: int, what: str):
    """Attributes of the start tag whose element name ends right before `start` (a space), read as
    the circuit's one-pass scan reads them. Returns ({name: [values]}, index of the closing '>')."""
    if doc[start:start + 1] != b" ":
        raise Refused(f"{what}: the element name is not followed by an attribute")
    in_quote, end = False, None
    for i in range(start, min(start + window, len(doc))):
        b = doc[i]
        if not in_quote:
            if b == 62:
                end = i
                break
            if b == 39:
                raise Refused(f"{what}: single quote at tag level")
            if b in (9, 10, 13):
                raise Refused(f"{what}: tab or line break at tag level")
        if b == 34:
            in_quote = not in_quote
    if end is None:
        raise Refused(f"{what}: the start tag does not close inside the scan window")
    tag = doc[start:end]
    outside = re.sub(rb'"[^"]*"', b'""', tag)
    if b" xmlns" in outside:
        raise Refused(f"{what}: namespace declaration")
    attrs = {}
    for m in re.finditer(rb' ([A-Za-z_][\w.\-]*)="([^"]*)"', tag):
        attrs.setdefault(m.group(1).decode(), []).append(m.group(2).decode("utf-8", "replace"))
    return attrs, end


def read_answer(doc: bytes):
    """The canonical answer as the circuit reads it: {"day": YYYYMMDD, "einvoices": [...]}. Every
    e-invoice element is listed with its offset; one the circuit would not count carries the
    reason under "refused"."""
    if len(doc) > M - EINVOICE_TAG - len(OPEN) + 1:
        raise Refused(f"the canonical answer is {len(doc)} bytes; the circuit handles at most {M - EINVOICE_TAG - len(OPEN) + 1}")
    if not doc.startswith(HEAD):
        raise Refused("this is not the answer the format describes")
    if not doc.endswith(TAIL):
        raise Refused("the answer does not end with its closing tags")
    header, _ = _start_tag(doc, len(HEAD), HEADER_TAG - 16, "header")
    sent = header.get("SendDateTime", [])
    if len(sent) != 1:
        raise Refused("SendDateTime is missing or repeated")
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T", sent[0])
    if m is None or not (1 <= int(m.group(2)) <= 12 and 1 <= int(m.group(3)) <= 31):
        raise Refused("SendDateTime is not a date and a time")
    day = int(m.group(1)) * 10000 + int(m.group(2)) * 100 + int(m.group(3))

    einvoices = []
    for hit in re.finditer(re.escape(OPEN), doc):
        at = hit.start()
        e = {"offset": at}
        try:
            attrs, end = _start_tag(doc, at + len(OPEN) - 1, EINVOICE_TAG - 16, "e-invoice")
            for name in ("Amount", "BuyerTin", "DocType", "EIC", "SellerTin", "Status"):
                if len(attrs.get(name, [])) != 1:
                    raise Refused(f"{name} is missing or repeated")
            amount = attrs["Amount"][0]
            if not AMOUNT.fullmatch(amount) or len(amount) > 15:
                raise Refused("the amount is not in the form the circuit reads")
            for name in ("BuyerTin", "SellerTin"):
                if not TAX_NUMBER.fullmatch(attrs[name][0]):
                    raise Refused("a tax number is not letter, eight digits, letter")
            if not EIC.fullmatch(attrs["EIC"][0]):
                raise Refused("the e-invoice code is not a UUID")
            if not end + len(TAIL) < len(doc):
                raise Refused("the element lies outside the signed answer")
            cents = int(amount.replace("-", "").replace(".", ""))
            e.update(eic=int(attrs["EIC"][0].replace("-", ""), 16), cents=cents, negative=amount.startswith("-"),
                     buyer=attrs["BuyerTin"][0], seller=attrs["SellerTin"][0],
                     doc_type=attrs["DocType"][0], status=attrs["Status"][0])
            if e["doc_type"] != "380":
                raise Refused("not a commercial invoice (type 380)")
            if e["status"] != "ACCEPTED":
                raise Refused("status is not ACCEPTED")
            if e["negative"]:
                raise Refused("negative amount")
        except Refused as why:
            e["refused"] = str(why)
        einvoices.append(e)
    return {"day": day, "einvoices": einvoices}


def countable(answer, buyer: str, seller: str = None):
    """The e-invoices of an answer the statement can count for this buyer (a tax number), in the
    order of the answer. With no seller given it is the seller of the first of them; e-invoices
    of another seller are left out."""
    out = []
    for e in answer["einvoices"]:
        if "refused" in e or e["buyer"] != buyer:
            continue
        if seller is None:
            seller = e["seller"]
        if e["seller"] == seller:
            out.append(e)
    return out, seller


def ingest(xml: bytes):
    """Signed answer (bare, or inside a SOAP envelope) -> (canonical answer, signature int,
    modulus int). Raises if it is unsigned or the signature does not verify."""
    return ingest_signed(xml, "GetEinvoicesResponse", b"Response", namespaces=(NAMESPACE,))


def prover_toml(doc: bytes, signature: int, modulus: int, offsets, count: int, buyer: int, seller: int,
                threshold: int, context: int, doc_len=None) -> str:
    """Inputs of the circuit. `offsets` are the starts of the counted elements; the unused slots
    repeat the last one, as the circuit asks."""
    if len(doc) > M:
        raise Refused(f"the canonical answer is {len(doc)} bytes; the circuit holds {M}")
    slots = list(offsets) + [offsets[-1]] * (K - len(offsets)) if offsets else [0] * K
    out = "doc = [" + ", ".join(str(b) for b in doc + bytes(M - len(doc))) + "]\n"
    out += f"doc_len = {len(doc) if doc_len is None else doc_len}\n"
    out += toml_limbs("signature", signature)
    out += toml_limbs("issuer_modulus", modulus) + toml_limbs("issuer_redc", redc_param(modulus))
    out += "offsets = [" + ", ".join(str(o) for o in slots[:K]) + "]\n"
    out += f'count = "{count}"\nbuyer = "{hex(buyer)}"\nseller = "{hex(seller)}"\n'
    out += f'threshold_cents = "{threshold}"\ncontext = "{hex(context)}"\n'
    return out


def published(counted, day: int, buyer: str, seller: str, context: int):
    """What the circuit must publish after the authority key hash: count, buyer tag, seller tag,
    day, and K nullifiers."""
    nullifiers = [poseidon2.hash([DOMAIN_NULLIFIER_EIC, context, e["eic"]]) for e in counted] + [0] * (K - len(counted))
    return [len(counted), poseidon2.hash([DOMAIN_BUYER, context, party_id(buyer)]),
            poseidon2.hash([DOMAIN_SELLER, context, party_id(seller)]), day] + nullifiers


def decode(values):
    """The public values of a proof of this kind, by name."""
    count = values[3]
    if len(values) != PUBLIC_VALUES or not 1 <= count <= K:
        raise ValueError("these are not the public values of a proof about e-invoices")
    return {
        "circuit": CIRCUIT,
        "format": "al",
        "statement": "open e-invoices to one buyer, as the authority states them",
        "invoice_count": count,
        "threshold_cents": values[0],
        "context": hex(values[1]),
        "issuer_key_hash": hex(values[2]),
        "buyer_tag": hex(values[4]),
        "seller_tag": hex(values[5]),
        "answer_day": values[6],
        "nullifiers": [hex(v) for v in values[7:7 + count]],
    }


# --- Invented answers ---
def tax_number(rng) -> str:
    return rng.choice("JKLM") + "".join(str(rng.randrange(10)) for _ in range(8)) + rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def money(cents: int) -> str:
    return ("-" if cents < 0 else "") + f"{abs(cents) // 100}.{abs(cents) % 100:02d}"


def einvoice(rng, seller: str, buyer: str, cents=None, status="ACCEPTED", doc_type="380", number=None):
    """One invented e-invoice as the attributes of its element."""
    received = datetime.datetime(2026, rng.randrange(1, 11), rng.randrange(1, 28), rng.randrange(8, 18),
                                 rng.randrange(60), rng.randrange(60))
    return {
        "EIC": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "DocNumber": number or f"{rng.randrange(1, 9000)}/2026",
        "DocType": doc_type,
        "RecDateTime": received.isoformat() + "+01:00",
        "DueDateTime": (received + datetime.timedelta(days=60)).isoformat() + "+01:00",
        "Status": status,
        "Amount": money(rng.randrange(10000, 30000000) if cents is None else cents),
        "PartyType": "SELLER",
        "BuyerTin": buyer,
        "SellerTin": seller,
    }


def signed_answer(key, einvoices, sent="2026-11-15T10:20:30Z", root="GetEinvoicesResponse") -> bytes:
    """An answer shaped like the specification's example: SOAP envelope, prefixed root and header,
    list elements without a prefix, attributes in no particular order."""
    ns = "{" + NAMESPACE + "}"
    answer = etree.Element(ns + root, nsmap={"ns2": NAMESPACE}, Id="Response", Version="1")
    etree.SubElement(answer, ns + "Header", UUID=str(uuid.uuid4()), RequestUUID=str(uuid.uuid4()), SendDateTime=sent)
    lst = etree.SubElement(answer, "Einvoices")
    for attrs in einvoices:
        etree.SubElement(lst, "Einvoice", **attrs)
    answer.append(signature_element(key, b"Response", canonical_without_signature(answer)))
    env = etree.Element("{http://schemas.xmlsoap.org/soap/envelope/}Envelope",
                        nsmap={"SOAP-ENV": "http://schemas.xmlsoap.org/soap/envelope/"})
    etree.SubElement(env, "{http://schemas.xmlsoap.org/soap/envelope/}Header")
    etree.SubElement(env, "{http://schemas.xmlsoap.org/soap/envelope/}Body").append(answer)
    return etree.tostring(env, pretty_print=True)


def invented_list(rng, n: int, others: int, seller: str, buyer: str):
    """`n` open invoices to `buyer` scattered among `others` e-invoices the statement must not
    count: another buyer's, a refused one, a paid one, one with a negative amount, one of the
    "factored invoice" type. Returns (list, total of the n)."""
    wanted = [einvoice(rng, seller, buyer) for _ in range(n)]
    total = sum(int(e["Amount"].replace(".", "")) for e in wanted)
    rest = []
    for i in range(others):
        kind = i % 5
        if kind == 0:
            rest.append(einvoice(rng, seller, tax_number(rng)))
        elif kind == 1:
            rest.append(einvoice(rng, seller, buyer, status="REFUSED"))
        elif kind == 2:
            rest.append(einvoice(rng, seller, buyer, status="PAID"))
        elif kind == 3:
            rest.append(einvoice(rng, seller, buyer, cents=-rng.randrange(10000, 900000)))
        else:
            rest.append(einvoice(rng, seller, buyer, doc_type="393"))
    mixed = wanted + rest
    rng.shuffle(mixed)
    return mixed, total


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("synth")
    s.add_argument("--out", required=True, help="file for the signed answer; a summary goes to OUT.json")
    s.add_argument("--n", type=int, default=3, help="open invoices to the buyer (1 to 10, default 3)")
    s.add_argument("--others", type=int, default=5, help="other e-invoices in the answer (default 5)")
    w = sub.add_parser("show")
    w.add_argument("file")
    a = ap.parse_args()

    if a.cmd == "synth":
        if not 1 <= a.n <= K:
            sys.exit(f"between 1 and {K} invoices")
        rng = random.Random(secrets.randbits(64))
        seller, buyer = tax_number(rng), tax_number(rng)
        mixed, total = invented_list(rng, a.n, a.others, seller, buyer)
        xml = signed_answer(new_key(), mixed)
        with open(a.out, "wb") as f:
            f.write(xml)
        summary = {"count": a.n, "total": money(total), "buyer": f"NUIS:{buyer}", "seller": f"NUIS:{seller}",
                   "einvoices_in_answer": len(mixed), "format": "al"}
        with open(a.out + ".json", "w") as f:
            json.dump(summary, f, indent=1)
        print(f"invented answer with {len(mixed)} e-invoices written to {a.out}: {a.n} open invoices to "
              f"{summary['buyer']} from {summary['seller']}, total {summary['total']}")
        return 0

    doc, _, _ = ingest(open(a.file, "rb").read())
    answer = read_answer(bytes(doc))
    ok = [e for e in answer["einvoices"] if "refused" not in e]
    print(f"signature valid; answer of day {answer['day']}, {len(answer['einvoices'])} e-invoice(s), "
          f"{len(ok)} of them commercial invoices with the status ACCEPTED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
