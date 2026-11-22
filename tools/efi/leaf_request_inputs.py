#!/usr/bin/env python3
"""Witness builder for noir/leaf_request_v0.

Turns a taxpayer-signed EFI `RegisterInvoiceRequest` (bare, or inside a SOAP envelope) into the
Prover file of the leaf circuit. Sources:

  xml <file>            a request as sent to the CIS
  synthetic             a freshly generated invoice signed by a throw-away RSA-2048 key (repo-safe);
                        --shape writes it in one of the other shapes the schema allows (SHAPES),
                        --tamper makes it one the circuit must refuse (TAMPERS)
  pair <out1> <out2>    two synthetic requests with the SAME invoice fields, key and salt: a plain
                        one and one stuffed with look-alike text. The circuit must return the same
                        outputs for both.

Privacy: this tool never prints UUIDs, IICs, amounts or signatures. It prints lengths and pass/fail.
"""
import argparse
import datetime
import hashlib
import random
import re
import secrets
import sys
import uuid

from lxml import etree

import formats
from efi_common import canonical_without_signature, ingest_signed, modulus_of, new_key, sign, \
    signature_element, signed_info, toml_bytes, toml_signature_block
from formats import MONTENEGRO

EFI = "{" + MONTENEGRO.namespace + "}"   # the Montenegrin element namespace, for the tools that edit such requests
MAX_DOC = 4096       # must match noir/leaf_request_v0/src/main.nr (TAG_WINDOW matches noir/pf_efi/src/request.nr)
TAG_WINDOW = 1280
# Invented parties, by format: seller name, buyer name, town, address.
PARTIES = {
    "me": ("Sintetički prodavac d.o.o.", "Sintetički kupac d.o.o.", "Budva", "Ulica bb"),
    "al": ("Shitës sintetik sh.p.k.", "Blerës sintetik sh.p.k.", "Tirana", "Rruga pa numër"),
}


def write_prover(path, doc: bytes, signature: int, modulus: int, salt: int, doc_len=None):
    if len(doc) > MAX_DOC:
        raise ValueError(f"canonical request is {len(doc)} bytes; v0 handles at most {MAX_DOC}")
    out = toml_bytes("doc", doc + bytes(MAX_DOC - len(doc)))
    out += f"doc_len = {len(doc) if doc_len is None else doc_len}\n"
    out += toml_signature_block(signature, modulus, salt)
    with open(path, "w") as f:
        f.write(out)


def precheck(doc: bytes):
    """Readable errors for what the reader does not take (the circuit enforces all of this itself).
    Returns the format the request is written in."""
    try:
        fmt = formats.of_request(doc)
        tag_start = fmt.tag_start(doc)
    except formats.UnknownFormat:
        raise ValueError("the request header is not one the reader takes (a format it does not know, a time "
                         "not written as the schema says, or a late-delivery word the schema does not have)")
    if b">" not in re.sub(rb'"[^"]*"', b'""', doc[tag_start:tag_start + TAG_WINDOW]):
        raise ValueError("<Invoice> start tag is longer than the reader's scan window")
    return fmt


def ingest_xml(xml: bytes):
    doc, signature, modulus = ingest_signed(xml, "RegisterInvoiceRequest", b"Request")
    precheck(doc)
    return doc, signature, modulus


# --- Synthetic invoices ---
def reg_code(rng):
    a = "abcdefghijklmnopqrstuvwxyz"
    return "".join([rng.choice(a), rng.choice(a)] + [str(rng.randrange(10)) for _ in range(3)]
                   + [rng.choice(a), rng.choice(a)] + [str(rng.randrange(10)) for _ in range(3)])


def party_number(rng, fmt=MONTENEGRO):
    """An invented identifier of the kind domestic companies carry in this format."""
    digits = "".join(str(rng.randrange(10)) for _ in range(8))
    if fmt.party_id_type == "NUIS":
        return rng.choice("JKLM") + digits + rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return digits


def core_fields(rng, fmt=MONTENEGRO):
    year = 2026
    issue = datetime.datetime(year, rng.randrange(1, 13), rng.randrange(1, 28), rng.randrange(8, 20),
                              rng.randrange(60), rng.randrange(60)).isoformat() + "+01:00"
    net = rng.randrange(1000, 500000)  # cents
    vat = net * 21 // 100
    return {
        "uuid": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "bu": reg_code(rng), "tcr": reg_code(rng), "soft": reg_code(rng), "oper": reg_code(rng),
        "ordinal": rng.randrange(1, 5000), "issue": issue, "year": year,
        "tin": party_number(rng, fmt),
        "net": net, "vat": vat, "total": net + vat,
    }


def money(cents: int) -> str:
    sign, cents = ("-", -cents) if cents < 0 else ("", cents)
    return f"{sign}{cents // 100}.{cents % 100:02d}"


def respell(time: str, zone: str) -> str:
    """The same moment as `time`, written in another zone: "Z", or an offset such as "-05:00"."""
    moment = datetime.datetime.fromisoformat(time.replace("Z", "+00:00"))
    if zone == "Z":
        return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sign = -1 if zone[0] == "-" else 1
    tz = datetime.timezone(sign * datetime.timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])))
    return moment.astimezone(tz).strftime("%Y-%m-%dT%H:%M:%S") + zone


def receipt_time(c) -> str:
    """The time an invented receipt carries: the invoice's own moment, on the country's clock. The
    receipt reader takes a time written with an offset only (noir/pf_efi/src/response.nr)."""
    return respell(c["issue"], "+01:00")


# Shapes of request the schema allows besides the plain one: the zone of the times spelled another
# way, the late-delivery mark in the header, a total of zero. The reader must take every one.
SHAPES = (
    "utc-z",                # both times in UTC, written with Z
    "offset-zero",          # both times in UTC, written +00:00
    "offset-minus-zero",    # the same, written -00:00
    "west-of-utc",          # written with a negative offset
    "quarter-hour-offset",  # an offset that is not a whole hour
    "send-z-issue-offset",  # the header in UTC with Z, the invoice with an offset
    "late-nointernet", "late-boundbook", "late-service", "late-technicalerror", "late-businessneeds",
    "late-utc-z",           # the late-delivery mark after a time written with Z
    "zero-total",           # a total of zero, written 0.00
    "zero-total-plain",     # the same, written 0 (the schema allows both)
)


def shaped(c, shape, position=0):
    """The invoice `c` written in one of SHAPES. "mixed" takes the shapes that leave the amount
    alone in turn, by the invoice's position in a run; None leaves the invoice as it is."""
    c = dict(c)
    if shape is None:
        return c
    if shape == "mixed":
        turn = [s for s in SHAPES if not s.startswith("zero-total")]
        shape = turn[position % len(turn)]
    zone = {"utc-z": "Z", "late-utc-z": "Z", "offset-zero": "+00:00", "offset-minus-zero": "-00:00",
            "west-of-utc": "-05:00", "quarter-hour-offset": "+05:45"}.get(shape)
    if zone:
        c["issue"] = respell(c["issue"], zone)
    if shape == "send-z-issue-offset":
        c["send"] = respell(c["issue"], "Z")
    if shape.startswith("late-"):
        c["late"] = "TECHNICALERROR" if shape == "late-utc-z" else shape[5:].upper()
    if shape.startswith("zero-total"):
        c["net"] = c["vat"] = c["total"] = 0
        c["plain_zero"] = shape == "zero-total-plain"
    return c


def build_request(key, c, tricky: bool, fmt=MONTENEGRO):
    """Unsigned request element, written in a NON-canonical attribute order on purpose.
    c["no_device"]: an invoice without a device code, numbered the way the Albanian specification
    numbers non-cash invoices. c["send"]: the header's time, when it is not the issue time.
    c["late"]: a late-delivery word for the header. c["plain_zero"]: amounts of zero written 0."""
    def amount(cents):
        return "0" if (cents == 0 and c.get("plain_zero")) else money(cents)

    EFI = "{" + fmt.namespace + "}"
    seller_name, default_buyer_name, town, address = PARTIES[fmt.name]
    device = "" if c.get("no_device") else c["tcr"]
    ikof_input = "|".join([c["tin"], c["issue"], str(c["ordinal"]), c["bu"], device, c["soft"], amount(c["total"])])
    iic_signature = sign(key, ikof_input.encode())
    iic = hashlib.md5(iic_signature).hexdigest().upper()

    req = etree.Element(EFI + "RegisterInvoiceRequest", nsmap={None: fmt.namespace}, Id="Request", Version=fmt.version)
    header = etree.SubElement(req, EFI + "Header", UUID=c["uuid"], SendDateTime=c.get("send", c["issue"]))
    if c.get("late"):
        header.set("SubseqDelivType", c["late"])
    inv = etree.SubElement(req, EFI + "Invoice")
    attrs = {
        "TypeOfInv": "NONCASH", "IssueDateTime": c["issue"],
        "InvNum": f'{c["bu"]}/{c["ordinal"]}/{c["year"]}/{c["tcr"]}', "InvOrdNum": str(c["ordinal"]),
        "TCRCode": c["tcr"], "IsIssuerInVAT": "true", "TotPriceWoVAT": amount(c["net"]),
        "TotVATAmt": amount(c["vat"]), "TotPrice": amount(c["total"]), "OperatorCode": c["oper"],
        "BusinUnitCode": c["bu"], "SoftCode": c["soft"], "IIC": iic,
        "IICSignature": iic_signature.hex().upper(), "IsReverseCharge": "false",
    }
    # One attribute differs between the two schemas: the Montenegrin one requires InvType and has no
    # IsSimplifiedInv, the Albanian one requires IsSimplifiedInv and has no InvType.
    if fmt.name == "al":
        attrs["IsSimplifiedInv"] = "false"
    else:
        attrs["InvType"] = "INVOICE"
    if tricky:
        # Free text that looks like attributes and markup. Canonical XML escapes the quotes.
        attrs["Note"] = 'x > y " TotPrice="0.01" InvOrdNum="1" IIC="' + "0" * 32 + '" /><Invoice TotPrice="0.02"'
        attrs["PayDeadline"] = "2026-12-31"
    if c.get("no_device"):
        del attrs["TCRCode"]
        attrs["InvNum"] = f'{c["ordinal"]}/{c["year"]}'
    for k, v in attrs.items():
        inv.set(k, v)
    pm = etree.SubElement(inv, EFI + "PayMethods")
    etree.SubElement(pm, EFI + "PayMethod", Type="ACCOUNT", Amt=amount(c["total"]))
    etree.SubElement(inv, EFI + "Seller", IDType=fmt.party_id_type, IDNum=c["tin"], Name=seller_name,
                     Address=address, Town=town, Country=fmt.country_code)
    buyer_name = 'Kupac "A&B" > d.o.o.' if tricky else default_buyer_name
    # c["buyer"]: {"type", "num"} to name another buyer, None for an invoice without one (retail sale).
    buyer = c.get("buyer", {"type": "TIN", "num": "12345678"})
    if buyer is not None:
        etree.SubElement(inv, EFI + "Buyer", IDType=buyer["type"], IDNum=buyer["num"], Name=buyer_name)
    items = etree.SubElement(inv, EFI + "Items")
    names = ['Usluga TotPrice="9.99"', 'Stavka > InvOrdNum="3"'] if tricky else ["Pravna usluga"]
    for n in names:
        etree.SubElement(items, EFI + "I", N=n, C="1", U="kom", Q="1.00", UPB=amount(c["net"]),
                         UPA=amount(c["total"]), R="0.00", RR="false", PB=amount(c["net"]), VR="21.00",
                         VA=amount(c["vat"]), PA=amount(c["total"]))
    st = etree.SubElement(inv, EFI + "SameTaxes")
    etree.SubElement(st, EFI + "SameTax", NumOfItems=str(len(names)), PriceBefVAT=amount(c["net"]),
                     VATRate="21.00", VATAmt=amount(c["vat"]))
    return req


def signed_xml(key, req) -> bytes:
    req.append(signature_element(key, b"Request", canonical_without_signature(req)))
    return etree.tostring(req)


# Negative cases. "signed-*" are documents the signer really signed and the circuit must still
# refuse; the others are forgeries by the prover.
TAMPERS = ("total-flip", "sig-flip", "wrong-key", "signed-dup-total", "signed-no-ordinal",
           "signed-bad-amount", "signed-truncated", "signed-cut-after-tag", "signed-namespace",
           "signed-tab-total", "signed-leading-zero", "signed-negative-zero",
           # times the schema does not allow
           "signed-offset-too-large", "signed-no-zone", "signed-lowercase-z", "signed-fraction",
           "signed-space-for-t", "signed-send-no-zone", "signed-send-z-then-text",
           # headers that are not one of the canonical shapes
           "signed-unknown-late", "signed-late-twice", "signed-late-after-uuid", "signed-uuid-twice",
           "signed-late-smuggles-uuid")


def synthetic(tamper, rng, shape=None):
    key = new_key()
    c = core_fields(rng)
    if shape is not None:
        c = shaped(c, shape)
    if tamper is None:
        return ingest_xml(signed_xml(key, build_request(key, c, tricky=False))) + (None,)

    doc = canonical_without_signature(build_request(key, c, tricky=False))
    tag_start = MONTENEGRO.tag_start(doc)   # leaf_request_v0 is a Montenegrin circuit
    tag_end = tag_start + re.sub(rb'"[^"]*"', lambda m: b'"' + b"x" * (len(m.group(0)) - 2) + b'"',
                                 doc[tag_start:]).index(b">")
    issue = rb'( IssueDateTime="[^"]{19})\+01:00"'
    sent = rb'(<Header SendDateTime="[^"]{19})\+01:00"'
    other_uuid = str(uuid.UUID(int=rng.getrandbits(128), version=4)).encode()
    signed_doc, doc_len = doc, None
    if tamper == "signed-dup-total":
        signed_doc = doc[:tag_end] + b' TotPrice="0.01"' + doc[tag_end:]
    elif tamper == "signed-no-ordinal":
        signed_doc = re.sub(rb' InvOrdNum="\d+"', b"", doc, count=1)
    elif tamper == "signed-bad-amount":
        signed_doc = re.sub(rb' TotPrice="(\d+)\.(\d\d)"', rb' TotPrice="\1,\2"', doc, count=1)
    elif tamper == "signed-truncated":
        signed_doc, doc_len = doc[:tag_start + 300], tag_start + 300  # signature covers a prefix only
    elif tamper == "signed-cut-after-tag":
        signed_doc, doc_len = doc[:tag_end + 1], tag_end + 1  # the start tag and nothing after it
    elif tamper == "signed-namespace":
        signed_doc = doc[:tag_end] + b' xmlns="urn:x"' + doc[tag_end:]  # no longer the EFI element
    elif tamper == "signed-tab-total":
        signed_doc = doc[:tag_end] + b'\tTotPrice="0.01"' + doc[tag_end:]  # a parser sees two totals
    elif tamper == "signed-leading-zero":
        signed_doc = re.sub(rb' TotPrice="', b' TotPrice="0', doc, count=1)
    elif tamper == "signed-negative-zero":
        signed_doc = re.sub(rb' TotPrice="[^"]*"', b' TotPrice="-0.00"', doc, count=1)
    elif tamper == "signed-offset-too-large":
        signed_doc = re.sub(issue, rb'\1+15:00"', doc, count=1)
    elif tamper == "signed-no-zone":
        signed_doc = re.sub(issue, rb'\1"', doc, count=1)
    elif tamper == "signed-lowercase-z":
        signed_doc = re.sub(issue, rb'\1z"', doc, count=1)
    elif tamper == "signed-fraction":
        signed_doc = re.sub(issue, rb'\1.5+01:00"', doc, count=1)
    elif tamper == "signed-space-for-t":
        signed_doc = re.sub(rb'( IssueDateTime="[^"]{10})T', rb"\1 ", doc, count=1)
    elif tamper == "signed-send-no-zone":
        signed_doc = re.sub(sent, rb'\1"', doc, count=1)
    elif tamper == "signed-send-z-then-text":
        signed_doc = re.sub(sent, rb'\1Z+01:00"', doc, count=1)
    elif tamper == "signed-unknown-late":
        signed_doc = doc.replace(b'" UUID="', b'" SubseqDelivType="POWERCUT" UUID="', 1)
    elif tamper == "signed-late-twice":
        signed_doc = doc.replace(b'" UUID="', b'" SubseqDelivType="SERVICE" SubseqDelivType="SERVICE" UUID="', 1)
    elif tamper == "signed-late-after-uuid":
        signed_doc = doc.replace(b'"></Header>', b'" SubseqDelivType="SERVICE"></Header>', 1)
    elif tamper == "signed-uuid-twice":
        signed_doc = doc.replace(b'" UUID="', b'" UUID="' + other_uuid + b'" UUID="', 1)
    elif tamper == "signed-late-smuggles-uuid":
        # Text in the mark's value that reads like the rest of a header carrying another identifier.
        signed_doc = doc.replace(b'" UUID="', b'" SubseqDelivType="SERVICE&quot; UUID=&quot;' + other_uuid + b'" UUID="', 1)
    assert tamper in ("total-flip", "sig-flip", "wrong-key", "signed-truncated", "signed-cut-after-tag") or signed_doc != doc, tamper
    signature = int.from_bytes(sign(key, signed_info(b"Request", signed_doc)), "big")
    modulus = modulus_of(key)

    witness_doc = doc if tamper in ("signed-truncated", "signed-cut-after-tag") else signed_doc
    if tamper == "total-flip":
        m = re.search(rb' TotPrice="(\d)', doc)
        flipped = b"1" if m.group(1) != b"1" else b"2"
        witness_doc = doc[:m.start(1)] + flipped + doc[m.end(1):]
    elif tamper == "sig-flip":
        signature ^= 1 << 7
    elif tamper == "wrong-key":
        modulus = modulus_of(new_key())
    return witness_doc, signature, modulus, doc_len


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    x = sub.add_parser("xml")
    x.add_argument("file")
    x.add_argument("--out", required=True)
    s = sub.add_parser("synthetic")
    s.add_argument("--out", required=True)
    s.add_argument("--tamper", choices=TAMPERS)
    s.add_argument("--shape", choices=SHAPES)
    p = sub.add_parser("pair")
    p.add_argument("out_plain")
    p.add_argument("out_tricky")
    a = ap.parse_args()
    rng = random.Random(secrets.randbits(64))

    if a.cmd == "xml":
        with open(a.file, "rb") as f:
            doc, signature, modulus = ingest_xml(f.read())
        print(f"ingest: signature valid, canonical request is {len(doc)} bytes")
        write_prover(a.out, doc, signature, modulus, secrets.randbits(248))
        print(f"wrote {a.out}")
    elif a.cmd == "synthetic":
        doc, signature, modulus, doc_len = synthetic(a.tamper, rng, a.shape)
        write_prover(a.out, doc, signature, modulus, secrets.randbits(248), doc_len)
        print(f"synthetic: {'valid' if a.tamper is None else 'tampered (' + a.tamper + ')'}"
              f"{', shape ' + a.shape if a.shape else ''}, {len(doc)} bytes")
        print(f"wrote {a.out}")
    else:
        key, c, salt = new_key(), core_fields(rng), secrets.randbits(248)
        for out, tricky in ((a.out_plain, False), (a.out_tricky, True)):
            doc, signature, modulus = ingest_xml(signed_xml(key, build_request(key, c, tricky)))
            write_prover(out, doc, signature, modulus, salt)
            print(f"pair: {'tricky' if tricky else 'plain'} request, {len(doc)} bytes, wrote {out}")


if __name__ == "__main__":
    sys.exit(main())
