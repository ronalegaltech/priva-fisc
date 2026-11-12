#!/usr/bin/env python3
"""Witness builder for noir/leaf_request_v0.

Turns a taxpayer-signed EFI `RegisterInvoiceRequest` (bare, or inside a SOAP envelope) into the
Prover file of the leaf circuit. Sources:

  xml <file>            a request as sent to the CIS
  synthetic             a freshly generated invoice signed by a throw-away RSA-2048 key (repo-safe)
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

from efi_common import NS, canonical_without_signature, ingest_signed, modulus_of, new_key, sign, \
    signature_element, signed_info, toml_bytes, toml_signature_block

EFI = "{https://efi.tax.gov.me/fs/schema}"
MAX_DOC = 4096       # must match noir/leaf_request_v0/src/main.nr (TAG_* match noir/pf_efi/src/request.nr)
TAG_START = 200
TAG_WINDOW = 1280
HEADER_RE = re.compile(
    rb'<RegisterInvoiceRequest xmlns="https://efi\.tax\.gov\.me/fs/schema" Id="Request" Version="1">'
    rb'<Header SendDateTime="[^"]{25}" UUID="[^"]{36}"></Header><Invoice '
)


def write_prover(path, doc: bytes, signature: int, modulus: int, salt: int, doc_len=None):
    if len(doc) > MAX_DOC:
        raise ValueError(f"canonical request is {len(doc)} bytes; v0 handles at most {MAX_DOC}")
    out = toml_bytes("doc", doc + bytes(MAX_DOC - len(doc)))
    out += f"doc_len = {len(doc) if doc_len is None else doc_len}\n"
    out += toml_signature_block(signature, modulus, salt)
    with open(path, "w") as f:
        f.write(out)


def precheck(doc: bytes):
    """Readable errors for the v0 liveness limits (the circuit enforces all of this itself)."""
    if not HEADER_RE.match(doc):
        raise ValueError("header does not match the v0 template (SubseqDelivType or 'Z' time zone?)")
    if b">" not in re.sub(rb'"[^"]*"', b'""', doc[TAG_START:TAG_START + TAG_WINDOW]):
        raise ValueError("<Invoice> start tag is longer than the v0 scan window")


def ingest_xml(xml: bytes):
    doc, signature, modulus = ingest_signed(xml, "RegisterInvoiceRequest", b"Request")
    precheck(doc)
    return doc, signature, modulus


# --- Synthetic invoices ---
def reg_code(rng):
    a = "abcdefghijklmnopqrstuvwxyz"
    return "".join([rng.choice(a), rng.choice(a)] + [str(rng.randrange(10)) for _ in range(3)]
                   + [rng.choice(a), rng.choice(a)] + [str(rng.randrange(10)) for _ in range(3)])


def core_fields(rng):
    year = 2026
    issue = datetime.datetime(year, rng.randrange(1, 13), rng.randrange(1, 28), rng.randrange(8, 20),
                              rng.randrange(60), rng.randrange(60)).isoformat() + "+01:00"
    net = rng.randrange(1000, 500000)  # cents
    vat = net * 21 // 100
    return {
        "uuid": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "bu": reg_code(rng), "tcr": reg_code(rng), "soft": reg_code(rng), "oper": reg_code(rng),
        "ordinal": rng.randrange(1, 5000), "issue": issue, "year": year,
        "tin": "".join(str(rng.randrange(10)) for _ in range(8)),
        "net": net, "vat": vat, "total": net + vat,
    }


def money(cents: int) -> str:
    return f"{cents // 100}.{cents % 100:02d}"


def build_request(key, c, tricky: bool):
    """Unsigned request element, written in a NON-canonical attribute order on purpose."""
    ikof_input = "|".join([c["tin"], c["issue"], str(c["ordinal"]), c["bu"], c["tcr"], c["soft"], money(c["total"])])
    iic_signature = sign(key, ikof_input.encode())
    iic = hashlib.md5(iic_signature).hexdigest().upper()

    req = etree.Element(EFI + "RegisterInvoiceRequest", nsmap={None: NS["e"]}, Id="Request", Version="1")
    etree.SubElement(req, EFI + "Header", UUID=c["uuid"], SendDateTime=c["issue"])
    inv = etree.SubElement(req, EFI + "Invoice")
    attrs = {
        "TypeOfInv": "NONCASH", "InvType": "INVOICE", "IsSimplifiedInv": "false", "IssueDateTime": c["issue"],
        "InvNum": f'{c["bu"]}/{c["ordinal"]}/{c["year"]}/{c["tcr"]}', "InvOrdNum": str(c["ordinal"]),
        "TCRCode": c["tcr"], "IsIssuerInVAT": "true", "TotPriceWoVAT": money(c["net"]),
        "TotVATAmt": money(c["vat"]), "TotPrice": money(c["total"]), "OperatorCode": c["oper"],
        "BusinUnitCode": c["bu"], "SoftCode": c["soft"], "IIC": iic,
        "IICSignature": iic_signature.hex().upper(), "IsReverseCharge": "false",
    }
    if tricky:
        # Free text that looks like attributes and markup. Canonical XML escapes the quotes.
        attrs["Note"] = 'x > y " TotPrice="0.01" InvOrdNum="1" IIC="' + "0" * 32 + '" /><Invoice TotPrice="0.02"'
        attrs["PayDeadline"] = "2026-12-31"
    for k, v in attrs.items():
        inv.set(k, v)
    pm = etree.SubElement(inv, EFI + "PayMethods")
    etree.SubElement(pm, EFI + "PayMethod", Type="ACCOUNT", Amt=money(c["total"]))
    etree.SubElement(inv, EFI + "Seller", IDType="TIN", IDNum=c["tin"], Name="Sintetički prodavac d.o.o.",
                     Address="Ulica bb", Town="Budva", Country="MNE")
    buyer_name = 'Kupac "A&B" > d.o.o.' if tricky else "Sintetički kupac d.o.o."
    etree.SubElement(inv, EFI + "Buyer", IDType="TIN", IDNum="12345678", Name=buyer_name)
    items = etree.SubElement(inv, EFI + "Items")
    names = ['Usluga TotPrice="9.99"', 'Stavka > InvOrdNum="3"'] if tricky else ["Pravna usluga"]
    for n in names:
        etree.SubElement(items, EFI + "I", N=n, C="1", U="kom", Q="1.00", UPB=money(c["net"]),
                         UPA=money(c["total"]), R="0.00", RR="false", PB=money(c["net"]), VR="21.00",
                         VA=money(c["vat"]), PA=money(c["total"]))
    st = etree.SubElement(inv, EFI + "SameTaxes")
    etree.SubElement(st, EFI + "SameTax", NumOfItems=str(len(names)), PriceBefVAT=money(c["net"]),
                     VATRate="21.00", VATAmt=money(c["vat"]))
    return req


def signed_xml(key, req) -> bytes:
    req.append(signature_element(key, b"Request", canonical_without_signature(req)))
    return etree.tostring(req)


# Negative cases. "signed-*" are documents the signer really signed and the circuit must still
# refuse; the others are forgeries by the prover.
TAMPERS = ("total-flip", "sig-flip", "wrong-key", "signed-dup-total", "signed-no-ordinal",
           "signed-bad-amount", "signed-truncated")


def synthetic(tamper, rng):
    key = new_key()
    c = core_fields(rng)
    if tamper is None:
        return ingest_xml(signed_xml(key, build_request(key, c, tricky=False))) + (None,)

    doc = canonical_without_signature(build_request(key, c, tricky=False))
    tag_end = TAG_START + re.sub(rb'"[^"]*"', lambda m: b'"' + b"x" * (len(m.group(0)) - 2) + b'"',
                                 doc[TAG_START:]).index(b">")
    signed_doc, doc_len = doc, None
    if tamper == "signed-dup-total":
        signed_doc = doc[:tag_end] + b' TotPrice="0.01"' + doc[tag_end:]
    elif tamper == "signed-no-ordinal":
        signed_doc = re.sub(rb' InvOrdNum="\d+"', b"", doc, count=1)
    elif tamper == "signed-bad-amount":
        signed_doc = re.sub(rb' TotPrice="(\d+)\.(\d\d)"', rb' TotPrice="\1,\2"', doc, count=1)
    elif tamper == "signed-truncated":
        signed_doc, doc_len = doc[:TAG_START + 300], TAG_START + 300  # signature covers a prefix only
    signature = int.from_bytes(sign(key, signed_info(b"Request", signed_doc)), "big")
    modulus = modulus_of(key)

    witness_doc = doc if tamper == "signed-truncated" else signed_doc
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
        doc, signature, modulus, doc_len = synthetic(a.tamper, rng)
        write_prover(a.out, doc, signature, modulus, secrets.randbits(248), doc_len)
        print(f"synthetic: {'valid' if a.tamper is None else 'tampered (' + a.tamper + ')'}, {len(doc)} bytes")
        print(f"wrote {a.out}")
    else:
        key, c, salt = new_key(), core_fields(rng), secrets.randbits(248)
        for out, tricky in ((a.out_plain, False), (a.out_tricky, True)):
            doc, signature, modulus = ingest_xml(signed_xml(key, build_request(key, c, tricky)))
            write_prover(out, doc, signature, modulus, salt)
            print(f"pair: {'tricky' if tricky else 'plain'} request, {len(doc)} bytes, wrote {out}")


if __name__ == "__main__":
    sys.exit(main())
