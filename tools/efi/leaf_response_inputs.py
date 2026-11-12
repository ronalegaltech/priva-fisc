#!/usr/bin/env python3
"""Witness builder for noir/leaf_response_v0.

Turns a signed EFI `RegisterInvoiceResponse` (bare, or inside a SOAP envelope) into the Prover
file of the leaf circuit. Two sources:

  xml <file>   a response as received from the CIS
  synthetic    a freshly generated response signed by a throw-away RSA-2048 key (repo-safe:
               no real identifiers, no real keys)

Canonicalization happens here, outside the circuit, and is NOT trusted: the circuit rebuilds the
canonical bytes itself from fixed templates and only succeeds if the signature matches them.

Privacy: this tool never prints UUIDs, FICs or signatures. It prints lengths and pass/fail only.
"""
import argparse
import datetime
import re
import secrets
import sys
import uuid

from lxml import etree

from efi_common import NS, canonical_without_signature, ingest_signed, modulus_of, new_key, sign, \
    signature_element, signed_info, toml_bytes, toml_signature_block

EFI = "{https://efi.tax.gov.me/fs/schema}"

# Must stay byte-identical to DOC_P0..DOC_P4 in noir/pf_efi/src/response.nr.
DOC_P0 = b'<RegisterInvoiceResponse xmlns="https://efi.tax.gov.me/fs/schema" Id="Response" Version="1"><Header RequestUUID="'
DOC_P1 = b'" SendDateTime="'
DOC_P2 = b'" UUID="'
DOC_P3 = b'"></Header><FIC>'
DOC_P4 = b"</FIC></RegisterInvoiceResponse>"
DOC_RE = re.compile(
    re.escape(DOC_P0) + b"(.{36})" + re.escape(DOC_P1) + b"(.{25})" + re.escape(DOC_P2)
    + b"(.{36})" + re.escape(DOC_P3) + b"(.{36})" + re.escape(DOC_P4),
    re.S,
)


def build_doc(req_uuid: bytes, send_dt: bytes, resp_uuid: bytes, fic: bytes) -> bytes:
    return DOC_P0 + req_uuid + DOC_P1 + send_dt + DOC_P2 + resp_uuid + DOC_P3 + fic + DOC_P4


def write_prover(path, fields, signature: int, modulus: int, salt: int):
    req_uuid, send_dt, resp_uuid, fic = fields
    out = toml_bytes("request_uuid", req_uuid) + toml_bytes("send_date_time", send_dt)
    out += toml_bytes("response_uuid", resp_uuid) + toml_bytes("fic", fic)
    out += toml_signature_block(signature, modulus, salt)
    with open(path, "w") as f:
        f.write(out)


def ingest_xml(xml: bytes):
    """Signed response -> (fields, signature int, modulus int). Raises on anything unexpected."""
    doc, signature, modulus = ingest_signed(xml, "RegisterInvoiceResponse", b"Response")
    m = DOC_RE.fullmatch(doc)
    if m is None:
        raise ValueError(f"canonical response does not match the v0 template (len {len(doc)})")
    return m.groups(), signature, modulus


def synthetic_soap(key, fields) -> bytes:
    """A response shaped like what the CIS sends: SOAP envelope, non-canonical attribute order."""
    req_uuid, send_dt, resp_uuid, fic = (f.decode() for f in fields)
    resp = etree.Element(EFI + "RegisterInvoiceResponse", nsmap={None: NS["e"]}, Id="Response", Version="1")
    etree.SubElement(resp, EFI + "Header", UUID=resp_uuid, RequestUUID=req_uuid, SendDateTime=send_dt)
    etree.SubElement(resp, EFI + "FIC").text = fic
    resp.append(signature_element(key, b"Response", canonical_without_signature(resp)))
    env = etree.Element("{http://schemas.xmlsoap.org/soap/envelope/}Envelope",
                        nsmap={"env": "http://schemas.xmlsoap.org/soap/envelope/"})
    etree.SubElement(env, "{http://schemas.xmlsoap.org/soap/envelope/}Header")
    etree.SubElement(env, "{http://schemas.xmlsoap.org/soap/envelope/}Body").append(resp)
    return etree.tostring(env, pretty_print=True)


def random_fields():
    dt = datetime.datetime.now().replace(microsecond=0).isoformat() + "+01:00"
    return tuple(s.encode() for s in (str(uuid.uuid4()), dt, str(uuid.uuid4()), str(uuid.uuid4())))


# Negative cases. "signed-*" are things a real signer could in principle emit and the circuit must
# still refuse; the others are forgeries by the prover.
TAMPERS = ("fic-flip", "sig-flip", "wrong-key", "signed-nonhex", "signed-markup", "signed-bad-date")


def synthetic(tamper):
    key = new_key()
    fields = random_fields()
    if tamper is None:
        return ingest_xml(synthetic_soap(key, fields))  # full ingest path, as for a real response

    req_uuid, send_dt, resp_uuid, fic = fields
    if tamper == "signed-nonhex":
        fic = fic[:5] + b"g" + fic[6:]
    elif tamper == "signed-markup":
        fic = fic[:20] + b"</FIC><FIC>" + fic[31:]
    elif tamper == "signed-bad-date":
        send_dt = send_dt[:10] + b" " + send_dt[11:]
    signed_fields = (req_uuid, send_dt, resp_uuid, fic)
    assert all(len(a) == len(b) for a, b in zip(signed_fields, fields))
    signature = int.from_bytes(sign(key, signed_info(b"Response", build_doc(*signed_fields))), "big")
    modulus = modulus_of(key)

    witness_fields = signed_fields
    if tamper == "fic-flip":
        flipped = b"0" if fic[0:1] != b"0" else b"1"
        witness_fields = (req_uuid, send_dt, resp_uuid, flipped + fic[1:])
    elif tamper == "sig-flip":
        signature ^= 1 << 7
    elif tamper == "wrong-key":
        modulus = modulus_of(new_key())
    return witness_fields, signature, modulus


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    x = sub.add_parser("xml")
    x.add_argument("file")
    x.add_argument("--out", required=True)
    s = sub.add_parser("synthetic")
    s.add_argument("--out", required=True)
    s.add_argument("--tamper", choices=TAMPERS)
    a = ap.parse_args()

    if a.cmd == "xml":
        with open(a.file, "rb") as f:
            fields, signature, modulus = ingest_xml(f.read())
        print("ingest: signature valid, canonical form matches v0 template")
    else:
        fields, signature, modulus = synthetic(a.tamper)
        print(f"synthetic: {'valid' if a.tamper is None else 'tampered (' + a.tamper + ')'}")
    write_prover(a.out, fields, signature, modulus, secrets.randbits(248))
    print(f"wrote {a.out}")


if __name__ == "__main__":
    sys.exit(main())
