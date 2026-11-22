#!/usr/bin/env python3
"""The signature layout the circuits rebuild, against real requests.

  python3 tools/efi/test_real_requests.py [--docx FILE]

The circuits do not parse `SignedInfo`: they rebuild its canonical text from a fixed template
around the digest (noir/pf_xmldsig, mirrored in efi_common.py) and check the RSA signature over
that. If real software wrote `SignedInfo` any other way, no real invoice could be proved.

The Montenegrin tax administration prints four requests "successfully sent" to its test service
in October 2020 in its access instructions ("Fiskalni servis - Uputstva za pristup fiskalizaciji",
v4.1, a DOCX published on gov.me, document id da00247f-14df-4ff2-a3ea-83ef15dc71e1; SHA-256
372260f57a56b61d853cccb80d9aa77bbccf826384626b5df68f7af213feca8d). They are signed with test
certificates of a certificate authority registered in Montenegro and come from two different
senders. The file is not kept in this repository: name it with --docx or in PF_EFI_ACCESS_DOCX.
Without it the test is skipped and exits with 0.

Checked for each of the four requests:
  * its canonical `SignedInfo` is byte for byte the fixed template around its own digest value;
  * its signature verifies over that template under the certificate it carries.
Checked for the one request whose printed text still gives the signed bytes (the registration of
a device): the digest of the canonical request is the digest that was signed.

Not shown by this test: the other three requests (a cash deposit and two invoices) are printed in
a form that no longer gives the signed bytes, so the canonicalization of a real invoice request is
still unconfirmed. The messages follow the schema of 2020, which differs from today's. There is no
receipt among them.
"""
import argparse
import base64
import copy
import hashlib
import html
import os
import re
import sys
import zipfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from efi_common import NS, SI_HEAD, SI_MID, SI_TAIL  # noqa: E402

PARSER = etree.XMLParser(resolve_entities=False, no_network=True)
EXPECTED_MESSAGES = 4
FULLY_PRINTED = "RegisterTCRRequest"


def envelopes(docx_path):
    """The distinct SOAP envelopes printed in the document, with the white space between elements
    (added for print) removed."""
    with zipfile.ZipFile(docx_path) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    paragraphs = []
    for p in re.findall(r"<w:p[ >].*?</w:p>", xml, flags=re.S):
        text = ""
        for m in re.finditer(r"<w:t(?: [^>]*)?>(.*?)</w:t>|<w:tab/>|<w:br/>|<w:cr/>", p, flags=re.S):
            text += html.unescape(m.group(1)) if m.group(1) is not None else ("\t" if m.group(0) == "<w:tab/>" else "\n")
        paragraphs.append(text)
    found = []
    for m in re.finditer(r"<(s|SOAP-ENV):Envelope .*?</\1:Envelope>", "\n".join(paragraphs), flags=re.S):
        compact = re.sub(r">\s+<", "><", m.group(0))
        if compact not in found:
            found.append(compact)
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--docx", default=os.environ.get("PF_EFI_ACCESS_DOCX"))
    a = ap.parse_args()
    if not a.docx:
        print("skipped: no document (see the top of tools/efi/test_real_requests.py)")
        return 0
    messages = envelopes(a.docx)
    failed = 0
    if len(messages) != EXPECTED_MESSAGES:
        print(f"FAIL: {len(messages)} distinct requests in the document, expected {EXPECTED_MESSAGES}")
        failed += 1

    for text in messages:
        root = etree.fromstring(text.encode("utf-8"), PARSER)
        request = next(e for e in root.iter() if isinstance(e.tag, str) and e.tag.endswith("Request"))
        kind = etree.QName(request).localname
        signature = request.find("ds:Signature", NS)
        digest_value = re.sub(r"\s+", "", signature.find(".//ds:DigestValue", NS).text).encode()
        signed_info = etree.tostring(signature.find("ds:SignedInfo", NS), method="c14n", exclusive=True)
        template = SI_HEAD + b"Request" + SI_MID + digest_value + SI_TAIL
        certificate = x509.load_der_x509_certificate(
            base64.b64decode(re.sub(r"\s+", "", signature.find(".//ds:X509Certificate", NS).text)))
        value = base64.b64decode(re.sub(r"\s+", "", signature.find("ds:SignatureValue", NS).text))
        try:
            certificate.public_key().verify(value, template, padding.PKCS1v15(), hashes.SHA256())
            verifies = True
        except InvalidSignature:
            verifies = False
        body = copy.deepcopy(request)
        body.remove(body.find("ds:Signature", NS))
        canonical = etree.tostring(body, method="c14n", exclusive=True)
        digest_matches = base64.b64encode(hashlib.sha256(canonical).digest()) == digest_value

        problems = []
        if signed_info != template:
            problems.append("SignedInfo is not the fixed template")
        if not verifies:
            problems.append("signature does not verify over the template")
        if kind == FULLY_PRINTED and not digest_matches:
            problems.append("digest of the canonical request is not the signed digest")
        failed += bool(problems)
        note = "digest of the request matches too" if digest_matches else "printed text does not give the signed bytes"
        print(f"{'FAIL' if problems else 'ok  '} {kind:27s} "
              + ("; ".join(problems) if problems else f"template identical, signature verifies; {note}"))

    print(f"{len(messages)} real requests: " + ("all as expected" if not failed else f"{failed} wrong"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
