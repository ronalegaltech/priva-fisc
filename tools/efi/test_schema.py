#!/usr/bin/env python3
"""Invented Montenegrin invoices against the schema the tax administration publishes.

  python3 tools/efi/test_schema.py [--xsd-dir DIR]

The schema is not kept in this repository. The administration serves it next to its service:

  https://efi.tax.gov.me/fs-v1/eficg-fiscalization-service.xsd
  https://efi.tax.gov.me/fs-v1/xmldsig-core-schema.xsd

Put both files in one directory and name it with --xsd-dir or in PF_EFI_XSD_DIR. Without a
directory the test is skipped and exits with 0.

KNOWN holds the SHA-256 of the files this test was last run against (fetched 22 Nov 2026). Other
digests are reported and the test goes on: the administration may have published a new revision.

Checked: requests as the generator writes them (a plain one, one with look-alike text in its
free-text attributes, one without a buyer, and one in each of the other shapes the request reader
is tested on: times in UTC or with another offset, the late-delivery mark, a total of zero) and
receipts. Checked too, so that a pass means something, that the schema refuses a request with an
attribute it does not know, a late-delivery word it does not have, and times written in ways the
reader refuses. Not checked: the Albanian format, whose schema is published only as a listing
inside the specification.
"""
import argparse
import hashlib
import os
import random
import shutil
import sys
import tempfile
import uuid

from lxml import etree

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import formats  # noqa: E402
from efi_common import new_key  # noqa: E402
from leaf_request_inputs import SHAPES, build_request, core_fields, receipt_time, shaped, signed_xml  # noqa: E402
from leaf_response_inputs import synthetic_soap  # noqa: E402

MAIN = "eficg-fiscalization-service.xsd"
KNOWN = {
    MAIN: "242c657173ec62f2193447ebc52e3ef26fc4eaecaf7e335c9b9631935591243a",
    "xmldsig-core-schema.xsd": "3c6f965494dbbb62db13d9261739c36068010fc9be0b019785570d63d9ac42ed",
}
PARSER = etree.XMLParser(resolve_entities=False, no_network=True)


def load_schema(xsd_dir):
    """The schema, compiled from a copy in which `\\/` in two patterns is written `/`: libxml2
    refuses the escaped form, and inside a pattern the two mean the same."""
    tmp = tempfile.mkdtemp()
    try:
        for name in KNOWN:
            with open(os.path.join(xsd_dir, name), "rb") as f:
                data = f.read()
            digest = hashlib.sha256(data).hexdigest()
            if digest != KNOWN[name]:
                print(f"note: {name} has SHA-256 {digest}, not the revision this test was written against")
            if name == MAIN:
                data = data.replace(b"\\/", b"/")
            with open(os.path.join(tmp, name), "wb") as f:
                f.write(data)
        return etree.XMLSchema(etree.parse(os.path.join(tmp, MAIN), PARSER))
    finally:
        shutil.rmtree(tmp)


def message(xml: bytes, fmt):
    """The EFI element of a file (bare, or inside a SOAP envelope) as a document of its own."""
    root = etree.fromstring(xml, PARSER)
    prefix = "{" + fmt.namespace + "}"
    if root.tag.startswith(prefix):
        return root
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.startswith(prefix):
            return etree.fromstring(etree.tostring(el), PARSER)
    raise ValueError("no element of the format in the file")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xsd-dir", default=os.environ.get("PF_EFI_XSD_DIR"))
    a = ap.parse_args()
    if not a.xsd_dir:
        print("skipped: no schema directory (see the top of tools/efi/test_schema.py)")
        return 0
    missing = [n for n in KNOWN if not os.path.isfile(os.path.join(a.xsd_dir, n))]
    if missing:
        print(f"FAIL: {', '.join(missing)} not found in {a.xsd_dir}")
        return 1
    schema = load_schema(a.xsd_dir)
    fmt = formats.MONTENEGRO
    rng = random.Random(20261122)
    taxpayer, authority = new_key(), new_key()

    cases = []   # (label, xml bytes, expected valid)
    for label, tricky, buyer in (("request", False, "default"), ("request with look-alike text", True, "default"),
                                 ("request without a buyer", False, None)):
        c = core_fields(rng, fmt)
        if buyer is None:
            c["buyer"] = None
        cases.append((label, signed_xml(taxpayer, build_request(taxpayer, c, tricky=tricky, fmt=fmt)), True))
    # The other shapes the generator writes, which the request reader is tested on.
    for shape in SHAPES:
        c = shaped(core_fields(rng, fmt), shape)
        cases.append((f"request, shape {shape}", signed_xml(taxpayer, build_request(taxpayer, c, tricky=False, fmt=fmt)), True))
    c = core_fields(rng, fmt)
    receipt = (c["uuid"].encode(), receipt_time(c).encode(), str(uuid.uuid4()).encode(), str(uuid.uuid4()).encode())
    cases.append(("receipt", synthetic_soap(authority, receipt, fmt), True))
    unknown = build_request(taxpayer, core_fields(rng, fmt), tricky=False, fmt=fmt)
    unknown.find("{" + fmt.namespace + "}Invoice").set("IsSimplifiedInv", "false")
    cases.append(("request with an attribute the schema does not know", signed_xml(taxpayer, unknown), False))
    # What the reader refuses in a header or a time, the schema refuses too.
    for label, late, issue in (("request with a late-delivery word the schema does not have", "POWERCUT", None),
                               ("request whose issue time has no zone", None, lambda t: t[:19]),
                               ("request whose issue time has an offset of 15 hours", None, lambda t: t[:19] + "+15:00"),
                               ("request whose issue time ends in a small z", None, lambda t: t[:19] + "z")):
        c = core_fields(rng, fmt)
        if late:
            c["late"] = late
        if issue:
            c["send"], c["issue"] = c["issue"], issue(c["issue"])
        cases.append((label, signed_xml(taxpayer, build_request(taxpayer, c, tricky=False, fmt=fmt)), False))
    # One spelling the schema allows and the reader does not: a total of zero with a minus sign.
    c = shaped(core_fields(rng, fmt), "zero-total")
    minus_zero = build_request(taxpayer, c, tricky=False, fmt=fmt)
    minus_zero.find("{" + fmt.namespace + "}Invoice").set("TotPrice", "-0.00")
    cases.append(("request with a total of -0.00 (valid; the reader refuses it, see the README)",
                  signed_xml(taxpayer, minus_zero), True))

    failed = 0
    for label, xml, expected in cases:
        valid = schema.validate(message(xml, fmt))
        ok = valid == expected
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {label}: {'valid' if valid else 'refused'}")
        if not ok and not valid:
            for e in list(schema.error_log)[:8]:
                print(f"     {e.message[:240]}")
    print(f"{len(cases) - failed}/{len(cases)} as expected against the published schema")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
