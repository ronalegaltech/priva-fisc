#!/usr/bin/env python3
"""The request reader on requests written by another implementation.

  python3 tools/efi/test_foreign_requests.py [--vectors DIR] [--xsd-dir DIR]

Every other test here feeds the reader requests that this repository's own generator wrote. This
one takes them from MonteFiskal (https://github.com/atakancelik/MonteFiskal, MIT), an independent
open-source client for the Montenegrin fiscalization service whose test vectors hold the exact
bytes of the request element before signing, for many kinds of invoice. The vectors are not kept
in this repository: copy the directory `test-vectors/xml` of that project somewhere and name it
with --vectors or in PF_EFI_VECTORS_DIR. Without it the test is skipped and exits with 0. Last run
against commit c515962 of that project (22 Nov 2026): sixteen invoice vectors, one of them with the
late-delivery mark in its header.

For each invoice vector:
  * the bytes have the digest the vector states;
  * this repository's canonicalization gives the same bytes;
  * signed here with a throw-away key, the request is valid under the published schema (only
    when --xsd-dir or PF_EFI_XSD_DIR is given, see test_schema.py);
  * the reader (noir/leaf_request_v0, executed, not proved) accepts it. A request longer than
    that circuit holds is reported and counted as not read.
"""
import argparse
import glob
import hashlib
import json
import os
import secrets
import subprocess
import sys

from lxml import etree

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from efi_common import canonical_without_signature, new_key  # noqa: E402
from leaf_request_inputs import MAX_DOC, ingest_xml, signed_xml, write_prover  # noqa: E402
import test_schema  # noqa: E402

PKG = os.path.normpath(os.path.join(HERE, "..", "..", "noir", "leaf_request_v0"))
PARSER = etree.XMLParser(resolve_entities=False, no_network=True)


def execute(name):
    r = subprocess.run(["nargo", "execute", "-p", name, "witness_foreign"], cwd=PKG, capture_output=True, text=True)
    os.remove(os.path.join(PKG, name + ".toml"))
    err = r.stderr.strip()
    if r.returncode != 0 and not any(k in err for k in ("Failed constraint", "Assertion failed", "Failed to solve")):
        raise RuntimeError(f"nargo failed for a reason other than a circuit constraint:\n{err}")
    return r.returncode == 0, next((l.strip() for l in err.splitlines() if "ssert" in l or "Failed" in l), "")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vectors", default=os.environ.get("PF_EFI_VECTORS_DIR"))
    ap.add_argument("--xsd-dir", default=os.environ.get("PF_EFI_XSD_DIR"))
    a = ap.parse_args()
    if not a.vectors:
        print("skipped: no vector directory (see the top of tools/efi/test_foreign_requests.py)")
        return 0
    vectors = []
    for path in sorted(glob.glob(os.path.join(a.vectors, "*.json"))):
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
        if v.get("kind") == "xml" and v.get("input", {}).get("message") == "invoice":
            vectors.append(v)
    if not vectors:
        print(f"FAIL: no invoice vectors in {a.vectors}")
        return 1
    schema = test_schema.load_schema(a.xsd_dir) if a.xsd_dir else None
    subprocess.run(["nargo", "compile"], cwd=PKG, check=True, capture_output=True)
    key = new_key()
    failed = accepted = 0

    for v in vectors:
        raw = v["expected"]["unsignedXml"].encode("utf-8")
        problems = []
        if hashlib.sha256(raw).hexdigest() != v["expected"]["canonicalSha256"]:
            problems.append("bytes do not have the stated digest")
        element = etree.fromstring(raw, PARSER)
        if canonical_without_signature(element) != raw:
            problems.append("canonical form differs")
        signed = signed_xml(key, element)
        if schema is not None and not schema.validate(etree.fromstring(signed, PARSER)):
            problems.append("not valid under the published schema")
        try:
            doc, signature, modulus = ingest_xml(signed)
        except ValueError as e:
            doc = None
            problems.append(f"not read [{e}]")
        if doc is not None and len(doc) > MAX_DOC:
            problems.append(f"{len(doc)} bytes, longer than this circuit reads")
        elif doc is not None:
            write_prover(os.path.join(PKG, "ProverForeign.toml"), doc, signature, modulus, secrets.randbits(248))
            ok, reason = execute("ProverForeign")
            if ok:
                accepted += 1
                marked = b" SubseqDelivType=" in doc[:400]
                result = f"accepted ({len(doc)} bytes{', late-delivery mark' if marked else ''})"
            else:
                problems.append(f"refused by the circuit [{reason[-80:]}]")
        failed += bool(problems)
        print(f"{'FAIL' if problems else 'ok  '} {v['id']:34s} {'; '.join(problems) if problems else result}")

    print(f"{len(vectors)} requests of another implementation: {accepted} read, {failed} wrong"
          + ("" if schema else " (schema not checked)"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
