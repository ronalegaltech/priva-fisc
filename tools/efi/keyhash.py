#!/usr/bin/env python3
"""Key hash of an RSA-2048 certificate, as published by the circuits.

  keyhash.py CERT.der|CERT.pem           print the key hash and the certificate's public facts
  keyhash.py --from-xml SIGNED.xml       same, for the certificate embedded in a signed EFI message

A verifier uses this to check that the `issuer key hash` of a proof is the tax authority's key:
take the authority's public certificate, compute the hash here, compare.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from efi_common import NS, toml_limbs

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.normpath(os.path.join(HERE, "..", "..", "noir", "rsa_key_hash"))


def load_cert(path, from_xml):
    data = open(path, "rb").read()
    if from_xml:
        root = etree.fromstring(data, etree.XMLParser(resolve_entities=False, no_network=True))
        b64 = root.find(".//ds:X509Certificate", NS).text
        return x509.load_der_x509_certificate(base64.b64decode(re.sub(r"\s", "", b64)))
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def key_hash(modulus: int) -> int:
    name = "ProverKey" + next(tempfile._get_candidate_names())
    path = os.path.join(PKG, name + ".toml")
    with open(path, "w") as f:
        f.write(toml_limbs("modulus", modulus))
    try:
        r = subprocess.run(["nargo", "execute", "-p", name, "witness_key"], cwd=PKG, capture_output=True, text=True)
    finally:
        os.remove(path)
    m = re.search(r"Circuit output: (0x[0-9a-f]+)", r.stdout + r.stderr)
    if r.returncode != 0 or m is None:
        raise RuntimeError("could not compute the key hash:\n" + r.stderr.strip())
    return int(m.group(1), 16)


def describe(cert):
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size != 2048 or pub.public_numbers().e != 65537:
        raise ValueError("certificate key is not RSA-2048 with e=65537")
    n = pub.public_numbers().n
    return {
        "key_hash": hex(key_hash(n)),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": hex(cert.serial_number),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "certificate_sha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "modulus": hex(n),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--from-xml", action="store_true")
    a = ap.parse_args()
    print(json.dumps(describe(load_cert(a.path, a.from_xml)), indent=1))


if __name__ == "__main__":
    sys.exit(main())
