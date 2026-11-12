"""Shared helpers for the EFI witness builders (see leaf_response_inputs.py, leaf_request_inputs.py).

Canonicalization and signature checking done here are conveniences for building a witness and for
failing early with a readable message. They are NOT trusted by the circuits, which rebuild or
re-hash the canonical bytes themselves.
"""
import base64
import copy
import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree

NS = {"ds": "http://www.w3.org/2000/09/xmldsig#", "e": "https://efi.tax.gov.me/fs/schema"}
DS = "{http://www.w3.org/2000/09/xmldsig#}"

# Must stay byte-identical to SI_HEAD / SI_MID / SI_TAIL in noir/pf_xmldsig/src/lib.nr.
SI_HEAD = (
    b'<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
    b'<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>'
    b'<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>'
    b'<Reference URI="#'
)
SI_MID = (
    b'"><Transforms>'
    b'<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform>'
    b'<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms>'
    b'<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod><DigestValue>'
)
SI_TAIL = b"</DigestValue></Reference></SignedInfo>"

LIMB_BITS = 120
NUM_LIMBS = 18


def signed_info(uri: bytes, doc: bytes) -> bytes:
    """Canonical SignedInfo for a document whose root carries Id=<uri>."""
    return SI_HEAD + uri + SI_MID + base64.b64encode(hashlib.sha256(doc).digest()) + SI_TAIL


def limbs(n: int) -> list:
    return [(n >> (LIMB_BITS * i)) & ((1 << LIMB_BITS) - 1) for i in range(NUM_LIMBS)]


def redc_param(modulus: int) -> int:
    # noir-bignum v0.10 Barrett parameter: floor(2^(2*MOD_BITS + 6) / modulus)
    return (1 << (2 * 2048 + 6)) // modulus


def toml_bytes(name: str, b: bytes) -> str:
    return f"{name} = [{', '.join(str(x) for x in b)}]\n"


def toml_limbs(name: str, n: int) -> str:
    return f"{name} = [{', '.join(chr(34) + hex(x) + chr(34) for x in limbs(n))}]\n"


def toml_signature_block(signature: int, modulus: int, salt: int) -> str:
    return (
        toml_limbs("signature", signature)
        + toml_limbs("modulus", modulus)
        + toml_limbs("redc_param", redc_param(modulus))
        + f'salt = "{hex(salt)}"\n'
    )


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign(key, data: bytes) -> bytes:
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def modulus_of(key) -> int:
    return key.public_key().public_numbers().n


def synthetic_cert_b64(key) -> str:
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "SYNTHETIC TEST SIGNER - NOT A REAL PARTY")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def signature_element(key, uri: bytes, doc: bytes):
    """A ds:Signature element (lxml) over canonical bytes `doc`, laid out like real EFI messages."""
    si = signed_info(uri, doc)
    sig = etree.Element(DS + "Signature", nsmap={None: NS["ds"]})
    sinfo = etree.SubElement(sig, DS + "SignedInfo")
    etree.SubElement(sinfo, DS + "CanonicalizationMethod", Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    etree.SubElement(sinfo, DS + "SignatureMethod", Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    ref = etree.SubElement(sinfo, DS + "Reference", URI="#" + uri.decode())
    tr = etree.SubElement(ref, DS + "Transforms")
    etree.SubElement(tr, DS + "Transform", Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    etree.SubElement(tr, DS + "Transform", Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    etree.SubElement(ref, DS + "DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
    etree.SubElement(ref, DS + "DigestValue").text = base64.b64encode(hashlib.sha256(doc).digest()).decode()
    etree.SubElement(sig, DS + "SignatureValue").text = base64.b64encode(sign(key, si)).decode()
    x = etree.SubElement(etree.SubElement(sig, DS + "KeyInfo"), DS + "X509Data")
    etree.SubElement(x, DS + "X509Certificate").text = synthetic_cert_b64(key)
    return sig


def canonical_without_signature(element) -> bytes:
    body = copy.deepcopy(element)
    s = body.find("ds:Signature", NS)
    if s is not None:
        body.remove(s)
    return etree.tostring(body, method="c14n", exclusive=True)


def ingest_signed(xml: bytes, localname: str, uri: bytes):
    """Signed EFI message (bare or in a SOAP envelope) -> (canonical doc, signature int, modulus int).

    Raises if the element is missing or unsigned, the signer key is not RSA-2048/e=65537, the
    canonical SignedInfo does not match the fixed template, or the signature does not verify.
    """
    root = etree.fromstring(xml, etree.XMLParser(remove_blank_text=True, resolve_entities=False, no_network=True))
    el = root if etree.QName(root).localname == localname else root.find(".//e:" + localname, NS)
    if el is None:
        raise ValueError(f"no {localname} element")
    sig = el.find("ds:Signature", NS)
    if sig is None:
        raise ValueError(f"{localname} is not signed")
    sig_value = base64.b64decode(sig.find("ds:SignatureValue", NS).text)
    cert = x509.load_der_x509_certificate(base64.b64decode(sig.find(".//ds:X509Certificate", NS).text))
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size != 2048 or pub.public_numbers().e != 65537:
        raise ValueError("signer key is not RSA-2048 with e=65537")
    doc = canonical_without_signature(el)
    si = etree.tostring(sig.find("ds:SignedInfo", NS), method="c14n", exclusive=True)
    if si != signed_info(uri, doc):
        raise ValueError("canonical SignedInfo does not match the fixed template or the document digest")
    pub.verify(sig_value, si, padding.PKCS1v15(), hashes.SHA256())  # raises if invalid
    return doc, int.from_bytes(sig_value, "big"), pub.public_numbers().n
