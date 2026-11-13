#!/usr/bin/env python3
"""Invented invoices for the debtor circuits (noir/debtor_k1, noir/debtor_k10): invoices one seller
issued to one buyer, scattered among its other invoices.

  synthetic(k, tamper=None, count=None) -> everything a Prover file needs, plus what a verifier
  should see come out.

Repo-safe: throw-away keys, invented identifiers.
"""
import random
import secrets
import uuid

import batch_inputs
import buyer as buyer_reader
from efi_common import modulus_of, new_key
from leaf_request_inputs import build_request, core_fields, ingest_xml as ingest_request, signed_xml
from leaf_response_inputs import ingest_xml as ingest_response, synthetic_soap

# Negative cases. Every one must be refused by the circuit. The altered invoice is the last one
# that counts.
TAMPERS = (
    "other-buyer",      # one invoice was issued to somebody else
    "other-id-type",    # same number, another kind of identifier
    "no-buyer",         # one invoice names no buyer (retail sale)
    "credit-note",      # one invoice has a negative total
    "reused-receipt",   # one genuine receipt backs two invoices
    "broken-link",      # a receipt that belongs to a different request
    "below-threshold",  # threshold above the real sum
    "wrong-year",       # stated year differs from the invoices' year
    "old-receipt",      # a receipt the authority dated in the previous year
    "forged-receipt",   # one receipt signed by a key that is not the authority's
    "forged-request",   # one request signed by a key that is not the taxpayer's
    "wrong-buyer-claimed",  # the prover names a buyer none of the invoices was issued to
    "count-zero",       # a statement about no invoices
    "count-too-large",  # more invoices than the circuit has slots
)
NEEDS_TWO = {"reused-receipt"}


def number(rng):
    return "".join(str(rng.randrange(10)) for _ in range(8))


def synthetic(k, tamper=None, count=None):
    """k signed pairs of which the first `count` (default: all) are invoices to one buyer. Slots
    after `count` hold invoices to other buyers, one of them a credit note: a prover's filler,
    which must not matter. Returns a dict."""
    rng = random.Random(secrets.randbits(64))
    taxpayer, authority = new_key(), new_key()
    base = core_fields(rng)
    count = k if count is None else count
    buyer = {"type": "TIN", "num": number(rng)}
    last = count - 1
    invoices, total, ordinal = [], 0, base["ordinal"]

    for n in range(k):
        c = dict(base)
        c["uuid"] = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        ordinal += rng.randrange(1, 40)  # other invoices lie in between
        c["ordinal"] = ordinal
        c["net"] = rng.randrange(1000, 300000)
        c["buyer"] = dict(buyer)
        if n >= count:
            c["buyer"]["num"] = number(rng)
            if n == k - 1:
                c["net"] = -100000
        elif n == last:
            if tamper == "other-buyer":
                c["buyer"]["num"] = number(rng)
            if tamper == "other-id-type":
                c["buyer"]["type"] = "VAT"
            if tamper == "no-buyer":
                c["buyer"] = None
            if tamper == "credit-note":
                c["net"] = -100000
        c["vat"] = c["net"] * 21 // 100
        c["total"] = c["net"] + c["vat"]
        if n < count:
            total += c["total"]

        req_key = new_key() if (tamper == "forged-request" and n == last) else taxpayer
        doc, req_sig, _ = ingest_request(signed_xml(req_key, build_request(req_key, c, tricky=False)))

        resp_fields = (c["uuid"].encode(), c["issue"].encode(), str(uuid.uuid4()).encode(), str(uuid.uuid4()).encode())
        if tamper == "old-receipt" and n == last:
            resp_fields = (resp_fields[0], (str(c["year"] - 1) + c["issue"][4:]).encode()) + resp_fields[2:]
        if tamper == "broken-link" and n == last:
            resp_fields = (str(uuid.uuid4()).encode(),) + resp_fields[1:]
        resp_key = new_key() if (tamper == "forged-receipt" and n == last) else authority
        fields, resp_sig, _ = ingest_response(synthetic_soap(resp_key, resp_fields))
        invoices.append({"doc": doc, "req_sig": req_sig, "resp": fields, "resp_sig": resp_sig,
                         "salt": secrets.randbits(248), "cents": c["total"]})

    if tamper == "reused-receipt" and count > 1:
        # The taxpayer signs a second request under the UUID of invoice 0 and reuses receipt 0.
        c = dict(base)
        c["uuid"] = invoices[0]["resp"][0].decode()
        c["ordinal"] = ordinal + 1
        c["net"], c["vat"], c["total"] = 100000, 21000, 121000
        c["buyer"] = dict(buyer)
        doc, req_sig, _ = ingest_request(signed_xml(taxpayer, build_request(taxpayer, c, tricky=False)))
        invoices[last] = dict(invoices[0], doc=doc, req_sig=req_sig, salt=secrets.randbits(248), cents=121000)

    claimed = buyer_reader.pack(buyer["type"], buyer["num"])
    if tamper == "wrong-buyer-claimed":
        claimed = buyer_reader.pack("TIN", number(rng))
    if tamper == "count-zero":
        count = 0
    if tamper == "count-too-large":
        count = k + 1
    return {
        "invoices": invoices,
        "taxpayer_modulus": modulus_of(taxpayer),
        "issuer_modulus": modulus_of(authority),
        "count": count,
        "buyer": claimed,
        "threshold": total + 1 if tamper == "below-threshold" else max(total, 0) // 2,
        "context": secrets.randbits(120),
        "year": base["year"] + (1 if tamper == "wrong-year" else 0),
        "total": total,
    }


def prover_toml(s):
    out = batch_inputs.invoice_toml(s["invoices"], s["taxpayer_modulus"], s["issuer_modulus"])
    out += f'count = "{s["count"]}"\nbuyer = "{hex(s["buyer"])}"\n'
    out += f'threshold_cents = "{s["threshold"]}"\ncontext = "{hex(s["context"])}"\nyear = "{s["year"]}"\n'
    return out
