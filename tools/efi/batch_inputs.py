#!/usr/bin/env python3
"""Witness builder for the batch circuits (noir/batch_k1, noir/batch_k10).

  synthetic --k K --out FILE [--tamper KIND] [--start N] [--threshold CENTS]
        K consecutive invoices of one synthetic taxpayer, each with a receipt signed by a synthetic
        "authority" key. Repo-safe: throw-away keys, invented identifiers.
  pairs --out FILE --threshold CENTS --year Y --context C  REQUEST.xml RESPONSE.xml [...]
        real request/response files, in ordinal order (one pair per invoice).

Privacy: prints counts and pass/fail only, never identifiers, amounts or signatures.
"""
import argparse
import random
import re
import secrets
import sys
import uuid

from efi_common import modulus_of, new_key, redc_param, sign, signed_info, toml_limbs
from leaf_request_inputs import EFI, build_request, core_fields, ingest_xml as ingest_request, money, signed_xml
from leaf_response_inputs import build_doc as build_response_doc, ingest_xml as ingest_response, synthetic_soap

M = 2048  # must match `global M` in noir/batch_k*/src/main.nr


def arr(xs):
    return "[" + ", ".join(str(x) for x in xs) + "]"


def limb_arr(n):
    return toml_limbs("x", n).split("=", 1)[1].strip()


def invoice_toml(invoices, taxpayer_mod, issuer_mod, m=M):
    """The invoice part of a Prover file, shared by the batch and aggregation-leaf circuits."""
    for inv in invoices:
        if len(inv["doc"]) > m:
            raise ValueError(f"a canonical request is {len(inv['doc'])} bytes; this circuit handles at most {m}")
    out = "request_docs = [" + ", ".join(arr(i["doc"] + bytes(m - len(i["doc"]))) for i in invoices) + "]\n"
    out += "request_lens = " + arr(i.get("doc_len", len(i["doc"])) for i in invoices) + "\n"
    out += "request_sigs = [" + ", ".join(limb_arr(i["req_sig"]) for i in invoices) + "]\n"
    for name, idx in (("resp_request_uuids", 0), ("resp_send_dts", 1), ("resp_uuids", 2), ("resp_fics", 3)):
        out += f"{name} = [" + ", ".join(arr(i["resp"][idx]) for i in invoices) + "]\n"
    out += "resp_sigs = [" + ", ".join(limb_arr(i["resp_sig"]) for i in invoices) + "]\n"
    out += toml_limbs("taxpayer_modulus", taxpayer_mod) + toml_limbs("taxpayer_redc", redc_param(taxpayer_mod))
    out += toml_limbs("issuer_modulus", issuer_mod) + toml_limbs("issuer_redc", redc_param(issuer_mod))
    out += "salts = [" + ", ".join(f'"{hex(i.setdefault("salt", secrets.randbits(248)))}"' for i in invoices) + "]\n"
    return out


def write_prover(path, invoices, taxpayer_mod, issuer_mod, threshold, context, year):
    """invoices: list of dicts with request doc/sig and the four response fields + sig."""
    out = invoice_toml(invoices, taxpayer_mod, issuer_mod)
    out += f'threshold_cents = "{threshold}"\ncontext = "{hex(context)}"\nyear = "{year}"\n'
    with open(path, "w") as f:
        f.write(out)


# Negative cases. Every one must be refused by the circuit.
TAMPERS = (
    "gap",              # ordinals 1,2,4,... (an invoice left out)
    "reused-receipt",   # one genuine receipt backs two invoices
    "broken-link",      # a receipt that belongs to a different request
    "below-threshold",  # threshold above the real sum
    "mixed-unit",       # one invoice from another business unit
    "mixed-device",     # one invoice from another device
    "wrong-year",       # stated year differs from the invoices' year
    "forged-receipt",   # one receipt signed by a key that is not the authority's
    "forged-request",   # one request signed by a key that is not the taxpayer's
    "total-edit",       # an amount changed after signing
    "old-receipt",      # a receipt the authority dated in the previous year
)


def synthetic(k, tamper, start, threshold, large=None, inflate=None):
    """k invented invoices. `large`: position of one invoice made far larger than the others
    (500,000.00 before tax), for tests of amount-weighted spot checks. `inflate`: position of one
    invoice that the taxpayer signs again showing 500,000.00 more than what was registered, keeping
    the registered identifiers; the circuits cannot see this, a spot check has to.

    Every invoice carries, under "authority", what the tax authority would have on record for it."""
    rng = random.Random(secrets.randbits(64))
    taxpayer, authority = new_key(), new_key()
    base = core_fields(rng)
    invoices, total = [], 0
    for n in range(k):
        c = dict(base)
        c["uuid"] = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        c["ordinal"] = start + n
        c["net"] = 50_000_000 if n == large else rng.randrange(1000, 300000)
        c["vat"] = c["net"] * 21 // 100
        c["total"] = c["net"] + c["vat"]
        if tamper == "gap" and n == k - 1 and k > 1:
            c["ordinal"] += 1
        if tamper == "mixed-unit" and n == k - 1 and k > 1:
            c["bu"] = c["bu"][:-1] + ("0" if c["bu"][-1] != "0" else "1")
        if tamper == "mixed-device" and n == k - 1 and k > 1:
            c["tcr"] = c["tcr"][:-1] + ("0" if c["tcr"][-1] != "0" else "1")
        total += c["total"]

        req_key = new_key() if (tamper == "forged-request" and n == k - 1) else taxpayer
        request = build_request(req_key, c, tricky=False)
        registered = request.find(EFI + "Invoice")
        record = {
            "iic": registered.get("IIC"), "ordinal": c["ordinal"], "issue_date_time": c["issue"],
            "total": money(c["total"]), "business_unit": c["bu"], "device": c["tcr"], "seller_tin": c["tin"],
        }
        if n == inflate:
            shown = dict(c, net=c["net"] + 50_000_000)
            shown["vat"] = shown["net"] * 21 // 100
            shown["total"] = shown["net"] + shown["vat"]
            total += shown["total"] - c["total"]
            request = build_request(req_key, shown, tricky=False)
            for name in ("IIC", "IICSignature"):
                request.find(EFI + "Invoice").set(name, registered.get(name))
        doc, req_sig, _ = ingest_request(signed_xml(req_key, request))

        resp_fields = (c["uuid"].encode(), (c["issue"]).encode(), str(uuid.uuid4()).encode(), str(uuid.uuid4()).encode())
        if tamper == "old-receipt" and n == k - 1:
            resp_fields = (resp_fields[0], (str(c["year"] - 1) + c["issue"][4:]).encode()) + resp_fields[2:]
        if tamper == "broken-link" and n == k - 1:
            resp_fields = (str(uuid.uuid4()).encode(),) + resp_fields[1:]
        resp_key = new_key() if (tamper == "forged-receipt" and n == k - 1) else authority
        fields, resp_sig, _ = ingest_response(synthetic_soap(resp_key, resp_fields))
        record["fic"] = fields[3].decode()
        invoices.append({"doc": doc, "req_sig": req_sig, "resp": fields, "resp_sig": resp_sig, "authority": record})

    if tamper == "reused-receipt" and k > 1:
        # The taxpayer signs a second request under the UUID of invoice 0 and reuses receipt 0.
        c = dict(base)
        c["uuid"] = invoices[0]["resp"][0].decode()
        c["ordinal"] = start + k - 1
        c["net"], c["vat"] = 100000, 21000
        c["total"] = 121000
        doc, req_sig, _ = ingest_request(signed_xml(taxpayer, build_request(taxpayer, c, tricky=False)))
        invoices[-1] = {"doc": doc, "req_sig": req_sig, "resp": invoices[0]["resp"], "resp_sig": invoices[0]["resp_sig"]}
    if tamper == "total-edit":
        d = invoices[-1]["doc"]
        m = re.search(rb' TotPrice="(\d)', d)
        invoices[-1]["doc"] = d[:m.start(1)] + (b"9" if m.group(1) != b"9" else b"8") + d[m.end(1):]

    if threshold is None:
        threshold = total // 2
    if tamper == "below-threshold":
        threshold = total + 1
    year = base["year"] + (1 if tamper == "wrong-year" else 0)
    return invoices, modulus_of(taxpayer), modulus_of(authority), threshold, secrets.randbits(120), year


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("synthetic")
    s.add_argument("--k", type=int, required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--tamper", choices=TAMPERS)
    s.add_argument("--start", type=int, default=1)
    s.add_argument("--threshold", type=int)
    p = sub.add_parser("pairs")
    p.add_argument("--out", required=True)
    p.add_argument("--threshold", type=int, required=True)
    p.add_argument("--year", type=int, required=True)
    p.add_argument("--context", type=lambda v: int(v, 0), default=1)
    p.add_argument("files", nargs="+")
    a = ap.parse_args()

    if a.cmd == "synthetic":
        invoices, tmod, imod, threshold, context, year = synthetic(a.k, a.tamper, a.start, a.threshold)
        print(f"synthetic batch: {a.k} invoice(s), {'valid' if a.tamper is None else 'tampered (' + a.tamper + ')'}")
    else:
        if len(a.files) % 2:
            sys.exit("pairs: give REQUEST.xml RESPONSE.xml for each invoice")
        invoices, tmods, imods = [], set(), set()
        for req_path, resp_path in zip(a.files[0::2], a.files[1::2]):
            with open(req_path, "rb") as f:
                doc, req_sig, tmod = ingest_request(f.read())
            with open(resp_path, "rb") as f:
                fields, resp_sig, imod = ingest_response(f.read())
            tmods.add(tmod)
            imods.add(imod)
            invoices.append({"doc": doc, "req_sig": req_sig, "resp": fields, "resp_sig": resp_sig})
        if len(tmods) != 1 or len(imods) != 1:
            sys.exit("pairs: the files are not all signed by one taxpayer key and one authority key")
        tmod, imod, threshold, context, year = tmods.pop(), imods.pop(), a.threshold, a.context, a.year
        print(f"real batch: {len(invoices)} pair(s), all signatures valid")
    write_prover(a.out, invoices, tmod, imod, threshold, context, year)
    print(f"wrote {a.out}")


if __name__ == "__main__":
    sys.exit(main())
