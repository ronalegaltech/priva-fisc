#!/usr/bin/env python3
"""PRIVA-FISC command line: make a proof over a run of invoices, check one.

  pf.py prove  --out DIR --threshold EUR --year Y [--context HEX] [--keep FILE]  REQ1.xml RESP1.xml [REQ2.xml RESP2.xml ...]
  pf.py prove  --out DIR --synthetic N [--keep FILE]      (invented invoices, for demos and tests)
  pf.py verify DIR [--taxpayer-cert FILE]

`prove` runs on the taxpayer's machine. It reads signed request/response files (in ordinal order),
proves the statement, and leaves in DIR only what may be handed over: the proof, its public values
and a readable statement. Witness files are deleted. With --keep it also writes, for the taxpayer
alone, the record needed to answer spot checks later (tools/efi/opening.py); without it the proof
cannot be spot-checked afterwards.

1 or 10 invoices give a batch proof (noir/batch_k1, noir/batch_k10), which publishes one nullifier
and one opening commitment per invoice. Any other number, up to 4096, gives an aggregated proof
(noir/agg_*, leaves of up to 10 invoices), which publishes one root for each instead.

`verify` runs on the verifier's machine. It does NOT trust a verification key supplied with the
proof: it derives the key from the circuit in this repository, checks the proof against it, and
looks the authority key up in registry/issuer_keys.json.

A proof names the taxpayer only by the hash of the signing key. Who that is comes from the
taxpayer's fiscalization certificate: with --taxpayer-cert (a certificate file, or any signed EFI
request, which embeds it) `verify` checks that the key in the certificate is the key of the proof
and prints the certificate's subject. Checking the certificate itself (issuer, validity,
revocation) is done with ordinary X.509 tools and is not part of this command.

Run `. tools/toolchain.env` first.
"""
import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "efi"))
import agg  # noqa: E402
import batch_inputs  # noqa: E402
import keyhash  # noqa: E402
import opening  # noqa: E402

SIZES = (1, 10)   # batch circuits
LEAF = 10         # leaf size of aggregated proofs
NOT_PROVED = (
    "that the tax authority saw the CONTENT of these invoices (its signature covers the request "
    "UUID and the receipt code only) - ask for a spot check, see tools/efi/opening.py",
    "that no invoices exist after the last one, or on other devices of the same taxpayer",
)


def pkg(k):
    return os.path.join(ROOT, "noir", f"batch_k{k}")


def run(cmd, cwd=None, what=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        tail = (r.stderr.strip() or r.stdout.strip()).splitlines()[-6:]
        sys.exit(f"{what or cmd[0]} failed:\n  " + "\n  ".join(tail))
    return r


def circuit_json(k):
    run(["nargo", "compile"], cwd=pkg(k), what=f"compiling batch_k{k}")
    return os.path.join(pkg(k), "target", f"batch_k{k}.json")


def read_values(path):
    data = open(path, "rb").read()
    return [int.from_bytes(data[i:i + 32], "big") for i in range(0, len(data), 32)]


def decode(values):
    k = (len(values) - 6) // 2
    if k not in SIZES or len(values) != 6 + 2 * k:
        sys.exit(f"unexpected number of public values ({len(values)})")
    return {
        "circuit": f"batch_k{k}",
        "invoice_count": k,
        "threshold_cents": values[0],
        "context": hex(values[1]),
        "year": values[2],
        "taxpayer_key_hash": hex(values[3]),
        "issuer_key_hash": hex(values[4]),
        "starts_at_ordinal_one": values[5] == 1,
        "nullifiers": [hex(v) for v in values[6:6 + k]],
        "opening_commitments": [hex(v) for v in values[6 + k:6 + 2 * k]],
    }


def prove(a):
    if a.synthetic:
        k = a.synthetic
        invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(k, None, 1, None)
    else:
        if not a.files or len(a.files) % 2:
            sys.exit("give REQUEST.xml RESPONSE.xml for each invoice, in ordinal order")
        if a.threshold is None or a.year is None:
            sys.exit("--threshold and --year are required with real files")
        invoices, tmods, imods = [], set(), set()
        for req_path, resp_path in zip(a.files[0::2], a.files[1::2]):
            doc, req_sig, tmod = batch_inputs.ingest_request(open(req_path, "rb").read())
            fields, resp_sig, imod = batch_inputs.ingest_response(open(resp_path, "rb").read())
            tmods.add(tmod)
            imods.add(imod)
            invoices.append({"doc": doc, "req_sig": req_sig, "resp": fields, "resp_sig": resp_sig})
        if len(tmods) != 1 or len(imods) != 1:
            sys.exit("the files are not all signed by one taxpayer key and one authority key")
        k, tmod, imod = len(invoices), tmods.pop(), imods.pop()
        threshold = round(float(a.threshold) * 100)
        context = int(a.context, 0) if a.context else secrets.randbits(120)
        year = a.year
    if k not in SIZES:
        os.makedirs(a.out, exist_ok=True)
        try:
            agg.make_proof(LEAF, invoices, tmod, imod, threshold, context, year, a.out, keep=a.keep)
        except agg.StepFailed as e:
            sys.exit(f"no proof: {e}")
        print(f"aggregated proof for {k} invoices written to {a.out} (proof, public_inputs, statement.json)")
        if a.keep:
            print(f"spot-check record written to {a.keep} - keep it private")
        return 0

    circuit = circuit_json(k)
    tag = "Run" + next(tempfile._get_candidate_names())
    prover_file = os.path.join(pkg(k), f"Prover{tag}.toml")
    witness = os.path.join(pkg(k), "target", f"witness{tag}.gz")
    os.makedirs(a.out, exist_ok=True)
    try:
        batch_inputs.write_prover(prover_file, invoices, tmod, imod, threshold, context, year)
        run(["nargo", "execute", "-p", f"Prover{tag}", f"witness{tag}"], cwd=pkg(k), what="the statement does not hold for these invoices; witness generation")
        with tempfile.TemporaryDirectory() as tmp:
            run(["bb", "prove", "-b", circuit, "-w", witness, "-o", tmp, "-t", "evm", "--write_vk"], what="proving")
            for name in ("proof", "public_inputs"):
                shutil.copy(os.path.join(tmp, name), os.path.join(a.out, name))
    finally:
        for p in (prover_file, witness):
            if os.path.exists(p):
                os.remove(p)
    statement = decode(read_values(os.path.join(a.out, "public_inputs")))
    with open(os.path.join(a.out, "statement.json"), "w") as f:
        json.dump(statement, f, indent=1)
    print(f"proof for {k} invoice(s) written to {a.out} (proof, public_inputs, statement.json)")
    if a.keep:
        agg.write_private(a.keep, {"invoices": [opening.opening_of(i["doc"], i["resp"][3], hex(i["salt"])) for i in invoices]})
        print(f"spot-check record written to {a.keep} - keep it private")
    return 0


def verify(a):
    values = read_values(os.path.join(a.dir, "public_inputs"))
    if len(values) == 13:
        try:
            ok, st, problems, leaf_size = agg.verify(a.dir)
        except agg.StepFailed as e:
            sys.exit(f"verification could not run: {e}")
        if not ok:
            print("PROOF INVALID: " + "; ".join(problems))
            return 1
        k = st["invoice_count"]
        circuit_line = f"agg_top over leaves of up to {leaf_size} (all verification keys derived locally)"
        published = "one root each (see statement.json)"
    else:
        st = decode(values)
        k = st["invoice_count"]
        circuit = circuit_json(k)
        with tempfile.TemporaryDirectory() as tmp:
            run(["bb", "write_vk", "-b", circuit, "-o", tmp, "-t", "evm"], what="deriving the verification key")
            r = subprocess.run(["bb", "verify", "-k", os.path.join(tmp, "vk"), "-p", os.path.join(a.dir, "proof"),
                                "-i", os.path.join(a.dir, "public_inputs"), "-t", "evm"], capture_output=True, text=True)
        if "Proof verified successfully" not in (r.stdout + r.stderr):
            print("PROOF INVALID")
            return 1
        circuit_line = f"{st['circuit']} (verification key derived locally)"
        published = f"{k} each (see statement.json)"

    with open(os.path.join(ROOT, "registry", "issuer_keys.json")) as f:
        keys = {int(e["key_hash"], 16): e for e in json.load(f)["keys"]}
    issuer = keys.get(int(st["issuer_key_hash"], 16))
    print("PROOF VALID")
    print(f"  circuit                : {circuit_line}")
    print(f"  what is proved         : {k} consecutive invoice(s) of one business unit and one device,")
    print(f"                           issued in {st['year']}, each signed by the taxpayer key and each with")
    print("                           an authority receipt for the same request; no receipt used twice;")
    print(f"                           sum of totals >= {st['threshold_cents'] // 100}.{st['threshold_cents'] % 100:02d} EUR")
    print(f"  starts at ordinal 1    : {'yes' if st['starts_at_ordinal_one'] else 'no'}")
    print(f"  taxpayer key hash      : {st['taxpayer_key_hash']}")
    print(f"  authority key hash     : {st['issuer_key_hash']}")
    if issuer:
        print(f"  authority key          : LISTED as {issuer['id']} ({issuer['status']})")
    else:
        print("  authority key          : NOT IN registry/issuer_keys.json - do not rely on this proof")
    print(f"  context                : {st['context']}")
    print(f"  nullifiers / openings  : {published}")
    cert_ok = True
    if a.taxpayer_cert:
        cert = keyhash.describe(keyhash.load_cert(a.taxpayer_cert, a.taxpayer_cert.lower().endswith(".xml")))
        cert_ok = int(cert["key_hash"], 16) == int(st["taxpayer_key_hash"], 16)
        if cert_ok:
            print(f"  taxpayer               : key matches the certificate of {cert['subject']}")
            print(f"                           (issued by {cert['issuer']}, valid {cert['not_before'][:10]} to {cert['not_after'][:10]})")
        else:
            print("  taxpayer               : the key in this certificate is NOT the key of the proof")
    print("  NOT proved:")
    for line in NOT_PROVED:
        print(f"    - {line}")
    if not cert_ok:
        return 3
    return 0 if issuer else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prove")
    p.add_argument("--out", required=True)
    p.add_argument("--threshold", help="minimum sum of totals, in EUR (e.g. 1500.00)")
    p.add_argument("--year", type=int)
    p.add_argument("--context", help="hex value naming the verifier/purpose; random if omitted")
    p.add_argument("--synthetic", type=int, metavar="N")
    p.add_argument("--keep", metavar="FILE", help="write the spot-check record (private) to FILE")
    p.add_argument("files", nargs="*")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    v.add_argument("--taxpayer-cert", help="taxpayer certificate (DER/PEM), or a signed EFI request (.xml)")
    a = ap.parse_args()
    return prove(a) if a.cmd == "prove" else verify(a)


if __name__ == "__main__":
    sys.exit(main())
