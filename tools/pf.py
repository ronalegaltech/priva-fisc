#!/usr/bin/env python3
"""PRIVA-FISC command line: make a proof over a run of invoices, check one.

  pf.py prove  --out DIR --threshold EUR --year Y [--context HEX] [--keep FILE]  REQ1.xml RESP1.xml [REQ2.xml RESP2.xml ...]
  pf.py prove  --out DIR --synthetic N [--keep FILE]      (invented invoices, for demos and tests)
  pf.py prove  --buyer TYPE:NUMBER --out DIR --threshold EUR --year Y --context HEX  REQ1.xml RESP1.xml [...]
  pf.py verify DIR [--context HEX] [--ledger FILE] [--taxpayer-cert FILE] [--buyer TYPE:NUMBER]

`prove` runs on the taxpayer's machine. It reads signed request/response files (in ordinal order),
proves the statement, and leaves in DIR only what may be handed over: the proof, its public values
and a readable statement. Witness files are deleted. With --keep it also writes, for the taxpayer
alone, the record needed to answer spot checks later (tools/efi/opening.py); without it the proof
cannot be spot-checked afterwards.

1 or 10 invoices give a batch proof (noir/batch_k1, noir/batch_k10), which publishes one nullifier
and one opening commitment per invoice. Any other number, up to 4096, gives an aggregated proof
(noir/agg_*, leaves of up to 10 invoices), which publishes one root for each instead.

With --buyer the statement is another one: the 1 to 10 invoices given were all issued to that
buyer (for example TIN:02345678, as the identifier stands in the invoices), none has a negative
total, and their totals reach the threshold. They need not be consecutive. The proof (noir/debtor_k1,
noir/debtor_k10) publishes a tag of the buyer instead of the buyer; `verify --buyer` recomputes the
tag and refuses a proof about somebody else. Such proofs cannot be spot-checked with opening.py yet.
With --synthetic N (1 to 10) any word after --buyer will do: the buyer is invented and printed.

`verify` runs on the verifier's machine. It does NOT trust a verification key supplied with the
proof: it derives the key from the circuit in this repository, checks the proof against it, and
looks the authority key up in registry/issuer_keys.json.

The context is a hexadecimal value the VERIFIER chooses and hands to the taxpayer (who passes it
to `prove`). Nullifiers are bound to it, so a proof made for one verifier is of no use to another.
Give the same value to `verify --context`: a proof made for another context is refused.

A proof alone cannot show that it was not presented before: that needs memory. `verify --ledger
FILE` keeps it: the nullifiers of every proof accepted with that file are written to it, and a
proof that repeats one of them in the same context is refused. (The Starknet registry does the same
on a chain.) A verifier who uses neither, or who accepts whatever context a proof carries, has no
protection against the same invoices being shown twice.

Exit status of `verify`: 0 valid, with a production authority key; 1 invalid; 2 valid, but the
authority key is not listed or is not a production key; 3 the certificate given is not the
taxpayer key of the proof; 4 the proof was made for another context; 5 a nullifier of this proof
is already in the ledger; 6 the proof is not about the buyer given.

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
import buyer as buyer_reader  # noqa: E402
import debtor_inputs  # noqa: E402
import keyhash  # noqa: E402
import opening  # noqa: E402
import poseidon2  # noqa: E402

SIZES = (1, 10)   # batch circuits
LEAF = 10         # leaf size of aggregated proofs
NOT_PROVED = (
    "that the tax authority saw the CONTENT of these invoices: its signature covers the request "
    "UUID and the receipt code only. Ordinals, amounts, year, business unit and device are what "
    "the taxpayer signed - ask for a spot check, see tools/efi/opening.py",
    "that the amounts are true: one inflated invoice can carry a large part of the total. "
    "With an aggregated proof, ask by amount (opening.py --seed): an invoice is then asked for "
    "in proportion to its share of the gross positive total, which you do not see; a credit "
    "note signed again as a smaller one is not found that way",
    "that no invoices exist after the last one, or on other devices of the same taxpayer",
)


NOT_PROVED_ONE_BUYER = (
    "that the tax authority saw the CONTENT of these invoices: its signature covers the request "
    "UUID and the receipt code only. Buyer, amounts and year are what the taxpayer signed - have "
    "the invoices opened and compare them with the authority's record",
    "that these are all the invoices issued to this buyer, or that no credit note to this buyer "
    "exists: the sum is a lower bound on what was invoiced",
    "that an invoice was paid or corresponds to a real sale",
)
DOMAIN_BUYER = int.from_bytes(b"PF-BUYER01", "big")
BUYER_FORM = re.compile(r"[A-Z]{2,4}:[0-9A-Za-z]{1,20}")


def pkg(k):
    return os.path.join(ROOT, "noir", f"batch_k{k}")


def parse_buyer(text):
    if not BUYER_FORM.fullmatch(text):
        sys.exit("--buyer must look like TIN:02345678: the kind of identifier, a colon, the number")
    return buyer_reader.pack(*text.split(":"))


def one_buyer_slots(values):
    """Slots of the circuit behind a proof about one buyer, or None if the values are of another kind."""
    return next((k for k in SIZES if len(values) == 7 + 2 * k), None)


def decode_one_buyer(values):
    k, count = one_buyer_slots(values), values[5]
    if not 1 <= count <= k:
        sys.exit("unexpected number of invoices in the public values")
    return {
        "circuit": f"debtor_k{k}",
        "statement": "invoices issued to one buyer",
        "invoice_count": count,
        "threshold_cents": values[0],
        "context": hex(values[1]),
        "year": values[2],
        "taxpayer_key_hash": hex(values[3]),
        "issuer_key_hash": hex(values[4]),
        "buyer_tag": hex(values[6]),
        "nullifiers": [hex(v) for v in values[7:7 + count]],
        "opening_commitments": [hex(v) for v in values[7 + k:7 + k + count]],
    }


def verify_one_buyer(proof_dir, k):
    """True if the proof verifies under the key derived here from noir/debtor_k{k}."""
    name = f"debtor_k{k}"
    with tempfile.TemporaryDirectory() as tmp:
        agg.run(["bb", "write_vk", "-b", agg.compiled(name), "-o", tmp, "-t", "evm"], what=f"key of {name}")
        return agg.bb_verifies(os.path.join(tmp, "vk"), os.path.join(proof_dir, "proof"),
                               os.path.join(proof_dir, "public_inputs"))


def prove_one_buyer(a):
    if a.synthetic:
        n = a.synthetic
        if not 1 <= n <= 10:
            sys.exit("a proof about one buyer holds 1 to 10 invoices")
        s = debtor_inputs.synthetic(1 if n == 1 else 10, count=n)
        if a.context:
            s["context"] = agg.parse_context(a.context)
        named = buyer_reader.unpack(s["buyer"])
    else:
        if not a.files or len(a.files) % 2:
            sys.exit("give REQUEST.xml RESPONSE.xml for each invoice")
        if a.threshold is None or a.year is None or a.context is None:
            sys.exit("--threshold, --year and --context (the value the verifier issued) are required with real files")
        named, wanted = a.buyer, parse_buyer(a.buyer)
        invoices, tmods, imods = [], set(), set()
        for number, (req_path, resp_path) in enumerate(zip(a.files[0::2], a.files[1::2]), 1):
            doc, req_sig, tmod = batch_inputs.ingest_request(open(req_path, "rb").read())
            fields, resp_sig, imod = batch_inputs.ingest_response(open(resp_path, "rb").read())
            try:
                found = buyer_reader.buyer_id(bytes(doc))
            except buyer_reader.BuyerError as e:
                sys.exit(f"no proof: invoice {number}: {e}")
            if found != wanted:
                sys.exit(f"no proof: invoice {number} was issued to another buyer")
            tmods.add(tmod)
            imods.add(imod)
            invoices.append({"doc": doc, "req_sig": req_sig, "resp": fields, "resp_sig": resp_sig, "salt": secrets.randbits(248)})
        if len(tmods) != 1 or len(imods) != 1:
            sys.exit("the files are not all signed by one taxpayer key and one authority key")
        n = len(invoices)
        if n > 10:
            sys.exit("a proof about one buyer holds 1 to 10 invoices")
        # Unused slots repeat the last pair: every slot must hold a well-formed signed pair.
        slots = invoices + [invoices[-1]] * ((1 if n == 1 else 10) - n)
        s = {"invoices": slots, "taxpayer_modulus": tmods.pop(), "issuer_modulus": imods.pop(), "count": n,
             "buyer": wanted, "threshold": round(float(a.threshold) * 100),
             "context": agg.parse_context(a.context), "year": a.year}

    k = len(s["invoices"])
    package = os.path.join(ROOT, "noir", f"debtor_k{k}")
    run(["nargo", "compile"], cwd=package, what=f"compiling debtor_k{k}")
    tag = "Run" + next(tempfile._get_candidate_names())
    prover_file = os.path.join(package, f"Prover{tag}.toml")
    witness = os.path.join(package, "target", f"witness{tag}.gz")
    os.makedirs(a.out, exist_ok=True)
    try:
        with open(prover_file, "w") as f:
            f.write(debtor_inputs.prover_toml(s))
        run(["nargo", "execute", "-p", f"Prover{tag}", f"witness{tag}"], cwd=package, what="the statement does not hold for these invoices; witness generation")
        with tempfile.TemporaryDirectory() as tmp:
            run(["bb", "prove", "-b", os.path.join(package, "target", f"debtor_k{k}.json"), "-w", witness, "-o", tmp, "-t", "evm", "--write_vk"], what="proving")
            for name in ("proof", "public_inputs"):
                shutil.copy(os.path.join(tmp, name), os.path.join(a.out, name))
    finally:
        for path in (prover_file, witness):
            if os.path.exists(path):
                os.remove(path)
    with open(os.path.join(a.out, "statement.json"), "w") as f:
        json.dump(decode_one_buyer(read_values(os.path.join(a.out, "public_inputs"))), f, indent=1)
    print(f"proof for {n} invoice(s) issued to one buyer written to {a.out} (proof, public_inputs, statement.json)")
    if a.synthetic:
        print(f"buyer of the invented invoices: {named}")
    if a.keep:
        agg.write_private(a.keep, {"statement": "invoices issued to one buyer", "buyer": named, "invoices": [
            dict(opening.opening_of(i["doc"], i["resp"][3], hex(i["salt"])), buyer=named) for i in s["invoices"][:n]]})
        print(f"record of the invoices written to {a.keep} - keep it private")
    return 0


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
    if a.buyer:
        return prove_one_buyer(a)
    if a.synthetic:
        k = a.synthetic
        invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(k, None, 1, None)
        if a.context:
            context = agg.parse_context(a.context)
    else:
        if not a.files or len(a.files) % 2:
            sys.exit("give REQUEST.xml RESPONSE.xml for each invoice, in ordinal order")
        if a.threshold is None or a.year is None or a.context is None:
            sys.exit("--threshold, --year and --context (the value the verifier issued) are required with real files")
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
        context = agg.parse_context(a.context)
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
    # Everything the verifier typed is read before anything is printed: a mistyped argument must
    # not leave "PROOF VALID" on the screen.
    expected_context = agg.parse_context(a.context) if a.context else None
    expected_buyer = parse_buyer(a.buyer) if a.buyer else None
    cert = None
    if a.taxpayer_cert:
        cert = keyhash.describe(keyhash.load_cert(a.taxpayer_cert, a.taxpayer_cert.lower().endswith(".xml")))
    ledger = {}
    if a.ledger and os.path.exists(a.ledger):
        with open(a.ledger) as f:
            ledger = json.load(f)

    values = read_values(os.path.join(a.dir, "public_inputs"))
    one_buyer = one_buyer_slots(values)
    kind = None if one_buyer else agg.kind_of(values)
    if one_buyer:
        if not verify_one_buyer(a.dir, one_buyer):
            print("PROOF INVALID")
            return 1
        st = decode_one_buyer(values)
        k = st["invoice_count"]
        circuit_line = f"{st['circuit']} (verification key derived locally)"
        nullifiers = st["nullifiers"]
        published = f"{k} nullifier(s), {k} opening commitment(s), a tag of the buyer"
    elif kind == "aggregate":
        ok, st, problems, leaf_size = agg.verify(a.dir)
        if not ok:
            print("PROOF INVALID: " + "; ".join(problems))
            return 1
        k = st["invoice_count"]
        circuit_line = f"agg_top over leaves of up to {leaf_size} (all verification keys derived locally)"
        nullifiers = [st["scope_nullifier"]]
        published = "one scope nullifier, one root over the opening commitments"
    else:
        if not agg.verify_batch(a.dir):
            print("PROOF INVALID")
            return 1
        st = decode(values)
        k = st["invoice_count"]
        circuit_line = f"{st['circuit']} (verification key derived locally)"
        nullifiers = st["nullifiers"]
        published = f"{k} nullifier(s), {k} opening commitment(s)"

    with open(os.path.join(ROOT, "registry", "issuer_keys.json")) as f:
        keys = {int(e["key_hash"], 16): e for e in json.load(f)["keys"]}
    issuer = keys.get(int(st["issuer_key_hash"], 16))
    print("PROOF VALID")
    print(f"  circuit                : {circuit_line}")
    if one_buyer:
        print(f"  what is proved         : {k} invoice(s) issued to one buyer in {st['year']}, each signed by the")
        print("                           taxpayer key and each with an authority receipt for the same request;")
        print("                           none with a negative total; no receipt used twice;")
        print(f"                           sum of totals >= {st['threshold_cents'] // 100}.{st['threshold_cents'] % 100:02d} EUR")
    else:
        print(f"  what is proved         : {k} consecutive invoice(s) of one business unit and one device,")
        print(f"                           issued in {st['year']}, each signed by the taxpayer key and each with")
        print("                           an authority receipt for the same request; no receipt used twice;")
        print(f"                           sum of totals >= {st['threshold_cents'] // 100}.{st['threshold_cents'] % 100:02d} EUR")
        print(f"  starts at ordinal 1    : {'yes' if st['starts_at_ordinal_one'] else 'no'}")
    print(f"  taxpayer key hash      : {st['taxpayer_key_hash']}")
    print(f"  authority key hash     : {st['issuer_key_hash']}")
    production = bool(issuer) and issuer.get("environment") == "production"
    if production:
        print(f"  authority key          : LISTED as {issuer['id']} ({issuer['status']})")
    elif issuer:
        print(f"  authority key          : listed as {issuer['id']}, NOT A PRODUCTION KEY ({issuer['status']})")
        print("                           receipts under this key can be had for invented invoices")
    else:
        print("  authority key          : NOT IN registry/issuer_keys.json - do not rely on this proof")
    context_ok = expected_context is None or expected_context == int(st["context"], 16)
    if a.context is None:
        print(f"  context                : {st['context']} (not compared: no --context given)")
    elif context_ok:
        print(f"  context                : {st['context']} (the one expected)")
    else:
        print(f"  context                : {st['context']} - NOT the expected one: this proof was made for another verifier")
    buyer_ok = True
    if one_buyer and expected_buyer is None:
        print(f"  buyer                  : tag {st['buyer_tag']} (not compared: no --buyer given)")
    elif one_buyer:
        buyer_ok = poseidon2.hash([DOMAIN_BUYER, int(st["context"], 16), expected_buyer]) == int(st["buyer_tag"], 16)
        print(f"  buyer                  : {a.buyer} (the one expected)" if buyer_ok else
              "  buyer                  : NOT the expected one: these invoices were issued to somebody else")
    elif expected_buyer is not None:
        buyer_ok = False
        print("  buyer                  : this kind of proof says nothing about buyers")
    print(f"  published              : {published}")
    seen = set(ledger.get(st["context"], []))
    repeated = [n for n in nullifiers if n in seen]
    if not a.ledger:
        print("  presented before       : not checked (no --ledger given); the nullifiers are:")
        for n in nullifiers:
            print(f"                           {n}")
    elif repeated:
        print(f"  presented before       : YES - {len(repeated)} nullifier(s) of this proof are already in the ledger")
    else:
        print("  presented before       : no (compared with the ledger)")
    cert_ok = True
    if cert:
        cert_ok = int(cert["key_hash"], 16) == int(st["taxpayer_key_hash"], 16)
        if cert_ok:
            print(f"  taxpayer               : key matches the certificate of {cert['subject']}")
            print(f"                           (issued by {cert['issuer']}, valid {cert['not_before'][:10]} to {cert['not_after'][:10]})")
        else:
            print("  taxpayer               : the key in this certificate is NOT the key of the proof")
    print("  NOT proved:")
    for line in NOT_PROVED_ONE_BUYER if one_buyer else NOT_PROVED:
        print(f"    - {line}")
    if not context_ok:
        return 4
    if not buyer_ok:
        return 6
    if repeated:
        return 5
    if not cert_ok:
        return 3
    if a.ledger:
        # Remembered only once nothing above objected to this presentation.
        ledger[st["context"]] = sorted(seen | set(nullifiers))
        with open(a.ledger, "w") as f:
            json.dump(ledger, f, indent=1)
    return 0 if production else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prove")
    p.add_argument("--out", required=True)
    p.add_argument("--threshold", help="minimum sum of totals, in EUR (e.g. 1500.00)")
    p.add_argument("--year", type=int)
    p.add_argument("--context", help="hex value the verifier issued for this presentation; random if omitted")
    p.add_argument("--synthetic", type=int, metavar="N")
    p.add_argument("--keep", metavar="FILE", help="write the spot-check record (private) to FILE")
    p.add_argument("--buyer", metavar="TYPE:NUMBER", help="prove that the invoices were all issued to this buyer, e.g. TIN:02345678")
    p.add_argument("files", nargs="*")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    v.add_argument("--context", help="the context this verifier issued (hex); a proof for another one is refused")
    v.add_argument("--ledger", metavar="FILE", help="remember accepted nullifiers here and refuse a repeat")
    v.add_argument("--taxpayer-cert", help="taxpayer certificate (DER/PEM), or a signed EFI request (.xml)")
    v.add_argument("--buyer", metavar="TYPE:NUMBER", help="the buyer this proof must be about; another one is refused")
    a = ap.parse_args()
    try:
        return prove(a) if a.cmd == "prove" else verify(a)
    except agg.StepFailed as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    sys.exit(main())
