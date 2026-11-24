#!/usr/bin/env python3
"""PRIVA-FISC command line: make a proof over a run of invoices, check one.

  pf.py prove  --out DIR --threshold EUR --year Y [--context HEX] [--keep FILE]  REQ1.xml RESP1.xml [REQ2.xml RESP2.xml ...]
  pf.py prove  --out DIR --synthetic N [--lines L] [--keep FILE]      (invented invoices, for demos and tests)
  pf.py prove  --buyer TYPE:NUMBER --out DIR --threshold EUR --year Y --context HEX  REQ1.xml RESP1.xml [...]
  pf.py prove  --einvoices ANSWER.xml --buyer NUIS:NUMBER --out DIR --threshold ALL --context HEX
  pf.py verify DIR [--context HEX] [--ledger FILE] [--taxpayer-cert FILE] [--buyer TYPE:NUMBER]
                   [--seller TYPE:NUMBER] [--since YYYYMMDD]
  (with --synthetic, --format al writes the invented invoices in the Albanian format)

`prove` runs on the taxpayer's machine. It reads signed request/response files (in ordinal order),
proves the statement, and leaves in DIR only what may be handed over: the proof, its public values
and a readable statement. Witness files are deleted. With --keep it also writes, for the taxpayer
alone, the record needed to answer spot checks later (tools/efi/opening.py); without it the proof
cannot be spot-checked afterwards.

1 or 10 invoices whose requests are at most 2,048 canonical bytes long give a batch proof
(noir/batch_k1, noir/batch_k10), which publishes one nullifier and one opening commitment per
invoice. Any other number, up to 4096, gives an aggregated proof (noir/agg_*), which publishes
one root for each instead; so do 1 or 10 invoices when one of them is longer. An aggregated
proof is built from leaves, and the tool picks the leaf circuit by the length of the requests: a
leaf holds up to 10 requests of up to 2,048 bytes, 5 of up to 8,192, 3 of up to 16,384 or 1 of up
to 32,768 (an invoice of one line takes about 1,500 to 1,800 bytes, each further line about 110).
A request longer than that cannot be proved.

With --buyer the statement is another one: the 1 to 10 invoices given were all issued to that
buyer (for example TIN:02345678, as the identifier stands in the invoices), none has a negative
total, and their totals reach the threshold. They need not be consecutive. The proof (noir/debtor_k1,
noir/debtor_k10) publishes a tag of the buyer instead of the buyer; `verify --buyer` recomputes the
tag and refuses a proof about somebody else. The longer the requests, the fewer invoices one such
proof holds, and the tool picks the circuit: 10 requests of up to 2,048 bytes, 7 of up to 4,096,
4 of up to 8,192, 2 of up to 16,384 or 1 of up to 32,768 (noir/debtor_k7_m4096 and so on). More
invoices than that are not proved together: the statement has no aggregated form. For Albanian
files there are circuits for requests of up to 2,048 bytes only.
With --synthetic N (1 to 10) any word after --buyer will do: the buyer is invented and printed;
--lines L gives the invented invoices L lines each.

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
is already in the ledger; 6 the proof is not about the buyer given; 7 it is not about the seller
given; 8 the authority's answer behind it is older than --since allows.

A proof names the taxpayer only by the hash of the signing key. Who that is comes from the
taxpayer's fiscalization certificate: with --taxpayer-cert (a certificate file, or any signed EFI
request, which embeds it) `verify` checks that the key in the certificate is the key of the proof
and prints the certificate's subject. Checking the certificate itself (issuer, validity,
revocation) is done with ordinary X.509 tools and is not part of this command.

Formats. The files of two countries are read: Montenegro, and Albania, whose fiscalization
exchanges the same signed messages (tools/efi/formats.py says what differs and what each format
was written against; the Albanian one against the published specification only). The format is
read from the files themselves. Each format has its own circuits, and `verify` says which format a
proof is in. For Albanian files only the statement about one buyer (--buyer) is built; the amounts
are then in lek, and a non-cash invoice, which carries no device code there, counts like any other.

E-invoices as the authority states them (--einvoices). In Albania's e-invoice service the
taxpayer's software can ask the central system for its e-invoices and gets back a list signed by
the tax authority, with the amount, the buyer, the seller and the status of each. From one such
answer `prove --einvoices` shows that up to ten commercial invoices in it were issued to the buyer
given, have the status ACCEPTED (not refused, not paid), and add up to the threshold. Here the
amounts stand under the authority's signature, so nothing has to be opened afterwards. The proof
publishes the day of the answer: `verify --since YYYYMMDD` refuses an older one, `--seller` checks
who the seller is. It names no taxpayer key. Like the Albanian format as a whole it rests on the
published specification only (tools/efi/einvoice.py).

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
import einvoice as ei  # noqa: E402
import formats  # noqa: E402
import keyhash  # noqa: E402
import opening  # noqa: E402
import poseidon2  # noqa: E402

SIZES = (1, 10)   # batch circuits
FAMILY = "standard"   # leaf circuits of aggregated proofs (tools/efi/agg.py)
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
NOT_PROVED_EINVOICES = (
    "that a sale took place: the authority states what is registered and in which status",
    "that the buyer approved an invoice: ACCEPTED is the status the central system shows, and an "
    "invoice may reach it without any act of the buyer - read it as not refused and not paid",
    "anything after the day of the answer: an invoice may have been paid or refused since",
    "that these are all the e-invoices issued to this buyer",
    "who presents the proof: nothing in it is signed by the taxpayer, whoever holds the answer can make it",
    "that an invoice was not also presented in a proof made from its registration messages "
    "(the nullifiers of the two kinds cannot be compared)",
)
DOMAIN_BUYER = int.from_bytes(b"PF-BUYER01", "big")
BUYER_FORM = re.compile(r"[A-Z]{2,4}:[0-9A-Za-z]{1,20}")


def pkg(k):
    return os.path.join(ROOT, "noir", f"batch_k{k}")


def parse_buyer(text):
    if not BUYER_FORM.fullmatch(text):
        sys.exit("--buyer must look like TIN:02345678: the kind of identifier, a colon, the number")
    return buyer_reader.pack(*text.split(":"))


def decode_one_buyer(values, fmt, circuit):
    k, count = agg.one_buyer_slots(values), values[5]
    if not 1 <= count <= k:
        sys.exit("unexpected number of invoices in the public values")
    return {
        "circuit": circuit,
        "format": fmt.name,
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


def one_buyer_circuit_for(fmt, invoices):
    """(slots, longest request, name) of the circuit that holds these invoices to one buyer. The
    longer the requests, the fewer of them one proof holds; without a circuit for them, no proof."""
    longest = max(len(i["doc"]) for i in invoices)
    choice = fmt.one_buyer_choice(len(invoices), longest)
    if choice is None:
        sys.exit(f"no proof: {len(invoices)} invoice(s) whose longest request is {longest} bytes do not fit one proof "
                 f"about one buyer, which holds {fmt.one_buyer_capacity()}")
    return choice


def prove_one_buyer(a):
    if a.synthetic:
        n = a.synthetic
        if not 1 <= n <= 10:
            sys.exit("a proof about one buyer holds 1 to 10 invoices")
        fmt = formats.by_name(a.format)
        if a.lines:
            # Invoices of several lines: the circuit follows from how long their requests are.
            s = debtor_inputs.synthetic(n, fmt=fmt, lines=a.lines)
            slots, longest, circuit = one_buyer_circuit_for(fmt, s["invoices"])
            s["invoices"] = s["invoices"] + [s["invoices"][-1]] * (slots - n)
        else:
            slots, longest = (1 if n == 1 else 10), batch_inputs.M
            circuit = fmt.one_buyer_circuit(slots)
            s = debtor_inputs.synthetic(slots, count=n, fmt=fmt)
        if a.context:
            s["context"] = agg.parse_context(a.context)
        named = buyer_reader.unpack(s["buyer"])
    else:
        if not a.files or len(a.files) % 2:
            sys.exit("give REQUEST.xml RESPONSE.xml for each invoice")
        if a.threshold is None or a.year is None or a.context is None:
            sys.exit("--threshold, --year and --context (the value the verifier issued) are required with real files")
        named, wanted = a.buyer, parse_buyer(a.buyer)
        invoices, tmods, imods, fmts = [], set(), set(), set()
        for number, (req_path, resp_path) in enumerate(zip(a.files[0::2], a.files[1::2]), 1):
            doc, req_sig, tmod, fields, resp_sig, imod, fmt = read_pair(req_path, resp_path, number)
            fmts.add(fmt)
            tmods.add(tmod)
            imods.add(imod)
            invoices.append({"doc": doc, "req_sig": req_sig, "resp": fields, "resp_sig": resp_sig, "salt": secrets.randbits(248)})
        if len(fmts) != 1:
            sys.exit("no proof: the files are not all in one country's format")
        n = len(invoices)
        slots, longest, circuit = one_buyer_circuit_for(fmt, invoices)
        # The buyer is read as the circuit chosen reads it, in an array as long as its requests.
        for number, invoice in enumerate(invoices, 1):
            try:
                found = buyer_reader.buyer_id(bytes(invoice["doc"]), size=longest)
            except buyer_reader.BuyerError as e:
                sys.exit(f"no proof: invoice {number}: {e}")
            if found != wanted:
                sys.exit(f"no proof: invoice {number} was issued to another buyer")
        if len(tmods) != 1 or len(imods) != 1:
            sys.exit("the files are not all signed by one taxpayer key and one authority key")
        # Unused slots repeat the last pair: every slot must hold a well-formed signed pair.
        s = {"invoices": invoices + [invoices[-1]] * (slots - n), "taxpayer_modulus": tmods.pop(),
             "issuer_modulus": imods.pop(), "count": n, "buyer": wanted, "threshold": round(float(a.threshold) * 100),
             "context": agg.parse_context(a.context), "year": a.year}

    package = os.path.join(ROOT, "noir", circuit)
    compile_circuit(circuit)
    tag = "Run" + next(tempfile._get_candidate_names())
    prover_file = os.path.join(package, f"Prover{tag}.toml")
    witness = os.path.join(package, "target", f"witness{tag}.gz")
    os.makedirs(a.out, exist_ok=True)
    try:
        with open(prover_file, "w") as f:
            f.write(debtor_inputs.prover_toml(s, longest))
        run(["nargo", "execute", "-p", f"Prover{tag}", f"witness{tag}"], cwd=package, what="the statement does not hold for these invoices; witness generation")
        with tempfile.TemporaryDirectory() as tmp:
            run(["bb", "prove", "-b", os.path.join(package, "target", f"{circuit}.json"), "-w", witness, "-o", tmp, "-t", "evm", "--write_vk"], what="proving")
            for name in ("proof", "public_inputs"):
                shutil.copy(os.path.join(tmp, name), os.path.join(a.out, name))
    finally:
        for path in (prover_file, witness):
            if os.path.exists(path):
                os.remove(path)
    with open(os.path.join(a.out, "statement.json"), "w") as f:
        json.dump(decode_one_buyer(read_values(os.path.join(a.out, "public_inputs")), fmt, circuit), f, indent=1)
    print(f"proof for {n} invoice(s) issued to one buyer written to {a.out} (proof, public_inputs, statement.json)")
    if longest > batch_inputs.M:
        print(f"  (circuit {circuit}: up to {slots} invoice(s) with requests of up to {longest} bytes)")
    if fmt is not formats.MONTENEGRO:
        print(f"format of the invoices: {fmt.country} ({fmt.basis})")
    if a.synthetic:
        print(f"buyer of the invented invoices: {named}")
    if a.keep:
        agg.write_private(a.keep, {"statement": "invoices issued to one buyer", "buyer": named, "invoices": [
            dict(opening.opening_of(i["doc"], i["resp"][3], hex(i["salt"])), buyer=named) for i in s["invoices"][:n]]})
        print(f"record of the invoices written to {a.keep} - keep it private")
    return 0


def read_pair(req_path, resp_path, number):
    """One signed request and its signed receipt, which must be in the same country's format."""
    try:
        doc, req_sig, tmod = batch_inputs.ingest_request(open(req_path, "rb").read())
        fmt = formats.of_request(bytes(doc))
        fields, resp_sig, imod = batch_inputs.ingest_response(open(resp_path, "rb").read(), fmt)
    except ValueError as e:
        sys.exit(f"no proof: invoice {number}: {e}")
    return doc, req_sig, tmod, fields, resp_sig, imod, fmt


def run(cmd, cwd=None, what=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        tail = (r.stderr.strip() or r.stdout.strip()).splitlines()[-6:]
        sys.exit(f"{what or cmd[0]} failed:\n  " + "\n  ".join(tail))
    return r


def compile_circuit(name):
    """Compile a circuit of this repository; the compile is watched for disk room (agg.compiled)."""
    try:
        return agg.compiled(name)
    except agg.StepFailed as e:
        sys.exit(str(e))


def circuit_json(k):
    return compile_circuit(f"batch_k{k}")


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


def prove_einvoices(a):
    if a.buyer is None or a.threshold is None or a.context is None:
        sys.exit("--buyer, --threshold and --context (the value the verifier issued) are required with --einvoices")
    if not ei.PARTY.fullmatch(a.buyer) or (a.seller and not ei.PARTY.fullmatch(a.seller)):
        sys.exit("with --einvoices a party is written NUIS:K12345678A (the letters NUIS, a colon, the tax number)")
    buyer, seller = a.buyer.split(":")[1], a.seller.split(":")[1] if a.seller else None
    try:
        doc, signature, modulus = ei.ingest(open(a.einvoices, "rb").read())
        answer = ei.read_answer(bytes(doc))
    except ValueError as e:
        sys.exit(f"no proof: {e}")
    counted, seller = ei.countable(answer, buyer, seller)
    if not counted:
        sys.exit("no proof: the answer lists no open commercial invoice to this buyer")
    if len(counted) > ei.K:
        sys.exit(f"no proof: the answer lists {len(counted)} open invoices to this buyer and a proof counts at most "
                 f"{ei.K}; ask the service for a shorter period")
    context = agg.parse_context(a.context)
    package = os.path.join(ROOT, "noir", ei.CIRCUIT)
    compile_circuit(ei.CIRCUIT)
    tag = "Run" + next(tempfile._get_candidate_names())
    prover_file = os.path.join(package, f"Prover{tag}.toml")
    witness = os.path.join(package, "target", f"witness{tag}.gz")
    os.makedirs(a.out, exist_ok=True)
    try:
        with open(prover_file, "w") as f:
            f.write(ei.prover_toml(bytes(doc), signature, modulus, [e["offset"] for e in counted], len(counted),
                                   ei.party_id(buyer), ei.party_id(seller), round(float(a.threshold) * 100), context))
        run(["nargo", "execute", "-p", f"Prover{tag}", f"witness{tag}"], cwd=package, what="the statement does not hold for this answer; witness generation")
        with tempfile.TemporaryDirectory() as tmp:
            run(["bb", "prove", "-b", os.path.join(package, "target", f"{ei.CIRCUIT}.json"), "-w", witness, "-o", tmp, "-t", "evm", "--write_vk"], what="proving")
            for name in ("proof", "public_inputs"):
                shutil.copy(os.path.join(tmp, name), os.path.join(a.out, name))
    finally:
        for path in (prover_file, witness):
            if os.path.exists(path):
                os.remove(path)
    with open(os.path.join(a.out, "statement.json"), "w") as f:
        json.dump(ei.decode(read_values(os.path.join(a.out, "public_inputs"))), f, indent=1)
    print(f"proof for {len(counted)} open e-invoice(s) to one buyer written to {a.out} (proof, public_inputs, statement.json)")
    print(f"answer of the authority dated {answer['day']}; seller NUIS:{seller}")
    print("format: Albania, e-invoice service (the published specification only; no real signed message has been seen)")
    if a.keep:
        print("nothing written to --keep: this statement publishes no opening commitments, the amounts are the authority's")
    return 0


def prove(a):
    if a.einvoices:
        return prove_einvoices(a)
    if a.buyer:
        return prove_one_buyer(a)
    if a.synthetic:
        if not formats.by_name(a.format).has_batch_circuits:
            sys.exit(f"no proof: for the format of {formats.by_name(a.format).country} only the statement about one buyer (--buyer) is built")
        k = a.synthetic
        lines = {position: a.lines for position in range(k)} if a.lines else None
        invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(k, None, 1, None, lines=lines)
        if a.context:
            context = agg.parse_context(a.context)
    else:
        if not a.files or len(a.files) % 2:
            sys.exit("give REQUEST.xml RESPONSE.xml for each invoice, in ordinal order")
        if a.threshold is None or a.year is None or a.context is None:
            sys.exit("--threshold, --year and --context (the value the verifier issued) are required with real files")
        invoices, tmods, imods = [], set(), set()
        for number, (req_path, resp_path) in enumerate(zip(a.files[0::2], a.files[1::2]), 1):
            doc, req_sig, tmod, fields, resp_sig, imod, fmt = read_pair(req_path, resp_path, number)
            if not fmt.has_batch_circuits:
                sys.exit(f"no proof: invoice {number} is in the format of {fmt.country}, for which only the "
                         "statement about one buyer (--buyer) is built")
            tmods.add(tmod)
            imods.add(imod)
            invoices.append({"doc": doc, "req_sig": req_sig, "resp": fields, "resp_sig": resp_sig})
        if len(tmods) != 1 or len(imods) != 1:
            sys.exit("the files are not all signed by one taxpayer key and one authority key")
        k, tmod, imod = len(invoices), tmods.pop(), imods.pop()
        threshold = round(float(a.threshold) * 100)
        context = agg.parse_context(a.context)
        year = a.year
    longest = max(len(i["doc"]) for i in invoices)
    if k not in SIZES or longest > batch_inputs.M:
        # Any number of invoices, and requests longer than the batch circuits read: leaves by
        # length of request, joined into one proof.
        if longest > agg.longest_request(FAMILY):
            sys.exit(f"no proof: a request is {longest} bytes, the longest the circuits read is {agg.longest_request(FAMILY)}")
        os.makedirs(a.out, exist_ok=True)
        try:
            agg.make_proof(FAMILY, invoices, tmod, imod, threshold, context, year, a.out, keep=a.keep)
        except agg.StepFailed as e:
            sys.exit(f"no proof: {e}")
        print(f"aggregated proof for {k} invoice{'s' if k != 1 else ''} written to {a.out} (proof, public_inputs, statement.json)")
        if k in SIZES:
            print(f"  (aggregated, not a batch proof: a request is {longest} bytes, and the batch circuits read "
                  f"up to {batch_inputs.M})")
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
    expected_seller = parse_buyer(a.seller) if a.seller else None
    if a.since is not None and not re.fullmatch(r"\d{8}", a.since):
        sys.exit("--since is a day written YYYYMMDD")
    cert = None
    if a.taxpayer_cert:
        cert = keyhash.describe(keyhash.load_cert(a.taxpayer_cert, a.taxpayer_cert.lower().endswith(".xml")))
    ledger = {}
    if a.ledger and os.path.exists(a.ledger):
        with open(a.ledger) as f:
            ledger = json.load(f)

    values = read_values(os.path.join(a.dir, "public_inputs"))
    stated = len(values) == ei.PUBLIC_VALUES   # e-invoices as the authority states them
    one_buyer = None if stated else agg.one_buyer_slots(values)
    kind = None if (one_buyer or stated) else agg.kind_of(values)
    fmt = formats.MONTENEGRO
    if stated:
        try:
            st = ei.decode(values)
        except ValueError:
            print("PROOF INVALID")
            return 1
        if not agg.verify_one_buyer(a.dir, ei.K, ei.CIRCUIT):
            print("PROOF INVALID")
            return 1
        fmt = formats.ALBANIA
        k = st["invoice_count"]
        circuit_line = f"{st['circuit']} (verification key derived locally)"
        nullifiers = st["nullifiers"]
        published = f"{k} nullifier(s), a tag of the buyer, a tag of the seller, the day of the answer"
    elif one_buyer:
        found = agg.one_buyer_circuit_of(a.dir, one_buyer)
        if found is None:
            print("PROOF INVALID")
            return 1
        fmt, circuit = found
        st = decode_one_buyer(values, fmt, circuit)
        k = st["invoice_count"]
        circuit_line = f"{st['circuit']} (verification key derived locally)"
        nullifiers = st["nullifiers"]
        published = f"{k} nullifier(s), {k} opening commitment(s), a tag of the buyer"
    elif kind == "aggregate":
        ok, st, problems, family = agg.verify(a.dir)
        if not ok:
            print("PROOF INVALID: " + "; ".join(problems))
            return 1
        k = st["invoice_count"]
        circuit_line = "agg_top over leaves by length of request (all verification keys derived locally)"
        leaves_line = agg.describe(family)
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
    if kind == "aggregate":
        print(f"  a leaf holds           : {leaves_line}")
    print(f"  format of the invoices : {fmt.country}" + ("" if fmt is formats.MONTENEGRO else f" - written against {fmt.basis}"))
    if stated:
        day = st["answer_day"]
        print(f"  what is proved         : in its signed answer of {day // 10000}-{day // 100 % 100:02d}-{day % 100:02d} the authority lists {k} e-invoice(s)")
        print("                           issued by one seller to one buyer, each a commercial invoice with the")
        print("                           status ACCEPTED (not refused, not paid) and no negative amount;")
        print(f"                           sum of amounts >= {st['threshold_cents'] // 100}.{st['threshold_cents'] % 100:02d} {fmt.currency}")
    elif one_buyer:
        print(f"  what is proved         : {k} invoice(s) issued to one buyer in {st['year']}, each signed by the")
        print("                           taxpayer key and each with an authority receipt for the same request;")
        print("                           none with a negative total; no receipt used twice;")
        print(f"                           sum of totals >= {st['threshold_cents'] // 100}.{st['threshold_cents'] % 100:02d} {fmt.currency}")
    else:
        print(f"  what is proved         : {k} consecutive invoice(s) of one business unit and one device,")
        print(f"                           issued in {st['year']}, each signed by the taxpayer key and each with")
        print("                           an authority receipt for the same request; no receipt used twice;")
        print(f"                           sum of totals >= {st['threshold_cents'] // 100}.{st['threshold_cents'] % 100:02d} EUR")
        print(f"  starts at ordinal 1    : {'yes' if st['starts_at_ordinal_one'] else 'no'}")
    if not stated:
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
    if (one_buyer or stated) and expected_buyer is None:
        print(f"  buyer                  : tag {st['buyer_tag']} (not compared: no --buyer given)")
    elif one_buyer or stated:
        buyer_ok = poseidon2.hash([DOMAIN_BUYER, int(st["context"], 16), expected_buyer]) == int(st["buyer_tag"], 16)
        print(f"  buyer                  : {a.buyer} (the one expected)" if buyer_ok else
              "  buyer                  : NOT the expected one: these invoices were issued to somebody else")
    elif expected_buyer is not None:
        buyer_ok = False
        print("  buyer                  : this kind of proof says nothing about buyers")
    seller_ok, fresh = True, True
    if stated:
        if expected_seller is None:
            print(f"  seller                 : tag {st['seller_tag']} (not compared: no --seller given)")
        else:
            seller_ok = poseidon2.hash([ei.DOMAIN_SELLER, int(st["context"], 16), expected_seller]) == int(st["seller_tag"], 16)
            print(f"  seller                 : {a.seller} (the one expected)" if seller_ok else
                  "  seller                 : NOT the expected one: these invoices were issued by somebody else")
        if a.since is None:
            print(f"  day of the answer      : {st['answer_day']} (not compared: no --since given)")
        else:
            fresh = st["answer_day"] >= int(a.since)
            print(f"  day of the answer      : {st['answer_day']} (not older than {a.since})" if fresh else
                  f"  day of the answer      : {st['answer_day']} - OLDER than {a.since}: invoices may have been paid or refused since")
    else:
        if expected_seller is not None:
            seller_ok = False
            print("  seller                 : this kind of proof names the seller by its key, see --taxpayer-cert")
        if a.since is not None:
            fresh = False
            print("  day of the answer      : this kind of proof is not made from an answer of the authority")
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
    if cert and stated:
        cert_ok = False
        print("  taxpayer               : this kind of proof names no taxpayer key, see --seller")
    elif cert:
        cert_ok = int(cert["key_hash"], 16) == int(st["taxpayer_key_hash"], 16)
        if cert_ok:
            print(f"  taxpayer               : key matches the certificate of {cert['subject']}")
            print(f"                           (issued by {cert['issuer']}, valid {cert['not_before'][:10]} to {cert['not_after'][:10]})")
        else:
            print("  taxpayer               : the key in this certificate is NOT the key of the proof")
    print("  NOT proved:")
    for line in NOT_PROVED_EINVOICES if stated else NOT_PROVED_ONE_BUYER if one_buyer else NOT_PROVED:
        print(f"    - {line}")
    if not context_ok:
        return 4
    if not buyer_ok:
        return 6
    if not seller_ok:
        return 7
    if not fresh:
        return 8
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
    p.add_argument("--format", default="me", choices=[f.name for f in formats.ALL],
                   help="with --synthetic: the country format of the invented invoices (default me)")
    p.add_argument("--lines", type=int, metavar="L",
                   help="with --synthetic: lines of each invented invoice (default 1; a request grows by about 145 bytes a line)")
    p.add_argument("--keep", metavar="FILE", help="write the spot-check record (private) to FILE")
    p.add_argument("--buyer", metavar="TYPE:NUMBER", help="prove that the invoices were all issued to this buyer, e.g. TIN:02345678")
    p.add_argument("--einvoices", metavar="ANSWER.xml", help="a signed answer of the Albanian e-invoice service listing e-invoices")
    p.add_argument("--seller", metavar="NUIS:NUMBER", help="with --einvoices: count only e-invoices of this seller")
    p.add_argument("files", nargs="*")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    v.add_argument("--context", help="the context this verifier issued (hex); a proof for another one is refused")
    v.add_argument("--ledger", metavar="FILE", help="remember accepted nullifiers here and refuse a repeat")
    v.add_argument("--taxpayer-cert", help="taxpayer certificate (DER/PEM), or a signed EFI request (.xml)")
    v.add_argument("--buyer", metavar="TYPE:NUMBER", help="the buyer this proof must be about; another one is refused")
    v.add_argument("--seller", metavar="TYPE:NUMBER", help="the seller a proof about e-invoices must be about")
    v.add_argument("--since", metavar="YYYYMMDD", help="refuse a proof about e-invoices whose answer the authority dated before this day")
    a = ap.parse_args()
    try:
        return prove(a) if a.cmd == "prove" else verify(a)
    except agg.StepFailed as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    sys.exit(main())
