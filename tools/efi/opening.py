#!/usr/bin/env python3
"""Spot-check ("örnek açtırma") helper.

A batch proof publishes one blinded opening commitment per invoice; an aggregated proof publishes
one root over all of them. After checking the proof (tools/pf.py verify) the verifier asks for a
few invoices; for each one the prover reveals the commitment's preimage and the verifier recomputes
the commitment. For an aggregated proof the prover adds a small proof (noir/spot_open_k*) that the
commitment sits under the published root and where, without showing the rest of the tree. The
verifier then compares the revealed values with what the tax authority's public invoice-check
service returns for that IIC (not done by this tool: querying the authority is a deliberate,
separate step).

  draw                                                                           (verifier)
  reveal  --record RECORD.json (--index I | --seed SEED --draw J) --out OPENING.json   (prover)
  check   --opening OPENING.json --proof DIR (--ordinal N | --first | --last | --seed SEED --draw J)
  compare --opening OPENING.json --authority LOOKUP.json [--taxpayer-cert FILE]  (verifier)

RECORD.json is the file written by `pf.py prove --keep`; it stays with the prover. I counts the
invoices from 0 in the order they were proved.

`check` first verifies the proof in DIR itself, then the opening against it. The verifier says
which invoice it asked for, so that the prover cannot answer with another one: --ordinal N requires
the opened invoice to carry that ordinal number; --first and --last require it to be the first or
the last invoice the proof covers. When a proof does not start at ordinal 1 the verifier asks for
the first invoice first: its ordinal and the published count give the range to draw the other
ordinals from.

Asking by amount (aggregated proofs). `draw` prints a random seed. The seed fixes a sequence of
points of the sum of all positive totals, numbered 1, 2, ...; for draw J the prover must open the
invoice whose share of that sum contains point J. Invoices are then asked for with probability
proportional to their amount. All points come from the one seed, so the verifier cannot pick a
point after seeing the answer to another; the prover's tool answers one seed per proof and at most
ten draws, because every answer tells the verifier roughly where the opened invoice sits in the
running total.

A request the prover does not answer is a failed spot check, whatever reason is given. The verifier
does not draw again and does not accept a new proof in its place.

An opening that matched is what the taxpayer proved, not yet what the authority has. The verifier
looks the invoice up at the tax authority by its IIC and writes what the authority shows into a
small file: {"iic", "fic", "ordinal", "issue_date_time", "total", "business_unit", "device",
"seller_tin"}. `compare` prints AGREES, or DIFFERENT followed by the names of the fields that
differ (never their values). With --taxpayer-cert it also requires the seller's tax number in the
authority's record to be the one in the taxpayer's certificate; without it the seller is not
compared and the tool says so. This tool does not query the authority.

Lower-level forms, for a batch whose Prover file is at hand:
  reveal --prover BATCH_PROVER.toml --index I --out OPENING.json
  check  --opening OPENING.json --commitment 0x... [--ordinal N]

An opening file contains the invoice's identifiers and amount. It is the disclosure itself, and
whoever holds it can check it against the published proof: give it only to the verifier who asked
for it. `check` prints MATCH / NO MATCH and nothing else.
"""
import argparse
import decimal
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import poseidon2  # noqa: E402

OPEN_PKG = os.path.normpath(os.path.join(HERE, "..", "..", "noir", "open_invoice"))
DOMAIN_OPENING = int.from_bytes(b"PF-OPENING", "big")
ORDER = ("iic", "fic", "ordinal", "issue_local_ts", "issue_tz", "total_negative", "total_cents", "unit", "device", "salt")


def reveal(prover_path, index):
    with open(prover_path, "rb") as f:
        p = tomllib.load(f)
    doc = bytes(p["request_docs"][index][: p["request_lens"][index]])
    return opening_of(doc, bytes(p["resp_fics"][index]), p["salts"][index])


def opening_of(doc, fic, salt):
    """The preimage of one invoice's opening commitment, from its canonical request and receipt code."""
    tag = doc[200:]

    def attr(name):
        m = re.search(rb' ' + name + rb'="([^"]*)"', tag)
        if m is None:
            raise ValueError(f"attribute {name.decode()} not found")
        return m.group(1).decode()

    seller = re.search(rb'<Seller [^>]*\bIDNum="([^"]*)"', doc)
    return {
        "iic": attr(b"IIC"),
        "fic": bytes(fic).decode(),
        "ordinal": int(attr(b"InvOrdNum")),
        "issue_date_time": attr(b"IssueDateTime"),
        "total": attr(b"TotPrice"),
        "business_unit": attr(b"BusinUnitCode"),
        "device": attr(b"TCRCode"),
        "salt": salt,
        # Not part of the commitment; the verifier needs it to query the invoice-check service.
        "seller_id": seller.group(1).decode() if seller else None,
    }


def field_values(o):
    dt = o["issue_date_time"]
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d", dt):
        raise ValueError("issue_date_time is not in the expected form")
    local = int(dt[0:4] + dt[5:7] + dt[8:10] + dt[11:13] + dt[14:16] + dt[17:19])
    tz = int(("1" if dt[19] == "+" else "2") + dt[20:22] + dt[23:25])
    total = o["total"]
    negative = total.startswith("-")
    digits = total.lstrip("-")
    cents = 0 if digits == "0" else int(digits.replace(".", ""))
    if digits != "0" and not re.fullmatch(r"\d+\.\d\d", digits):
        raise ValueError("total is not in the expected form")
    for code in (o["business_unit"], o["device"]):
        if not re.fullmatch(r"[a-z]{2}\d{3}[a-z]{2}\d{3}", code):
            raise ValueError("a registration code is not in the expected form")
    return {
        "iic": hex(int(o["iic"], 16)),
        "fic": hex(int(o["fic"].replace("-", ""), 16)),
        "ordinal": str(o["ordinal"]),
        "issue_local_ts": str(local),
        "issue_tz": str(tz),
        "total_negative": "1" if negative else "0",
        "total_cents": str(cents),
        # Registration codes enter the circuit as their ten bytes, packed big-endian.
        "unit": hex(int.from_bytes(o["business_unit"].encode(), "big")),
        "device": hex(int.from_bytes(o["device"].encode(), "big")),
        "salt": o["salt"],
    }


MAX_DRAWS = 10


def new_seed():
    return secrets.token_hex(16)


def draw_point(seed, root, number):
    """Point number `number` (1, 2, ...) of the sequence that `seed` fixes for the proof with this
    opening root: 64 bits, standing for that fraction of the sum of positive totals."""
    if not re.fullmatch(r"[0-9a-f]{32}", seed) or not 1 <= number <= 0xFFFFFFFF:
        raise ValueError("a seed is 32 hexadecimal characters and draws are numbered from 1")
    data = b"PF-DRAW" + bytes.fromhex(seed) + root.to_bytes(32, "big") + number.to_bytes(4, "big")
    return int.from_bytes(hashlib.sha256(data).digest()[:8], "big")


def positive_cents(o):
    """An opened invoice's total in cents when it is positive, else 0."""
    total = o["total"]
    if total.startswith("-") or total == "0":
        return 0
    return int(total.replace(".", ""))


def recompute(o):
    """The opening commitment of these values, as the circuits compute it."""
    values = field_values(o)
    return poseidon2.hash([DOMAIN_OPENING] + [int(values[name], 0) for name in ORDER])


def recompute_in_circuit(o):
    """The same value from the open_invoice circuit (needs nargo). Used to cross-check `recompute`."""
    values = field_values(o)
    name = "ProverOpen" + next(tempfile._get_candidate_names())
    path = os.path.join(OPEN_PKG, name + ".toml")
    with open(path, "w") as f:
        f.write("".join(f'{k} = "{v}"\n' for k, v in values.items()))
    try:
        r = subprocess.run(["nargo", "execute", "-p", name, "witness_open"], cwd=OPEN_PKG, capture_output=True, text=True)
    finally:
        os.remove(path)
    m = re.search(r"Circuit output: (0x[0-9a-f]+)", r.stdout + r.stderr)
    if r.returncode != 0 or m is None:
        raise RuntimeError("could not recompute the commitment:\n" + r.stderr.strip())
    return int(m.group(1), 16)


def reveal_from_record(record_path, index=None, point=None, seed=None, draw=None):
    """Opening of one invoice from the prover's record: the one at position `index`, or the one
    that covers draw number `draw` of `seed`. For an aggregated proof the opening comes with a
    proof of where it sits under the published root. (`point` gives the 64-bit point directly; the
    tests use it to play a prover who answers with the wrong invoice.)"""
    import agg  # here, not at the top: agg.py uses this module too
    with open(record_path) as f:
        record = json.load(f)
    if "tree" not in record:
        if index is None:
            raise ValueError("a batch proof is opened by position")
        if not 0 <= index < len(record["invoices"]):
            raise ValueError("no invoice at this position")
        return dict(record["invoices"][index], position=index)

    leaves, tree = record["leaves"], record["tree"]
    root = agg.openings_root(int(tree["h"], 16), tree["sum"])
    if seed is not None:
        if draw is None or not 1 <= draw <= MAX_DRAWS:
            raise ValueError(f"draws are numbered 1 to {MAX_DRAWS}")
        if record.get("seed") not in (None, seed):
            raise ValueError("this proof was already opened for another seed; answering a second one "
                             "would tell the verifier more about the totals than a spot check should")
        point = draw_point(seed, root, draw)
        if record.get("seed") is None:
            record["seed"] = seed
            agg.write_private(record_path, record)
    r = point or 0
    if index is None:
        # The invoice whose range [sum before it, sum before it + its total) holds the point.
        target = (r * tree["sum"]) >> 64
        before = 0
        amounts = [p for leaf in leaves for p in leaf["plus"][:leaf["count"]]]
        for i, p in enumerate(amounts):
            if before <= target < before + p:
                index = i
                break
            before += p
        if index is None:
            raise ValueError("no invoice with a positive total")
    if not 0 <= index < len(record["invoices"]):
        raise ValueError("no invoice at this position")
    leaf_index, slot = 0, index
    while slot >= leaves[leaf_index]["count"]:
        slot -= leaves[leaf_index]["count"]
        leaf_index += 1

    def climb(node):
        """(our node is the left child, sibling hash, sibling sum) from the leaf up to `node`."""
        if "leaf" in node:
            return [] if node["leaf"] == leaf_index else None
        below = climb(node["left"])
        if below is not None:
            return below + [(True, int(node["right"]["h"], 16), node["right"]["sum"])]
        below = climb(node["right"])
        if below is not None:
            return below + [(False, int(node["left"]["h"], 16), node["left"]["sum"])]
        return None

    path = climb(tree)
    depth = 12  # MAX_DEPTH in noir/pf_efi/src/spot.nr; the top proof admits no deeper tree
    pad = depth - len(path)
    leaf = leaves[leaf_index]
    openings = [int(v, 16) for v in leaf["openings"]]
    flags = lambda values: "[" + ", ".join("true" if v else "false" for v in values) + "]"  # noqa: E731
    text = f"openings = {agg.hexlist(openings)}\nplus = {agg.hexlist(leaf['plus'])}\nslot = \"{slot}\"\n"
    text += f"used = {flags([True] * len(path) + [False] * pad)}\n"
    text += f"node_is_left = {flags([p[0] for p in path] + [False] * pad)}\n"
    text += f"sibling = {agg.hexlist([p[1] for p in path] + [0] * pad)}\n"
    text += f"sibling_sum = {agg.hexlist([p[2] for p in path] + [0] * pad)}\n"
    text += f'root = "{hex(root)}"\n'
    text += f'commitment = "{hex(openings[slot])}"\namount = "{leaf["plus"][slot]}"\nr = "{r}"\n'
    with tempfile.TemporaryDirectory() as tmp:
        agg.prove(f"spot_open_k{len(openings)}", text, tmp, "evm")
        proof = open(os.path.join(tmp, "proof"), "rb").read()
        public = open(os.path.join(tmp, "public_inputs"), "rb").read()
    o = dict(record["invoices"][index])
    o["proof"] = {"proof": proof.hex(), "public_inputs": public.hex()}
    return o


def check_against_proof(o, proof_dir, ordinal=None, edge=None, point=None, seed=None, draw=None, verified=False):
    """True if the proof in `proof_dir` is valid, the opening is one it commits to, and it is the
    invoice asked for: the one with this `ordinal`, the "first" / "last" invoice of the proof
    (`edge`), or the one that covers draw number `draw` of `seed`. `verified=True` skips the check
    of the proof itself, for a caller that has just done it."""
    import agg  # here, not at the top: agg.py uses this module too
    if ordinal is not None and o.get("ordinal") != ordinal:
        return False
    values = agg.fields_of(os.path.join(proof_dir, "public_inputs"))
    kind = agg.kind_of(values)
    commitment = recompute(o)
    if kind != "aggregate":
        # Batch proof: threshold, context, year, two key hashes, a flag, K nullifiers, K commitments.
        if not (verified or agg.verify_batch(proof_dir)):
            return False
        position = o.get("position", -1)
        if point is not None or seed is not None or (edge and position != (0 if edge == "first" else kind - 1)):
            return False
        return isinstance(position, int) and 0 <= position < kind and values[6 + kind + position] == commitment
    ok, st, _, leaf_size = agg.verify(proof_dir) if not verified else (True, agg.decode(values), [], agg.leaf_size_of(values))
    if not ok or leaf_size is None:
        return False
    located = o.get("proof")
    if not isinstance(located, dict):
        return False
    public = bytes.fromhex(located["public_inputs"])
    if len(public) != 7 * 32:
        return False
    # (root, commitment, amount, draw) as given to the circuit, then its three answers.
    root, shown, amount, r, covers, is_first, is_last = (
        int.from_bytes(public[i:i + 32], "big") for i in range(0, len(public), 32))
    if root != int(st["opening_root"], 16) or shown != commitment or amount != positive_cents(o):
        return False
    if edge == "first" and is_first != 1 or edge == "last" and is_last != 1:
        return False
    if seed is not None:
        point = draw_point(seed, root, draw)
    if point is not None and (r != point or covers != 1):
        return False
    # The circuit is the one for the leaf size the proof itself names, not one the opening names.
    return agg.verify_proof(f"spot_open_k{leaf_size}", bytes.fromhex(located["proof"]), public)


COMPARED = ("iic", "fic", "ordinal", "issue_date_time", "total", "business_unit", "device")


def cents(value):
    """An amount as exact cents. Accepts "12.50", "12.5", "12" and JSON numbers; anything with
    more than two decimals, or that is not a plain decimal number, is refused."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError("not an amount")
    text = repr(value) if isinstance(value, float) else str(value)
    if not re.fullmatch(r"-?[0-9]+(\.[0-9]{1,2})?", text):
        raise ValueError("not an amount with at most two decimals")
    return int(decimal.Decimal(text) * 100)


def differences(o, lookup, certificate_subject=None):
    """Names of the fields in which an opening differs from what the authority has for that IIC.
    With the subject of the taxpayer's certificate, "seller" is added when the seller's tax number
    in the authority's record is not the one the certificate carries."""
    def normal(name, value):
        if name in ("iic", "fic"):
            return str(value).replace("-", "").lower()
        if name == "ordinal":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("not a number")
            return value
        if name == "total":
            return cents(value)
        if not isinstance(value, str):
            raise ValueError("not text")
        return value

    out = []
    for name in COMPARED:
        try:
            same = normal(name, o[name]) == normal(name, lookup[name])
        except (KeyError, ValueError, TypeError):
            same = False
        if not same:
            out.append(name)
    if certificate_subject is not None:
        # The certificate names its holder by tax number in organizationIdentifier (2.5.4.97),
        # written VATME-<number>.
        m = re.search(r"VATME-([0-9]+)", certificate_subject)
        seller = str(lookup.get("seller_tin", "")) if isinstance(lookup, dict) else ""
        if m is None or not seller or seller != m.group(1):
            out.append("seller")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("draw")
    r = sub.add_parser("reveal")
    source = r.add_mutually_exclusive_group(required=True)
    source.add_argument("--record")
    source.add_argument("--prover")
    r.add_argument("--index", type=int)
    r.add_argument("--seed")
    r.add_argument("--draw", type=int)
    r.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("--opening", required=True)
    target = c.add_mutually_exclusive_group(required=True)
    target.add_argument("--proof")
    target.add_argument("--commitment")
    c.add_argument("--ordinal", type=int)
    c.add_argument("--first", action="store_true")
    c.add_argument("--last", action="store_true")
    c.add_argument("--seed")
    c.add_argument("--draw", type=int)
    m = sub.add_parser("compare")
    m.add_argument("--opening", required=True)
    m.add_argument("--authority", required=True, help="what the authority shows for this IIC, as JSON")
    m.add_argument("--taxpayer-cert", help="taxpayer certificate (DER/PEM), or a signed EFI request (.xml)")
    a = ap.parse_args()

    if a.cmd == "draw":
        print(new_seed())
        return 0

    if a.cmd == "compare":
        subject = None
        if a.taxpayer_cert:
            import keyhash
            subject = keyhash.describe(keyhash.load_cert(a.taxpayer_cert, a.taxpayer_cert.lower().endswith(".xml")))["subject"]
        with open(a.opening) as f, open(a.authority) as g:
            differing = differences(json.load(f), json.load(g), subject)
        if differing:
            print("DIFFERENT: " + ", ".join(differing))
        else:
            print("AGREES" if subject is not None else "AGREES (seller not compared: no --taxpayer-cert given)")
        return 1 if differing else 0

    if a.cmd == "reveal":
        by_draw = a.seed is not None or a.draw is not None
        if (a.index is None) == (not by_draw) or (by_draw and (a.seed is None or a.draw is None)):
            ap.error("say which invoice: --index I, or --seed SEED --draw J")
        if a.prover and by_draw:
            ap.error("a batch Prover file is opened by --index")
        try:
            o = reveal_from_record(a.record, a.index, seed=a.seed, draw=a.draw) if a.record else reveal(a.prover, a.index)
        except ValueError as e:
            sys.exit(f"cannot open: {e}")
        with open(a.out, "w") as f:
            json.dump(o, f, indent=1)
        print("wrote the opening")
        return 0

    by_draw = a.seed is not None or a.draw is not None
    asked = sum([a.ordinal is not None, a.first, a.last, by_draw])
    if by_draw and (a.seed is None or a.draw is None):
        ap.error("a draw is named by --seed SEED --draw J")
    if a.commitment and (a.first or a.last or by_draw):
        ap.error("--first, --last and draws need the proof: use --proof DIR")
    if a.proof and asked != 1:
        ap.error("with --proof, say which invoice was asked for, once: --ordinal N, --first, --last or --seed SEED --draw J")
    with open(a.opening) as f:
        o = json.load(f)
    edge = "first" if a.first else "last" if a.last else None
    import agg
    try:
        if a.proof:
            ok = check_against_proof(o, a.proof, ordinal=a.ordinal, edge=edge, seed=a.seed, draw=a.draw)
        else:
            ok = recompute(o) == int(a.commitment, 16) and (a.ordinal is None or o.get("ordinal") == a.ordinal)
    except (KeyError, ValueError, TypeError, AttributeError, OSError, agg.StepFailed):
        # A malformed opening, a proof directory that is not one, a circuit that refuses: no match.
        ok = False
    print("MATCH" if ok else "NO MATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
