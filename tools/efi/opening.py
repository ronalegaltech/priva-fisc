#!/usr/bin/env python3
"""Spot-check ("örnek açtırma") helper.

A batch proof publishes one blinded opening commitment per invoice; an aggregated proof publishes
one root over all of them. After seeing the proof the verifier asks for a few invoices; for each
one the prover reveals the commitment's preimage and the verifier recomputes the commitment. For an
aggregated proof the prover adds a small proof (noir/spot_open_k*) that the commitment sits under
the published root and where, without showing the rest of the tree. The verifier then compares the
revealed values with what the tax authority's public invoice-check service returns for that IIC
(not done by this tool: querying the authority is a deliberate, separate step).

  draw                                                                         (verifier side)
  reveal --record RECORD.json (--index I | --point R) --out OPENING.json       (prover side)
  check  --opening OPENING.json --proof DIR (--ordinal N | --first | --last | --point R)   (verifier)
  compare --opening OPENING.json --authority LOOKUP.json                       (verifier side)

RECORD.json is the file written by `pf.py prove --keep`; it stays with the prover. I counts the
invoices from 0 in the order they were proved.

The verifier says which invoice it asked for, so that the prover cannot answer with another one:
--ordinal N requires the opened invoice to carry that ordinal number; --first and --last require
it to be the first or the last invoice the proof covers. When a proof does not start at ordinal 1
the verifier asks for the first invoice first: its ordinal and the published count give the range
to draw the other ordinals from.

--point R (aggregated proofs) asks for an invoice by amount instead of by number. `draw` prints a
random R; it stands for a point of the sum of all positive totals, and the prover must open the
invoice whose share of that sum contains the point. Invoices are then opened with probability
proportional to their amount: one invoice that carries most of a total is asked for most of the
time, which asking by number would not do.

An opening that matched is what the taxpayer proved, not yet what the authority has. The verifier
looks the invoice up at the tax authority by its IIC and writes what the authority shows into a
small file: {"iic", "fic", "ordinal", "issue_date_time", "total", "business_unit", "device"}.
`compare` prints AGREES, or DIFFERENT followed by the names of the fields that differ (never their
values). The verifier also compares the seller in the authority's record with the taxpayer's
certificate. This tool does not query the authority.

Lower-level forms, for a batch whose Prover file is at hand:
  reveal --prover BATCH_PROVER.toml --index I --out OPENING.json
  check  --opening OPENING.json --commitment 0x...

An opening file contains the invoice's identifiers and amount. It is the disclosure itself: give it
only to the verifier who asked for it. This tool prints MATCH / NO MATCH and nothing else.
"""
import argparse
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


def reveal_from_record(record_path, index=None, point=None):
    """Opening of one invoice from the prover's record: the one at position `index`, or, when only
    `point` is given, the one that covers that draw. For an aggregated proof the opening comes with
    a proof of where it sits under the published root (made for the draw `point`, 0 if none)."""
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
    r = point or 0
    if index is None:
        # The invoice whose range [sum before it, sum before it + its total) holds the point.
        target = (r * tree["sum"]) >> 64
        index, before = None, 0
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
    depth = 12  # MAX_DEPTH in noir/pf_efi/src/spot.nr
    if len(path) > depth:
        raise ValueError("the tree is deeper than the spot-check circuit follows")
    pad = depth - len(path)
    leaf = leaves[leaf_index]
    openings = [int(v, 16) for v in leaf["openings"]]
    flags = lambda values: "[" + ", ".join("true" if v else "false" for v in values) + "]"  # noqa: E731
    text = f"openings = {agg.hexlist(openings)}\nplus = {agg.hexlist(leaf['plus'])}\nslot = \"{slot}\"\n"
    text += f"used = {flags([True] * len(path) + [False] * pad)}\n"
    text += f"node_is_left = {flags([p[0] for p in path] + [False] * pad)}\n"
    text += f"sibling = {agg.hexlist([p[1] for p in path] + [0] * pad)}\n"
    text += f"sibling_sum = {agg.hexlist([p[2] for p in path] + [0] * pad)}\n"
    text += f'root = "{hex(agg.openings_root(int(tree["h"], 16), tree["sum"]))}"\n'
    text += f'commitment = "{hex(openings[slot])}"\namount = "{leaf["plus"][slot]}"\nr = "{r}"\n'
    name = f"spot_open_k{len(openings)}"
    with tempfile.TemporaryDirectory() as tmp:
        agg.prove(name, text, tmp, "evm")
        proof = open(os.path.join(tmp, "proof"), "rb").read()
        public = open(os.path.join(tmp, "public_inputs"), "rb").read()
    o = dict(record["invoices"][index], position=index)
    o["proof"] = {"leaf_size": len(openings), "proof": proof.hex(), "public_inputs": public.hex()}
    return o


def check_against_proof(o, proof_dir, ordinal=None, edge=None, point=None):
    """True if the opening is one the proof in `proof_dir` commits to and is the invoice asked for:
    the one with this `ordinal`, the "first" / "last" invoice of the proof (`edge`), or the one
    that covers the draw `point`."""
    import agg  # here, not at the top: agg.py uses this module too
    if ordinal is not None and o.get("ordinal") != ordinal:
        return False
    commitment = recompute(o)
    values = agg.fields_of(os.path.join(proof_dir, "public_inputs"))
    if len(values) != 13:
        # Batch proof: threshold, context, year, two key hashes, a flag, K nullifiers, K commitments.
        k = (len(values) - 6) // 2
        position = o.get("position", -1)
        if point is not None or (edge and position != (0 if edge == "first" else k - 1)):
            return False
        return 0 <= position < k and values[6 + k + position] == commitment
    located = o.get("proof")
    if not located or located.get("leaf_size") not in agg.LEAF_SIZES:
        return False
    public = bytes.fromhex(located["public_inputs"])
    if len(public) != 7 * 32:
        return False
    # (root, commitment, amount, draw) as given to the circuit, then its three answers.
    root, shown, amount, draw, covers, is_first, is_last = (
        int.from_bytes(public[i:i + 32], "big") for i in range(0, len(public), 32))
    if root != int(agg.decode(values)["opening_root"], 16) or shown != commitment or amount != positive_cents(o):
        return False
    if edge == "first" and is_first != 1 or edge == "last" and is_last != 1:
        return False
    if point is not None and (draw != point or covers != 1):
        return False
    return agg.verify_proof(f"spot_open_k{located['leaf_size']}", bytes.fromhex(located["proof"]), public)


COMPARED = ("iic", "fic", "ordinal", "issue_date_time", "total", "business_unit", "device")


def differences(o, lookup):
    """Names of the fields in which an opening differs from what the authority has for that IIC."""
    def normal(name, value):
        if name in ("iic", "fic"):
            return str(value).replace("-", "").lower()
        if name == "ordinal":
            return int(value)
        if name == "total":
            text = str(value)
            return int(text.replace(".", "")) if "." in text else int(text) * 100
        return str(value)

    out = []
    for name in COMPARED:
        try:
            same = normal(name, o[name]) == normal(name, lookup[name])
        except (KeyError, ValueError):
            same = False
        if not same:
            out.append(name)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("draw")
    r = sub.add_parser("reveal")
    source = r.add_mutually_exclusive_group(required=True)
    source.add_argument("--record")
    source.add_argument("--prover")
    which = r.add_mutually_exclusive_group(required=True)
    which.add_argument("--index", type=int)
    which.add_argument("--point", type=int)
    r.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("--opening", required=True)
    target = c.add_mutually_exclusive_group(required=True)
    target.add_argument("--proof")
    target.add_argument("--commitment")
    asked = c.add_mutually_exclusive_group()
    asked.add_argument("--ordinal", type=int)
    asked.add_argument("--first", action="store_true")
    asked.add_argument("--last", action="store_true")
    asked.add_argument("--point", type=int)
    m = sub.add_parser("compare")
    m.add_argument("--opening", required=True)
    m.add_argument("--authority", required=True, help="what the authority shows for this IIC, as JSON")
    a = ap.parse_args()
    if a.cmd == "draw":
        print(secrets.randbits(64))
        return 0
    if a.cmd == "compare":
        with open(a.opening) as f, open(a.authority) as g:
            differing = differences(json.load(f), json.load(g))
        print("DIFFERENT: " + ", ".join(differing) if differing else "AGREES")
        return 1 if differing else 0
    if a.cmd == "check" and a.proof and a.ordinal is None and a.point is None and not (a.first or a.last):
        ap.error("with --proof, say which invoice was asked for: --ordinal N, --first, --last or --point R")
    if a.cmd == "reveal" and a.prover and a.index is None:
        ap.error("a batch Prover file is opened by --index")

    if a.cmd == "reveal":
        try:
            o = reveal_from_record(a.record, a.index, a.point) if a.record else reveal(a.prover, a.index)
        except ValueError as e:
            sys.exit(f"cannot open: {e}")
        with open(a.out, "w") as f:
            json.dump(o, f, indent=1)
        print(f"wrote opening for invoice position {o.get('position', a.index)}")
        return 0
    with open(a.opening) as f:
        o = json.load(f)
    edge = "first" if a.first else "last" if a.last else None
    try:
        if a.proof:
            ok = check_against_proof(o, a.proof, ordinal=a.ordinal, edge=edge, point=a.point)
        else:
            ok = recompute(o) == int(a.commitment, 16) and (a.ordinal is None or o.get("ordinal") == a.ordinal)
    except (KeyError, ValueError, TypeError):
        ok = False
    print("MATCH" if ok else "NO MATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
