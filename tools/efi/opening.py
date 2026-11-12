#!/usr/bin/env python3
"""Spot-check ("örnek açtırma") helper.

A batch proof publishes one blinded opening commitment per invoice; an aggregated proof publishes
one root over all of them. After seeing the proof the verifier names a few invoice positions; for
each one the prover reveals the commitment's preimage (and, for an aggregated proof, the hashes
that lead from it to the root) and the verifier recomputes. The verifier then compares the revealed
values with what the tax authority's public invoice-check service returns for that IIC (not done by
this tool: querying the authority is a deliberate, separate step).

  reveal --record RECORD.json --index I --out OPENING.json                    (prover side)
  check  --opening OPENING.json --proof DIR (--ordinal N | --first | --last)  (verifier side)

RECORD.json is the file written by `pf.py prove --keep`; it stays with the prover. I counts the
invoices from 0 in the order they were proved.

The verifier says which invoice it asked for, so that the prover cannot answer with another one:
--ordinal N requires the opened invoice to carry that ordinal number; --first and --last require
it to be the first or the last invoice the proof covers. When a proof does not start at ordinal 1
the verifier asks for the first invoice first: its ordinal and the published count give the range
to draw the other ordinals from.

What the verifier still has to do by hand with an opening that matched: look the invoice up at the
tax authority by its IIC, compare receipt code, ordinal, time, total, business unit and device with
the opening, and compare the seller in the authority's record with the taxpayer's certificate.

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


def reveal_from_record(record_path, index):
    """Opening of invoice `index` from the prover's record, with its position and, for an
    aggregated proof, the path to the root."""
    with open(record_path) as f:
        record = json.load(f)
    if not 0 <= index < len(record["invoices"]):
        raise ValueError("no invoice at this position")
    o = dict(record["invoices"][index])
    o["position"] = index
    if "tree" not in record:
        return o
    # Which leaf, and which slot in it.
    leaf_index, slot = 0, index
    while slot >= record["leaves"][leaf_index]["count"]:
        slot -= record["leaves"][leaf_index]["count"]
        leaf_index += 1

    def climb(node):
        """Sibling hashes from the leaf up to `node`, or None if the leaf is not below it."""
        if "leaf" in node:
            return [] if node["leaf"] == leaf_index else None
        below = climb(node["left"])
        if below is not None:
            return below + [["right", node["right"]["h"]]]
        below = climb(node["right"])
        if below is not None:
            return below + [["left", node["left"]["h"]]]
        return None

    o["path"] = {"leaf": record["leaves"][leaf_index]["openings"], "slot": slot, "siblings": climb(record["tree"])}
    return o


def check_against_proof(o, proof_dir, ordinal=None, edge=None):
    """True if the opening is one the proof in `proof_dir` commits to and is the invoice asked for:
    the one with this `ordinal`, or the "first" / "last" invoice of the proof (`edge`)."""
    import agg  # here, not at the top: agg.py uses this module too
    if ordinal is not None and o.get("ordinal") != ordinal:
        return False
    commitment = recompute(o)
    values = agg.fields_of(os.path.join(proof_dir, "public_inputs"))
    if len(values) != 13:
        # Batch proof: threshold, context, year, two key hashes, a flag, K nullifiers, K commitments.
        k = (len(values) - 6) // 2
        position = o.get("position", -1)
        if edge and position != (0 if edge == "first" else k - 1):
            return False
        return 0 <= position < k and values[6 + k + position] == commitment
    path = o.get("path")
    if not path or len(path["leaf"]) not in agg.LEAF_SIZES or not 0 <= path["slot"] < len(path["leaf"]):
        return False
    leaf = [int(v, 16) for v in path["leaf"]]
    slot = path["slot"]
    if leaf[slot] != commitment:
        return False
    sides = [side for side, _ in path["siblings"]]
    # The first invoice sits in slot 0 of the leftmost leaf: every sibling on the way up is on the
    # right. The last one is the last used slot of the rightmost leaf (unused slots hold zero).
    if edge == "first" and (slot != 0 or any(side != "right" for side in sides)):
        return False
    if edge == "last" and (any(leaf[slot + 1:]) or any(side != "left" for side in sides)):
        return False
    h = agg.slot_hash(leaf)
    for side, sibling in path["siblings"]:
        if side not in ("left", "right"):
            return False
        h = agg.pair_hash(int(sibling, 16), h) if side == "left" else agg.pair_hash(h, int(sibling, 16))
    return h == int(agg.decode(values)["opening_root"], 16)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("reveal")
    source = r.add_mutually_exclusive_group(required=True)
    source.add_argument("--record")
    source.add_argument("--prover")
    r.add_argument("--index", type=int, required=True)
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
    a = ap.parse_args()
    if a.cmd == "check" and a.proof and a.ordinal is None and not (a.first or a.last):
        ap.error("with --proof, say which invoice was asked for: --ordinal N, --first or --last")

    if a.cmd == "reveal":
        o = reveal_from_record(a.record, a.index) if a.record else reveal(a.prover, a.index)
        with open(a.out, "w") as f:
            json.dump(o, f, indent=1)
        print(f"wrote opening for invoice position {a.index}")
        return 0
    with open(a.opening) as f:
        o = json.load(f)
    edge = "first" if a.first else "last" if a.last else None
    try:
        if a.proof:
            ok = check_against_proof(o, a.proof, ordinal=a.ordinal, edge=edge)
        else:
            ok = recompute(o) == int(a.commitment, 16) and (a.ordinal is None or o.get("ordinal") == a.ordinal)
    except (KeyError, ValueError, TypeError):
        ok = False
    print("MATCH" if ok else "NO MATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
