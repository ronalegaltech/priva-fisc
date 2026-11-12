#!/usr/bin/env python3
"""Spot-check ("örnek açtırma") helper.

A batch proof publishes one blinded opening commitment per invoice; an aggregated proof publishes
one root over all of them. After seeing the proof the verifier names a few invoice positions; for
each one the prover reveals the commitment's preimage (and, for an aggregated proof, the hashes
that lead from it to the root) and the verifier recomputes. The verifier then compares the revealed
values with what the tax authority's public invoice-check service returns for that IIC (not done by
this tool: querying the authority is a deliberate, separate step).

  reveal --record RECORD.json --index I --out OPENING.json            (prover side)
  check  --opening OPENING.json --proof DIR [--ordinal N]             (verifier side)

RECORD.json is the file written by `pf.py prove --keep`; it stays with the prover. I counts the
invoices from 0 in the order they were proved. With --ordinal the check also requires the opened
invoice to carry that ordinal number.

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
OPEN_PKG = os.path.normpath(os.path.join(HERE, "..", "..", "noir", "open_invoice"))


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
    return {
        "iic": hex(int(o["iic"], 16)),
        "fic": hex(int(o["fic"].replace("-", ""), 16)),
        "ordinal": str(o["ordinal"]),
        "issue_local_ts": str(local),
        "issue_tz": str(tz),
        "total_negative": "1" if negative else "0",
        "total_cents": str(cents),
        "salt": o["salt"],
    }


def recompute(o):
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


def check_against_proof(o, proof_dir):
    """True if the opening is the one the proof in `proof_dir` commits to at its position."""
    import agg  # here, not at the top: agg.py uses this module too
    commitment = recompute(o)
    values = agg.fields_of(os.path.join(proof_dir, "public_inputs"))
    if len(values) != 13:
        # Batch proof: threshold, context, year, two key hashes, a flag, K nullifiers, K commitments.
        k = (len(values) - 6) // 2
        return 0 <= o.get("position", -1) < k and values[6 + k + o["position"]] == commitment
    path = o.get("path")
    if not path or len(path["leaf"]) not in agg.LEAF_SIZES or not 0 <= path["slot"] < len(path["leaf"]):
        return False
    leaf = [int(v, 16) for v in path["leaf"]]
    if leaf[path["slot"]] != commitment:
        return False
    h = agg.slot_hash(leaf)
    for side, sibling in path["siblings"]:
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
    c.add_argument("--ordinal", type=int)
    a = ap.parse_args()

    if a.cmd == "reveal":
        o = reveal_from_record(a.record, a.index) if a.record else reveal(a.prover, a.index)
        with open(a.out, "w") as f:
            json.dump(o, f, indent=1)
        print(f"wrote opening for invoice position {a.index}")
        return 0
    with open(a.opening) as f:
        o = json.load(f)
    try:
        ok = check_against_proof(o, a.proof) if a.proof else recompute(o) == int(a.commitment, 16)
    except (KeyError, ValueError, TypeError):
        ok = False
    if a.ordinal is not None and o.get("ordinal") != a.ordinal:
        ok = False
    print("MATCH" if ok else "NO MATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
