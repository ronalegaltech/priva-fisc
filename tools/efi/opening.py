#!/usr/bin/env python3
"""Spot-check ("örnek açtırma") helper for the batch circuits.

A batch proof publishes one blinded opening commitment per invoice. After seeing the proof the
verifier names a few invoice positions; for each one the prover reveals the commitment's preimage
and the verifier recomputes the commitment. The verifier then compares the revealed values with
what the tax authority's public invoice-check service returns for that IIC (not done by this tool:
querying the authority is a deliberate, separate step).

  reveal --prover BATCH_PROVER.toml --index I --out OPENING.json      (prover side)
  check  --opening OPENING.json --commitment 0x...                    (verifier side)

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
    tag = doc[200:]

    def attr(name):
        m = re.search(rb' ' + name + rb'="([^"]*)"', tag)
        if m is None:
            raise ValueError(f"attribute {name.decode()} not found")
        return m.group(1).decode()

    seller = re.search(rb'<Seller [^>]*\bIDNum="([^"]*)"', doc)
    return {
        "iic": attr(b"IIC"),
        "fic": bytes(p["resp_fics"][index]).decode(),
        "ordinal": int(attr(b"InvOrdNum")),
        "issue_date_time": attr(b"IssueDateTime"),
        "total": attr(b"TotPrice"),
        "salt": p["salts"][index],
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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("reveal")
    r.add_argument("--prover", required=True)
    r.add_argument("--index", type=int, required=True)
    r.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("--opening", required=True)
    c.add_argument("--commitment", required=True)
    a = ap.parse_args()

    if a.cmd == "reveal":
        with open(a.out, "w") as f:
            json.dump(reveal(a.prover, a.index), f, indent=1)
        print(f"wrote opening for invoice position {a.index}")
        return 0
    with open(a.opening) as f:
        got = recompute(json.load(f))
    ok = got == int(a.commitment, 16)
    print("MATCH" if ok else "NO MATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
