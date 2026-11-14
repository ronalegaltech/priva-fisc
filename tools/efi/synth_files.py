#!/usr/bin/env python3
"""Write invented invoices to disk as signed files, the way a taxpayer's software would hold them.

  python3 tools/efi/synth_files.py --n 10 --out DIR

DIR gets request_01.xml, receipt_01.xml, request_02.xml, ... and summary.json. The invoices are
consecutive, of one business unit and one device in one year, all issued to one buyer, signed by a
throw-away taxpayer key and a throw-away authority key. summary.json holds what `pf.py prove` asks
for on the command line: the year, the sum of the totals and the buyer.

The same files can go into different kinds of proof (a batch, a proof about the buyer), which is
how the tests show that an invoice presented in one kind is recognised in the other.
"""
import argparse
import json
import os
import random
import secrets
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from efi_common import new_key  # noqa: E402
from leaf_request_inputs import build_request, core_fields, signed_xml  # noqa: E402
from leaf_response_inputs import synthetic_soap  # noqa: E402

BUYER = {"type": "TIN", "num": "12345678"}


def write(n, out, start=1):
    """n consecutive invented invoices from ordinal `start`, as signed pairs under `out`."""
    rng = random.Random(secrets.randbits(64))
    taxpayer, authority = new_key(), new_key()
    base = core_fields(rng)
    base["buyer"] = BUYER
    os.makedirs(out, exist_ok=True)
    total = 0
    for i in range(n):
        c = dict(base)
        c["uuid"] = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        c["ordinal"] = start + i
        c["net"] = rng.randrange(1000, 300000)
        c["vat"] = c["net"] * 21 // 100
        c["total"] = c["net"] + c["vat"]
        total += c["total"]
        with open(os.path.join(out, f"request_{i + 1:02d}.xml"), "wb") as f:
            f.write(signed_xml(taxpayer, build_request(taxpayer, c, tricky=False)))
        receipt = (c["uuid"].encode(), c["issue"].encode(), str(uuid.uuid4()).encode(), str(uuid.uuid4()).encode())
        with open(os.path.join(out, f"receipt_{i + 1:02d}.xml"), "wb") as f:
            f.write(synthetic_soap(authority, receipt))
    summary = {"count": n, "year": base["year"], "total": f"{total // 100}.{total % 100:02d}",
               "buyer": f"{BUYER['type']}:{BUYER['num']}"}
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, required=True, help="number of invoices")
    ap.add_argument("--out", required=True, help="directory for the files")
    a = ap.parse_args()
    if not 1 <= a.n <= 99:
        sys.exit("between 1 and 99 invoices")
    s = write(a.n, a.out)
    print(f"{s['count']} invented invoices written to {a.out}: year {s['year']}, total {s['total']}, buyer {s['buyer']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
