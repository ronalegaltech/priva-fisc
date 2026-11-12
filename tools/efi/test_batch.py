#!/usr/bin/env python3
"""Accept/reject tests for a batch circuit on synthetic invoice chains.

  python3 tools/efi/test_batch.py            # 1-invoice circuit (fast)
  python3 tools/efi/test_batch.py --k 10     # 10-invoice circuit

Valid chains must execute (starting at ordinal 1 and elsewhere); every tampered chain must be
refused by the circuit.
"""
import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, "batch_inputs.py")
sys.path.insert(0, HERE)
from batch_inputs import TAMPERS  # noqa: E402

NEEDS_TWO = {"gap", "reused-receipt", "mixed-unit", "mixed-device"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=1)
    a = ap.parse_args()
    pkg = os.path.normpath(os.path.join(HERE, "..", "..", "noir", f"batch_k{a.k}"))
    subprocess.run(["nargo", "compile"], cwd=pkg, check=True, capture_output=True)
    failed = 0

    def run(label, want_accept, *extra):
        nonlocal failed
        out = os.path.join(pkg, "ProverTest.toml")
        subprocess.run([sys.executable, GEN, "synthetic", "--k", str(a.k), "--out", out, *extra], check=True, capture_output=True)
        r = subprocess.run(["nargo", "execute", "-p", "ProverTest", "witness_test"], cwd=pkg, capture_output=True, text=True)
        os.remove(out)
        err = r.stderr.strip()
        if r.returncode != 0 and not any(s in err for s in ("Failed constraint", "Assertion failed", "Failed to solve")):
            raise RuntimeError(f"nargo failed for a reason other than a circuit constraint:\n{err}")
        accepted = r.returncode == 0
        reason = next((l.strip() for l in err.splitlines() if "ssert" in l or "Failed" in l), "")
        starts = re.search(r"Circuit output: \(0x[0-9a-f]+, 0x[0-9a-f]+, (true|false)", r.stdout + r.stderr)
        ok = accepted == want_accept
        detail = "accepted" if accepted else f"rejected [{reason[-62:]}]"
        if accepted and starts:
            detail += f" (starts at ordinal 1: {starts.group(1)})"
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {label:18s} {detail}")
        return starts.group(1) if (accepted and starts) else None

    s1 = run("valid from 1", True, "--start", "1")
    s2 = run("valid from 37", True, "--start", "37")
    if (s1, s2) != ("true", "false"):
        failed += 1
        print("FAIL  starts-at-one flag is wrong")
    for t in TAMPERS:
        if a.k == 1 and t in NEEDS_TWO:
            continue
        run(t, False, "--tamper", t)
    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
