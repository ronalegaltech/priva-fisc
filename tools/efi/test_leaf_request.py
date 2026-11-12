#!/usr/bin/env python3
"""Accept/reject tests for noir/leaf_request_v0 on synthetic invoices.

  * a valid request must execute;
  * a plain request and one stuffed with look-alike text, carrying the same invoice fields, must
    give identical circuit outputs (the reader was not fooled);
  * every tampered case must be refused by the circuit.

Run from anywhere:  python3 tools/efi/test_leaf_request.py
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.normpath(os.path.join(HERE, "..", "..", "noir", "leaf_request_v0"))
GEN = os.path.join(HERE, "leaf_request_inputs.py")
sys.path.insert(0, HERE)
from leaf_request_inputs import TAMPERS  # noqa: E402


def execute(name):
    r = subprocess.run(["nargo", "execute", "-p", name, "witness_test"], cwd=PKG, capture_output=True, text=True)
    os.remove(os.path.join(PKG, name + ".toml"))
    err = r.stderr.strip()
    if r.returncode != 0 and not any(k in err for k in ("Failed constraint", "Assertion failed", "Failed to solve")):
        raise RuntimeError(f"nargo failed for a reason other than a circuit constraint:\n{err}")
    reason = next((l.strip() for l in err.splitlines() if "ssert" in l or "Failed" in l), "")
    out = re.search(r"Circuit output: (.*)", r.stdout + r.stderr)
    return r.returncode == 0, reason, out.group(1) if out else None


def gen(*args):
    subprocess.run([sys.executable, GEN, *args], check=True, capture_output=True)


def main():
    subprocess.run(["nargo", "compile"], cwd=PKG, check=True, capture_output=True)
    failed = 0

    def report(label, ok, detail=""):
        nonlocal failed
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {label:20s} {detail}")

    gen("synthetic", "--out", os.path.join(PKG, "ProverTest.toml"))
    accepted, reason, _ = execute("ProverTest")
    report("valid", accepted, "accepted" if accepted else f"rejected [{reason}]")

    gen("pair", os.path.join(PKG, "ProverPlain.toml"), os.path.join(PKG, "ProverTricky.toml"))
    ok1, r1, out1 = execute("ProverPlain")
    ok2, r2, out2 = execute("ProverTricky")
    same = ok1 and ok2 and out1 is not None and out1 == out2
    report("look-alike text", same, "same outputs as the plain invoice" if same else f"DIFFERENT or rejected [{r1} {r2}]")

    for tamper in TAMPERS:
        gen("synthetic", "--out", os.path.join(PKG, "ProverTest.toml"), "--tamper", tamper)
        accepted, reason, _ = execute("ProverTest")
        report(tamper, not accepted, "accepted (WRONG)" if accepted else f"rejected [{reason[-75:]}]")

    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
