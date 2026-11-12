#!/usr/bin/env python3
"""Accept/reject tests for noir/leaf_response_v0 on synthetic responses.

One valid case must execute; every tampered case must be refused by the circuit.
Run from anywhere:  python3 tools/efi/test_leaf_response.py
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.normpath(os.path.join(HERE, "..", "..", "noir", "leaf_response_v0"))
GEN = os.path.join(HERE, "leaf_response_inputs.py")
sys.path.insert(0, HERE)
from leaf_response_inputs import TAMPERS  # noqa: E402


def run_case(tamper):
    name = "ProverTest"
    out = os.path.join(PKG, name + ".toml")
    cmd = [sys.executable, GEN, "synthetic", "--out", out]
    if tamper:
        cmd += ["--tamper", tamper]
    subprocess.run(cmd, check=True, capture_output=True)
    r = subprocess.run(["nargo", "execute", "-p", name, "witness_test"], cwd=PKG, capture_output=True, text=True)
    os.remove(out)
    err = r.stderr.strip()
    if r.returncode != 0 and "Failed constraint" not in err and "Assertion failed" not in err and "Failed to solve" not in err:
        raise RuntimeError(f"nargo failed for a reason other than a circuit constraint:\n{err}")
    reason = next((l.strip() for l in err.splitlines() if "ssert" in l or "Failed" in l), "")
    return r.returncode == 0, reason


def main():
    subprocess.run(["nargo", "compile"], cwd=PKG, check=True, capture_output=True)
    failed = 0
    for tamper in (None,) + TAMPERS:
        accepted, last = run_case(tamper)
        want = tamper is None
        ok = accepted == want
        failed += not ok
        label = tamper or "valid"
        verdict = "accepted" if accepted else "rejected"
        print(f"{'PASS' if ok else 'FAIL'}  {label:16s} {verdict}" + ("" if accepted else f"   [{last[-70:]}]"))
    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
