#!/usr/bin/env python3
"""The Python Poseidon2 used by the tools must give the values the circuits compute.

  python3 tools/efi/test_poseidon2.py

Checks the permutation against the published test vector, the hash against a circuit for every
input length from 0 to 10, and the opening commitment against the open_invoice circuit.
"""
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agg  # noqa: E402
import opening  # noqa: E402
import poseidon2  # noqa: E402

# Permutation of (0, 1, 2, 3), from the Poseidon2 reference parameters for this field.
VECTOR = (
    0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737,
    0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662,
    0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb,
    0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a,
)


def main():
    failed = 0

    def report(label, good):
        nonlocal failed
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label}", flush=True)

    report("permutation test vector", tuple(poseidon2.permute([0, 1, 2, 3])) == VECTOR)

    for n in range(11):
        values = [secrets.randbelow(poseidon2.P) for _ in range(n)]
        padded = values + [0] * (10 - n)
        _, out = agg.execute("poseidon2_check", f'values = {agg.hexlist(padded)}\nn = "{n}"\n', want_output=True)
        report(f"hash of {n} element(s) equals the circuit", out[0] == poseidon2.hash(values))

    o = {
        "iic": secrets.token_hex(16),
        "fic": "01234567-89ab-4cde-8f01-23456789abcd",
        "ordinal": 4711,
        "issue_date_time": "2026-03-09T14:05:59+01:00",
        "total": "-1234.56",
        "salt": hex(secrets.randbits(248)),
    }
    report("opening commitment equals the open_invoice circuit", opening.recompute(o) == opening.recompute_in_circuit(o))

    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
