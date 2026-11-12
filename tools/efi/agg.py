#!/usr/bin/env python3
"""Aggregated proof: 2 leaves of K invoices -> one root proof (noir/agg_*; method in noir/pf_efi/src/agg.nr).

  agg.py prove  --k K --out DIR --synthetic            (2*K invented invoices)
  agg.py verify --k K DIR

`prove` leaves in DIR only the root proof, its public values and a readable statement.
`verify` derives BOTH verification keys locally: the root's (to check the proof) and the leaf's (to
compare its key hash with the `leaf_vk_hash` the root proof names). Run `. tools/toolchain.env` first.
"""
import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import batch_inputs  # noqa: E402

B = 2  # leaves per root in the circuits that exist today


class StepFailed(Exception):
    """A circuit refused its inputs, or the prover could not make a valid proof."""


def pkg(name):
    return os.path.join(ROOT, "noir", name)


def run(cmd, cwd=None, what=""):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        lines = (r.stderr.strip() or r.stdout.strip()).splitlines()
        reason = next((l.strip() for l in lines if "ssertion failed" in l or "Failed" in l), lines[-1] if lines else "")
        raise StepFailed(f"{what}: {reason}")
    return r


def compiled(name):
    run(["nargo", "compile"], cwd=pkg(name), what=f"compiling {name}")
    return os.path.join(pkg(name), "target", f"{name}.json")


def execute(name, toml_text, want_output=False):
    """Run a circuit on inputs. Returns (witness path, parsed output fields). Removes the input file."""
    tag = "Run" + next(tempfile._get_candidate_names())
    path = os.path.join(pkg(name), f"Prover{tag}.toml")
    with open(path, "w") as f:
        f.write(toml_text)
    try:
        r = run(["nargo", "execute", "-p", f"Prover{tag}", f"witness{tag}"], cwd=pkg(name), what=name)
    finally:
        os.remove(path)
    out = None
    if want_output:
        m = re.search(r"Circuit output: (.*)", r.stdout + r.stderr)
        out = re.findall(r"0x[0-9a-f]+", m.group(1)) if m else []
    return os.path.join(pkg(name), "target", f"witness{tag}.gz"), out


def fields_of(path):
    data = open(path, "rb").read()
    return [int.from_bytes(data[i:i + 32], "big") for i in range(0, len(data), 32)]


def hexlist(values):
    return "[" + ", ".join(f'"{hex(v)}"' for v in values) + "]"


def fic_int(invoice):
    return int(invoice["resp"][3].decode().replace("-", ""), 16)


def prove_leaves(k, invoices, tmod, imod, context, year, gamma, work):
    """Prove each leaf for recursion. Returns per-leaf dicts: proof fields, public values, summary, blind."""
    leaf, leaf_open = f"agg_leaf_k{k}", f"agg_leaf_k{k}_open"
    circuit = compiled(leaf)
    compiled(leaf_open)
    leaves = []
    for b in range(B):
        group = invoices[b * k:(b + 1) * k]
        common = batch_inputs.invoice_toml(group, tmod, imod)
        tail = f'context = "{hex(context)}"\nyear = "{year}"\ngamma = "{hex(gamma)}"\n'
        w_open, summary = execute(leaf_open, common + tail, want_output=True)
        os.remove(w_open)
        blind = secrets.randbits(248)
        witness, _ = execute(leaf, common + f'blind = "{hex(blind)}"\n' + tail)
        out = os.path.join(work, f"leaf{b}")
        try:
            run(["bb", "prove", "-b", circuit, "-w", witness, "-o", out, "-t", "noir-recursive", "--write_vk"], what=f"proving leaf {b}")
        finally:
            os.remove(witness)
        leaves.append({"dir": out, "summary": [int(x, 16) for x in summary], "blind": blind,
                       "public": fields_of(os.path.join(out, "public_inputs"))})
    return leaves


def root_inputs(leaves, sorted_fics, threshold, context, year, leaf_vk_hash=None, summaries=None):
    d0 = leaves[0]["dir"]
    vk = fields_of(os.path.join(d0, "vk"))
    key_hash = fields_of(os.path.join(d0, "vk_hash"))[0] if leaf_vk_hash is None else leaf_vk_hash
    summaries = summaries or [l["summary"] for l in leaves]
    t = f"leaf_vk = {hexlist(vk)}\n"
    t += "leaf_proofs = [" + ", ".join(hexlist(fields_of(os.path.join(l["dir"], "proof"))) for l in leaves) + "]\n"
    t += "summaries = [" + ", ".join(hexlist(s) for s in summaries) + "]\n"
    t += f"blinds = {hexlist([l['blind'] for l in leaves])}\n"
    t += f"sorted_fics = {hexlist(sorted_fics)}\n"
    t += f'taxpayer_key_hash = "{hex(leaves[0]["public"][3])}"\nissuer_key_hash = "{hex(leaves[0]["public"][4])}"\n'
    t += f'threshold_cents = "{threshold}"\ncontext = "{hex(context)}"\nyear = "{year}"\nleaf_vk_hash = "{hex(key_hash)}"\n'
    return t


def compute_gamma(k, invoices, sorted_fics):
    name = f"agg_gamma_k{k}_b2"
    compiled(name)
    groups = [[fic_int(i) for i in invoices[b * k:(b + 1) * k]] for b in range(B)]
    text = "fics = [" + ", ".join(hexlist(g) for g in groups) + f"]\nsorted = {hexlist(sorted_fics)}\n"
    witness, out = execute(name, text, want_output=True)
    os.remove(witness)
    return int(out[0], 16)


def prove(k, invoices, tmod, imod, threshold, context, year, out_dir, hooks=None):
    """Full pipeline. `hooks` lets tests tamper with intermediate values; see test_agg.py."""
    hooks = hooks or {}
    assert len(invoices) == B * k
    sorted_fics = sorted(fic_int(i) for i in invoices)
    gamma = compute_gamma(k, invoices, sorted_fics)
    root = f"agg_root_k{k}_b2"
    root_circuit = compiled(root)
    os.makedirs(out_dir, exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        leaves = prove_leaves(k, invoices, tmod, imod, context, year, hooks.get("leaf_gamma", gamma), work)
        text = root_inputs(leaves, hooks.get("sorted", sorted_fics), threshold, context, year,
                           leaf_vk_hash=hooks.get("leaf_vk_hash"),
                           summaries=hooks["summaries"]([l["summary"] for l in leaves]) if "summaries" in hooks else None)
        witness, _ = execute(root, text)
        try:
            run(["bb", "prove", "-b", root_circuit, "-w", witness, "-o", work, "-t", "evm", "--write_vk"], what="proving the root")
        finally:
            os.remove(witness)
        for name in ("proof", "public_inputs"):
            shutil.copy(os.path.join(work, name), os.path.join(out_dir, name))
    st = decode(fields_of(os.path.join(out_dir, "public_inputs")), k)
    with open(os.path.join(out_dir, "statement.json"), "w") as f:
        json.dump(st, f, indent=1)
    return st


def decode(v, k):
    if len(v) != 10:
        raise StepFailed(f"unexpected number of public values ({len(v)})")
    return {
        "circuit": f"agg_root_k{k}_b2", "invoice_count": B * k,
        "threshold_cents": v[0], "context": hex(v[1]), "year": v[2], "leaf_vk_hash": hex(v[3]),
        "taxpayer_key_hash": hex(v[4]), "issuer_key_hash": hex(v[5]), "starts_at_ordinal_one": v[6] == 1,
        "nullifier_root": hex(v[7]), "opening_root": hex(v[8]), "scope_nullifier": hex(v[9]),
    }


def verify(k, proof_dir):
    """Returns (ok, statement, problems)."""
    st = decode(fields_of(os.path.join(proof_dir, "public_inputs")), k)
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        run(["bb", "write_vk", "-b", compiled(f"agg_root_k{k}_b2"), "-o", os.path.join(tmp, "root"), "-t", "evm"], what="root key")
        run(["bb", "write_vk", "-b", compiled(f"agg_leaf_k{k}"), "-o", os.path.join(tmp, "leaf"), "-t", "noir-recursive"], what="leaf key")
        r = subprocess.run(["bb", "verify", "-k", os.path.join(tmp, "root", "vk"), "-p", os.path.join(proof_dir, "proof"),
                            "-i", os.path.join(proof_dir, "public_inputs"), "-t", "evm"], capture_output=True, text=True)
        if "Proof verified successfully" not in (r.stdout + r.stderr):
            problems.append("the root proof does not verify")
        local_leaf_hash = fields_of(os.path.join(tmp, "leaf", "vk_hash"))[0]
    if int(st["leaf_vk_hash"], 16) != local_leaf_hash:
        problems.append("the proof names a leaf circuit that is not the one in this repository")
    return not problems, st, problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prove")
    p.add_argument("--k", type=int, choices=(1, 10), required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--synthetic", action="store_true", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--k", type=int, choices=(1, 10), required=True)
    v.add_argument("dir")
    a = ap.parse_args()
    try:
        if a.cmd == "prove":
            invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(B * a.k, None, 1, None)
            st = prove(a.k, invoices, tmod, imod, threshold, context, year, a.out)
            print(f"aggregated proof for {st['invoice_count']} invoices written to {a.out}")
            return 0
        ok, st, problems = verify(a.k, a.dir)
    except StepFailed as e:
        print(f"FAILED - {e}")
        return 1
    if not ok:
        print("PROOF NOT ACCEPTED: " + "; ".join(problems))
        return 1
    print("PROOF VALID")
    print(f"  what is proved      : {st['invoice_count']} consecutive invoices (2 leaves of {a.k}) of one business unit and device,")
    print(f"                        issued in {st['year']}, each with an authority receipt for the same request;")
    print(f"                        no receipt used twice; sum of totals >= {st['threshold_cents'] // 100}.{st['threshold_cents'] % 100:02d} EUR")
    print(f"  starts at ordinal 1 : {'yes' if st['starts_at_ordinal_one'] else 'no'}")
    print("  leaf circuit        : matches this repository")
    print(f"  taxpayer key hash   : {st['taxpayer_key_hash']}")
    print(f"  authority key hash  : {st['issuer_key_hash']} (compare with registry/issuer_keys.json)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
