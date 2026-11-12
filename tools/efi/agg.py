#!/usr/bin/env python3
"""Aggregated proof over any number of invoices (noir/agg_*; method in noir/pf_efi/src/agg.nr).

  agg.py prove  --k K --n N --out DIR --synthetic [--keep FILE]    N invented invoices, leaves of K
  agg.py verify DIR

The invoices are cut, in order, into leaves of up to K (the last leaf may be partly filled). Leaves
are proved one by one, joined pairwise by node proofs into one proof for the whole run, and closed
by a top proof that also checks the sorted list of receipt codes. `prove` leaves in DIR only the top
proof, its public values and a readable statement. With --keep it also writes, for the prover
alone, the record needed to answer spot checks later (tools/efi/opening.py).

`verify` derives every verification key locally: the top's (to check the proof) and those of the
leaf, node and sorted-list circuits (to compare their key hashes with the ones the proof names).
At most 4096 invoices per proof. Run `. tools/toolchain.env` first.
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
import poseidon2  # noqa: E402

# BN254 scalar field, the field the circuits compute in.
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
DOMAIN_PAIR = int.from_bytes(b"PF-PAIR001", "big")
DOMAIN_GAMMA = int.from_bytes(b"PF-GAMMA01", "big")
DOMAIN_CODES = int.from_bytes(b"PF-CODES01", "big")
SORTED = "agg_sorted_s4096"
SORTED_CAPACITY = 4096
LEAF_SIZES = (1, 10)


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


_compiled = {}


def compiled(name):
    if name not in _compiled:
        run(["nargo", "compile"], cwd=pkg(name), what=f"compiling {name}")
        _compiled[name] = os.path.join(pkg(name), "target", f"{name}.json")
    return _compiled[name]


def execute(name, toml_text, want_output=False):
    """Run a circuit on inputs. Returns (witness path, output fields as ints). Removes the input file."""
    compiled(name)
    tag = "Run" + next(tempfile._get_candidate_names())
    path = os.path.join(pkg(name), f"Prover{tag}.toml")
    with open(path, "w") as f:
        f.write(toml_text)
    try:
        r = run(["nargo", "execute", "-p", f"Prover{tag}", f"witness{tag}"], cwd=pkg(name), what=name)
    finally:
        os.remove(path)
    witness = os.path.join(pkg(name), "target", f"witness{tag}.gz")
    out = None
    if want_output:
        m = re.search(r"Circuit output: (.*)", r.stdout + r.stderr)
        out = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", m.group(1))] if m else []
        os.remove(witness)
        witness = None
    return witness, out


def prove(name, toml_text, out_dir, target):
    """Execute and prove; leaves proof, public_inputs, vk and vk_hash in out_dir."""
    witness, _ = execute(name, toml_text)
    try:
        run(["bb", "prove", "-b", compiled(name), "-w", witness, "-o", out_dir, "-t", target, "--write_vk"], what=f"proving {name}")
    finally:
        os.remove(witness)


def fields_of(path):
    data = open(path, "rb").read()
    return [int.from_bytes(data[i:i + 32], "big") for i in range(0, len(data), 32)]


_vk_hash = {}


def vk_hash(name, target="noir-recursive"):
    """Key hash of a circuit in this repository, derived locally."""
    if (name, target) not in _vk_hash:
        with tempfile.TemporaryDirectory() as tmp:
            run(["bb", "write_vk", "-b", compiled(name), "-o", tmp, "-t", target], what=f"key of {name}")
            _vk_hash[(name, target)] = fields_of(os.path.join(tmp, "vk_hash"))[0]
    return _vk_hash[(name, target)]


def hexlist(values):
    return "[" + ", ".join(f'"{hex(v)}"' for v in values) + "]"


def hash3(a, b, c):
    return poseidon2.hash([a, b, c])


def pair_hash(left, right):
    return hash3(DOMAIN_PAIR, left, right)


def slot_hash(values):
    """Poseidon2 over the slots of one leaf, as the leaf circuit hashes them."""
    return poseidon2.hash(values)


def fic_int(invoice):
    return int(invoice["resp"][3].decode().replace("-", ""), 16)


def cut(invoices, k):
    """Leaves of up to k, in order, as (slots, count). A short last leaf repeats its last invoice
    in the unused slots: every slot must hold a well-formed signed pair, but only the first `count`
    are part of the statement."""
    leaves = []
    for b in range(0, len(invoices), k):
        part = invoices[b:b + k]
        leaves.append((part + [part[-1]] * (k - len(part)), len(part)))
    return leaves


def tree_reduce(items, join):
    """Pair neighbours level by level; an odd one out moves up unchanged."""
    while len(items) > 1:
        items = [join(items[i], items[i + 1]) if i + 1 < len(items) else items[i] for i in range(0, len(items), 2)]
    return items[0]


def sorted_toml(sorted_fics, gamma, blind=None):
    padded = list(sorted_fics) + [0] * (SORTED_CAPACITY - len(sorted_fics))
    t = f"sorted = {hexlist(padded)}\nn = {len(sorted_fics)}\n"
    if blind is not None:
        t += f'blind = "{hex(blind)}"\n'
    return t + f'gamma = "{hex(gamma)}"\n'


def challenge(leaves, sorted_fics):
    """gamma = H(commitment to the codes in leaf order, commitment to the sorted list)."""
    chains = []
    for slots, count in leaves:
        codes = [fic_int(i) for i in slots[:count]] + [0] * (len(slots) - count)
        chains.append(hash3(DOMAIN_CODES, count, slot_hash(codes)))
    fic_chain = tree_reduce(chains, pair_hash)
    _, (_, sorted_chain) = execute(SORTED + "_open", sorted_toml(sorted_fics, 0), want_output=True)
    return hash3(DOMAIN_GAMMA, fic_chain, sorted_chain), sorted_chain


def join_run_values(left, right):
    """The joined run, computed as the node circuit does (indices as in pf_efi::agg::Run)."""
    return [
        left[0] + right[0], left[1], right[2], left[3], left[4], left[5] + right[5], left[6] + right[6],
        left[7] * right[7] % P, pair_hash(left[8], right[8]), pair_hash(left[9], right[9]),
        pair_hash(left[10], right[10]),
    ]


def run_proof_toml(prefix_plural, items):
    """Shared lines for proofs about runs that a node or the top circuit verifies."""
    return (
        f"{prefix_plural[0]} = [" + ", ".join(hexlist(fields_of(os.path.join(i["dir"], "vk"))) for i in items) + "]\n"
        + f"{prefix_plural[1]} = [" + ", ".join(hexlist(fields_of(os.path.join(i["dir"], "proof"))) for i in items) + "]\n"
    )


def make_proof(k, invoices, tmod, imod, threshold, context, year, out_dir, hooks=None, keep=None):
    """Full pipeline. `keep`: where to write the prover's spot-check record. `hooks` lets tests
    tamper with intermediate values; see test_agg.py."""
    hooks = hooks or {}
    n = len(invoices)
    if n == 0:
        raise StepFailed("no invoices")
    if n > SORTED_CAPACITY:
        raise StepFailed(f"at most {SORTED_CAPACITY} invoices with the sorted-list circuit that exists today")
    leaves = hooks["cut"](invoices, k) if "cut" in hooks else cut(invoices, k)
    leaf, leaf_open = f"agg_leaf_k{k}", f"agg_leaf_k{k}_open"
    leaf_hash = hooks.get("leaf_vk_hash", vk_hash(leaf))
    node_hash = vk_hash("agg_node")
    sorted_hash = vk_hash(SORTED)

    # A test may substitute the sorted list from the start, as a cheating prover would.
    sorted_fics = hooks["sorted"](invoices) if "sorted" in hooks else sorted(fic_int(i) for i in invoices)
    gamma, sorted_chain = challenge(leaves, sorted_fics)
    public = f'context = "{hex(context)}"\nyear = "{year}"\ngamma = "{hex(gamma)}"\n'
    hashes = f'leaf_vk_hash = "{hex(leaf_hash)}"\nnode_vk_hash = "{hex(node_hash)}"\n'
    os.makedirs(out_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as work:
        counter = [0]

        def new_dir():
            counter[0] += 1
            return os.path.join(work, f"p{counter[0]}")

        # leaves
        items = []
        for index, (slots, count) in enumerate(leaves):
            claimed = hooks.get("count", lambda _index, c: c)(index, count)
            common = batch_inputs.invoice_toml(slots, tmod, imod) + f'count = "{claimed}"\n'
            leaf_gamma = hooks.get("leaf_gamma", gamma)
            leaf_public = public.replace(f'gamma = "{hex(gamma)}"', f'gamma = "{hex(leaf_gamma)}"')
            _, values = execute(leaf_open, common + leaf_public, want_output=True)
            blind = secrets.randbits(248)
            d = new_dir()
            prove(leaf, common + f'blind = "{hex(blind)}"\n' + leaf_public + hashes, d, "noir-recursive")
            items.append({"dir": d, "is_leaf": True, "run": values[:11], "blind": blind,
                          "openings": values[11:], "tree": {"h": hex(values[10]), "leaf": index}})
        keys = fields_of(os.path.join(items[0]["dir"], "public_inputs"))
        tkh, ikh = keys[5], keys[6]
        key_lines = f'taxpayer_key_hash = "{hex(tkh)}"\nissuer_key_hash = "{hex(ikh)}"\n'
        if "runs" in hooks:
            hooks["runs"](items)

        # nodes
        def join(left, right):
            blind_out = secrets.randbits(248)
            d = new_dir()
            flags = [hooks.get("is_leaf", lambda i: i["is_leaf"])(i) for i in (left, right)]
            text = run_proof_toml(("vks", "proofs"), (left, right))
            text += "is_leaf = [" + ", ".join("true" if f else "false" for f in flags) + "]\n"
            text += "runs = [" + ", ".join(hexlist(i["run"]) for i in (left, right)) + "]\n"
            text += f'blinds = {hexlist([left["blind"], right["blind"]])}\nblind_out = "{hex(blind_out)}"\n'
            prove("agg_node", text + key_lines + public + hashes, d, "noir-recursive")
            joined = join_run_values(left["run"], right["run"])
            return {"dir": d, "is_leaf": False, "run": joined, "blind": blind_out,
                    "tree": {"h": hex(joined[10]), "left": left["tree"], "right": right["tree"]}}

        leaf_items = list(items)
        whole = tree_reduce(items, join)

        # sorted list
        sorted_blind = secrets.randbits(248)
        sorted_dir = new_dir()
        prove(SORTED, sorted_toml(sorted_fics, gamma, sorted_blind), sorted_dir, "noir-recursive")
        sorted_prod = 1
        for s in sorted_fics:
            sorted_prod = sorted_prod * (gamma - s) % P

        # top
        text = f'run_vk = {hexlist(fields_of(os.path.join(whole["dir"], "vk")))}\n'
        text += f'run_proof = {hexlist(fields_of(os.path.join(whole["dir"], "proof")))}\n'
        text += f'run_is_leaf = {"true" if whole["is_leaf"] else "false"}\n'
        text += f'run_fields = {hexlist(whole["run"])}\nrun_blind = "{hex(whole["blind"])}"\n'
        text += f'sorted_vk = {hexlist(fields_of(os.path.join(sorted_dir, "vk")))}\n'
        text += f'sorted_proof = {hexlist(fields_of(os.path.join(sorted_dir, "proof")))}\n'
        text += f'sorted_prod = "{hex(sorted_prod)}"\nsorted_chain = "{hex(sorted_chain)}"\nsorted_blind = "{hex(sorted_blind)}"\n'
        text += key_lines + f'threshold_cents = "{threshold}"\ncontext = "{hex(context)}"\nyear = "{year}"\n'
        text += hashes + f'sorted_vk_hash = "{hex(sorted_hash)}"\n'
        top_dir = new_dir()
        prove("agg_top", text, top_dir, "evm")
        for name in ("proof", "public_inputs"):
            shutil.copy(os.path.join(top_dir, name), os.path.join(out_dir, name))
    st = decode(fields_of(os.path.join(out_dir, "public_inputs")))
    with open(os.path.join(out_dir, "statement.json"), "w") as f:
        json.dump(st, f, indent=1)
    if keep:
        import opening  # here, not at the top: opening.py uses this module too
        record = {
            "invoices": [opening.opening_of(i["doc"], i["resp"][3], hex(i["salt"])) for i in invoices],
            "leaves": [{"count": count, "openings": [hex(v) for v in item["openings"]]}
                       for (_, count), item in zip(leaves, leaf_items)],
            "tree": whole["tree"],
        }
        write_private(keep, record)
    return st


def write_private(path, record):
    """The spot-check record names invoices and amounts: readable by the owner only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f, indent=1)


def decode(v):
    if len(v) != 13:
        raise StepFailed(f"unexpected number of public values ({len(v)})")
    return {
        "circuit": "agg_top", "threshold_cents": v[0], "context": hex(v[1]), "year": v[2],
        "leaf_vk_hash": hex(v[3]), "node_vk_hash": hex(v[4]), "sorted_vk_hash": hex(v[5]),
        "taxpayer_key_hash": hex(v[6]), "issuer_key_hash": hex(v[7]), "starts_at_ordinal_one": v[8] == 1,
        "invoice_count": v[9], "nullifier_root": hex(v[10]), "opening_root": hex(v[11]),
        "scope_nullifier": hex(v[12]),
    }


def verify(proof_dir):
    """Returns (ok, statement, problems, leaf size or None)."""
    st = decode(fields_of(os.path.join(proof_dir, "public_inputs")))
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        run(["bb", "write_vk", "-b", compiled("agg_top"), "-o", tmp, "-t", "evm"], what="top key")
        r = subprocess.run(["bb", "verify", "-k", os.path.join(tmp, "vk"), "-p", os.path.join(proof_dir, "proof"),
                            "-i", os.path.join(proof_dir, "public_inputs"), "-t", "evm"], capture_output=True, text=True)
    if "Proof verified successfully" not in (r.stdout + r.stderr):
        problems.append("the top proof does not verify")
    leaf_size = next((k for k in LEAF_SIZES if vk_hash(f"agg_leaf_k{k}") == int(st["leaf_vk_hash"], 16)), None)
    if leaf_size is None:
        problems.append("the proof names a leaf circuit that is not in this repository")
    if int(st["node_vk_hash"], 16) != vk_hash("agg_node"):
        problems.append("the proof names a node circuit that is not the one in this repository")
    if int(st["sorted_vk_hash"], 16) != vk_hash(SORTED):
        problems.append("the proof names a sorted-list circuit that is not the one in this repository")
    return not problems, st, problems, leaf_size


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prove")
    p.add_argument("--k", type=int, choices=LEAF_SIZES, required=True)
    p.add_argument("--n", type=int, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--synthetic", action="store_true", required=True)
    p.add_argument("--keep", help="write the prover's spot-check record to this file")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    a = ap.parse_args()
    try:
        if a.cmd == "prove":
            invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(a.n, None, 1, None)
            st = make_proof(a.k, invoices, tmod, imod, threshold, context, year, a.out, keep=a.keep)
            print(f"aggregated proof for {st['invoice_count']} invoices written to {a.out}")
            return 0
        ok, st, problems, leaf_size = verify(a.dir)
    except StepFailed as e:
        print(f"FAILED - {e}")
        return 1
    if not ok:
        print("PROOF NOT ACCEPTED: " + "; ".join(problems))
        return 1
    print("PROOF VALID")
    print(f"  what is proved      : {st['invoice_count']} consecutive invoices (leaves of up to {leaf_size}) of one business unit and device,")
    print(f"                        issued in {st['year']}, each with an authority receipt for the same request;")
    print(f"                        no receipt used twice; sum of totals >= {st['threshold_cents'] // 100}.{st['threshold_cents'] % 100:02d} EUR")
    print(f"  starts at ordinal 1 : {'yes' if st['starts_at_ordinal_one'] else 'no'}")
    print("  circuits            : leaf, node and sorted-list circuits match this repository")
    print(f"  taxpayer key hash   : {st['taxpayer_key_hash']}")
    print(f"  authority key hash  : {st['issuer_key_hash']} (compare with registry/issuer_keys.json)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
