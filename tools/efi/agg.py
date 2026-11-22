#!/usr/bin/env python3
"""Aggregated proof over any number of invoices (noir/agg_*; method in noir/pf_efi/src/agg.nr).

  agg.py prove  --n N --out DIR --synthetic [--family F] [--keep FILE] [--context HEX]    N invented invoices
  agg.py verify DIR
  agg.py circuits [--family F]      the three values a verifier pins: leaf circuits, node, sorted list

The invoices are cut, in order, into leaves. There are leaf circuits of several sizes, because an
invoice costs more the longer its request is: in the standard family a leaf holds up to 10
requests of up to 2,048 bytes, 5 of up to 8,192, 3 of up to 16,384, or 1 of up to 32,768. Each
leaf is the circuit that takes the most invoices from where the cut stands, and the last invoices
of a leaf may be missing. Leaves are proved one by one, joined pairwise by node proofs into one
proof for the whole run, and closed by a top proof that also checks the sorted list of receipt
codes. `prove` leaves in DIR only the top proof, its public values and a readable statement. With
--keep it also writes, for the prover alone, the record needed to answer spot checks later
(tools/efi/opening.py).

`verify` derives every verification key locally: the top's (to check the proof) and those of the
leaf, node and sorted-list circuits (to compare with the values the proof names: one commitment to
the key hashes of the leaf circuits, and the key hashes of the other two).
At most 4096 invoices per proof. Run `. tools/toolchain.env` first.
"""
import argparse
import hashlib
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
import formats  # noqa: E402
import poseidon2  # noqa: E402

# BN254 scalar field, the field the circuits compute in.
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
DOMAIN_PAIR = int.from_bytes(b"PF-PAIR001", "big")
DOMAIN_GAMMA = int.from_bytes(b"PF-GAMMA01", "big")
DOMAIN_CODES = int.from_bytes(b"PF-CODES01", "big")
DOMAIN_SUM_LEAF = int.from_bytes(b"PF-SUMLEAF", "big")
DOMAIN_SUM_PAIR = int.from_bytes(b"PF-SUMPAIR", "big")
DOMAIN_SUM_ROOT = int.from_bytes(b"PF-SUMROOT", "big")
DOMAIN_LEAF_KEYS = int.from_bytes(b"PF-LEAVES1", "big")
SORTED = "agg_sorted_s4096"
SORTED_CAPACITY = 4096

# The leaf circuits a tree may be built from, by family: (slots, longest request in bytes, circuit).
# The node and top circuits take LEAF_KINDS key hashes; a family with fewer circuits repeats its
# last one. "small" exists for the tests: its leaves hold one invoice and are quick to prove.
LEAF_KINDS = 4
FAMILIES = {
    "standard": ((10, 2048, "agg_leaf_k10"), (5, 8192, "agg_leaf_k5_m8192"),
                 (3, 16384, "agg_leaf_k3_m16384"), (1, 32768, "agg_leaf_k1_m32768")),
    "small": ((1, 2048, "agg_leaf_k1"), (1, 4096, "agg_leaf_k1_m4096")),
}


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
    """Key hash of a circuit in this repository, derived locally. Deriving the key of a large
    circuit takes a quarter of a minute, and an aggregate names several, so the value is kept
    beside the compiled circuit, under the digest of the compiled file it was derived from: it is
    derived again whenever that file changes."""
    if (name, target) not in _vk_hash:
        circuit = compiled(name)
        with open(circuit, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        kept = os.path.join(os.path.dirname(circuit), f"key_hash_{target}.json")
        value = None
        try:
            with open(kept) as f:
                saved = json.load(f)
            if saved.get("circuit") == digest:
                value = int(saved["key_hash"], 16)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass
        if value is None:
            with tempfile.TemporaryDirectory() as tmp:
                run(["bb", "write_vk", "-b", circuit, "-o", tmp, "-t", target], what=f"key of {name}")
                value = fields_of(os.path.join(tmp, "vk_hash"))[0]
            with open(kept, "w") as f:
                json.dump({"circuit": digest, "key_hash": hex(value)}, f)
        _vk_hash[(name, target)] = value
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


# The tree of opening commitments, which also carries the sum of positive totals under every node
# (noir/pf_efi/src/agg.nr and spot.nr).
def openings_leaf(openings, plus):
    return poseidon2.hash([DOMAIN_SUM_LEAF, poseidon2.hash(openings), poseidon2.hash(plus)])


def openings_join(left, left_sum, right, right_sum):
    return poseidon2.hash([DOMAIN_SUM_PAIR, left, left_sum, right, right_sum])


def openings_root(chain, total):
    return poseidon2.hash([DOMAIN_SUM_ROOT, chain, total])


def verify_proof(name, proof, public_inputs, target="evm"):
    """True if `proof` (bytes) is a valid proof of circuit `name` for these public inputs (bytes),
    under a verification key derived locally."""
    with tempfile.TemporaryDirectory() as tmp:
        run(["bb", "write_vk", "-b", compiled(name), "-o", tmp, "-t", target], what=f"key of {name}")
        for label, data in (("proof", proof), ("public_inputs", public_inputs)):
            with open(os.path.join(tmp, label), "wb") as f:
                f.write(data)
        return bb_verifies(os.path.join(tmp, "vk"), os.path.join(tmp, "proof"), os.path.join(tmp, "public_inputs"), target)


def bb_verifies(vk, proof, public_inputs, target="evm"):
    """True if `bb verify` accepts. Decided by its exit status, never by what it prints: its error
    messages quote file paths, and a path can be made to say anything."""
    if not all(os.path.isfile(p) for p in (vk, proof, public_inputs)):
        return False
    r = subprocess.run(["bb", "verify", "-k", vk, "-p", proof, "-i", public_inputs, "-t", target],
                       capture_output=True, text=True)
    return r.returncode == 0


def parse_context(text):
    """A context given on the command line: hexadecimal, with or without 0x."""
    try:
        value = int(text, 16)
    except (TypeError, ValueError):
        raise StepFailed(f"the context must be a hexadecimal number, got {text!r}")
    if not 0 <= value < P:
        raise StepFailed("the context is out of range")
    return value


BATCH_SIZES = (1, 10)
AGGREGATE_VALUES = 12


def kind_of(values):
    """"aggregate", or the batch size, from the number of public values of a proof."""
    if len(values) == AGGREGATE_VALUES:
        return "aggregate"
    for k in BATCH_SIZES:
        if len(values) == 6 + 2 * k:
            return k
    raise StepFailed(f"unexpected number of public values ({len(values)})")


def one_buyer_slots(values):
    """Slots of the circuit behind a proof about one buyer, or None if the values are of another kind."""
    return next((k for k in BATCH_SIZES if len(values) == 7 + 2 * k), None)


def verify_one_buyer(proof_dir, k, name=None):
    """True if the proof verifies under the key derived here from the circuit `name`
    (noir/debtor_k{k}, the Montenegrin one, unless another is named)."""
    name = name or f"debtor_k{k}"
    with tempfile.TemporaryDirectory() as tmp:
        run(["bb", "write_vk", "-b", compiled(name), "-o", tmp, "-t", "evm"], what=f"key of {name}")
        return bb_verifies(os.path.join(tmp, "vk"), os.path.join(proof_dir, "proof"),
                           os.path.join(proof_dir, "public_inputs"))


def one_buyer_format(proof_dir, k):
    """The format whose circuit the proof about one buyer in `proof_dir` verifies under, or None.
    Each format has its own circuit and key; the proof is tried under each key, derived here. The
    format a statement.json names only decides which one is tried first."""
    hint = None
    try:
        with open(os.path.join(proof_dir, "statement.json")) as f:
            hint = json.load(f).get("format")
    except (OSError, ValueError, AttributeError):
        pass
    for f in sorted(formats.ALL, key=lambda f: f.name != hint):
        if verify_one_buyer(proof_dir, k, f.one_buyer_circuit(k)):
            return f
    return None


def verify_batch(proof_dir):
    """True if the batch proof in `proof_dir` verifies under a locally derived key."""
    k = kind_of(fields_of(os.path.join(proof_dir, "public_inputs")))
    if k == "aggregate":
        return False
    name = f"batch_k{k}"
    with tempfile.TemporaryDirectory() as tmp:
        run(["bb", "write_vk", "-b", compiled(name), "-o", tmp, "-t", "evm"], what=f"key of {name}")
        return bb_verifies(os.path.join(tmp, "vk"), os.path.join(proof_dir, "proof"),
                           os.path.join(proof_dir, "public_inputs"))


def fic_int(invoice):
    return int(invoice["resp"][3].decode().replace("-", ""), 16)


def leaf_kinds(family):
    """The LEAF_KINDS leaf circuits of a family, as (slots, longest request, circuit)."""
    kinds = FAMILIES[family]
    return kinds + (kinds[-1],) * (LEAF_KINDS - len(kinds))


def leaf_keys(family):
    """Key hashes of the family's leaf circuits, derived locally, in the order the circuits take them."""
    return [vk_hash(name) for _, _, name in leaf_kinds(family)]


def leaf_keys_hash(keys):
    """What a tree publishes about its leaf circuits (pf_efi::agg::leaf_keys_commitment)."""
    return poseidon2.hash([DOMAIN_LEAF_KEYS] + list(keys))


def slot_counts(family):
    """The numbers of slots the family's leaves have, largest first."""
    return sorted({k for k, _, _ in FAMILIES[family]}, reverse=True)


def longest_request(family):
    return max(m for _, m, _ in FAMILIES[family])


def cut(invoices, family):
    """Leaves, in order, as (kind, slots, count): `kind` is the place of the leaf circuit in the
    family. From where the cut stands, the circuit is taken that holds the most of the next
    invoices (a circuit holds an invoice if its request fits), the one for shorter requests when
    two hold the same number. A leaf that is not full repeats its last invoice in the unused
    slots: every slot must hold a well-formed signed pair, but only the first `count` are part of
    the statement."""
    kinds = FAMILIES[family]
    leaves, at = [], 0
    while at < len(invoices):
        best = (0, 0)
        for kind, (k, m, _) in enumerate(kinds):
            run = 0
            while run < k and at + run < len(invoices) and len(invoices[at + run]["doc"]) <= m:
                run += 1
            if run > best[1]:
                best = (kind, run)
        kind, run = best
        if run == 0:
            raise StepFailed(f"invoice {at + 1}: its request is {len(invoices[at]['doc'])} bytes, "
                             f"the longest the circuits read is {longest_request(family)}")
        part = invoices[at:at + run]
        leaves.append((kind, part + [part[-1]] * (kinds[kind][0] - run), run))
        at += run
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
    for _, slots, count in leaves:
        codes = [fic_int(i) for i in slots[:count]] + [0] * (len(slots) - count)
        chains.append(hash3(DOMAIN_CODES, count, slot_hash(codes)))
    fic_chain = tree_reduce(chains, pair_hash)
    _, (_, sorted_chain) = execute(SORTED + "_open", sorted_toml(sorted_fics, 0), want_output=True)
    return hash3(DOMAIN_GAMMA, fic_chain, sorted_chain), sorted_chain


def join_run_values(left, right):
    """The joined run, computed as the node circuit does (indices as in pf_efi::agg::Run)."""
    return [
        left[0] + right[0], left[1], right[2], left[3], left[4], left[5] + right[5], left[6] + right[6],
        left[7] * right[7] % P, pair_hash(left[8], right[8]),
        openings_join(left[9], left[5], right[9], right[5]), left[10], max(left[11], right[11]) + 1,
    ]


def run_proof_toml(prefix_plural, items):
    """Shared lines for proofs about runs that a node or the top circuit verifies."""
    return (
        f"{prefix_plural[0]} = [" + ", ".join(hexlist(fields_of(os.path.join(i["dir"], "vk"))) for i in items) + "]\n"
        + f"{prefix_plural[1]} = [" + ", ".join(hexlist(fields_of(os.path.join(i["dir"], "proof"))) for i in items) + "]\n"
    )


def make_proof(family, invoices, tmod, imod, threshold, context, year, out_dir, hooks=None, keep=None):
    """Full pipeline, with the leaf circuits of `family`. `keep`: where to write the prover's
    spot-check record. `hooks` lets tests tamper with intermediate values; see test_agg.py."""
    hooks = hooks or {}
    n = len(invoices)
    if n == 0:
        raise StepFailed("no invoices")
    if n > SORTED_CAPACITY:
        raise StepFailed(f"at most {SORTED_CAPACITY} invoices with the sorted-list circuit that exists today")
    leaves = hooks["cut"](invoices, family) if "cut" in hooks else cut(invoices, family)
    kinds = leaf_kinds(family)
    keys = hooks["leaf_keys"](leaf_keys(family)) if "leaf_keys" in hooks else leaf_keys(family)
    keys_hash = hooks.get("leaf_keys_hash", leaf_keys_hash(keys))
    node_hash = vk_hash("agg_node")
    sorted_hash = vk_hash(SORTED)

    # A test may substitute the sorted list from the start, as a cheating prover would.
    sorted_fics = hooks["sorted"](invoices) if "sorted" in hooks else sorted(fic_int(i) for i in invoices)
    gamma, sorted_chain = challenge(leaves, sorted_fics)
    public = f'context = "{hex(context)}"\nyear = "{year}"\ngamma = "{hex(gamma)}"\n'
    hashes = f'leaf_keys_hash = "{hex(keys_hash)}"\nnode_vk_hash = "{hex(node_hash)}"\n'
    key_list = f"leaf_keys = {hexlist(keys)}\n"
    os.makedirs(out_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as work:
        counter = [0]

        def new_dir():
            counter[0] += 1
            return os.path.join(work, f"p{counter[0]}")

        # leaves
        items = []
        for index, (kind, slots, count) in enumerate(leaves):
            _, longest, leaf = kinds[kind]
            leaf_open = leaf + "_open"
            claimed = hooks.get("count", lambda _index, c: c)(index, count)
            common = batch_inputs.invoice_toml(slots, tmod, imod, longest) + f'count = "{claimed}"\n'
            leaf_gamma = hooks.get("leaf_gamma", gamma)
            leaf_public = public.replace(f'gamma = "{hex(gamma)}"', f'gamma = "{hex(leaf_gamma)}"')
            _, values = execute(leaf_open, common + leaf_public, want_output=True)
            blind = secrets.randbits(248)
            d = new_dir()
            prove(leaf, common + f'blind = "{hex(blind)}"\n' + leaf_public + hashes, d, "noir-recursive")
            items.append({"dir": d, "is_leaf": True, "kind": kind, "run": values[:12], "blind": blind,
                          "openings": values[12:], "tree": {"h": hex(values[9]), "sum": values[5], "leaf": index}})
        first_public = fields_of(os.path.join(items[0]["dir"], "public_inputs"))
        tkh, ikh = first_public[5], first_public[6]
        key_lines = f'taxpayer_key_hash = "{hex(tkh)}"\nissuer_key_hash = "{hex(ikh)}"\n'
        if "runs" in hooks:
            hooks["runs"](items)

        # nodes
        def join(left, right):
            blind_out = secrets.randbits(248)
            d = new_dir()
            flags = [hooks.get("is_leaf", lambda i: i["is_leaf"])(i) for i in (left, right)]
            which = [hooks.get("leaf_kind", lambda i: i["kind"])(i) for i in (left, right)]
            text = run_proof_toml(("vks", "proofs"), (left, right))
            text += "is_leaf = [" + ", ".join("true" if f else "false" for f in flags) + "]\n"
            text += "leaf_kinds = [" + ", ".join(f'"{w}"' for w in which) + "]\n"
            text += "runs = [" + ", ".join(hexlist(i["run"]) for i in (left, right)) + "]\n"
            text += f'blinds = {hexlist([left["blind"], right["blind"]])}\nblind_out = "{hex(blind_out)}"\n'
            prove("agg_node", text + key_lines + key_list + public + hashes, d, "noir-recursive")
            joined = join_run_values(left["run"], right["run"])
            # A node has no place in the list of leaf circuits; the circuits ignore the number.
            return {"dir": d, "is_leaf": False, "kind": 0, "run": joined, "blind": blind_out,
                    "tree": {"h": hex(joined[9]), "sum": joined[5], "left": left["tree"], "right": right["tree"]}}

        leaf_items = list(items)
        whole = hooks.get("reduce", tree_reduce)(items, join)

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
        text += f'run_is_leaf = {"true" if whole["is_leaf"] else "false"}\nrun_leaf_kind = "{whole["kind"]}"\n'
        text += f'run_fields = {hexlist(whole["run"])}\nrun_blind = "{hex(whole["blind"])}"\n'
        text += f'sorted_vk = {hexlist(fields_of(os.path.join(sorted_dir, "vk")))}\n'
        text += f'sorted_proof = {hexlist(fields_of(os.path.join(sorted_dir, "proof")))}\n'
        text += f'sorted_prod = "{hex(sorted_prod)}"\nsorted_chain = "{hex(sorted_chain)}"\nsorted_blind = "{hex(sorted_blind)}"\n'
        text += key_lines + key_list + f'threshold_cents = "{threshold}"\ncontext = "{hex(context)}"\nyear = "{year}"\n'
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
        opened = [opening.opening_of(i["doc"], i["resp"][3], hex(i["salt"])) for i in invoices]
        record = {"invoices": opened, "leaves": [], "tree": whole["tree"]}
        at = 0
        for (_, slots, count), item in zip(leaves, leaf_items):
            plus = [opening.positive_cents(o) for o in opened[at:at + count]] + [0] * (len(slots) - count)
            at += count
            if openings_leaf(item["openings"], plus) != int(item["tree"]["h"], 16):
                raise StepFailed("the spot-check record does not match what the leaf circuit computed")
            record["leaves"].append({"count": count, "openings": [hex(v) for v in item["openings"]], "plus": plus})
        write_private(keep, record)
    return st


def write_private(path, record):
    """The spot-check record names invoices and amounts: readable by the owner only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f, indent=1)


def decode(v):
    if len(v) != AGGREGATE_VALUES:
        raise StepFailed(f"unexpected number of public values ({len(v)})")
    return {
        "circuit": "agg_top", "threshold_cents": v[0], "context": hex(v[1]), "year": v[2],
        "leaf_keys_hash": hex(v[3]), "node_vk_hash": hex(v[4]), "sorted_vk_hash": hex(v[5]),
        "taxpayer_key_hash": hex(v[6]), "issuer_key_hash": hex(v[7]), "starts_at_ordinal_one": v[8] == 1,
        "invoice_count": v[9], "opening_root": hex(v[10]), "scope_nullifier": hex(v[11]),
    }


def family_of(values, families=None):
    """The family of leaf circuits an aggregated proof names, or None if it is not one of ours
    (or not one of `families`, for a caller that expects certain ones). The family with the
    smaller circuits is tried first: its keys are quick to derive."""
    named = int(decode(values)["leaf_keys_hash"], 16)
    by_size = sorted(families or FAMILIES, key=lambda f: sum(k * m for k, m, _ in FAMILIES[f]))
    return next((f for f in by_size if leaf_keys_hash(leaf_keys(f)) == named), None)


def circuits(family):
    """The three values a verifier of aggregated proofs pins (the Starknet registry is deployed
    with them): the commitment to the leaf circuits' key hashes, and the key hashes of the node
    and sorted-list circuits."""
    return leaf_keys_hash(leaf_keys(family)), vk_hash("agg_node"), vk_hash(SORTED)


def describe(family):
    """What the leaves of a family hold, in words."""
    kinds = FAMILIES[family]
    return (f"{kinds[0][0]} request{'s' if kinds[0][0] != 1 else ''} of up to {kinds[0][1]:,} bytes"
            + "".join(f", or {k} of up to {m:,}" for k, m, _ in kinds[1:]))


def verify(proof_dir, families=None):
    """Returns (ok, statement, problems, family of leaf circuits or None). `families` limits the
    families of leaf circuits the proof may come from; by default any family here will do."""
    st = decode(fields_of(os.path.join(proof_dir, "public_inputs")))
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        run(["bb", "write_vk", "-b", compiled("agg_top"), "-o", tmp, "-t", "evm"], what="top key")
        accepted = bb_verifies(os.path.join(tmp, "vk"), os.path.join(proof_dir, "proof"),
                               os.path.join(proof_dir, "public_inputs"))
    if not accepted:
        problems.append("the top proof does not verify")
    family = family_of(fields_of(os.path.join(proof_dir, "public_inputs")), families)
    if family is None:
        problems.append("the proof names leaf circuits that are not the ones in this repository")
    if int(st["node_vk_hash"], 16) != vk_hash("agg_node"):
        problems.append("the proof names a node circuit that is not the one in this repository")
    if int(st["sorted_vk_hash"], 16) != vk_hash(SORTED):
        problems.append("the proof names a sorted-list circuit that is not the one in this repository")
    return not problems, st, problems, family


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prove")
    p.add_argument("--family", choices=list(FAMILIES), default="standard", help="the leaf circuits to build from")
    p.add_argument("--n", type=int, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--synthetic", action="store_true", required=True)
    p.add_argument("--keep", help="write the prover's spot-check record to this file")
    p.add_argument("--context", help="hex value naming the verifier and purpose; random if omitted")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    c = sub.add_parser("circuits")
    c.add_argument("--family", choices=list(FAMILIES), default="standard")
    a = ap.parse_args()
    try:
        if a.cmd == "circuits":
            for value in circuits(a.family):
                print(hex(value))
            return 0
        if a.cmd == "prove":
            invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(a.n, None, 1, None)
            if a.context:
                context = parse_context(a.context)
            st = make_proof(a.family, invoices, tmod, imod, threshold, context, year, a.out, keep=a.keep)
            print(f"aggregated proof for {st['invoice_count']} invoices written to {a.out}")
            return 0
        ok, st, problems, family = verify(a.dir)
    except StepFailed as e:
        print(f"FAILED - {e}")
        return 1
    if not ok:
        print("PROOF NOT ACCEPTED: " + "; ".join(problems))
        return 1
    print("TOP PROOF AND CIRCUITS OK - authority key, context and earlier presentations are NOT checked here: use tools/pf.py verify")
    print(f"  what is proved      : {st['invoice_count']} consecutive invoices of one business unit and device,")
    print(f"                        issued in {st['year']}, each with an authority receipt for the same request;")
    print(f"                        no receipt used twice; sum of totals >= {st['threshold_cents'] // 100}.{st['threshold_cents'] % 100:02d} EUR")
    print(f"  starts at ordinal 1 : {'yes' if st['starts_at_ordinal_one'] else 'no'}")
    print(f"  circuits            : leaf, node and sorted-list circuits match this repository (leaves: {describe(family)})")
    print(f"  taxpayer key hash   : {st['taxpayer_key_hash']}")
    print(f"  authority key hash  : {st['issuer_key_hash']} (compare with registry/issuer_keys.json)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
