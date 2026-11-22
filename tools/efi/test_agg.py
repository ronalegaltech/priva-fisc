#!/usr/bin/env python3
"""Accept/reject tests for the aggregation tree, all the way through PROVING.

  python3 tools/efi/test_agg.py                      # the small family: leaves of 1 invoice (fast)
  python3 tools/efi/test_agg.py --family standard    # leaves of up to 10, 5, 3 and 1, by length of request

The proofs inside a node or the top proof are only checked when that proof is made, so every case
here runs the prover. A case counts as "refused" when a circuit rejects its inputs or no valid proof
comes out. After some accepted proofs a spot check is played out: the opening of an invoice must
lead to the root the proof publishes, and an edited or misplaced opening must not.

Both families hold leaf circuits for requests of different lengths, and both are run with trees
that mix them: the small one cheaply and with the ways a prover could misuse the mix, the standard
one with the circuits real invoices would go through.
"""
import argparse
import json
import os
import secrets
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agg  # noqa: E402
import batch_inputs  # noqa: E402
import opening  # noqa: E402


def fake_sorted(invoices):
    """Strictly increasing, right length, but not the leaves' codes (hides a reused receipt)."""
    codes = sorted({agg.fic_int(i) for i in invoices})
    while len(codes) < len(invoices):
        codes.append(codes[-1] + 1)
    return codes


def bump_first_run(items):
    items[0]["run"][5] += 10**8  # sum_plus of the first leaf


def skip_four(invoices, family):
    """First leaf: only 6 of the first 10 invoices. Second leaf: invoices 11 to 20. Four left out."""
    first = invoices[:6]
    return [(0, first + [first[-1]] * 4, 6), (0, invoices[10:20], 10)]


def foreign_key_in_unused_place(keys):
    """The list of leaf circuits with a key of another circuit in a place no leaf of the tree uses."""
    return keys[:-1] + [agg.vk_hash("agg_node")]


def other_kind(item):
    """A leaf named as the family's other leaf circuit."""
    return 1 - item["kind"]


def spot_check(record, proof_dir, positions, n):
    """Yields (label, passed) for a spot check of the given invoice positions (the run starts at
    ordinal 1 and holds n invoices). The proof itself was verified by the caller."""
    def check(o, **asked):
        return opening.check_against_proof(o, proof_dir, verified=True, **asked)

    openings = [opening.reveal_from_record(record, index=i) for i in positions]
    for i, o in zip(positions, openings):
        yield f"spot check: invoice {i + 1} opens", check(o, ordinal=i + 1)
    o = dict(openings[0])
    cents = int(o["total"].replace(".", "")) + 1
    o["total"] = f"{cents // 100}.{cents % 100:02d}"
    yield "spot check: amount raised by one cent", not check(o, ordinal=o["ordinal"])
    o = dict(openings[0])
    o["device"] = o["device"][:-1] + ("0" if o["device"][-1] != "0" else "1")
    yield "spot check: another device code", not check(o, ordinal=o["ordinal"])
    yield "spot check: asked for another ordinal", not check(openings[0], ordinal=openings[0]["ordinal"] + 1)
    if len(openings) > 1:
        o = dict(openings[0])
        o["proof"] = openings[1]["proof"]
        yield "spot check: opening with another's proof", not check(o, ordinal=o["ordinal"])
    first, last = opening.reveal_from_record(record, index=0), opening.reveal_from_record(record, index=n - 1)
    yield "spot check: first invoice shown as first", check(first, edge="first")
    yield "spot check: last invoice shown as last", check(last, edge="last")
    if n > 2:
        middle = opening.reveal_from_record(record, index=n // 2)
        yield "spot check: a middle invoice as first", not check(middle, edge="first")
        yield "spot check: a middle invoice as last", not check(middle, edge="last")
    if n > 1:
        yield "spot check: last invoice as first", not check(last, edge="first")
        yield "spot check: first invoice as last", not check(first, edge="last")

    # Asking by amount: the verifier's seed fixes the points; exactly one invoice covers each.
    seed = opening.new_seed()
    covering = opening.reveal_from_record(record, seed=seed, draw=1)
    yield "spot check: the invoice covering draw 1", check(covering, seed=seed, draw=1)
    yield "spot check: same opening for draw 2", not check(covering, seed=seed, draw=2)
    yield "spot check: same opening, another seed", not check(covering, seed=opening.new_seed(), draw=1)
    if n > 1:
        root = int(agg.decode(agg.fields_of(os.path.join(proof_dir, "public_inputs")))["opening_root"], 16)
        other = covering["ordinal"] % n  # position of the next invoice (ordinals start at 1)
        wrong = opening.reveal_from_record(record, index=other, point=opening.draw_point(seed, root, 1))
        yield "spot check: another invoice for that draw", not check(wrong, seed=seed, draw=1)
        yield "spot check: ...which is still a member", check(wrong, ordinal=other + 1)
    refused = 0
    for bad in ({"seed": opening.new_seed(), "draw": 1}, {"seed": seed, "draw": opening.MAX_DRAWS + 1}):
        try:
            opening.reveal_from_record(record, **bad)
        except ValueError:
            refused += 1
    yield "prover's tool: no second seed, no eleventh draw", refused == 2


def weighted_draws(record, proof_dir, large):
    """Ten draws by amount against a run in which one invoice carries almost all of the total."""
    seed, hits = opening.new_seed(), 0
    for number in range(1, opening.MAX_DRAWS + 1):
        o = opening.reveal_from_record(record, seed=seed, draw=number)
        if not opening.check_against_proof(o, proof_dir, seed=seed, draw=number, verified=True):
            yield "draw by amount: opening accepted", False
            return
        hits += o["ordinal"] == large + 1
    yield f"draws by amount asking for the large invoice: {hits} of {opening.MAX_DRAWS}", hits >= 7


def left_deep(items, join):
    """Joins the leaves one after another instead of pairwise: the first leaves end up deepest."""
    whole = items[0]
    for item in items[1:]:
        whole = join(whole, item)
    return whole


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", default="small", choices=list(agg.FAMILIES))
    a = ap.parse_args()
    family = a.family
    failed = 0

    def case(label, n, tamper=None, hooks=None, expect=None, spot=None, large=None, lines=None, leaves=None):
        """n invoices. expect=None: must be accepted. Otherwise: must be refused, with `expect` in
        the reason. spot: invoice positions to open after an accepted proof. large: position of
        one invoice far larger than the rest; the draws by amount must mostly ask for it. lines:
        {position: number of lines} for invoices longer than one line. leaves: the numbers of
        slots the leaves of the accepted tree must have, in order."""
        nonlocal failed
        invoices, tmod, imod, threshold, context, year = batch_inputs.synthetic(n, tamper, 1, None, large=large, lines=lines)
        checks = []
        with tempfile.TemporaryDirectory() as out:
            record = os.path.join(out, "record.json") if spot or large is not None or leaves else None
            proof_dir = os.path.join(out, "proof")
            try:
                st = agg.make_proof(family, invoices, tmod, imod, threshold, context, year, proof_dir, hooks=hooks, keep=record)
                # The verifier of these tests accepts the family under test and no other.
                ok, _, problems, _ = agg.verify(proof_dir, families=(family,))
                counted = st["invoice_count"] == n
                outcome, reason = ("accepted", "") if ok and counted else ("refused", "; ".join(problems) or "wrong invoice count")
                if outcome == "accepted" and leaves:
                    with open(record) as f:
                        built = [len(leaf["openings"]) for leaf in json.load(f)["leaves"]]
                    checks.append((f"leaves of {', '.join(str(k) for k in leaves)} slots", built == leaves))
                if outcome == "accepted" and spot:
                    checks += list(spot_check(record, proof_dir, spot, n))
                if outcome == "accepted" and large is not None:
                    checks += list(weighted_draws(record, proof_dir, large))
            except agg.StepFailed as e:
                outcome, reason = "refused", str(e)
        good = (outcome == "accepted") if expect is None else (outcome == "refused" and expect in reason)
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label:38s} {outcome}" + (f" [{reason[-72:]}]" if reason else ""), flush=True)
        for what, passed in checks:
            failed += not passed
            print(f"{'PASS' if passed else 'FAIL'}  {what:38s} {'as required' if passed else 'WRONG'}", flush=True)

    if family == "small":
        case("valid, 1 leaf (no node)", 1)
        case("valid, 2 leaves", 2)
        case("valid, 3 leaves (node over node+leaf)", 3, spot=[2, 0])
        case("receipt reused across leaves", 2, tamper="reused-receipt", expect="a receipt is used twice")
        case("...hidden behind a fake sorted list", 2, tamper="reused-receipt", hooks={"sorted": fake_sorted},
             expect="sorted list does not match")
        case("gap between leaves", 2, tamper="gap", expect="ordinals are not consecutive across runs")
        case("another device in second leaf", 2, tamper="mixed-device", expect="mixed devices")
        case("total below threshold", 2, tamper="below-threshold", expect="total is below the threshold")
        case("leaf proved with another challenge", 2, hooks={"leaf_gamma": 12345}, expect="proving agg_node")
        case("run edited after proving", 2, hooks={"runs": bump_first_run}, expect="proving agg_node")
        case("leaf passed off as a node", 2, hooks={"is_leaf": lambda item: False}, expect="proving agg_node")
        # Leaf circuits for requests of different lengths in one tree. In this family the second
        # circuit reads up to 4,096 bytes; an invoice of 8 lines needs it.
        case("valid, a long request among short ones", 3, lines={1: 8}, spot=[1, 0], leaves=[1, 1, 1])
        case("valid, one long request (no node)", 1, lines={0: 8})
        case("long leaf named as the short circuit", 2, lines={1: 8}, hooks={"leaf_kind": other_kind},
             expect="proving agg_node")
        case("commitment to other leaf circuits", 2, hooks={"leaf_keys_hash": 1},
             expect="not the leaf circuits of this tree")
        case("a foreign key among the leaf circuits", 2, hooks={"leaf_keys": foreign_key_in_unused_place},
             expect="names leaf circuits that are not the ones in this repository")
        case("no such leaf circuit", 2, hooks={"leaf_kind": lambda item: agg.LEAF_KINDS},
             expect="no such leaf circuit")
        case("request longer than any leaf reads", 2, lines={1: 40}, expect="the longest the circuits read is 4096")
        case("leaf said to hold two invoices", 1, hooks={"count": lambda index, c: 2}, expect="more invoices than this circuit holds")
        case("valid, 4 leaves, one large invoice", 4, large=2)
        case("tree too deep for a spot check", 14, hooks={"reduce": left_deep}, expect="deeper than a spot check can follow")
    else:
        # Requests of every length the family reads, in one run: 2 lines and fewer fit the leaf
        # of 10; 30 lines need the leaf of 5, 70 lines the leaf of 3, 150 lines the leaf of 1.
        case("valid, 14 invoices of mixed lengths", 14, lines={3: 30, 6: 70, 8: 150}, spot=[8, 6, 3, 0],
             leaves=[5, 3, 1, 10])
        case("request longer than any leaf reads", 3, lines={1: 240}, expect="the longest the circuits read is 32768")
        case("valid, 20 invoices (2 full leaves)", 20)
        case("valid, 23 invoices (10 + 10 + 3)", 23, spot=[22, 4])
        case("valid, 7 invoices (one leaf, no node)", 7, spot=[6])
        case("unused slot counted as an invoice", 7, hooks={"count": lambda index, c: c + 1},
             expect="ordinals are not consecutive")
        case("leaf said to hold no invoice", 7, hooks={"count": lambda index, c: 0}, expect="no invoices")
        case("leaf said to hold 11 invoices", 7, hooks={"count": lambda index, c: 11},
             expect="more invoices than this circuit holds")
        case("four invoices left out between leaves", 20, hooks={"cut": skip_four},
             expect="ordinals are not consecutive across runs")
        case("receipt reused across leaves", 20, tamper="reused-receipt", hooks={"sorted": fake_sorted},
             expect="sorted list does not match")
    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
