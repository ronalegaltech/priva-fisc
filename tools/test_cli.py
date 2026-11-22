#!/usr/bin/env python3
"""The command line on signed files, as a taxpayer and a verifier would use it.

  python3 tools/test_cli.py

Writes an invented signed request and receipt to disk, proves from the files, and checks what
`pf.py verify` prints and returns: for the right and for another context, with the taxpayer's
certificate and with someone else's, for an altered public value, and when the claim is false.
Then the same invoice as a statement about its buyer, and a spot check of that proof; files in the
Albanian format; an answer of the e-invoice service; and requests written the other ways the
schema allows (times in UTC, the late-delivery mark, the first hour of a year). One invoice at a
time, so only the 1-invoice circuits are used.
"""
import json
import os
import random
import secrets
import subprocess
import sys
import tempfile
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "efi"))
from efi_common import new_key  # noqa: E402
from leaf_request_inputs import build_request, core_fields, receipt_time, respell, shaped, signed_xml  # noqa: E402
from leaf_response_inputs import synthetic_soap  # noqa: E402

PF = os.path.join(HERE, "pf.py")


def pf(*args):
    r = subprocess.run([sys.executable, PF, *args], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def tool(*args):
    """tools/efi/opening.py, the spot-check helper."""
    r = subprocess.run([sys.executable, os.path.join(HERE, "efi", "opening.py"), *args], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    rng = random.Random(secrets.randbits(64))
    taxpayer, stranger, authority = new_key(), new_key(), new_key()
    c = core_fields(rng)
    c["ordinal"] = 1
    failed = 0

    def report(label, good, detail=""):
        nonlocal failed
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not good else ""), flush=True)

    with tempfile.TemporaryDirectory() as d:
        request, receipt, other = (os.path.join(d, n) for n in ("request.xml", "receipt.xml", "other.xml"))
        with open(request, "wb") as f:
            f.write(signed_xml(taxpayer, build_request(taxpayer, c, tricky=False)))
        with open(other, "wb") as f:
            f.write(signed_xml(stranger, build_request(stranger, c, tricky=False)))
        fields = (c["uuid"].encode(), receipt_time(c).encode(), str(uuid.uuid4()).encode(), str(uuid.uuid4()).encode())
        with open(receipt, "wb") as f:
            f.write(synthetic_soap(authority, fields))
        total = f"{c['total'] // 100}.{c['total'] % 100:02d}"
        above = f"{c['total'] // 100 + 1}.00"
        proof = os.path.join(d, "proof")
        common = ("--year", str(c["year"]), "--context", "0x33", request, receipt)

        code, out = pf("prove", "--out", proof, "--threshold", total, *common)
        report("proof from the signed files", code == 0 and os.path.exists(os.path.join(proof, "proof")), out[-200:])

        code, out = pf("verify", proof, "--context", "0x33")
        report("verify: valid, authority key not listed (exit 2)", code == 2 and "PROOF VALID" in out and "NOT IN registry" in out, out[-200:])
        code, out = pf("verify", proof, "--context", "0x34")
        report("verify: made for another context (exit 4)", code == 4 and "NOT the expected one" in out, out[-200:])
        code, out = pf("verify", proof, "--context", "0x33", "--taxpayer-cert", request)
        report("verify: the taxpayer's certificate matches", code == 2 and "key matches the certificate" in out, out[-200:])
        code, out = pf("verify", proof, "--context", "0x33", "--taxpayer-cert", other)
        report("verify: someone else's certificate (exit 3)", code == 3 and "NOT the key of the proof" in out, out[-200:])

        ledger = os.path.join(d, "ledger.json")
        code, out = pf("verify", proof, "--context", "0x33", "--ledger", ledger)
        report("verify with a ledger: first presentation", code == 2 and "presented before       : no" in out, out[-300:])
        code, out = pf("verify", proof, "--context", "0x33", "--ledger", ledger)
        report("verify with a ledger: the same proof again (exit 5)", code == 5 and "presented before       : YES" in out, out[-300:])
        code, out = pf("verify", proof, "--context", "not-hex")
        report("verify: a mistyped context prints no verdict", code != 0 and "PROOF VALID" not in out, out[-200:])

        # The same invoice as a statement about its buyer (the invented requests name TIN:12345678).
        to_buyer = os.path.join(d, "to_buyer")
        record = os.path.join(d, "record.json")
        code, out = pf("prove", "--buyer", "TIN:12345678", "--out", to_buyer, "--threshold", total, "--keep", record, *common)
        report("one buyer: proof from the signed files", code == 0 and os.path.exists(os.path.join(to_buyer, "proof")), out[-200:])
        code, out = pf("verify", to_buyer, "--context", "0x33", "--buyer", "TIN:12345678")
        report("one buyer: valid for the buyer expected (exit 2)", code == 2 and "PROOF VALID" in out and "(the one expected)" in out
               and "format of the invoices : Montenegro" in out and " EUR" in out, out[-300:])
        code, out = pf("verify", to_buyer, "--context", "0x33")
        report("one buyer: without --buyer the tag is shown, not compared", code == 2 and "not compared: no --buyer given" in out, out[-300:])
        code, out = pf("verify", to_buyer, "--context", "0x33", "--buyer", "TIN:87654321")
        report("one buyer: another buyer expected (exit 6)", code == 6 and "issued to somebody else" in out, out[-300:])
        code, out = pf("verify", to_buyer, "--context", "0x33", "--buyer", "TIN:12345678", "--ledger", ledger)
        report("one buyer: the invoice was already shown in a batch proof (exit 5)", code == 5 and "presented before       : YES" in out, out[-300:])
        code, out = pf("verify", proof, "--context", "0x33", "--buyer", "TIN:12345678")
        report("a batch proof says nothing about buyers (exit 6)", code == 6 and "says nothing about buyers" in out, out[-300:])
        code, out = pf("prove", "--buyer", "TIN:87654321", "--out", os.path.join(d, "wrong_buyer"), "--threshold", total, *common)
        report("one buyer: an invoice issued to somebody else is refused", code != 0 and "another buyer" in out
               and not os.path.exists(os.path.join(d, "wrong_buyer", "proof")), out[-200:])

        # Spot check of the proof about one buyer: the verifier asks for the invoice in place 0.
        shown = os.path.join(d, "shown.json")
        code, out = tool("reveal", "--record", record, "--index", "0", "--out", shown)
        report("one buyer: the taxpayer opens the invoice asked for", code == 0 and os.path.exists(shown), out[-200:])
        code, out = tool("check", "--opening", shown, "--proof", to_buyer, "--index", "0")
        report("one buyer: the opening matches the proof", code == 0 and out.strip() == "MATCH", out[-200:])
        code, out = tool("check", "--opening", shown, "--proof", to_buyer, "--index", "1")
        report("one buyer: asked for another place, no match", code == 1 and out.strip() == "NO MATCH", out[-200:])
        code, out = tool("check", "--opening", shown, "--proof", proof, "--first")
        report("one buyer: the opening does not fit the batch proof", code == 1 and out.strip() == "NO MATCH", out[-200:])
        true_opening = json.load(open(shown))
        for label, edit in (
            ("another buyer named", lambda o: o.update(buyer="TIN:87654321")),
            ("the buyer left out", lambda o: o.pop("buyer")),
            ("amount raised by one cent", lambda o: o.update(total=f"{(c['total'] + 1) // 100}.{(c['total'] + 1) % 100:02d}")),
        ):
            edited = dict(true_opening)
            edit(edited)
            json.dump(edited, open(shown, "w"))
            code, out = tool("check", "--opening", shown, "--proof", to_buyer, "--index", "0")
            report(f"one buyer: {label}, no match", code == 1 and out.strip() == "NO MATCH", out[-200:])
        json.dump(true_opening, open(shown, "w"))
        on_record = {k: true_opening[k] for k in ("iic", "fic", "ordinal", "issue_date_time", "total", "business_unit", "device")}
        lookup = os.path.join(d, "lookup.json")
        for label, extra, want_code, want in (
            ("the record names no buyer: said, not compared", {}, 0, "buyer not compared"),
            ("the record names the same buyer", {"buyer": "TIN:12345678"}, 0, "AGREES (seller not compared: no --taxpayer-cert given)"),
            ("the record names another buyer", {"buyer": "TIN:87654321"}, 1, "DIFFERENT: buyer"),
        ):
            json.dump(on_record | extra, open(lookup, "w"))
            code, out = tool("compare", "--opening", shown, "--authority", lookup)
            report(f"one buyer: {label}", code == want_code and want in out and (extra == {} or out.strip() == want), out[-200:])

        # Invented invoices written to disk by the generator the demos use.
        written = os.path.join(d, "written")
        r = subprocess.run([sys.executable, os.path.join(HERE, "efi", "synth_files.py"), "--n", "1", "--out", written],
                           capture_output=True, text=True)
        summary = json.load(open(os.path.join(written, "summary.json"))) if r.returncode == 0 else {}
        code, out = pf("prove", "--buyer", summary.get("buyer", "TIN:0"), "--out", os.path.join(d, "from_written"),
                       "--threshold", summary.get("total", "0"), "--year", str(summary.get("year", 0)), "--context", "0x44",
                       os.path.join(written, "request_01.xml"), os.path.join(written, "receipt_01.xml"))
        report("generated files: a proof about their buyer at exactly their total", r.returncode == 0 and code == 0, (r.stderr + out)[-200:])

        # Files in the Albanian format: a non-cash invoice, which carries no device code there.
        al = os.path.join(d, "albanian")
        r = subprocess.run([sys.executable, os.path.join(HERE, "efi", "synth_files.py"), "--n", "1", "--out", al, "--format", "al"],
                           capture_output=True, text=True)
        s_al = json.load(open(os.path.join(al, "summary.json"))) if r.returncode == 0 else {}
        al_files = (os.path.join(al, "request_01.xml"), os.path.join(al, "receipt_01.xml"))
        al_common = ("--threshold", s_al.get("total", "0"), "--year", str(s_al.get("year", 0)), "--context", "0x55")
        al_buyer = s_al.get("buyer", "NUIS:0")
        al_proof, al_record, al_shown = (os.path.join(d, n) for n in ("al_proof", "al_record.json", "al_shown.json"))
        code, out = pf("prove", "--buyer", al_buyer, "--out", al_proof, "--keep", al_record, *al_common, *al_files)
        report("Albanian files: a proof about their buyer", r.returncode == 0 and code == 0 and "Albania" in out, (r.stderr + out)[-300:])
        code, out = pf("verify", al_proof, "--context", "0x55", "--buyer", al_buyer)
        report("Albanian files: valid, and the verifier is told the format (exit 2)",
               code == 2 and "PROOF VALID" in out and "debtor_al_k1" in out and "Albania" in out and " ALL" in out, out[-400:])
        code, out = pf("verify", al_proof, "--context", "0x55", "--buyer", "NUIS:K99999999Z")
        report("Albanian files: another buyer expected (exit 6)", code == 6 and "issued to somebody else" in out, out[-300:])
        statement_path = os.path.join(al_proof, "statement.json")
        if os.path.exists(statement_path):
            statement = json.load(open(statement_path))
            json.dump(dict(statement, format="me", circuit="debtor_k1"), open(statement_path, "w"))
        code, out = pf("verify", al_proof, "--context", "0x55")
        report("Albanian files: a statement.json that names another format changes nothing",
               code == 2 and "debtor_al_k1" in out and "Albania" in out, out[-400:])
        code, out = pf("prove", "--out", os.path.join(d, "al_batch"), *al_common, *al_files)
        report("Albanian files: the statement about a consecutive run is refused, with the reason",
               code != 0 and "only the statement about one buyer" in out and not os.path.exists(os.path.join(d, "al_batch", "proof")), out[-300:])
        code, out = pf("prove", "--buyer", al_buyer, "--out", os.path.join(d, "mixed"), *al_common, al_files[0], receipt)
        report("a request and a receipt of different formats are refused",
               code != 0 and "not in the format of its request" in out and not os.path.exists(os.path.join(d, "mixed", "proof")), out[-300:])
        code, out = tool("reveal", "--record", al_record, "--index", "0", "--out", al_shown)
        opened = json.load(open(al_shown)) if code == 0 else {}
        report("Albanian files: the opened invoice carries no device code", code == 0 and opened.get("device", "") is None, out[-200:])
        code, out = tool("check", "--opening", al_shown, "--proof", al_proof, "--index", "0")
        report("Albanian files: the opening matches the proof", code == 0 and out.strip() == "MATCH", out[-200:])
        al_on_record = {k: opened.get(k) for k in ("iic", "fic", "ordinal", "issue_date_time", "total", "business_unit")}
        al_lookup = os.path.join(d, "al_lookup.json")
        json.dump(al_on_record | {"buyer": al_buyer}, open(al_lookup, "w"))
        code, out = tool("compare", "--opening", al_shown, "--authority", al_lookup)
        report("Albanian files: a record that names no device agrees", code == 0 and out.strip().startswith("AGREES"), out[-200:])
        json.dump(al_on_record | {"buyer": al_buyer, "device": "ab123cd456"}, open(al_lookup, "w"))
        code, out = tool("compare", "--opening", al_shown, "--authority", al_lookup)
        report("Albanian files: a record that names a device differs", code == 1 and out.strip() == "DIFFERENT: device", out[-200:])

        # E-invoices as the authority states them: one signed answer of the Albanian e-invoice service.
        answer = os.path.join(d, "answer.xml")
        r = subprocess.run([sys.executable, os.path.join(HERE, "efi", "einvoice.py"), "synth", "--out", answer, "--n", "2", "--others", "5"],
                           capture_output=True, text=True)
        s_ei = json.load(open(answer + ".json")) if r.returncode == 0 else {}
        ei_buyer, ei_seller, ei_total = s_ei.get("buyer", "NUIS:K00000000A"), s_ei.get("seller", "NUIS:K00000000A"), s_ei.get("total", "0")
        ei_proof, ei_ledger = os.path.join(d, "ei_proof"), os.path.join(d, "ei_ledger.json")
        code, out = pf("prove", "--einvoices", answer, "--buyer", ei_buyer, "--threshold", ei_total, "--context", "0x66", "--out", ei_proof)
        report("e-invoices: a proof from one signed answer at exactly their total", r.returncode == 0 and code == 0, (r.stderr + out)[-300:])
        code, out = pf("verify", ei_proof, "--context", "0x66", "--buyer", ei_buyer, "--seller", ei_seller, "--since", "20261101")
        report("e-invoices: valid for the buyer, the seller and the day expected (exit 2)",
               code == 2 and "PROOF VALID" in out and "einvoice_al_k10" in out and " ALL" in out and "(not older than 20261101)" in out
               and out.count("(the one expected)") == 3, out[-500:])
        code, out = pf("verify", ei_proof, "--context", "0x66", "--buyer", "NUIS:K99999999Z")
        report("e-invoices: another buyer expected (exit 6)", code == 6 and "issued to somebody else" in out, out[-300:])
        code, out = pf("verify", ei_proof, "--context", "0x66", "--seller", "NUIS:K99999999Z")
        report("e-invoices: another seller expected (exit 7)", code == 7 and "issued by somebody else" in out, out[-300:])
        code, out = pf("verify", ei_proof, "--context", "0x66", "--since", "20270101")
        report("e-invoices: an answer older than the verifier allows (exit 8)", code == 8 and "OLDER than 20270101" in out, out[-300:])
        code, out = pf("verify", ei_proof, "--context", "0x66", "--taxpayer-cert", request)
        report("e-invoices: the proof names no taxpayer key (exit 3)", code == 3 and "names no taxpayer key" in out, out[-300:])
        code, out = pf("verify", ei_proof, "--context", "0x66", "--ledger", ei_ledger)
        report("e-invoices: first presentation with a ledger", code == 2 and "presented before       : no" in out, out[-300:])
        code, out = pf("verify", ei_proof, "--context", "0x66", "--ledger", ei_ledger)
        report("e-invoices: the same e-invoices again (exit 5)", code == 5 and "presented before       : YES" in out, out[-300:])
        code, out = pf("prove", "--einvoices", answer, "--buyer", "NUIS:K99999999Z", "--threshold", "1", "--context", "0x66",
                       "--out", os.path.join(d, "ei_none"))
        report("e-invoices: no open invoice to the buyer named, no proof",
               code != 0 and "no open commercial invoice" in out and not os.path.exists(os.path.join(d, "ei_none", "proof")), out[-300:])
        code, out = pf("prove", "--einvoices", answer, "--buyer", ei_buyer, "--threshold", str(float(ei_total) + 1), "--context", "0x66",
                       "--out", os.path.join(d, "ei_above"))
        report("e-invoices: threshold above their total is refused",
               code != 0 and not os.path.exists(os.path.join(d, "ei_above", "proof")), out[-300:])
        code, out = pf("verify", to_buyer, "--context", "0x33", "--seller", "TIN:12345678")
        report("a proof from registration messages names the seller by its key (exit 7)",
               code == 7 and "names the seller by its key" in out, out[-300:])
        code, out = pf("verify", to_buyer, "--context", "0x33", "--since", "20260101")
        report("a proof from registration messages has no day of an answer (exit 8)",
               code == 8 and "not made from an answer of the authority" in out, out[-300:])

        # A directory with no proof in it, named after the words a careless check would look for.
        trap = os.path.join(d, "Proof verified successfully")
        os.makedirs(trap)
        with open(os.path.join(trap, "public_inputs"), "wb") as f:
            f.write(open(os.path.join(proof, "public_inputs"), "rb").read())
        code, out = pf("verify", trap, "--context", "0x33")
        report("verify: a directory without a proof (exit 1)", code == 1 and "PROOF INVALID" in out and "PROOF VALID" not in out, out[-200:])

        path = os.path.join(proof, "public_inputs")
        data = bytearray(open(path, "rb").read())
        data[31] ^= 1  # the threshold, by one cent
        with open(path, "wb") as f:
            f.write(data)
        code, out = pf("verify", proof, "--context", "0x33")
        report("verify: a public value altered (exit 1)", code == 1 and "PROOF INVALID" in out, out[-200:])

        refused = os.path.join(d, "refused")
        code, out = pf("prove", "--out", refused, "--threshold", above, *common)
        report("prove: threshold above the total is refused", code != 0 and not os.path.exists(os.path.join(refused, "proof")), out[-200:])
        code, out = pf("prove", "--out", refused, "--threshold", total, "--year", str(c["year"] + 1), "--context", "0x33", request, receipt)
        report("prove: another year is refused", code != 0 and not os.path.exists(os.path.join(refused, "proof")), out[-200:])
        code, out = pf("prove", "--out", refused, "--threshold", total, "--year", str(c["year"]), request, receipt)
        report("prove: real files need the verifier's context", code != 0 and not os.path.exists(os.path.join(refused, "proof")), out[-200:])
        code, out = pf("prove", "--out", refused, "--threshold", total, "--year", str(c["year"]), "--context", "0x33", other, receipt)
        report("prove: a receipt with someone else's request still proves (the receipt names no taxpayer)",
               code == 0, out[-200:])

        def pair(invoice, name):
            """The signed request and receipt of an invented invoice, as files."""
            paths = os.path.join(d, name + "_request.xml"), os.path.join(d, name + "_receipt.xml")
            with open(paths[0], "wb") as f:
                f.write(signed_xml(taxpayer, build_request(taxpayer, invoice, tricky=False)))
            answer = (invoice["uuid"].encode(), receipt_time(invoice).encode(), str(uuid.uuid4()).encode(), str(uuid.uuid4()).encode())
            with open(paths[1], "wb") as f:
                f.write(synthetic_soap(authority, answer))
            return paths

        # A request with its times in UTC, written with Z, and the late-delivery mark in its header.
        late = shaped(dict(core_fields(rng), ordinal=1), "late-utc-z")
        late_total = f"{late['total'] // 100}.{late['total'] % 100:02d}"
        late_proof, late_record, late_shown = (os.path.join(d, n) for n in ("late_proof", "late_record.json", "late_shown.json"))
        late_args = ("--threshold", late_total, "--year", str(late["year"]), "--context", "0x77", *pair(late, "late"))
        code, out = pf("prove", "--out", late_proof, "--keep", late_record, *late_args)
        report("times in UTC and a late-delivery mark: proof from the signed files", code == 0, out[-300:])
        code, out = pf("verify", late_proof, "--context", "0x77")
        report("times in UTC and a late-delivery mark: valid (exit 2)", code == 2 and "PROOF VALID" in out, out[-300:])
        code, out = tool("reveal", "--record", late_record, "--index", "0", "--out", late_shown)
        opened = json.load(open(late_shown)) if code == 0 else {}
        report("times in UTC: the opened invoice shows its time as written", opened.get("issue_date_time", "").endswith("Z"), out[-200:])
        code, out = tool("check", "--opening", late_shown, "--proof", late_proof, "--first")
        report("times in UTC: the opening matches the proof", code == 0 and out.strip() == "MATCH", out[-200:])
        json.dump(dict(opened, issue_date_time=opened.get("issue_date_time", "")[:19] + "+00:00"), open(late_shown, "w"))
        code, out = tool("check", "--opening", late_shown, "--proof", late_proof, "--first")
        report("times in UTC: the same moment spelled +00:00 is another opening", code == 1 and out.strip() == "NO MATCH", out[-200:])
        code, out = pf("prove", "--buyer", "TIN:12345678", "--out", os.path.join(d, "late_buyer"), *late_args)
        report("times in UTC and a late-delivery mark: proof about the buyer", code == 0, out[-300:])

        # Half past midnight on 1 January 2027 on the country's clock, written in UTC: the text
        # says 31 December 2026, the invoice belongs to 2027.
        first = dict(core_fields(rng), ordinal=1, year=2027, issue=respell("2027-01-01T00:30:00+01:00", "Z"))
        first_total = f"{first['total'] // 100}.{first['total'] % 100:02d}"
        first_files = pair(first, "first")
        code, out = pf("prove", "--out", os.path.join(d, "first_proof"), "--threshold", first_total, "--year", "2027",
                       "--context", "0x78", *first_files)
        report("first hour of a year, written in UTC: proved under the new year",
               code == 0 and first["issue"].startswith("2026-12-31T23:30"), out[-300:])
        code, out = pf("prove", "--out", os.path.join(d, "first_wrong"), "--threshold", first_total, "--year", "2026",
                       "--context", "0x78", *first_files)
        report("first hour of a year, written in UTC: refused under the year as written",
               code != 0 and not os.path.exists(os.path.join(d, "first_wrong", "proof")), out[-300:])

    print("all cases behave as required" if not failed else f"{failed} case(s) WRONG")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
