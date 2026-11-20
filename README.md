# PRIVA-FISC

Proofs over signed fiscal records.

In Montenegro's electronic fiscalization system (EFI, law 46/2019) every invoice leaves two signed
files with the taxpayer: the request the taxpayer signed and sent to the tax authority, and the
receipt the authority signed back. PRIVA-FISC takes a run of such pairs and produces one proof of a
statement like "these are 10 consecutive invoices of one cash register, each with a valid receipt,
and their total is at least 5,000 EUR", without showing the invoices to whoever checks the proof.

Status: research prototype. It has not been reviewed by anyone outside the team. Do not rely on it.

## What a proof says

For one taxpayer key and one authority key:

- every invoice request is signed by the taxpayer key;
- every receipt is signed by the authority key, names the request it answers, and was dated by the
  authority in the stated year;
- as the taxpayer signed them, all invoices come from one business unit and device, carry the
  stated year, and are numbered without a gap;
- no receipt is used twice;
- the sum of the totals is at least the stated threshold.

The verifier sees the two key hashes, the year, the threshold, how many invoices there are, whether
the run starts at ordinal 1, the context the proof was made for, and nullifiers and opening
commitments (one of each per invoice in a batch proof; one scope nullifier and one root in an
aggregate proof). It does not see amounts, parties or invoice codes. When a run starts at ordinal
1, the count tells which ordinals it covers.

The context is a value the verifier chooses and gives to the taxpayer. Nullifiers are bound to it,
so a proof made for one verifier is of no use to another. A nullifier comes from the invoice's
receipt code, which only the authority issues: signing the invoice again does not change it. A
proof alone cannot show that it was not presented before; a verifier that keeps the nullifiers it
has accepted (`pf.py verify --ledger`, or the Starknet registry) can refuse a repeat. The other
side of that choice: the receipt code is printed on the invoice, so someone who knows it and the
context can tell whether that invoice is in a batch proof. An aggregate proof publishes no
per-invoice nullifiers.

Verifiers who want to catch one invoice being presented to several of them, financiers of
receivables for instance, have to use one context and one ledger between them: only then is the
nullifier of an invoice the same for all, and the second presentation refused. That has a price.
Everyone who shares the context sees what the others' proofs published: the taxpayer's key hash,
the threshold, the number of invoices, and a buyer tag they can test against any tax number they
care to guess. A ledger that keeps only nullifiers, or a statement made for the verifier's own
context with nullifiers made for the shared one, would show less; neither is built.

### A second statement: invoices to one buyer

The circuits `debtor_k1` and `debtor_k10` say something else about a set of invoices: each was
issued to one named buyer, each has its receipt, no receipt is used twice, and their totals (none
negative) add up to at least a threshold. The invoices need not be consecutive or come from one
device. The verifier sees the number of invoices, a tag it can recompute from the buyer's tax
number and its context, and a nullifier and an opening commitment per invoice. A nullifier is the
same value as in a batch proof, so an invoice shown in one kind of proof is recognised in the
other.

This is what a financier of receivables asks a seller about one debtor. It is a lower bound on
what was invoiced to that buyer: it does not say these are all the invoices to that buyer, and it
says nothing about credit notes. The buyer is the taxpayer's word like the total, to be confirmed
by opening invoices; and the tag hides the buyer only from someone who cannot guess the tax
number. `pf.py prove --buyer TIN:02345678 ...` makes such a proof from 1 to 10 signed pairs and
`pf.py verify --buyer TIN:02345678` refuses one about somebody else (exit status 6). It takes about
4 s for one invoice and 33 s for ten on the laptop of the measurements below, under 4 GB.

A spot check works as for a batch, with one difference: the invoices are not consecutive, so the
verifier asks for the invoice in a given place of the proof (`opening.py check --proof DIR
--index I`). What the taxpayer opens then names the buyer too, and the buyer is checked against
the proof with the rest. The Starknet registry records this kind of proof too; its nullifiers are
those of a batch, so the two kinds share a context and its ledger.

### A second country's format: Albania

Albania's fiscalization exchanges the same two signed messages and signs them the same way
("Fiscalization Service, Technical Specification", version 09, published by the tax
administration). What differs is fixed text (the address of the schema, the version, how the
response is spelled) and one attribute: a non-cash invoice carries no device code there, while in
Montenegro every invoice has one. `noir/pf_efi/src/format.nr` holds these differences and nothing
else. A circuit is built for one format, so each country has its own circuits and verification
keys; adding the second format left the verification keys of the Montenegrin circuits unchanged.

For Albanian files the statement about one buyer is built (`debtor_al_k1`, `debtor_al_k10`).
`pf.py` reads the format from the files themselves and `verify` says which format a proof is in;
amounts are then in lek, and an invoice without a device code has device 0 in its opening. The
statement about a consecutive run is not built for this format: we have not established from the
specification which invoices the number of an invoice without a device code is consecutive with.

What this rests on: the published specification, and nothing else. No real signed Albanian
message has been seen. The response is spelled as in the specification's example, with the prefix
`ns2`; a service that spells it otherwise needs another template in `format.nr`. Nothing Albanian
is in the Starknet registry, whose verifier for this statement is the Montenegrin circuit's.

### A third statement: e-invoices as the authority states them (Albania)

In the receipts above the authority signs four values and none of them is an amount. Albania's
e-invoice service has a message in which the authority signs more. A taxpayer's software can ask
the central system for its e-invoices, and the answer, signed by the authority, lists for each of
them its code, the document type, the amount, the tax numbers of buyer and seller, and its status:
accepted, refused, paid or partially paid ("Einvoice Service, Technical Specification", version
04).

The circuit `einvoice_al_k10` reads one such answer and shows that up to ten e-invoices in it are
commercial invoices issued by one seller to one buyer, each with the status ACCEPTED and no
negative amount, and that their amounts reach a threshold. The verifier sees the authority's key
hash, the number of e-invoices, a tag of the buyer and a tag of the seller, the day the authority
put on its answer, and a nullifier per e-invoice. Because the amounts stand under the authority's
signature, there is nothing to open afterwards and no spot check; and because the answer can be
asked for again, nothing depends on files having been kept.

```sh
python3 tools/efi/einvoice.py synth --out /tmp/answer.xml      # an invented signed answer; buyer, seller and total in /tmp/answer.xml.json
python3 tools/pf.py prove --einvoices /tmp/answer.xml --buyer NUIS:<buyer> --threshold 1.00 --context 0x2e --out /tmp/open
python3 tools/pf.py verify /tmp/open --context 0x2e --buyer NUIS:<buyer> --seller NUIS:<seller> --since 20261101
```

It takes about 10 s and 2 GB on the laptop of the measurements below (945,269 gates: one
signature covers all the invoices). What it does not say:

- that a sale took place; the authority states what is registered and in which status;
- that the buyer approved an invoice: ACCEPTED is the status the central system shows, and an
  invoice may reach it without any act of the buyer; read it as "not refused and not paid";
- anything after the day of the answer; `verify --since` lets the verifier refuse an old one;
- who presents the proof: nothing in it is signed by the taxpayer, so whoever holds the answer
  can make it;
- that an invoice was not also presented in a proof made from its registration messages: the
  nullifier here comes from the e-invoice code, there from the receipt code.

Like the Albanian format as a whole this rests on the published specification only. No real
answer has been seen; the name of the root element, the list elements being written without a
prefix, and three attribute names are taken from the specification's tables and examples and
have to be confirmed on a real message. Nothing of it is in the Starknet registry.

## What a proof does not say

- That the authority saw the content of an invoice. The authority's signature covers only the
  request identifier, the receipt code and its own timestamp. Everything else the statement uses
  (ordinal, total, business unit, device) is what the taxpayer signed, and the taxpayer can sign
  the same registered invoice again with other content. A taxpayer who registers cheap invoices
  and then signs different amounts, or drops an invoice and renumbers the rest, would pass. The
  answer is a spot check: the verifier asks for a few invoices, the taxpayer opens those, and the
  verifier compares them with the authority's public invoice lookup and the seller in it with the
  taxpayer's certificate. A renumbered run fails at any opening after the gap. See
  `tools/efi/opening.py`.
- That the amounts are true. One inflated invoice can carry most of a threshold, and asking for a
  few invoices by number will usually miss it. With an aggregated proof the verifier can ask by
  amount: its seed fixes points of the sum of positive totals, and the taxpayer must open the
  invoice that covers each point, so an invoice is asked for with probability equal to its share
  of that sum. What this gives and what it does not:
  - It finds inflated invoices in proportion to their share of the GROSS sum of positive totals,
    which the verifier does not see. A taxpayer can enlarge that sum with a genuine large invoice
    and its genuine credit note; the net stays the same and most draws then land on the genuine
    invoice. So the number of draws gives no computable assurance when credit notes may exist.
  - It does not find a credit note that was signed again as a smaller one, as zero or as a small
    invoice: its amount is small or negative, so it is drawn rarely or never. Only asking by
    number can find it, with probability (invoices asked) / (invoices in the run).
  - Each answer tells the verifier roughly where the opened invoice sits in the running total.
    The prover's tool therefore answers one seed per proof and at most ten draws.
  - A request that is not answered is a failed spot check. The verifier does not draw again.
- That no invoices exist after the last one, or on another device of the same taxpayer.
- That an invoice was paid or corresponds to a real sale.

## Layout

| Path | Contents |
|---|---|
| `noir/` | Circuits. `pf_xmldsig` (XML signature checks), `pf_efi` (EFI request, receipt, batch and aggregation logic, and the country formats), `batch_k1`, `batch_k10` (1 and 10 invoices in one proof), `debtor_k1`, `debtor_k10` (invoices to one buyer; `debtor_al_*` for Albanian files), `einvoice_al_k10` (open e-invoices to one buyer, from an answer in which the Albanian authority signs amounts and status), `agg_*` and `pf_agg` (any number of invoices, in leaves of up to 10, joined into one proof), `spot_open_*` (where an opened invoice sits in an aggregated proof). See `noir/README.md`. |
| `starknet/` | Three verifier contracts generated by Garaga (10-invoice batch, aggregate, invoices to one buyer) and `pf_registry` (authority-key list and nullifier ledger). |
| `tools/` | `pf.py prove` and `pf.py verify`, the spot-check tool, a demonstration (`demo.py`), witness builders, test runners, and a script that runs the whole flow on a local Starknet network. |
| `registry/` | Authority keys a verifier may accept. |
| `docs/SDD-v0.5.md` | Design document (in Turkish). |

## Running it

You need Noir 1.0.0, Barretenberg 6.0.0, Scarb 2.21.0, Starknet Foundry 0.64.1 with
universal-sierra-compiler, Garaga built from commit `d97b4d3`, starknet-devnet 0.10.1, and Python
3.12 with `lxml` and `cryptography`. `tools/toolchain.env` puts them on the path and expects this
layout (set `PF_TOOLCHAIN` to use another directory than `~/.pf-toolchain`):

| Under `~/.pf-toolchain` | What | Needed for |
|---|---|---|
| `nargo/bin/nargo` | Noir 1.0.0, from the `noir-lang/noir` release | everything |
| `bb/bb` | Barretenberg 6.0.0 | proving and verifying |
| `scarb/bin/scarb` | Scarb 2.21.0, from the `software-mansion/scarb` release | contracts |
| `snfoundry/bin/snforge`, `sncast` | Starknet Foundry 0.64.1 | contract tests, local network run |
| `usc/bin/universal-sierra-compiler` | 2.10.3 | contract tests |
| `devnet/starknet-devnet` | 0.10.1, from the `0xSpaceShard/starknet-devnet` release | local network run |
| `garaga/`, `garaga-venv/bin/garaga` | Garaga at commit `d97b4d3269fe`, installed from source into its own Python environment | regenerating the verifiers |
| `rustup/`, `cargo/` | Rust | building Garaga and snforge's Scarb plugin |

The versions belong together: Garaga at that commit generates verifiers for proofs of
Barretenberg 6.0.0, and Noir 1.0.0 is what that Barretenberg reads.

```sh
. tools/toolchain.env

python3 tools/demo.py    # the whole story in five minutes: an honest taxpayer, then an inflated invoice

python3 tools/pf.py prove --synthetic 10 --context 0x2a --out /tmp/proof    # 10 invented invoices
python3 tools/pf.py verify /tmp/proof --context 0x2a    # valid; warns that the invented authority key is not listed

python3 tools/pf.py prove --synthetic 25 --context 0x2b --out /tmp/agg --keep /tmp/record.json    # 25 invoices, one proof
python3 tools/pf.py verify /tmp/agg --context 0x2b --ledger /tmp/ledger.json    # a second run refuses the repeat

# from signed files: ten invented invoices on disk, three of them as a statement about their buyer
python3 tools/efi/synth_files.py --n 10 --out /tmp/files
python3 tools/pf.py prove --buyer TIN:12345678 --threshold 1.00 --year 2026 --context 0x2c --out /tmp/buyer \
    /tmp/files/request_01.xml /tmp/files/receipt_01.xml /tmp/files/request_02.xml /tmp/files/receipt_02.xml \
    /tmp/files/request_03.xml /tmp/files/receipt_03.xml
python3 tools/pf.py verify /tmp/buyer --context 0x2c --buyer TIN:12345678

# the same statement from files in the Albanian format (non-cash invoices, which carry no device code there)
python3 tools/efi/synth_files.py --n 2 --format al --out /tmp/al
python3 tools/pf.py prove --buyer NUIS:K12345678A --threshold 1.00 --year 2026 --context 0x2d --out /tmp/al_buyer \
    /tmp/al/request_01.xml /tmp/al/receipt_01.xml /tmp/al/request_02.xml /tmp/al/receipt_02.xml
python3 tools/pf.py verify /tmp/al_buyer --context 0x2d --buyer NUIS:K12345678A

# spot check: the prover opens invoice 18, the verifier checks it against the proof
python3 tools/efi/opening.py reveal --record /tmp/record.json --index 17 --out /tmp/opening.json
python3 tools/efi/opening.py check --opening /tmp/opening.json --proof /tmp/agg --ordinal 18

# spot check by amount: the verifier's seed fixes the points, the prover opens the invoice at point 1
SEED=$(python3 tools/efi/opening.py draw)
python3 tools/efi/opening.py reveal --record /tmp/record.json --seed $SEED --draw 1 --out /tmp/opening.json
python3 tools/efi/opening.py check --opening /tmp/opening.json --proof /tmp/agg --seed $SEED --draw 1
# then: look the invoice up at the authority, note what it shows, and compare
python3 tools/efi/opening.py compare --opening /tmp/opening.json --authority lookup.json --taxpayer-cert certificate.der

sh tools/test.sh                              # every fast test, about 10 minutes once compiled
sh tools/test.sh full                         # adds the 10-invoice circuits, contracts, local network
```

With real files, give the request and receipt of each invoice in ordinal order:

```sh
python3 tools/pf.py prove --out DIR --threshold 5000.00 --year 2026 --keep RECORD.json req1.xml resp1.xml req2.xml resp2.xml ...
```

One or ten invoices give a batch proof, which publishes a nullifier and an opening commitment per
invoice. Any other number, up to 4,096, gives an aggregated proof, which publishes one root for
each instead. `--keep` writes the record the taxpayer needs to answer a spot check later; it names
invoices and amounts and stays with the taxpayer.

`verify` does not trust a verification key shipped with a proof. It derives the key from the
circuit in this repository and looks the authority key up in `registry/issuer_keys.json`. For an
aggregate it also derives the key hashes of the leaf, node and sorted-list circuits and compares
them with the ones the proof names. With `--context` it refuses a proof made for another context;
a verifier should always pass the context it issued. With `--ledger` it refuses a proof whose
nullifiers it has accepted before. Whether a proof is valid is decided by the verifier program's
exit status, never by text. It exits with 0 only for a valid proof under a production authority
key.

A proof names the taxpayer only by the hash of the signing key. Who that is comes from the
taxpayer's fiscalization certificate:

```sh
python3 tools/pf.py verify DIR --taxpayer-cert certificate.der    # or any signed request .xml
```

checks that the key in the certificate is the key of the proof and prints the certificate's
subject. The certificate itself (issuer, validity, revocation) is checked with ordinary X.509 tools.

## Measurements

Apple M3, 16 GB.

| | Gates | Proving | Memory | Proof |
|---|---|---|---|---|
| 1 invoice (batch) | 341,657 | 2 to 3 s | 1.0 GB | 9.9 KB |
| 10 invoices (batch) | 3,327,727 | 20 to 24 s | 4 to 6 GB | 11.1 KB |
| 3 invoices (one partly filled leaf) | 3,329,410 per leaf; top 1.47M; sorted list 255,262 | 64 s in total | 4 to 6 GB per leaf | 10.7 KB |
| 13 invoices (10 + 3) | same circuits, one node of 1.47M | 104 s in total | 4 to 6 GB per leaf | 10.7 KB |
| 25 invoices (10 + 10 + 5) | same circuits, two nodes | 148 s in total | 4 to 6 GB per leaf | 10.7 KB |
| 100 invoices (10 leaves) | same circuits, nine nodes | 426 s in total | 4 to 6 GB per leaf | 10.7 KB |
| 1,000 invoices (100 leaves) | same circuits, 99 nodes | 4,043 s in total (67 minutes) | 5.3 GB at most | 10.7 KB |
| one spot-check opening | 8,387 | about 1 s | under 0.1 GB | 17 KB file |

An aggregate costs about 40 s more for every further leaf of 10 (times vary by a tenth from run to
run). Leaves are proved one after another, so memory does not grow with the number of invoices.

On Starknet each kind of proof is accepted in one transaction: about 865M L2 gas for the batch of
10, 861M for 3 invoices to one buyer and 822M for an aggregate of 25, under the documented limit
of 1.11 * 10^9 per transaction. The figures are from the public test network (Sepolia, run of
20 Nov 2026 with invented invoices; addresses and fees in `starknet/README.md`) and agree with a
local network to within a quarter of a percent. The on-chain cost of an aggregate does not grow
with the number of invoices. Nothing has been deployed to mainnet.

## Limits

- The circuits read requests of up to 2,048 canonical bytes whose `<Invoice>` start tag fits in
  1,280 bytes, with timestamps at offset +01:00 or +02:00. Anything else cannot be proved (it does
  not produce a wrong proof).
- Invoice type and corrective references are not read yet. The seller's tax number is not read
  from the invoice on purpose: it is a field the taxpayer writes, while the signing certificate
  carries the same identity vouched for by the certificate authority.
- An aggregate holds up to 4,096 invoices (the capacity of the sorted-list circuit). At the speed
  measured above that is between four and five hours on a laptop; nothing above 1,000 invoices
  has been run.
- The tool needs both signed files of every invoice: the taxpayer's request and the authority's
  receipt. The receipt cannot be made again later. Montenegro's fiscalization law does not oblige
  the taxpayer or the invoicing software to keep these messages; the tax administration's
  functional specification (v4.2) asks the software for an electronic journal of invoices, not
  for the signed messages, while the administration's own system keeps every request it receives
  in full. We have not yet confirmed with software vendors which products keep them. Where they
  were not kept, nothing can be proved about past invoices.
- The Albanian formats (registration messages, and the answer of the e-invoice service) were
  written against the published specifications alone; no real signed message of those services
  has been seen. For registration messages only the statement about one buyer is built.
- The only real authority key in the registry is the 2020 test-environment signer. Receipts from
  a test environment can be had for invented invoices, so `verify` does not treat it as a
  production key.
- A scope nullifier (aggregate proofs) rests on unit and device codes the taxpayer wrote. It allows
  one aggregate per taxpayer key, unit, device, year and context; a spot check is what confirms
  the codes. On a chain nobody runs a spot check, so there the same receipts can be attested again
  under another code.

## Data

Everything in this repository is synthetic: invented invoices signed by throw-away keys. The one
exception is the public certificate data of the EFI test signer in `registry/`. Real invoices,
taxpayer certificates and private keys do not belong here.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
