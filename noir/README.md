# Circuits

Noir 1.0.0, proved with Barretenberg 6.0.0 (`bb prove -t evm`, hiding mode).

| Package | Kind | What it does |
|---|---|---|
| `pf_xmldsig` | library | Enveloped XML-DSig with exclusive C14N, SHA-256 and RSA-2048 PKCS#1 v1.5: rebuilds the canonical `SignedInfo` from a fixed template around the document digest, checks the signature, hashes the signer key. The first 512 bytes of `SignedInfo` never change, so their SHA-256 state is a constant and only the last three blocks are hashed in the circuit. Parsers for UUIDs, timestamps, amounts and registration codes that constrain every character. |
| `pf_efi` | library | `request.nr` reads a taxpayer-signed `RegisterInvoiceRequest`; `buyer.nr` reads the buyer named in it; `response.nr` rebuilds the authority-signed `RegisterInvoiceResponse` (318 bytes in the Montenegrin format); `format.nr` holds what differs from one country to another (fixed text, and whether every invoice names a device); `einvoice.nr` reads an answer of the Albanian e-invoice service that lists e-invoices with their amounts and status; `batch.nr` is the statement over K invoices; `debtor.nr` is the statement over invoices issued to one buyer; `agg.nr` holds the aggregation method: runs of invoices, how two runs are joined, the sorted-list check; `spot.nr` locates one opened invoice under the root of an aggregate. |
| `pf_agg` | library | The proofs above the leaves: a node verifies two proofs of adjacent runs, the top verifies the proof of the whole run and the sorted-list proof. |
| `batch_k1`, `batch_k10` | circuit | 1 and 10 invoices in one proof. |
| `debtor_k1`, `debtor_k10` | circuit | 1 and up to 10 invoices issued to one buyer: number of invoices, buyer tag, total at least a threshold (381,165 and 3,717,548 gates; about 4 s and 33 s with `pf.py prove --buyer`). |
| `debtor_al_k1`, `debtor_al_k10` | circuit | The same statement for invoices in the Albanian format (see below). An invoice without a device code has device 0 in its opening commitment (385,176 and 3,756,153 gates). |
| `debtor_k7_m4096`, `debtor_k4_m8192`, `debtor_k2_m16384`, `debtor_k1_m32768` | circuit | The same statement for longer requests: up to 7 invoices whose requests are at most 4,096 bytes, 4 of up to 8,192, 2 of up to 16,384, 1 of up to 32,768 (3,672,650, 3,325,430, 2,896,505 and 2,694,845 gates). `pf.py` takes the circuit for the shortest requests that holds the invoices given. No aggregated form: more invoices to one buyer take several proofs. Montenegrin format only, and no Starknet verifier: these proofs are checked off chain. |
| `einvoice_al_k10` | circuit | Up to 10 open e-invoices of one seller to one buyer, read from ONE answer of Albania's e-invoice service in which the authority signs amount, parties and status of every e-invoice: number of e-invoices, buyer tag, seller tag, day of the answer, total at least a threshold (945,269 gates; about 10 s with `pf.py prove --einvoices`). Statement and limits in `pf_efi/src/einvoice.nr`. |
| `agg_leaf_k10`, `agg_leaf_k5_m8192`, `agg_leaf_k3_m16384`, `agg_leaf_k1_m32768` | circuit | Aggregation leaves, one for each length of request: up to 10 invoices whose requests are at most 2,048 bytes, 5 of up to 8,192, 3 of up to 16,384, 1 of up to 32,768. A leaf checks its invoices (it may hold fewer than it has slots) and publishes a blinded commitment to the run. 3,368,744, 3,835,607, 4,028,042 and 2,517,213 gates. |
| `agg_leaf_k1`, `agg_leaf_k1_m4096` | circuit | Two leaves of one invoice (requests of up to 2,048 and 4,096 bytes): a second, small family of leaf circuits, with which the tests build trees that mix leaf circuits without proving the large ones. 346,893 and 491,581 gates. |
| `agg_node` | circuit | Joins two adjacent runs, each proved by a leaf of the tree's family or by another node. |
| `agg_sorted_s4096` | circuit | Up to 4,096 receipt codes sorted strictly increasing. |
| `agg_top` | circuit | Final proof of an aggregate. |
| `agg_leaf_k*_open`, `agg_sorted_s4096_open` | helper | Executed by the prover to get the private inputs of the next proof up. Never proved, never shared. |
| `spot_open_k1`, `spot_open_k3`, `spot_open_k5`, `spot_open_k10` | circuit | Spot check against an aggregated proof, one circuit for each number of slots a leaf can have: an opened invoice sits under the published root; whether it is the first, the last, and whether it covers the point of the total the verifier drew. About 8,000 gates. |
| `open_invoice`, `poseidon2_check` | helper | Circuit forms of the opening commitment and of the hash. Executed only by `tools/efi/test_poseidon2.py`, which checks the Python implementation the tools use against them. |
| `buyer_check` | helper | The buyer identifier of one whole request, as `buyer.nr` reads it (45,712 gates for a 2,048-byte request). Executed only by `tools/efi/test_buyer.py`, which checks the Python reference (`tools/efi/buyer.py`) against it. |
| `rsa_key_hash` | helper | Key hash of an RSA modulus, as the circuits publish it. |
| `leaf_request_v0`, `leaf_response_v0` | circuit | A request or a receipt on its own. Used for component tests and benchmarks. |

Leaf, node and sorted-list proofs are made with `-t noir-recursive` so that another circuit can
verify them; batch and top proofs with `-t evm`.

## How the documents are read

No XML parser and no canonicalizer runs inside a circuit.

The receipt has a fixed canonical layout, so the circuit takes its four fields, checks each
character, and builds the only byte string it is willing to hash. If a proof exists, the authority
signed exactly those fields. A canonicalization mistake outside the circuit can stop a proof from
being made; it cannot make a false one.

The request varies in length. Its header is matched byte for byte against the shapes a canonical
header can take: the country's text, the time (20 characters when it ends in `Z`, 25 with an
offset), optionally the late-delivery mark with one of its five words, the request identifier.
Canonical XML writes attributes in the order of their names with one space before each, so there
are no other shapes, nothing in the header is searched for, and an attribute written twice fits
none of them. The `<Invoice>` start tag begins where the header ends. It is then scanned once,
tracking "inside a quoted value" and "tag still open". An attribute counts only where ` Name="`
starts outside a quoted value, and each wanted attribute must appear exactly once. Canonical XML
never leaves a raw `"` inside a value, so text typed into a free-text field cannot pass for an
attribute. Refused outside a value, because canonical XML never has them there and an XML parser
could read them differently from this scan: a single quote, a tab or line break, and a namespace
declaration on `<Invoice>`. The document must end with its two closing tags. Numbers have one
accepted form (no leading zeros, no zero with a minus sign). Times are read as the schema writes
them, in UTC with `Z` or with any offset up to 14 hours, month, day and time of day in range. A
time is committed to as written (its digits and how its zone is spelled); the year of an invoice
is the year of that moment on the country's clock, which a time written in UTC does not show at
the turn of the year.

## Country formats

Every circuit that reads a request or a receipt is built for one format, a compile-time constant
from `pf_efi/src/format.nr`: the canonical request up to the value of `SendDateTime`, the canonical
response with zeros where its four values go, whether every invoice names a device, and how far
the country's clock is ahead of UTC at the turn of the year. Where the request reader looks
follows from the length of that text and from how the header is written. Each format therefore gives
its own circuit and its own verification key, and a document of one format is refused by a
circuit of another (header template mismatch for a request, a signature that does not verify for
a receipt).

`MONTENEGRO` was written against the published schema and real messages of the tax
administration's test environment. `ALBANIA` was written against the published specification only
(version 09): no real signed message has been seen, and the response is spelled as in the
specification's example, with the prefix `ns2`. In the Albanian format the device code is optional,
because a non-cash invoice carries none: it may occur once or not at all, and an invoice without
one has device 0. Only the statement about one buyer has circuits for this format.

## An answer in which the authority signs content

`einvoice.nr` reads another kind of document: the authority's signed answer to "get my
e-invoices" in Albania's e-invoice service. Each e-invoice is one element whose attributes carry
its code, type, amount, the two tax numbers and its status. The answer must begin with the
format's text, which names the message; the header's start tag is scanned for the day of the
answer. The prover says where each counted `<Einvoice ` element starts: canonical XML leaves no raw
`<` in text or inside an attribute value, so those bytes can only be the start of such an element.
Its start tag is scanned once, like `<Invoice>` in a request, each wanted attribute exactly once.
One signature and one hash cover all the e-invoices of the answer, which is why ten invoices
cost a quarter of what ten signed pairs cost. The amounts are the authority's statement, so this
statement publishes no opening commitments. Its nullifier comes from the e-invoice code, not from
the receipt code of the registration, and the two cannot be compared.

## What is derived from what

The authority signs only the request UUID, the receipt code (FIC) and its own timestamp.
Everything else the statement uses comes from the request, which the taxpayer signs and could sign
again differently. Three rules follow:

- A nullifier is derived from the context and the FIC, never from anything the taxpayer writes.
- The year is checked against the authority's timestamp on the receipt as well as against the
  invoice's own date, so receipts of another year cannot be brought into a run.
- Every request field the statement relies on (ordinal, time, total, business unit, device) is in
  the invoice's opening commitment, together with IIC and FIC, so that a spot check against the
  authority's record covers all of them. `tools/efi/test_replay.py` shows both.

The scope nullifier of an aggregate is derived from the context, a second hash of the taxpayer key
that is never published, unit, device and year. With the published key hash in its place, anyone
holding an invoice (unit and device codes are printed on it) could recompute it.

## How runs are joined

Invoices are cut, in ordinal order, into leaves. What an invoice costs grows with the length of its
request (hashing it is most of the cost), so there are leaf circuits of several sizes, each about
as large as one proof can be: 10 slots for requests of up to 2,048 bytes, 5 for up to 8,192, 3 for
up to 16,384, 1 for up to 32,768. From where the cut stands, the tool takes the circuit that holds
the most of the next invoices. A leaf circuit has a fixed number of slots;
a private `count` says how many of them, from the first, are the statement. The other slots must
still hold well-formed signed pairs (the prover repeats one of its own), but nothing read from
them reaches the result, so any number of invoices fits. A leaf proof publishes only a blinded
commitment to its run (count, first and last ordinal, unit, device, partial sums). A node opens two
such commitments, checks that the right run continues the left one, and commits to the joined run.
The top proof compares the grand total with the threshold.

That no receipt is used twice across leaves is checked without any proof revealing a receipt code.
The prover proves a list of all codes sorted strictly increasing, and the top proof compares the
product of `(gamma - code)` over the leaves with the same product over the sorted list. `gamma` is
the hash of commitments to both lists, so the prover cannot pick it.

A tree may mix the leaf circuits of one family. Every proof in it carries one value for them, a
commitment to their key hashes; a node is given the list, checks it against the commitment, and
verifies a child under the key in the place the prover names, or under the node key. The top proof
publishes that commitment and the key hashes of the node and sorted-list circuits. A verifier has
to compare the three with the circuits it trusts. `tools/pf.py verify` and the Starknet registry
do.

An aggregate publishes one root over the opening commitments of all its invoices instead of the
commitments themselves. The tree under that root also carries, at every node, the sum of the
positive totals below it. In a spot check the prover reveals an invoice and proves, with the small
`spot_open` circuit, that its commitment sits under the root, without showing the path: sibling
hashes and sums and the other commitments of the leaf are not revealed. The same proof tells the
verifier whether the invoice is the first or the last of the run, and whether it covers a point
of the sum of positive totals. Points come from a seed the verifier chooses; asking by point opens
invoices with probability proportional to their amount, the way auditors sample by monetary unit
(`tools/efi/opening.py`, `spot.nr`).

Two limits of asking by amount are worth knowing before relying on it. The share is taken of the
gross sum of positive totals, which the verifier does not see and which genuine invoices that
were later credited enlarge; and an answer tells the verifier roughly where the opened invoice
sits in the running total, so answers add up to knowledge of the total. The README lists what
follows from both.

The top proof accepts a tree at most 12 joins deep, whatever shape the prover gives it, so that
every invoice of a valid aggregate can be opened by the spot-check circuit.

Outside a circuit the tools compute Poseidon2 in Python (`tools/efi/poseidon2.py`).

## Tests

`sh ../tools/test.sh` runs everything below and the command-line test in one go; `full` adds the
10-invoice circuits, the contracts and the local network run.

```sh
(cd pf_xmldsig && nargo test)                  # 39
(cd pf_efi && nargo test)                      # 117
python3 ../tools/efi/test_leaf_response.py     # 7 cases
python3 ../tools/efi/test_leaf_request.py      # 40 cases: 15 shapes the schema allows, 24 it does not or that were tampered with
python3 ../tools/efi/test_replay.py            # 6 checks on an invoice signed again
python3 ../tools/efi/test_debtor.py            # invoices to one buyer: 23 cases (--k 10: 21; --format al for Albanian files)
python3 ../tools/efi/test_debtor.py --long     # the same statement on the four circuits for longer requests: 31 cases
python3 ../tools/efi/test_batch.py --k 1       # 17 cases
python3 ../tools/efi/test_batch.py --k 10      # 16 cases
python3 ../tools/efi/test_opening.py           # 23 cases
python3 ../tools/efi/test_poseidon2.py         # 19 checks of the Python hash against circuits
python3 ../tools/efi/test_agg.py                      # the small family of leaves: 20 cases through proving, 39 checks on accepted proofs
python3 ../tools/efi/test_agg.py --family standard    # the leaves real invoices go through: 10 cases, 55 checks
```

The aggregation tests always run the prover. Proofs inside a node or the top proof are checked
when that proof is made, not when its witness is generated, so a test that only executes the outer
circuit shows nothing about what is inside.

Compiling a large circuit takes four to six minutes. The large circuits sit 4% to 20% under 2^22
gates (3,367,061 for the batch of 10, 3,756,153 for the Albanian statement about one buyer,
4,028,042 for the leaf of three requests of up to 16,384 bytes); past that, proving time and
memory double. The leaves for long requests were sized to that bound: a request of 8,192 bytes
costs about 780,000 gates and one of 16,384 about 1,360,000, against 347,000 for 2,048. Most of an invoice's cost is hashing the request
(about 150,000 gates for 2,048 bytes) and the two RSA checks.
