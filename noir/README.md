# Circuits

Noir 1.0.0, proved with Barretenberg 6.0.0 (`bb prove -t evm`, hiding mode).

| Package | Kind | What it does |
|---|---|---|
| `pf_xmldsig` | library | Enveloped XML-DSig with exclusive C14N, SHA-256 and RSA-2048 PKCS#1 v1.5: rebuilds the canonical `SignedInfo` from a fixed template around the document digest, checks the signature, hashes the signer key. The first 512 bytes of `SignedInfo` never change, so their SHA-256 state is a constant and only the last three blocks are hashed in the circuit. Parsers for UUIDs, timestamps, amounts and registration codes that constrain every character. |
| `pf_efi` | library | `request.nr` reads a taxpayer-signed `RegisterInvoiceRequest`; `response.nr` rebuilds the 318-byte authority-signed `RegisterInvoiceResponse`; `batch.nr` is the statement over K invoices; `agg.nr` holds the aggregation method: runs of invoices, how two runs are joined, the sorted-list check. |
| `pf_agg` | library | The proofs above the leaves: a node verifies two proofs of adjacent runs, the top verifies the proof of the whole run and the sorted-list proof. |
| `batch_k1`, `batch_k10` | circuit | 1 and 10 invoices in one proof. |
| `agg_leaf_k1`, `agg_leaf_k10` | circuit | Aggregation leaf: checks its invoices (the 10-slot leaf may hold fewer), publishes a blinded commitment to the run. |
| `agg_node` | circuit | Joins two adjacent runs, each proved by a leaf or by another node. |
| `agg_sorted_s4096` | circuit | Up to 4,096 receipt codes sorted strictly increasing. |
| `agg_top` | circuit | Final proof of an aggregate. |
| `agg_leaf_k*_open`, `agg_sorted_s4096_open` | helper | Executed by the prover to get the private inputs of the next proof up. Never proved, never shared. |
| `open_invoice`, `poseidon2_check` | helper | Circuit forms of the opening commitment and of the hash. Executed only by `tools/efi/test_poseidon2.py`, which checks the Python implementation the tools use against them. |
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

The request varies in length. Its header is matched against a fixed template, which puts the
request identifier and the start of `<Invoice` at fixed offsets. The start tag is then scanned once,
tracking "inside a quoted value" and "tag still open". An attribute counts only where ` Name="`
starts outside a quoted value, and each wanted attribute must appear exactly once. Canonical XML
never leaves a raw `"` inside a value, so text typed into a free-text field cannot pass for an
attribute. Refused outside a value, because canonical XML never has them there and an XML parser
could read them differently from this scan: a single quote, a tab or line break, and a namespace
declaration on `<Invoice>`. The document must end with its two closing tags. Numbers and dates
have one accepted form (no leading zeros, month, day and time in range, offset +01:00 or +02:00).

## What is derived from what

The authority signs only the request UUID and the receipt code (FIC). Everything else the
statement uses comes from the request, which the taxpayer signs and could sign again differently.
Two rules follow:

- A nullifier is derived from the context and the FIC, never from anything the taxpayer writes.
- Every request field the statement relies on (ordinal, time, total, business unit, device) is in
  the invoice's opening commitment, together with IIC and FIC, so that a spot check against the
  authority's record covers all of them. `tools/efi/test_replay.py` shows both.

The scope nullifier of an aggregate is derived from the context, a second hash of the taxpayer key
that is never published, unit, device and year. With the published key hash in its place, anyone
holding an invoice (unit and device codes are printed on it) could recompute it.

## How runs are joined

Invoices are cut, in ordinal order, into leaves of up to 10. The leaf circuit always has 10 slots;
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

The top proof names the key hashes of the leaf, node and sorted-list circuits it was built from. A
verifier has to compare them with the circuits it trusts. `tools/pf.py verify` and the Starknet
registry do.

An aggregate publishes one root over the opening commitments of all its invoices instead of the
commitments themselves. In a spot check the prover reveals an invoice together with the other
commitments of its leaf and the sibling hashes up to that root (`tools/efi/opening.py`). The tools
compute Poseidon2 in Python (`tools/efi/poseidon2.py`), so checking an opening needs no Noir
toolchain.

## Tests

```sh
(cd pf_xmldsig && nargo test)                  # 27
(cd pf_efi && nargo test)                      # 31
python3 ../tools/efi/test_leaf_response.py     # 7 cases
python3 ../tools/efi/test_leaf_request.py      # 14 cases
python3 ../tools/efi/test_replay.py            # 6 checks on an invoice signed again
python3 ../tools/efi/test_batch.py --k 1       # 8 cases
python3 ../tools/efi/test_batch.py --k 10      # 12 cases
python3 ../tools/efi/test_opening.py           # 4 cases
python3 ../tools/efi/test_poseidon2.py         # 13 checks of the Python hash against circuits
python3 ../tools/efi/test_agg.py               # 13 cases through proving, 12 spot checks
python3 ../tools/efi/test_agg.py --k 10        # 8 cases (full and partly filled leaves), 22 spot checks
```

The aggregation tests always run the prover. Proofs inside a node or the top proof are checked
when that proof is made, not when its witness is generated, so a test that only executes the outer
circuit shows nothing about what is inside.

Compiling the 10-invoice circuits takes about four minutes each. They sit about 20% under 2^22
gates; past that, proving time and memory double. Most of an invoice's cost is hashing the request
(about 150,000 gates for 2,048 bytes) and the two RSA checks.
