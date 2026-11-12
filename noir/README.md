# Circuits

Noir 1.0.0, proved with Barretenberg 6.0.0 (`bb prove -t evm`, hiding mode).

| Package | Kind | What it does |
|---|---|---|
| `pf_xmldsig` | library | Enveloped XML-DSig with exclusive C14N, SHA-256 and RSA-2048 PKCS#1 v1.5: rebuilds the canonical `SignedInfo` from a fixed template around the document digest, checks the signature, hashes the signer key. Parsers for UUIDs, timestamps, amounts and registration codes that constrain every character. |
| `pf_efi` | library | `request.nr` reads a taxpayer-signed `RegisterInvoiceRequest`; `response.nr` rebuilds the 318-byte authority-signed `RegisterInvoiceResponse`; `batch.nr` is the statement over K invoices; `agg.nr` holds the aggregation method: runs of invoices, how two runs are joined, the sorted-list check. |
| `pf_agg` | library | The proofs above the leaves: a node verifies two proofs of adjacent runs, the top verifies the proof of the whole run and the sorted-list proof. |
| `batch_k1`, `batch_k10` | circuit | 1 and 10 invoices in one proof. |
| `agg_leaf_k1`, `agg_leaf_k10` | circuit | Aggregation leaf: checks its invoices, publishes a blinded commitment to the run. |
| `agg_node` | circuit | Joins two adjacent runs, each proved by a leaf or by another node. |
| `agg_sorted_s256` | circuit | Up to 256 receipt codes sorted strictly increasing. |
| `agg_top` | circuit | Final proof of an aggregate. |
| `agg_leaf_k*_open`, `agg_sorted_s256_open`, `agg_chain_k*`, `agg_hash3` | helper | Executed by the prover to get private inputs and the challenge. Never proved, never shared. |
| `open_invoice` | helper | Recomputes one invoice's opening commitment during a spot check. |
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
attribute. A single quote outside a value is refused, which keeps this scan and an XML parser
reading the same bytes in step.

## How runs are joined

Invoices are cut, in ordinal order, into leaves of 10. A leaf proof publishes only a blinded
commitment to its run (count, first and last ordinal, unit, device, partial sums). A node opens two
such commitments, checks that the right run continues the left one, and commits to the joined run.
The top proof compares the grand total with the threshold.

That no receipt is used twice across leaves is checked without any proof revealing a receipt code.
The prover proves a list of all codes sorted strictly increasing, and the top proof compares the
product of `(gamma - code)` over the leaves with the same product over the sorted list. `gamma` is
the hash of commitments to both lists, so the prover cannot pick it.

The top proof names the key hashes of the leaf, node and sorted-list circuits it was built from. A
verifier has to compare them with the circuits it trusts. `tools/efi/agg.py verify` and the Starknet
registry do.

## Tests

```sh
(cd pf_xmldsig && nargo test)                  # 13
(cd pf_efi && nargo test)                      # 14
python3 ../tools/efi/test_leaf_response.py     # 7 cases
python3 ../tools/efi/test_leaf_request.py      # 9 cases
python3 ../tools/efi/test_batch.py --k 1       # 8 cases
python3 ../tools/efi/test_batch.py --k 10      # 12 cases
python3 ../tools/efi/test_opening.py           # 4 cases
python3 ../tools/efi/test_agg.py               # 12 cases, each through proving
python3 ../tools/efi/test_agg.py --k 10        # 3 cases: 20 and 30 invoices, one attack
```

The aggregation tests always run the prover. Proofs inside a node or the top proof are checked
when that proof is made, not when its witness is generated, so a test that only executes the outer
circuit shows nothing about what is inside.

Compiling the 10-invoice circuits takes about four minutes each. They sit 1.6% under 2^22 gates;
past that, proving time and memory double.
