# Circuits

Noir 1.0.0, proved with Barretenberg 6.0.0 (`bb prove -t evm`, hiding mode).

| Package | Kind | What it does |
|---|---|---|
| `pf_xmldsig` | library | Enveloped XML-DSig with exclusive C14N, SHA-256 and RSA-2048 PKCS#1 v1.5: rebuilds the canonical `SignedInfo` from a fixed template around the document digest, checks the signature, hashes the signer key. Parsers for UUIDs, timestamps, amounts and registration codes that constrain every character. |
| `pf_efi` | library | `request.nr` reads a taxpayer-signed `RegisterInvoiceRequest`; `response.nr` rebuilds the 318-byte authority-signed `RegisterInvoiceResponse`; `batch.nr` is the statement over K invoices; `agg.nr` is the leaf side of the aggregation. |
| `pf_agg` | library | Root of the aggregation: verifies two leaf proofs inside a circuit and checks what only shows across leaves. |
| `batch_k1`, `batch_k10` | circuit | 1 and 10 invoices in one proof. |
| `agg_leaf_k1`, `agg_leaf_k10` | circuit | Aggregation leaf. Proved with `-t noir-recursive`. |
| `agg_root_k1_b2`, `agg_root_k10_b2` | circuit | Aggregation root over two leaves. |
| `agg_leaf_k*_open`, `agg_gamma_k*_b2` | helper | Executed by the prover to get private inputs for the root. Never proved, never shared. |
| `open_invoice` | helper | Recomputes one invoice's opening commitment during a spot check. |
| `rsa_key_hash` | helper | Key hash of an RSA modulus, as the circuits publish it. |
| `leaf_request_v0`, `leaf_response_v0` | circuit | A request or a receipt on its own. Used for component tests and benchmarks. |

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
attribute.

## Tests

```sh
(cd pf_xmldsig && nargo test)                  # 13
(cd pf_efi && nargo test)                      # 8
python3 ../tools/efi/test_leaf_response.py     # 7 cases
python3 ../tools/efi/test_leaf_request.py      # 9 cases
python3 ../tools/efi/test_batch.py --k 1       # 8 cases
python3 ../tools/efi/test_batch.py --k 10      # 12 cases
python3 ../tools/efi/test_opening.py           # 4 cases
python3 ../tools/efi/test_agg.py               # 9 cases, each through proving
python3 ../tools/efi/test_agg.py --k 10        # 3 cases
```

The aggregation tests always run the prover. The proofs inside a root are checked when the root is
proved, not when its witness is generated, so a test that only executes the root shows nothing
about the leaves.

Compiling the 10-invoice circuits takes about four minutes each.
