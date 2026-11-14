#!/bin/sh
# Regenerate the Starknet verifiers and the proof fixtures used by the Cairo tests. Run after ANY
# change under noir/: each verifier embeds its circuit's verification key, so an old verifier
# rejects proofs of a new circuit.
#
#   . tools/toolchain.env && sh tools/starknet/refresh_fixture.sh
#
# Garaga produces three verifiers: for the 10-invoice batch circuit, for the top circuit of the
# aggregation and for the circuit about invoices issued to one buyer. The fixtures are proofs over
# invented invoices signed by throw-away keys (10 invoices for the batch, 20 in two leaves for the
# aggregate, 3 invoices to one buyer), all made for the same context (ASCII "PF-TEST") so that the
# tests can show which kinds of proof a context takes together. The batch is proved from signed
# files, and three of those files are proved once more as a proof about their buyer: with that
# pair the tests show that an invoice presented in one kind is refused in the other.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TESTS="$ROOT/starknet/pf_registry/tests"
CONTEXT=0x50462d54455354

# gen NAME CIRCUIT_JSON CONTRACT_NAME: write starknet/NAME from the circuit's verification key.
# Garaga names every verifier contract the same; give each its own so both can be declared.
gen() {
    bb write_vk -b "$2" -o "$WORK/vk_$1" -t evm >/dev/null 2>&1
    ( cd "$WORK" && "$PF_GARAGA" gen --system ultra_keccak_zk_honk --vk "$WORK/vk_$1/vk" --project-name "$1" >/dev/null 2>&1 )
    V="$ROOT/starknet/$1"
    mkdir -p "$V"
    rm -rf "$V/src" && cp -R "$WORK/$1/src" "$V/src"
    cp "$WORK/$1/Scarb.toml" "$WORK/$1/.tool-versions" "$V/"
    python3 - "$V/src/honk_verifier.cairo" "$3" <<'PY'
import sys
path, name = sys.argv[1], sys.argv[2]
text = open(path).read()
assert text.count("mod UltraKeccakZKHonkVerifier") == 1
open(path, "w").write(text.replace("mod UltraKeccakZKHonkVerifier", "mod " + name))
PY
}

# calldata NAME PROOF_DIR OUT_FILE
calldata() {
    mkdir -p "$WORK/cd_$1"
    ( cd "$WORK" && "$PF_GARAGA" calldata --system ultra_keccak_zk_honk --proof "$2/proof" --vk "$WORK/vk_$1/vk" \
        --public-inputs "$2/public_inputs" --format snforge --output-path "$WORK/cd_$1" >/dev/null 2>&1 )
    cp "$WORK/cd_$1/proof_calldata.txt" "$3"
}

python3 "$ROOT/tools/efi/synth_files.py" --n 10 --out "$WORK/files" >/dev/null
PAIRS=""
for i in 01 02 03 04 05 06 07 08 09 10; do PAIRS="$PAIRS $WORK/files/request_$i.xml $WORK/files/receipt_$i.xml"; done
YEAR="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["year"])' "$WORK/files/summary.json")"
BUYER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["buyer"])' "$WORK/files/summary.json")"
# shellcheck disable=SC2086
python3 "$ROOT/tools/pf.py" prove --out "$WORK/batch" --threshold 1.00 --year "$YEAR" --context "$CONTEXT" $PAIRS >/dev/null
gen pf_batch_k10_verifier "$ROOT/noir/batch_k10/target/batch_k10.json" PfBatchK10Verifier
calldata pf_batch_k10_verifier "$WORK/batch" "$TESTS/proof_calldata.txt"

python3 "$ROOT/tools/efi/agg.py" prove --k 10 --n 20 --synthetic --context "$CONTEXT" --out "$WORK/agg" >/dev/null
gen pf_agg_top_verifier "$ROOT/noir/agg_top/target/agg_top.json" PfAggTopVerifier
calldata pf_agg_top_verifier "$WORK/agg" "$TESTS/agg_proof_calldata.txt"

python3 "$ROOT/tools/pf.py" prove --synthetic 3 --buyer any --context "$CONTEXT" --out "$WORK/debtor" >/dev/null
gen pf_debtor_k10_verifier "$ROOT/noir/debtor_k10/target/debtor_k10.json" PfDebtorK10Verifier
calldata pf_debtor_k10_verifier "$WORK/debtor" "$TESTS/debtor_proof_calldata.txt"

# the first three invoices of the batch again, as a proof about their buyer
# shellcheck disable=SC2086
set -- $PAIRS
python3 "$ROOT/tools/pf.py" prove --buyer "$BUYER" --out "$WORK/again" --threshold 1.00 --year "$YEAR" --context "$CONTEXT" "$1" "$2" "$3" "$4" "$5" "$6" >/dev/null
calldata pf_debtor_k10_verifier "$WORK/again" "$TESTS/debtor_same_invoices_calldata.txt"

echo "verifiers and fixtures refreshed; now run: (cd starknet/pf_registry && snforge test)"
