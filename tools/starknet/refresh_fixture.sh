#!/bin/sh
# Regenerate the Starknet verifiers and the proof fixtures used by the Cairo tests. Run after ANY
# change under noir/: each verifier embeds its circuit's verification key, so an old verifier
# rejects proofs of a new circuit.
#
#   . tools/toolchain.env && sh tools/starknet/refresh_fixture.sh
#
# Garaga produces two verifiers: one for the 10-invoice batch circuit and one for the top circuit
# of the aggregation. The fixtures are proofs over invented invoices signed by throw-away keys
# (10 invoices for the batch, 20 in two leaves for the aggregate).
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TESTS="$ROOT/starknet/pf_registry/tests"

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

python3 "$ROOT/tools/pf.py" prove --synthetic 10 --out "$WORK/batch" >/dev/null
gen pf_batch_k10_verifier "$ROOT/noir/batch_k10/target/batch_k10.json" PfBatchK10Verifier
calldata pf_batch_k10_verifier "$WORK/batch" "$TESTS/proof_calldata.txt"

python3 "$ROOT/tools/efi/agg.py" prove --k 10 --n 20 --synthetic --out "$WORK/agg" >/dev/null
gen pf_agg_top_verifier "$ROOT/noir/agg_top/target/agg_top.json" PfAggTopVerifier
calldata pf_agg_top_verifier "$WORK/agg" "$TESTS/agg_proof_calldata.txt"

echo "verifiers and fixtures refreshed; now run: (cd starknet/pf_registry && snforge test)"
