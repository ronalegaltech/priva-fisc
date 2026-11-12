#!/bin/sh
# Regenerate the Starknet verifier for the 10-invoice batch circuit and the proof fixture used by
# the Cairo tests. Run after ANY change to noir/pf_xmldsig, noir/pf_efi or noir/batch_k10: the
# verifier embeds the circuit's verification key, so an old verifier rejects proofs of a new circuit.
#
#   . tools/toolchain.env && sh tools/starknet/refresh_fixture.sh
#
# The fixture is a proof over invented invoices signed by throw-away keys (repo-safe).
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 "$ROOT/tools/pf.py" prove --synthetic 10 --out "$WORK/proof"
bb write_vk -b "$ROOT/noir/batch_k10/target/batch_k10.json" -o "$WORK/vk" -t evm >/dev/null 2>&1

cd "$WORK"
"$PF_GARAGA" gen --system ultra_keccak_zk_honk --vk "$WORK/vk/vk" --project-name pf_batch_k10_verifier >/dev/null 2>&1
V="$ROOT/starknet/pf_batch_k10_verifier"
rm -rf "$V/src" && cp -R "$WORK/pf_batch_k10_verifier/src" "$V/src"
cp "$WORK/pf_batch_k10_verifier/Scarb.toml" "$WORK/pf_batch_k10_verifier/.tool-versions" "$V/"

"$PF_GARAGA" calldata --system ultra_keccak_zk_honk --proof "$WORK/proof/proof" --vk "$WORK/vk/vk" \
    --public-inputs "$WORK/proof/public_inputs" --format snforge --output-path "$ROOT/starknet/pf_registry/tests" >/dev/null 2>&1
echo "verifier and fixture refreshed; now run: (cd starknet/pf_registry && snforge test)"
