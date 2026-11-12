#!/bin/sh
# End-to-end run on a LOCAL Starknet network (starknet-devnet): real transactions, nothing leaves
# this machine and nothing is deployed to a public network.
#
#   . tools/toolchain.env && sh tools/starknet/devnet_demo.sh
#
# Steps: start a fresh local network -> declare the ECIP helper, the generated verifier and the
# registry -> deploy the registry -> list the authority key -> submit a 10-invoice proof ->
# read back what was recorded -> submit the same proof again (must be refused).
# The invoices are invented and signed by throw-away keys.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${PF_DEVNET_PORT:-5055}"
URL="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"
ACCOUNTS="$WORK/accounts.json"
"$PF_TOOLCHAIN/devnet/starknet-devnet" --seed 7 --port "$PORT" --accounts 1 >"$WORK/devnet.log" 2>&1 &
DEVNET_PID=$!
trap 'kill $DEVNET_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT
i=0; until curl -s -m 2 "$URL/is_alive" >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 60 ] && { echo "local network did not start"; exit 1; }; sleep 0.5; done

rpc() { curl -s -m 20 "$URL" -H 'content-type: application/json' -d "$1"; }
ACC="$(rpc '{"jsonrpc":"2.0","id":1,"method":"devnet_getPredeployedAccounts","params":{}}')"
ADDR="$(printf '%s' "$ACC" | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"][0]["address"])')"
KEY="$(printf '%s' "$ACC" | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"][0]["private_key"])')"
SN="sncast --accounts-file $ACCOUNTS --account demo"
sncast --accounts-file "$ACCOUNTS" account import --name demo --address "$ADDR" --private-key "$KEY" --type oz --url "$URL" --silent >/dev/null 2>&1

cd "$ROOT/starknet/pf_registry"
declare_class() { $SN declare --url "$URL" --contract-name "$1" 2>&1 | sed -n 's/^Class Hash: *//p'; }
echo "1/6 declaring contracts on the local network ..."
ECIP="$(declare_class UniversalECIP)"; VERIFIER="$(declare_class UltraKeccakZKHonkVerifier)"; REGISTRY="$(declare_class PrivaFiscRegistry)"
[ -n "$ECIP" ] && [ -n "$VERIFIER" ] && [ -n "$REGISTRY" ] || { echo "declare failed"; exit 1; }
echo "2/6 deploying the registry ..."
CONTRACT="$($SN deploy --url "$URL" --class-hash "$REGISTRY" --constructor-calldata "$ADDR" "$VERIFIER" 2>&1 | sed -n 's/^Contract Address: *//p')"
[ -n "$CONTRACT" ] || { echo "deploy failed"; exit 1; }

echo "3/6 proving 10 invented invoices ..."
python3 "$ROOT/tools/pf.py" prove --synthetic 10 --out "$WORK/proof" >/dev/null
bb write_vk -b "$ROOT/noir/batch_k10/target/batch_k10.json" -o "$WORK/vk" -t evm >/dev/null 2>&1
( cd "$WORK" && "$PF_GARAGA" calldata --system ultra_keccak_zk_honk --proof "$WORK/proof/proof" --vk "$WORK/vk/vk" \
    --public-inputs "$WORK/proof/public_inputs" --format starkli >"$WORK/calldata.txt" 2>/dev/null )
KEYHASH="$(python3 -c 'import json,sys; v=int(json.load(open(sys.argv[1]))["issuer_key_hash"],16); print(hex(v & ((1<<128)-1)), hex(v>>128))' "$WORK/proof/statement.json")"

echo "4/6 listing the authority key and submitting the proof ..."
# shellcheck disable=SC2086
$SN invoke --url "$URL" --contract-address "$CONTRACT" --function set_issuer_key --calldata $KEYHASH 1 >/dev/null 2>&1
# shellcheck disable=SC2046
TX="$($SN invoke --url "$URL" --contract-address "$CONTRACT" --function attest_batch --calldata $(cat "$WORK/calldata.txt") 2>&1 | sed -n 's/^Transaction Hash: *//p')"
[ -n "$TX" ] || { echo "submission failed"; exit 1; }
rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"starknet_getTransactionReceipt\",\"params\":[\"$TX\"]}" | python3 -c '
import sys,json
r=json.load(sys.stdin)["result"]
print("    execution: %s, l2_gas: %s, fee at local default price: %.3f STRK" % (r["execution_status"], r["execution_resources"]["l2_gas"], int(r["actual_fee"]["amount"],16)/1e18))
sys.exit(0 if r["execution_status"]=="SUCCEEDED" else 1)'

echo "5/6 what the registry recorded:"
$SN call --url "$URL" --contract-address "$CONTRACT" --function attestation_count 2>&1 | sed -n 's/^Response: */    attestations: /p'
$SN call --url "$URL" --contract-address "$CONTRACT" --function get_attestation --calldata 1 2>&1 | sed -n 's/^Response: */    /p' | cut -c1-110

echo "6/6 submitting the same proof again ..."
REASON="$(python3 -c 'print(b"invoice already presented".hex())')"
# shellcheck disable=SC2046
if $SN invoke --url "$URL" --contract-address "$CONTRACT" --function attest_batch --calldata $(cat "$WORK/calldata.txt") 2>&1 | grep -q -e "$REASON" -e "invoice already presented"; then
    echo "    refused: invoice already presented"
else
    echo "    NOT refused as expected"; exit 1
fi
COUNT="$($SN call --url "$URL" --contract-address "$CONTRACT" --function attestation_count 2>&1 | sed -n 's/^Response: *//p')"
[ "$COUNT" = "1_u64" ] && echo "done: one attestation recorded, replay refused" || { echo "unexpected attestation count $COUNT"; exit 1; }
