#!/bin/sh
# End-to-end run on a LOCAL Starknet network (starknet-devnet): real transactions, nothing leaves
# this machine and nothing is deployed to a public network.
#
#   . tools/toolchain.env && sh tools/starknet/devnet_demo.sh
#
# Steps: start a fresh local network -> declare the ECIP helper, the three verifiers and the
# registry -> deploy the registry -> for a 10-invoice batch proof, a proof about 3 invoices issued
# to one buyer (made for the context of the batch) and a 25-invoice aggregate proof: list the
# authority key, submit the proof, read back what was recorded, submit it again (must be refused).
# In between, three invoices of the batch are proved once more as invoices issued to their buyer:
# a valid proof of another kind, which the registry must refuse because it has seen the invoices.
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

# u256 of a 32-byte big-endian file or of a hex string, as "low high"
u256_of_file() { python3 -c 'import sys; v=int.from_bytes(open(sys.argv[1],"rb").read(),"big"); print(hex(v & ((1<<128)-1)), hex(v>>128))' "$1"; }
u256_of_key() { python3 -c 'import json,sys; v=int(json.load(open(sys.argv[1]))["issuer_key_hash"],16); print(hex(v & ((1<<128)-1)), hex(v>>128))' "$1"; }
receipt() {
    rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"starknet_getTransactionReceipt\",\"params\":[\"$1\"]}" | python3 -c '
import sys,json
r=json.load(sys.stdin)["result"]
print("    execution: %s, l2_gas: %s, fee at local default price: %.3f STRK" % (r["execution_status"], r["execution_resources"]["l2_gas"], int(r["actual_fee"]["amount"],16)/1e18))
sys.exit(0 if r["execution_status"]=="SUCCEEDED" else 1)'
}
REASON="$(python3 -c 'print(b"invoice already presented".hex())')"

cd "$ROOT/starknet/pf_registry"
declare_class() { $SN declare --url "$URL" --contract-name "$1" 2>&1 | sed -n 's/^Class Hash: *//p'; }
echo "1/7 declaring contracts on the local network ..."
ECIP="$(declare_class UniversalECIP)"; BATCH_V="$(declare_class PfBatchK10Verifier)"
AGG_V="$(declare_class PfAggTopVerifier)"; DEBTOR_V="$(declare_class PfDebtorK10Verifier)"
REGISTRY="$(declare_class PrivaFiscRegistry)"
[ -n "$ECIP" ] && [ -n "$BATCH_V" ] && [ -n "$AGG_V" ] && [ -n "$DEBTOR_V" ] && [ -n "$REGISTRY" ] || { echo "declare failed"; exit 1; }

echo "2/7 deploying the registry (it is told which circuits aggregate proofs must come from) ..."
CIRCUITS=""
for c in agg_leaf_k10 agg_node agg_sorted_s4096; do
    bb write_vk -b "$ROOT/noir/$c/target/$c.json" -o "$WORK/vk_$c" -t noir-recursive >/dev/null 2>&1
    CIRCUITS="$CIRCUITS $(u256_of_file "$WORK/vk_$c/vk_hash")"
done
# shellcheck disable=SC2086
CONTRACT="$($SN deploy --url "$URL" --class-hash "$REGISTRY" --constructor-calldata "$ADDR" "$BATCH_V" "$AGG_V" $CIRCUITS "$DEBTOR_V" 2>&1 | sed -n 's/^Contract Address: *//p')"
[ -n "$CONTRACT" ] || { echo "deploy failed"; exit 1; }

# present KIND(function) CIRCUIT_JSON PROOF_DIR LABEL
present() {
    bb write_vk -b "$2" -o "$WORK/vk_$1" -t evm >/dev/null 2>&1
    mkdir -p "$WORK/cd_$1"
    ( cd "$WORK/cd_$1" && "$PF_GARAGA" calldata --system ultra_keccak_zk_honk --proof "$3/proof" --vk "$WORK/vk_$1/vk" \
        --public-inputs "$3/public_inputs" --format starkli >"$WORK/cd_$1/calldata.txt" 2>/dev/null )
    # shellcheck disable=SC2046
    $SN invoke --url "$URL" --contract-address "$CONTRACT" --function set_issuer_key --calldata $(u256_of_key "$3/statement.json") 1 >/dev/null 2>&1
    # shellcheck disable=SC2046
    TX="$($SN invoke --url "$URL" --contract-address "$CONTRACT" --function "$1" --calldata $(cat "$WORK/cd_$1/calldata.txt") 2>&1 | sed -n 's/^Transaction Hash: *//p')"
    [ -n "$TX" ] || { echo "    submission failed"; exit 1; }
    receipt "$TX"
    # shellcheck disable=SC2046
    if $SN invoke --url "$URL" --contract-address "$CONTRACT" --function "$1" --calldata $(cat "$WORK/cd_$1/calldata.txt") 2>&1 | grep -q -e "$REASON" -e "invoice already presented"; then
        echo "    same $4 again: refused (invoice already presented)"
    else
        echo "    same $4 again: NOT refused as expected"; exit 1
    fi
}

# refuse FUNCTION CIRCUIT_JSON PROOF_DIR LABEL: a valid proof the registry must turn down, because
# it is about invoices it has already recorded
# shellcheck disable=SC2086,SC2046
refuse() {
    bb write_vk -b "$2" -o "$WORK/vk_again" -t evm >/dev/null 2>&1
    mkdir -p "$WORK/cd_again"
    ( cd "$WORK/cd_again" && "$PF_GARAGA" calldata --system ultra_keccak_zk_honk --proof "$3/proof" --vk "$WORK/vk_again/vk" \
        --public-inputs "$3/public_inputs" --format starkli >"$WORK/cd_again/calldata.txt" 2>/dev/null )
    if $SN invoke --url "$URL" --contract-address "$CONTRACT" --function "$1" --calldata $(cat "$WORK/cd_again/calldata.txt") 2>&1 | grep -q -e "$REASON" -e "invoice already presented"; then
        echo "    $4: refused (invoice already presented)"
    else
        echo "    $4: NOT refused as expected"; exit 1
    fi
}

echo "3/7 batch of 10 invented invoices, from signed files: prove, list the authority key, submit ..."
python3 "$ROOT/tools/efi/synth_files.py" --n 10 --out "$WORK/files" >/dev/null
PAIRS=""
for i in 01 02 03 04 05 06 07 08 09 10; do PAIRS="$PAIRS $WORK/files/request_$i.xml $WORK/files/receipt_$i.xml"; done
YEAR="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["year"])' "$WORK/files/summary.json")"
BUYER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["buyer"])' "$WORK/files/summary.json")"
CTX="0x$(python3 -c 'import secrets; print(secrets.token_hex(15))')"
# shellcheck disable=SC2086
python3 "$ROOT/tools/pf.py" prove --out "$WORK/batch" --threshold 1.00 --year "$YEAR" --context "$CTX" $PAIRS >/dev/null
present attest_batch "$ROOT/noir/batch_k10/target/batch_k10.json" "$WORK/batch" batch

echo "4/7 three of those invoices again, as a proof about their buyer: prove, submit ..."
# shellcheck disable=SC2086
set -- $PAIRS
python3 "$ROOT/tools/pf.py" prove --buyer "$BUYER" --out "$WORK/again" --threshold 1.00 --year "$YEAR" --context "$CTX" "$1" "$2" "$3" "$4" "$5" "$6" >/dev/null
refuse attest_one_buyer "$ROOT/noir/debtor_k10/target/debtor_k10.json" "$WORK/again" "the same invoices as a proof about their buyer"

echo "5/7 3 other invented invoices issued to one buyer, in the context of the batch: prove, list the key, submit ..."
python3 "$ROOT/tools/pf.py" prove --synthetic 3 --buyer any --context "$CTX" --out "$WORK/debtor" >/dev/null
present attest_one_buyer "$ROOT/noir/debtor_k10/target/debtor_k10.json" "$WORK/debtor" "one-buyer proof"

echo "6/7 aggregate of 25 invented invoices: prove three leaves (10, 10 and 5), join them, list the key, submit ..."
python3 "$ROOT/tools/efi/agg.py" prove --k 10 --n 25 --synthetic --out "$WORK/agg" >/dev/null
present attest_aggregate "$ROOT/noir/agg_top/target/agg_top.json" "$WORK/agg" aggregate

echo "7/7 what the registry recorded:"
COUNT="$($SN call --url "$URL" --contract-address "$CONTRACT" --function attestation_count 2>&1 | sed -n 's/^Response: *//p')"
echo "    attestations: $COUNT"
[ "$COUNT" = "3_u64" ] && echo "done: three attestations recorded (10 invoices, 3 to one buyer, 25 aggregated), all replays refused" || { echo "unexpected attestation count"; exit 1; }
