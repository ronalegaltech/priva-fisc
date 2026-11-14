#!/bin/sh
# The flow of devnet_demo.sh on a PUBLIC test network (Starknet Sepolia): deploy the account if
# needed, declare the ECIP helper, the verifiers and the registry, deploy the registry, list the
# authority key, submit a 10-invoice batch proof, a proof about 3 invoices issued to one buyer and
# a 25-invoice aggregate proof, and show that presenting the same invoices again is refused, also
# when they come back in another kind of proof. The invoices are invented and signed by throw-away
# keys; nothing from a real taxpayer is used.
#
#   . tools/toolchain.env && sh tools/starknet/sepolia_demo.sh
#
# The account is an sncast account (name in PF_ACCOUNT, default pf-demo). Its key lives in sncast's
# accounts file, never in this repository. Create it once with
#   sncast account create --network sepolia --name pf-demo
# and send test STRK to the address it prints. At the gas price of 13 Nov 2026 the whole run takes
# about 470 STRK (declaring each of the three verifiers is about 115 STRK). PF_SKIP_AGGREGATE=1 and
# PF_SKIP_ONE_BUYER=1 each leave out one kind of proof and its verifier, about 135 STRK; with both
# the run takes about 200 STRK.
#
# The script can be run again after a failure: a class that is already declared is reused, so is a
# registry already deployed by an earlier run (its address is kept in PF_STATE), and a proof the
# registry already recorded is reported as such.
#
# Rehearsal on a local network: PF_RPC_URL=http://127.0.0.1:5055 PF_ACCOUNTS_FILE=... PF_STATE=...
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ACCOUNT="${PF_ACCOUNT:-pf-demo}"
STATE="${PF_STATE:-$HOME/.pf-toolchain/sepolia-demo.env}"
if [ -n "${PF_RPC_URL:-}" ]; then NET="--url $PF_RPC_URL"; EXPLORER="${PF_EXPLORER:-}"
else NET="--network sepolia"; EXPLORER="${PF_EXPLORER:-https://sepolia.voyager.online}"; fi
link() { if [ -n "$EXPLORER" ]; then echo "$EXPLORER/$1/$2"; else echo "$2"; fi; }
FILE=""; [ -n "${PF_ACCOUNTS_FILE:-}" ] && FILE="--accounts-file $PF_ACCOUNTS_FILE"
SN="sncast $FILE --account $ACCOUNT --wait"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
REASON="$(python3 -c 'print(b"invoice already presented".hex())')"
cd "$ROOT/starknet/pf_registry"

u256_of_file() { python3 -c 'import sys; v=int.from_bytes(open(sys.argv[1],"rb").read(),"big"); print(hex(v & ((1<<128)-1)), hex(v>>128))' "$1"; }
u256_of_key() { python3 -c 'import json,sys; v=int(json.load(open(sys.argv[1]))["issuer_key_hash"],16); print(hex(v & ((1<<128)-1)), hex(v>>128))' "$1"; }
field() { sed -n "s/^$1: *//p" | head -1; }
# shellcheck disable=SC2086
receipt() {
    sncast --json get tx-receipt "$1" $NET 2>/dev/null | python3 -c '
import sys,json
def find(o,k):
    if isinstance(o,dict):
        if k in o: return o[k]
        for v in o.values():
            r=find(v,k)
            if r is not None: return r
    if isinstance(o,list):
        for v in o:
            r=find(v,k)
            if r is not None: return r
o=json.loads(sys.stdin.read().strip().splitlines()[-1])
fee=find(o,"actual_fee"); amount=fee.get("amount") if isinstance(fee,dict) else fee
fee=int(str(amount),16) if str(amount).startswith("0x") else int(amount)
status=find(o,"execution_status")
print("    execution: %s, l2_gas: %s, fee: %.3f STRK" % (status, find(o,"l2_gas"), fee/1e18))
sys.exit(0 if str(status).upper().startswith("SUCC") else 1)'
}

# shellcheck disable=SC2086
ADDR="$(sncast $FILE account list 2>/dev/null | awk -v n="$ACCOUNT" '$0 ~ "^- "n":" {f=1} f && /address:/ {print $2; exit}')"
[ -n "$ADDR" ] || { echo "no sncast account named $ACCOUNT"; exit 1; }
# shellcheck disable=SC2086
BAL="$(sncast $FILE --account "$ACCOUNT" get balance $NET 2>&1 | sed -n 's/^Balance: *\([0-9]*\) fri.*/\1/p')"
echo "account $ADDR, balance $(python3 -c "print('%.2f' % (int('${BAL:-0}')/1e18))") STRK"
[ "${BAL:-0}" != "0" ] || { echo "the account has no test STRK; send some to the address above and run again"; exit 1; }

echo "1/8 account ..."
# shellcheck disable=SC2086
if sncast get class-hash-at "$ADDR" $NET >/dev/null 2>&1; then echo "    already deployed"
else sncast $FILE --wait account deploy --name "$ACCOUNT" $NET >"$WORK/acc.log" 2>&1 || { cat "$WORK/acc.log"; exit 1; }; echo "    deployed"; fi

echo "2/8 declaring contracts ..."
# shellcheck disable=SC2086
declare_class() {
    HASH="$(sncast utils class-hash --contract-name "$1" 2>/dev/null | field 'Class Hash')"
    OUT="$($SN declare $NET --contract-name "$1" 2>&1 || true)"
    if printf '%s' "$OUT" | grep -q "Transaction Hash"; then echo "    $1 declared" >&2
    elif printf '%s' "$OUT" | grep -q -i "already declared"; then echo "    $1 was already declared" >&2
    else printf '%s\n' "$OUT" >&2; echo "declaring $1 failed" >&2; exit 1; fi
    printf '%s' "$HASH"
}
ECIP="$(declare_class UniversalECIP)"; BATCH_V="$(declare_class PfBatchK10Verifier)"
if [ -z "${PF_SKIP_AGGREGATE:-}" ]; then AGG_V="$(declare_class PfAggTopVerifier)"; else AGG_V="0x0"; fi
if [ -z "${PF_SKIP_ONE_BUYER:-}" ]; then DEBTOR_V="$(declare_class PfDebtorK10Verifier)"; else DEBTOR_V="0x0"; fi
REGISTRY="$(declare_class PrivaFiscRegistry)"
[ -n "$ECIP" ] && [ -n "$BATCH_V" ] && [ -n "$AGG_V" ] && [ -n "$DEBTOR_V" ] && [ -n "$REGISTRY" ] || exit 1

echo "3/8 registry ..."
CONTRACT=""; [ -f "$STATE" ] && CONTRACT="$(sed -n "s/^$REGISTRY=//p" "$STATE" | head -1)"
if [ -n "$CONTRACT" ]; then echo "    reusing $CONTRACT"
else
    CIRCUITS=""
    for c in agg_leaf_k10 agg_node agg_sorted_s4096; do
        bb write_vk -b "$ROOT/noir/$c/target/$c.json" -o "$WORK/vk_$c" -t noir-recursive >/dev/null 2>&1
        CIRCUITS="$CIRCUITS $(u256_of_file "$WORK/vk_$c/vk_hash")"
    done
    # shellcheck disable=SC2086
    CONTRACT="$($SN deploy $NET --class-hash "$REGISTRY" --constructor-calldata "$ADDR" "$BATCH_V" "$AGG_V" $CIRCUITS "$DEBTOR_V" 2>&1 | field 'Contract Address')"
    [ -n "$CONTRACT" ] || { echo "deploy failed"; exit 1; }
    mkdir -p "$(dirname "$STATE")"; echo "$REGISTRY=$CONTRACT" >>"$STATE"
    echo "    deployed at $CONTRACT"
fi

# present FUNCTION CIRCUIT_JSON PROOF_DIR LABEL
# shellcheck disable=SC2086,SC2046
present() {
    bb write_vk -b "$2" -o "$WORK/vk_$1" -t evm >/dev/null 2>&1
    mkdir -p "$WORK/cd_$1"
    ( cd "$WORK/cd_$1" && "$PF_GARAGA" calldata --system ultra_keccak_zk_honk --proof "$3/proof" --vk "$WORK/vk_$1/vk" \
        --public-inputs "$3/public_inputs" --format starkli >"$WORK/cd_$1/calldata.txt" 2>/dev/null )
    $SN invoke $NET --contract-address "$CONTRACT" --function set_issuer_key --calldata $(u256_of_key "$3/statement.json") 1 >/dev/null 2>&1
    OUT="$($SN invoke $NET --contract-address "$CONTRACT" --function "$1" --calldata $(cat "$WORK/cd_$1/calldata.txt") 2>&1 || true)"
    TX="$(printf '%s\n' "$OUT" | field 'Transaction Hash')"
    if [ -n "$TX" ]; then echo "    $4 accepted: $(link tx "$TX")"; receipt "$TX"
    elif printf '%s' "$OUT" | grep -q -e "$REASON" -e "invoice already presented"; then echo "    $4 was already recorded by an earlier run"; return 0
    else printf '%s\n' "$OUT"; echo "    submission failed"; exit 1; fi
    if $SN invoke $NET --contract-address "$CONTRACT" --function "$1" --calldata $(cat "$WORK/cd_$1/calldata.txt") 2>&1 | grep -q -e "$REASON" -e "invoice already presented"; then
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
    if $SN invoke $NET --contract-address "$CONTRACT" --function "$1" --calldata $(cat "$WORK/cd_again/calldata.txt") 2>&1 | grep -q -e "$REASON" -e "invoice already presented"; then
        echo "    $4: refused (invoice already presented)"
    else
        echo "    $4: NOT refused as expected"; exit 1
    fi
}

echo "4/8 batch of 10 invented invoices, from signed files: prove, list the authority key, submit ..."
python3 "$ROOT/tools/efi/synth_files.py" --n 10 --out "$WORK/files" >/dev/null
PAIRS=""
for i in 01 02 03 04 05 06 07 08 09 10; do PAIRS="$PAIRS $WORK/files/request_$i.xml $WORK/files/receipt_$i.xml"; done
YEAR="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["year"])' "$WORK/files/summary.json")"
BUYER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["buyer"])' "$WORK/files/summary.json")"
CTX="0x$(python3 -c 'import secrets; print(secrets.token_hex(15))')"
# shellcheck disable=SC2086
python3 "$ROOT/tools/pf.py" prove --out "$WORK/batch" --threshold 1.00 --year "$YEAR" --context "$CTX" $PAIRS >/dev/null
present attest_batch "$ROOT/noir/batch_k10/target/batch_k10.json" "$WORK/batch" batch

if [ -z "${PF_SKIP_ONE_BUYER:-}" ]; then
    echo "5/8 three of those invoices again, as a proof about their buyer: prove, submit ..."
    # shellcheck disable=SC2086
    set -- $PAIRS
    python3 "$ROOT/tools/pf.py" prove --buyer "$BUYER" --out "$WORK/again" --threshold 1.00 --year "$YEAR" --context "$CTX" "$1" "$2" "$3" "$4" "$5" "$6" >/dev/null
    refuse attest_one_buyer "$ROOT/noir/debtor_k10/target/debtor_k10.json" "$WORK/again" "the same invoices as a proof about their buyer"

    echo "6/8 3 other invented invoices issued to one buyer, in the context of the batch: prove, list the key, submit ..."
    python3 "$ROOT/tools/pf.py" prove --synthetic 3 --buyer any --context "$CTX" --out "$WORK/debtor" >/dev/null
    present attest_one_buyer "$ROOT/noir/debtor_k10/target/debtor_k10.json" "$WORK/debtor" "one-buyer proof"
else
    echo "5/8 and 6/8 proofs about one buyer left out (PF_SKIP_ONE_BUYER)"
fi

if [ -z "${PF_SKIP_AGGREGATE:-}" ]; then
    echo "7/8 aggregate of 25 invented invoices: prove, list the key, submit ..."
    python3 "$ROOT/tools/efi/agg.py" prove --k 10 --n 25 --synthetic --out "$WORK/agg" >/dev/null
    present attest_aggregate "$ROOT/noir/agg_top/target/agg_top.json" "$WORK/agg" aggregate
else
    echo "7/8 aggregate left out (PF_SKIP_AGGREGATE)"
fi

echo "8/8 what the registry recorded:"
# shellcheck disable=SC2086
COUNT="$($SN call $NET --contract-address "$CONTRACT" --function attestation_count 2>&1 | field 'Response')"
echo "    registry: $(link contract "$CONTRACT")"
echo "    attestations: $COUNT"
