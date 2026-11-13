#!/bin/sh
# Every test in one command.
#
#   . tools/toolchain.env && sh tools/test.sh          # about 10 minutes once the circuits are compiled
#   . tools/toolchain.env && sh tools/test.sh full     # about 40 minutes more, needs 6 GB of free memory
# The first run compiles every circuit it touches, which adds about 15 minutes (four minutes for
# each of the 10-invoice circuits).
#
# The default run covers the libraries, the 1-invoice circuits, the command line, the spot-check
# tools and the aggregation tree over leaves of one invoice (which proves, joins and verifies real
# proofs). `full` adds the 10-invoice circuits, the Starknet contracts against real proofs, the run
# on a local Starknet network and the demonstration.
#
# Needs: nargo and Python with lxml and cryptography for everything; bb for the aggregation tests
# and the demonstration; scarb, snforge and universal-sierra-compiler for the contract tests;
# starknet-devnet and sncast for the local network run. Exit status 0 only if everything passed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
FAILED=""
ESC="$(printf '\033')"

# step LABEL COMMAND...: run, show the last line, remember a failure
step() {
    label="$1"; shift
    out="$("$@" 2>&1)"; code=$?
    last="$(printf '%s\n' "$out" | tail -1 | sed "s/$ESC\[[0-9;]*m//g")"
    if [ $code -eq 0 ]; then
        printf 'ok    %-34s %s\n' "$label" "$last"
    else
        printf 'FAIL  %-34s %s\n' "$label" "$last"
        FAILED="$FAILED $label;"
    fi
}

in_dir() { ( cd "$1" && shift && "$@" ); }

step "pf_xmldsig unit tests"       in_dir noir/pf_xmldsig nargo test
step "pf_efi unit tests"           in_dir noir/pf_efi nargo test
step "python hash against circuits" python3 tools/efi/test_poseidon2.py
step "authority receipt"           python3 tools/efi/test_leaf_response.py
step "taxpayer request"            python3 tools/efi/test_leaf_request.py
step "buyer named in a request"    python3 tools/efi/test_buyer.py
step "1 invoice"                   python3 tools/efi/test_batch.py --k 1
step "1 invoice to one buyer"      python3 tools/efi/test_debtor.py
step "invoice signed again"        python3 tools/efi/test_replay.py
step "spot check and comparison"   python3 tools/efi/test_opening.py
step "command line on files"       python3 tools/test_cli.py
step "aggregation, leaves of 1"    python3 tools/efi/test_agg.py

if [ "${1:-}" = "full" ]; then
    step "10 invoices"                 python3 tools/efi/test_batch.py --k 10
    step "10 invoices to one buyer"    python3 tools/efi/test_debtor.py --k 10
    step "aggregation, leaves of 10"   python3 tools/efi/test_agg.py --k 10
    step "registry contract"           in_dir starknet/pf_registry snforge test
    step "local Starknet network"      sh tools/starknet/devnet_demo.sh
    step "demonstration"               python3 tools/demo.py
fi

if [ -n "$FAILED" ]; then
    echo "FAILED:$FAILED"
    exit 1
fi
echo "all tests passed"
