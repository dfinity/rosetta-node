#!/usr/bin/env bash

set -euo pipefail

export RUST_BACKTRACE=1

dfx start \
    --background \
    --clean \
    --host 0.0.0.0:8000

dfx deploy \
    --argument "(principal \"$(dfx identity get-principal)\", vec { record { principal \"qnooh-7ujws-a4bd3-ghlod-k3mz6-zsrba-xiiqe-dalex-3ja2a-ktqte-iae\"; record { doms = 18446744073709551615 } } }, null, null)" \
    --network=local \
    ledger

exec ic-rosetta-api \
    --canister-id $(jq -r .ledger.local ~/.dfx/local/canister_ids.json) \
    --ic-url http://127.0.0.1:8000 \
    --address 0.0.0.0 \
    --port 8080 \
    ${1+"$@"}
