#!/usr/bin/env bash

set -euo pipefail

export RUST_BACKTRACE=1

dfx start \
    --background \
    --clean \
    --host 0.0.0.0:8000

dfx deploy \
    --argument "record { minting_account = \"807077e900000000000000000000000000000000000000000000000000000000\"; initial_values = vec { record { \"ea7161aa15fd1f1ab8ead80c5f2556a449b42eeadbb7be94d450df1ec1ecf0cd\"; record { doms = 18446744073709551615 } } }; archive_canister = null; max_message_size_bytes = null}" \
    --network=local \
    ledger

exec ic-rosetta-api \
    --canister-id $(jq -r .ledger.local ~/.dfx/local/canister_ids.json) \
    --ic-url http://127.0.0.1:8000 \
    --address 0.0.0.0 \
    --port 8080 \
    ${1+"$@"}
