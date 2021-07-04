#!/usr/bin/env bash
set -euo pipefail

# We use this script to export new versions of our source to the coinbase guys

ROSETTA_NODE_PATH=~/rosetta-node

ROSETTA_TMPDIR=$(mktemp -d)

mv $ROSETTA_NODE_PATH/.git $ROSETTA_TMPDIR

rm -rf $ROSETTA_NODE_PATH/*

mv $ROSETTA_TMPDIR/.git $ROSETTA_NODE_PATH

rm -rf $ROSETTA_TMPDIR

cp --parents -r \
   canister_client \
   crypto \
   interfaces \
   phantom_newtype \
   protobuf \
   registry/provisional_whitelist \
   registry/routing_table \
   registry/subnet_type \
   registry/transport \
   rosetta-api \
   rust_canisters/dfn_candid \
   rust_canisters/dfn_core \
   rust_canisters/dfn_json \
   rust_canisters/dfn_macro \
   rust_canisters/dfn_protobuf \
   rust_canisters/on_wire \
   sys \
   tree_deserializer \
   types/base_types \
   types/error_types \
   types/ic00_types \
   types/types \
   utils \
   nns/constants \
   nns/common \
   config \
   monitoring/logger \
   monitoring/metrics \
   registry/client \
   registry/common \
   registry/keys \
   types/wasm_types \
   rust_canisters/dfn_http \
   crypto/internal/crypto_lib/basic_sig/iccsa \
   rosetta-node/certified_vars \
   certified_vars \
   monitoring/context_logger \
   base/thread \
   $ROSETTA_NODE_PATH
