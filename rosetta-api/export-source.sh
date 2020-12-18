#!/bin/bash
set -euo pipefail

# We use this script to export new versions of our source to the coinbase guys

ROSETTA_NODE_PATH=~/rosetta-node

# Why try and pretend that bash scripts are anything but a nasty hack
rsync -av --relative rosetta-api crypto/tree_hash crypto/internal_types crypto/sha256 types/error_types types/types types/base_types types/ic00_types canister_client phantom_newtype utils utils/actix-utils sys rust_canisters/dfn_candid rust_canisters/on_wire rust_canisters/dfn_json rust_canisters/dfn_core rust_canisters/dfn_macro registry/transport registry/routing_table protobuf interfaces tree_deserializer registry/provisional_whitelist types/wasm_types $ROSETTA_NODE_PATH
