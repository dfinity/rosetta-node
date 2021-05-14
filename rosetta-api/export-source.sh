#!/bin/bash
set -euo pipefail

# We use this script to export new versions of our source to the coinbase guys

ROSETTA_NODE_PATH=${ROSETTA_NODE_PATH:-~/rosetta-node}

# Why try and pretend that bash scripts are anything but a nasty hack
rsync \
    -av \
    --relative \
    canister_client \
    crypto/internal \
    crypto/sha256 \
    crypto/tree_hash \
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
    rust_canisters/on_wire \
    sys \
    tree_deserializer \
    types/base_types \
    types/error_types \
    types/ic00_types \
    types/types \
    utils \
    utils/actix-utils \
    "$ROSETTA_NODE_PATH"
