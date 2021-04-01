#!/usr/bin/env bash
set -euo pipefail

# We use this script to export new versions of our source to the coinbase guys

ROSETTA_NODE_PATH=~/rosetta-node

# Why try and pretend that bash scripts are anything but a nasty hack
rsync \
  -av \
  --relative \
  base/thread \
  canister_client \
  config \
  crypto \
  interfaces \
  monitoring/context_logger \
  monitoring/logger \
  monitoring/metrics \
  nns/common \
  nns/constants \
  phantom_newtype \
  protobuf \
  registry/client \
  registry/common \
  registry/keys \
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
  $ROSETTA_NODE_PATH
