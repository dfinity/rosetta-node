#!/usr/bin/env bash
set -euo pipefail

# We use this script to export new versions of our source to the coinbase guys

ROSETTA_NODE_PATH=~/rosetta-node2

rm -rf $ROSETTA_NODE_PATH/*

cp --parents -r \
  artifact_manager \
  artifact_pool \
  base/server \
  base/thread \
  canister_client \
  canister_sandbox \
  canonical_state \
  certified_vars \
  config \
  consensus \
  cow_state \
  criterion_time \
  crypto \
  cycles_account_manager \
  embedders \
  execution_environment \
  http_handler \
  ingress_manager \
  interfaces \
  memory_tracker \
  messaging \
  monitoring/context_logger \
  monitoring/logger \
  monitoring/metrics \
  monitoring/metrics_exporter \
  nns/common \
  nns/constants \
  p2p \
  phantom_newtype \
  prep \
  protobuf \
  registry/client \
  registry/common \
  registry/keys \
  registry/provisional_whitelist \
  registry/routing_table \
  registry/subnet_type \
  registry/transport \
  replica \
  replicated_state \
  replica_tests \
  rosetta-api \
  runtime \
  rust_canisters/canister_test \
  rust_canisters/dfn_candid \
  rust_canisters/dfn_core \
  rust_canisters/dfn_http \
  rust_canisters/dfn_json \
  rust_canisters/dfn_macro \
  rust_canisters/dfn_protobuf \
  rust_canisters/on_wire \
  state_layout \
  state_manager \
  sys \
  system_api \
  test_utilities \
  transport \
  tree_deserializer \
  types/base_types \
  types/error_types \
  types/ic00_types \
  types/types \
  types/types_test_utils \
  types/wasm_types \
  universal_canister/lib \
  utils \
  validator \
  wasm_utils \
  Cargo.lock \
  Cargo.toml \
  $ROSETTA_NODE_PATH
