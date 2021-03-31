FROM rust:1.50.0-buster as builder-00

ARG GITHUB_TOKEN

ARG RELEASE=master

WORKDIR /var/tmp

RUN \
  rustup target add wasm32-unknown-unknown && \
  (curl -H "Authorization: token ${GITHUB_TOKEN}" -L https://api.github.com/repos/dfinity-lab/dfinity/tarball/${RELEASE} | tar xz --strip-components=1) && \
  cd rs/rosetta-api && \
  cargo build --release --package ic-rosetta-api --bin ic-rosetta-api && \
  cargo build --target wasm32-unknown-unknown --release --package ledger-canister --bin ledger-canister

FROM debian:sid-slim as builder-01

WORKDIR /var/tmp

COPY --from=builder-00 \
  /var/tmp/rs/target/wasm32-unknown-unknown/release/ledger-canister.wasm \
  /var/tmp/

RUN \
  apt update && \
  apt install -y \
    binaryen && \
  wasm-opt -Oz --strip-debug ledger-canister.wasm -o ledger-canister.wasm

FROM debian:buster-slim

ARG RELEASE

ARG SDK_VER=0.6.26

LABEL RELEASE=${RELEASE}

WORKDIR /root

COPY --from=builder-01 \
  /var/tmp/ledger-canister.wasm \
  /root/

COPY --from=builder-00 \
  /var/tmp/rs/target/release/ic-rosetta-api \
  /usr/local/bin/

COPY --from=builder-00 \
  /var/tmp/rs/rosetta-api/docker/credential.txt \
  /var/tmp/rs/rosetta-api/ledger.did \
  /var/tmp/rs/rosetta-api/log_config.yml \
  /root/

COPY \
  dfx.json \
  entry.sh \
  /root/

ADD \
  https://sdk.dfinity.org/downloads/dfx/${SDK_VER}/x86_64-linux/dfx-${SDK_VER}.tar.gz \
  /var/tmp/dfx.tar.gz

RUN \
  apt update && \
  apt install -y \
    ca-certificates \
    jq && \
  apt autoremove --purge -y && \
  tar xfz /var/tmp/dfx.tar.gz -C /usr/local/bin && \
  rm -rf \
    /tmp/* \
    /var/lib/apt/lists/* \
    /var/tmp/*

ENTRYPOINT ["/root/entry.sh"]
