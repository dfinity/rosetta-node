FROM rust:1.47.0 as builder
ARG GITHUB_TOKEN
ARG RELEASE=main
WORKDIR /usr/src
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        build-essential \
        cmake \
        libbz2-dev \
        libclang-dev \
        liblz4-dev \
        librocksdb-dev \
        libsnappy-dev \
        libzstd-dev
ENV LLVM_CONFIG_PATH=/usr/bin/llvm-config-7
ENV ROCKSDB_LIB_DIR=/usr/lib
RUN curl \
        --header "Authorization: token $GITHUB_TOKEN" \
        --location https://api.github.com/repos/dfinity-lab/rosetta-node/tarball/$RELEASE \
        --output tarball.tar.gz && \
    mkdir rosetta-node && \
    tar xzf tarball.tar.gz --directory rosetta-node --strip-components=1 && \
    cd rosetta-node/rosetta-api && \
    cargo build --release --package ic-rosetta-api

FROM ubuntu:latest as ledger-canister
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl1.1
COPY --from=builder /usr/src/rosetta-node/rosetta-api/target/release/ic-ledger-canister /usr/local/bin/ic-ledger-canister
ENTRYPOINT ["/usr/local/bin/ic-ledger-canister"]

FROM ubuntu:latest as rosetta-api
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl1.1
COPY --from=builder /usr/src/rosetta-node/rosetta-api/target/release/ic-rosetta-api /usr/local/bin/ic-rosetta-api
ENTRYPOINT ["/usr/local/bin/ic-rosetta-api"]
