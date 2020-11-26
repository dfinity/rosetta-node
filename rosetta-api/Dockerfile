FROM rust:1.47.0 as builder
ARG GITHUB_ORG=dfinity-lab
ARG GITHUB_REPO=rosetta-node
ARG GITHUB_TOKEN
ARG RELEASE=master
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
        --location https://api.github.com/repos/$GITHUB_ORG/$GITHUB_REPO/tarball/$RELEASE \
        --output tarball.tar.gz && \
    mkdir dfinity && \
    tar xzf tarball.tar.gz --directory dfinity --strip-components=1 && \
    cd dfinity/rs && \
    cargo build --release --package ic-rosetta-api

FROM ubuntu:latest
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl1.1
COPY --from=builder /usr/src/dfinity/rs/target/release/ic-rosetta-api /usr/local/bin/ic-rosetta-api
ENTRYPOINT ["/usr/local/bin/ic-rosetta-api"]
