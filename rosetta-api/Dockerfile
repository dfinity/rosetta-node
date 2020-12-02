FROM ubuntu:latest as ledger-canister
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl1.1
COPY target/release/ic-ledger-canister /usr/local/bin/ic-ledger-canister
ENTRYPOINT ["/usr/local/bin/ic-ledger-canister"]

FROM ubuntu:latest as rosetta-api
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl1.1
COPY target/release/ic-rosetta-api /usr/local/bin/ic-rosetta-api
ENTRYPOINT ["/usr/local/bin/ic-rosetta-api"]
