FROM ubuntu:latest as rosetta-api
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl1.1
COPY target/release/ic-rosetta-api /usr/local/bin/ic-rosetta-api
ENTRYPOINT ["/usr/local/bin/ic-rosetta-api"]
