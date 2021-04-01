# Docker image for local deployment & integration testing

The `Dockerfile` of this image builds `ic-rosetta-api` and `ledger-canister`
from a fresh checkout, then bundles the build result along with a recent SDK
release in the built image. Upon startup, the built image starts a local
replica, deploys the `ledger` and starts `ic-rosetta-api`, which can then be
used for testing Rosetta API calls.

## Building

```shell
$ docker build \
    --file local-deployment.Dockerfile \
    --build-arg GITHUB_TOKEN=token \
    --build-arg RELEASE=master \
    --build-arg SDK_VER=0.6.26 \
    --tag my-ic-testnet \
    .
```

`GITHUB_TOKEN` is mandatory. Other build arguments have default values as listed
above.

## Using

```shell
$ docker run -it --rm --publish 2053:8080 my-ic-testnet
```

After a few seconds, there should be a log entry `You are all caught up to block
0`. And Rosetta API clients may connect to `http://localhost:2053` for testing.

The image's entrypoint always assume it's a fresh start; do not attempt to stop
and restart a created container.

## Credential

See `credential.txt` for the initial account's credential. It'll contain
`2^64-1` ICP tokens. `credential.txt` is also available at
`/root/credential.txt` in the built image.

## Image with only `ic-rosetta-api`

There's also an image which only builds & ships `ic-rosetta-api`, which is
intended to test against a public test net instead of a local one:

```shell
$ docker build \
    --file local-deployment.Dockerfile \
    --build-arg GITHUB_TOKEN=token \
    --build-arg RELEASE=master \
    --tag my-ic-rosetta-api \
    .
$ docker run -it --rm --publish 2053:8080 my-ic-testnet --canister-id xxx --ic-url xxx
```
