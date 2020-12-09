#!/bin/bash
set -euo pipefail

# TODO replace this with some rust code
# This doesn't deploy a real ledger, just a staging one for coinbase to test out
# "2vxsx-fae" is the anonymous canister ID

read -r -p "Are you sure you want to wipe the staging ledger canister? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    dfx deploy --network=ic ledger --argument '(principal "2vxsx-fae", vec {})'
fi
