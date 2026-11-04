#!/usr/bin/env bash
# Prints EASYNET.md, the note shipped in every easynet tarball (freebank-easynet-<version>-<host>.tar.gz), so the Guix
# build and the Mac workflow ship the same text.
#   contrib/easynet-readme.sh <version>
set -euo pipefail
VER=${1:?version}
cat <<EOF
# FreeBank $VER, easynet build

The same source as FreeBank v$VER, built with \`configure --with-easynet\`: its one public network is easynet,
mbdrivechains' CPU-mined test network with eCash's rules (L1 magic ea5e4e04, reset 4, release easynet-4 or later).
Not for beta or mainnet.

- FreeBank network magic fb4bea05, P2P port 28455, RPC port 28454, data directory \`easynet\`.
- Fixed seed 163.47.9.132:28455. The easynet L1 node is reachable at 163.47.9.132:28533.
- Run it against an easynet L1 node and enforcer (slot 130, \`--fork=ecash\`): github.com/mbdrivechains/bitcoin,
  releases easynet-N.
- **v1.1.0 (gram notes) starts a new FreeBank-easynet chain** on the same L1: a new genesis and magic (was
  fb4bea03). Start from an empty data directory; move the old one aside. The new chain credits only slot-130 treasury
  changes in L1 blocks from 1,100: the treasury's money before it belongs to the old chain (a fresh chain would
  otherwise credit every deposit again after its withdrawals were paid). Credit signatures bind from genesis.
- Upgrading between builds of the same chain: swap the binaries and keep the data directory (no \`-reindex\`).
EOF
