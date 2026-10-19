#!/usr/bin/env bash
# Prints EASYNET.md, the note shipped in every easynet tarball (freebank-easynet-<version>-<host>.tar.gz), so the Guix
# build and the Mac workflow ship the same text.
#   contrib/easynet-readme.sh <version>
set -euo pipefail
VER=${1:?version}
cat <<EOF
# FreeBank $VER, easynet build

The same source as FreeBank v$VER, built with \`configure --with-easynet\`: its one public network is easynet,
mbdrivechains' CPU-mined test network with eCash's rules (L1 magic ea5e4e03, reset 3). Not for beta or mainnet.

- FreeBank network magic fb4bea03, P2P port 28455, RPC port 28454, data directory \`easynet\`.
- Fixed seed 163.47.9.132:28455. The easynet L1 node is reachable at 163.47.9.132:28533.
- Run it against an easynet L1 node and enforcer (slot 130): github.com/mbdrivechains/bitcoin, releases easynet-N.
EOF
