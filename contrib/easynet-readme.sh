#!/usr/bin/env bash
# Prints EASYNET.md, the note shipped in every easynet tarball (freebank-easynet-<version>-<host>.tar.gz), so the Guix
# build and the Mac workflow ship the same text.
#   contrib/easynet-readme.sh <version>
set -euo pipefail
VER=${1:?version}
# The chain's identity comes from the source itself (CEasynetParams), so the note never drifts from the build: each
# FreeBank-easynet restart (D-2026-11-19-3: easynet runs the latest master) moves the magic and the deposit start.
CP="$(dirname "$0")/../src/chainparams.cpp"
EASY=$(sed -n '/^class CEasynetParams/,/^};/p' "$CP")
MAGIC=$(printf '%s\n' "$EASY" | sed -n 's/.*pchMessageStart\[\([0-3]\)\] = 0x\([0-9a-f][0-9a-f]\);.*/\2/p' | tr -d '\n')
DSTART=$(printf '%s\n' "$EASY" | sed -n 's/.*consensus\.nDepositStartL1Height = \([0-9]*\);.*/\1/p')
GENESIS=$(printf '%s\n' "$EASY" | sed -n 's/.*hashGenesisBlock == uint256S("0x\([0-9a-f]*\)").*/\1/p')
[ ${#MAGIC} = 8 ] && [ -n "$DSTART" ] && [ ${#GENESIS} = 64 ] || { echo "easynet-readme.sh: cannot read easynet's magic/deposit start/genesis from $CP" >&2; exit 1; }
DSTART_FMT=$(printf "%'d" "$DSTART" 2>/dev/null || echo "$DSTART")
case "$VER" in [0-9]*) SRCNAME="FreeBank v$VER" ;; *) SRCNAME="FreeBank $VER" ;; esac   # a release, or a master build
cat <<EOF
# FreeBank $VER, easynet build

The same source as $SRCNAME, built with \`configure --with-easynet\`: its one public network is easynet,
mbdrivechains' CPU-mined test network with eCash's rules (L1 magic ea5e4e04, reset 4, release easynet-4 or later).
Not for beta or mainnet.

**easynet is a public test network. Its coins, notes and tokens have no value, and it may be restarted. Never pay for
them or accept them as payment.** The full notice is NOTICE.md, in this tarball.

- FreeBank network magic $MAGIC, genesis $GENESIS, P2P port 28455, RPC port 28454, data directory \`easynet\`.
- Fixed seed 163.47.9.132:28455. The easynet L1 node is reachable at 163.47.9.132:28533.
- Run it against an easynet L1 node and enforcer (slot 130, \`--fork=ecash\`): github.com/mbdrivechains/bitcoin,
  releases easynet-N.
- **Each FreeBank-easynet restart starts a new chain** on the same L1 (easynet runs the latest FreeBank master and
  restarts when a change needs it): a new genesis and magic, so old-chain nodes stay apart. Start from an empty data
  directory; move the old one aside. This chain credits only slot-130 treasury changes in L1 blocks from $DSTART_FMT:
  the treasury's money before it belongs to the old chains (a fresh chain would otherwise credit every deposit again
  after its withdrawals were paid). Credit signatures bind from genesis.
- The pool rules that mainnet switches on at 31 October 2027 switch on here at 16 November 2026 00:00 UTC, judged by
  the median time of eCash blocks.
- Upgrading between builds of the same chain: swap the binaries and keep the data directory (no \`-reindex\`).
EOF
