# FreeBank

**Credit creation on a BIP 300/301 drivechain.** FreeBank is a Bitcoin sidechain for
*bills of exchange* — short-dated credit instruments backed by an escrow bond — in the
lineage of Scottish free banking (1716–1845), cryptographically translated. It is designed
to run as a CUSF/BIP 300–301 sidechain (e.g. alongside the drivechain enforcer), with a
drivechain-patched Bitcoin node as an alternative mainchain.

> Be your own bank. Make your own credit.

FreeBank is a C++ fork of the BitAssets sidechain chassis (MIT). It is **experimental,
pre-audit software** — run it on regtest/testnet/signet with test coins only.

## What works today

- **BIP 300/301 sidechain**: activates into a slot, advances by blind-merged-mining (BMM),
  credits deposits (M5) and produces withdrawal bundles (M3).
- **Two mainchain transports**, selected at startup with `-mainchaintransport`:
  - `jsonrpc` — a drivechain-patched Bitcoin node's HTTP-RPC (the classic path).
  - `enforcer` — the CUSF `bip300301_enforcer` gRPC surface, invoked at runtime via
    `grpcurl` (nothing of the enforcer is vendored or linked). BMM and deposit crediting
    are verified end-to-end on this path.
- **Bills of exchange** (the credit primitive): a unique, stateful instrument with
  `bill_id = sha256(encrypted_body)` as its identity (the node never decrypts the body),
  a face amount, a maturity + grace window, a consensus-enforced escrow bond posted by the
  acceptor, and ownership advanced by endorsement. Terminal states are **retired** (the
  drawee pays the current holder and reclaims the escrow) or **defaulted** (after
  maturity + grace the holder claims the escrow). Full lifecycle — issue → endorse →
  retire/default — runs on-chain. RPCs: `issuebill`, `endorsebill`, `retirebill`,
  `claimbillescrow`, `listbills`, `getbill`, `listmybills`.

## Build

Native build (Ubuntu 24.04 shown; other platforms per standard Bitcoin Core build docs):

```sh
./autogen.sh
./configure --without-gui --with-incompatible-bdb --disable-bench
make -j"$(nproc)"
```

Binaries land in `src/`: `freebankd`, `freebank-cli`, `freebank-tx`.

Run the unit tests:

```sh
src/test/test_bitcoin
```

## Run

FreeBank is a sidechain — it needs a BIP 300/301 mainchain to merge-mine against. Point it
at one of the two transports:

```sh
# against a drivechain-patched Bitcoin node (JSON-RPC)
freebankd -mainchaintransport=jsonrpc

# against the CUSF enforcer (gRPC via grpcurl); deposits also need the mainchain node's REST
freebankd -mainchaintransport=enforcer \
          -enforceraddr=127.0.0.1:50051 \
          -mainchainrest=127.0.0.1:8332
```

Advance the chain with `freebank-cli refreshbmm`, once the slot is active on the mainchain.

## License

MIT — see [`COPYING`](COPYING). Inherited from Bitcoin Core / the BitAssets chassis.

## Status

Alpha. Consensus surfaces (bills, deposits, the transport layer) have unit + integration
coverage and, for the bills and transport code, adversarial review; the withdrawal *payout*
round-trip depends on the mainchain enforcer's bundle handling. Not yet audited; do not use
with real value.
