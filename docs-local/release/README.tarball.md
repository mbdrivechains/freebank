# FreeBank (Rust) — pre-release

FreeBank is a Bitcoin **drivechain sidechain** (BIP 300/301, CUSF enforcer)
built on LayerTwo Labs' `plain-bitassets` chassis. This tarball contains the
Rust FreeBank daemon and its command-line tools.

> **This is a PRE-RELEASE for the eCash beta network.** It is a fresh-genesis
> MVP: the peg (deposits + withdrawals) and blind-merge-mining only — the
> FreeBank credit layer (houses, notes, bills, deposits, pools, settlement,
> inert oracle) is NOT in this build and lands as later `0.3.x` upgrades on the
> same chain. Do not point it at a production network.

## Contents

| File | Purpose |
|------|---------|
| `freebankd` | the FreeBank node daemon |
| `freebank-cli` | RPC command-line client for a running `freebankd` |
| `freebank-tx` | companion stub (raw-tx tooling is not part of the Rust build) |
| `COPYING` | license / NOTICE |

## Identity (fixed at genesis)

- **Sidechain slot:** 130
- **Version:** 0.3.3

## Default ports and paths

| Purpose | Default |
|---------|---------|
| P2P (net-addr) | `0.0.0.0:4130` |
| RPC | `127.0.0.1:6130` |
| ZMQ | `127.0.0.1:28130` |
| Mainchain enforcer gRPC | `127.0.0.1:50051` |
| Data directory (Linux) | `~/.local/share/freebank` |

`freebankd` refuses to start unless the CUSF enforcer's `ValidatorService` is
reachable and `Serving` at the mainchain gRPC address.

## Running headless

`freebankd` has a GUI by default; pass `--headless` to run without it (as
BitWindow / the sidechain orchestrator launches it):

```
./freebankd --headless \
  --mainchain-grpc-host 127.0.0.1 --mainchain-grpc-port 50051 \
  --network signet
```

## Networks

`--network` accepts one of:

| Value | Purpose |
|-------|---------|
| `signet` | default; a signet-backed mainchain |
| `regtest` | local regtest |
| `forknet` | forknet |
| `alphanet` | the eCash **alphanet** generation (BitWindow `--network alphanet`) |
| `betanet` | the eCash **betanet** generation (BitWindow `--network betanet`) |

Each network carries its own P2P magic (`FB 42 94 C0…C4`), so nodes on
different networks — alphanet and betanet included — can never handshake with
each other.

### Peers (no DNS seeding)

FreeBank has no DNS seeds: a node finds its first peer either from a
compiled-in seed list or from one you give it by hand.

| Network | First peer |
|---------|-----------|
| `betanet` | automatic — the baked-in beta seed node `163.47.9.132:4130` |
| every other network | none baked in; supply one by hand |

To add a peer by hand (any network):

```
./freebank-cli --rpc-port 6130 connect-peer <host>:4130
```

Once connected, peers are remembered across restarts. `4130` is the FreeBank
P2P port; the RPC port `6130` is separate and should not be dialled as a peer.

Then talk to it with the CLI:

```
./freebank-cli --rpc-port 6130 getblockcount
```

Run `./freebankd --help` and `./freebank-cli --help` for the full flag list.

## Disabled chassis features

FreeBank is a peg-only credit chain, not a token/market chain. The upstream
plain-bitassets chassis ships BitAssets, an AMM, and Dutch auctions; these are
**disabled on the FreeBank chain** (operator decision 2026-09-15). A transaction
that uses any of them is rejected by consensus in both the mempool and at block
connect, with a stable reject reason:

| Family | Disabled transactions | Disabled coin/output kinds | Reject reason |
|--------|-----------------------|----------------------------|---------------|
| BitAssets | reservation, registration, mint, update | `BitAsset`, `BitAssetControl`, `BitAssetReservation` | `freebank: bitasset transactions are disabled on this chain` |
| AMM | mint, burn, swap | `AmmLpToken` | `freebank: amm transactions are disabled on this chain` |
| Dutch auctions | create, bid, collect | `DutchAuctionReceipt` | `freebank: dutch auction transactions are disabled on this chain` |

The corresponding RPC methods and CLI commands are removed, and the GUI's
BitAssets/AMM/Dutch-auction tab is hidden. The underlying type/enum variants and
state modules are **retained** so the serialization tag order is unchanged
(upstream merges stay possible) and so the credit layer can be added back later
on the same chain as versioned 0.3.x upgrades. The two-way peg (deposits,
withdrawals, BMM) and plain Bitcoin transfers are unaffected.
