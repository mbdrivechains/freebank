# FreeBank (Rust) — MVP for the eCash beta

> This file is the README for the public **`rust`** branch of
> `github.com/mbdrivechains/freebank` and for the release tarballs. It is authored here (in the
> gateway knowledge base) and copied to the orphan `rust` branch at publish time as `README.md`
> (see `RUST_PUBLISH_RUNBOOK_0.3.0.md`). The C++ `master` branch keeps its own README.

---

FreeBank is a Bitcoin **drivechain sidechain** (BIP 300/301, via the CUSF enforcer). This branch is
the **Rust** FreeBank, built on LayerTwo Labs' [`plain-bitassets`](https://github.com/LayerTwo-Labs/plain-bitassets)
chassis. The C++ FreeBank lives on the `master` branch and on the `v0.2.x` releases.

## What this is (and is not)

**This is a fresh-genesis, peg-only MVP for the eCash beta network.**

- **In this build:** the inherited two-way peg (deposits + withdrawal bundles) and blind-merge-mining.
- **Not in this build:** the FreeBank credit layer — bills of exchange, discount houses, notes, term
  deposits, AMM pools, settlement, and the inert-gold oracle. Those land as later `0.3.x` upgrades on
  the **same chain** (the chain identity is fixed at genesis; credit ops are added as append-only,
  activation-gated upgrades — no re-genesis).
- **Fresh genesis:** the Rust node cannot continue the C++ FreeBank chain. It starts a new chain on a
  new (beta) network. Do not point it at anything of real value.

## What's new in 0.3.3 — a beta node finds peers by itself

FreeBank has **no DNS seeding**: a node's first peer comes either from a seed list compiled into the
binary or from an address you give it by hand. Through 0.3.2 every list shipped empty, so a fresh node
sat there with no peers until someone handed it one.

0.3.3 bakes in the **beta seed node `163.47.9.132:4130`**, so `freebankd --network betanet` now finds
the network on its own from an empty data directory. Every other network still ships no seeds and needs
a peer by hand:

```
./freebank-cli --rpc-port 6130 connect-peer <host>:4130
```

(`4130` is the P2P port; the RPC port `6130` is a different thing and is not a peer address.)

No consensus rules change in 0.3.3, and it is wire-compatible with 0.3.2 — a 0.3.2 node and a 0.3.3
node on betanet are the same network and peer with each other normally.

## 0.3.2 — the eCash beta network

0.3.2 added the **`betanet`** network for the eCash **beta**: run `freebankd --network betanet`. Betanet has its
own P2P magic (`FB 42 94 C4`, continuing the `FB 42 94 Cx` scheme after alphanet's `C3`), so a beta node can never
handshake with an alphanet node or any other network.

The FreeBank chain on the eCash beta is a **fresh genesis**: start with an empty data directory
(`~/.local/share/freebank` on Linux). Default ports: RPC **6130**, P2P **4130**, ZMQ **28130**.

## Consensus rules since 0.3.1

0.3.1 added consensus rules rejecting transactions with no inputs and re-created outputs: a
transaction must spend at least one input, an output that already exists cannot be created again, and
a block may not contain the same transaction twice. Without them a transaction could be mined twice
and a later reorg could leave nodes with different UTXO sets. The same fix is offered upstream as
[LayerTwo-Labs/plain-bitassets#61](https://github.com/LayerTwo-Labs/plain-bitassets/pull/61).

These are consensus changes: **0.3.1 and later cannot sync a chain started by 0.3.0** — they need a fresh
genesis. The RPC port default also moved to `6130` (was `8454`) in 0.3.1, matching the 6000 + slot convention
of the other Rust sidechains.

## Identity (fixed at genesis)

- **Sidechain slot:** 130
- **Version:** 0.3.3
- Same daemon and asset names as the C++ FreeBank (a BitWindow / release-channel drop-in).

## Contents of the tarball

| File | Purpose |
|------|---------|
| `freebank/bin/freebankd` | the FreeBank node daemon |
| `freebank/bin/freebank-cli` | RPC command-line client for a running `freebankd` |
| `freebank/bin/freebank-tx` | companion stub (raw-tx tooling is not part of the Rust build) |
| `freebank/COPYING` | licence / NOTICE (see **Licence** below) |
| `freebank/README.md` | this file |

## Default ports and paths

| Purpose | Default |
|---------|---------|
| P2P (`--net-addr`) | `0.0.0.0:4130` |
| RPC | `127.0.0.1:6130` |
| ZMQ | `127.0.0.1:28130` |
| Mainchain enforcer gRPC | `127.0.0.1:50051` |
| Data directory (Linux) | `~/.local/share/freebank` |

`freebankd` refuses to start unless the CUSF enforcer's `ValidatorService` is reachable and `Serving`
at the mainchain gRPC address.

## Running headless

`freebankd` ships with a GUI by default; pass `--headless` to run without it (this is how BitWindow /
the sidechain orchestrator launch it):

```
./freebankd --headless \
  --mainchain-grpc-host 127.0.0.1 --mainchain-grpc-port 50051 \
  --network betanet
```

`--network` accepts one of:

| Value | Purpose |
|-------|---------|
| `signet` | default; a signet-backed mainchain |
| `regtest` | local regtest |
| `forknet` | forknet |
| `alphanet` | the eCash **alphanet** generation (BitWindow `--network alphanet`) |
| `betanet` | the eCash **beta** generation (BitWindow `--network betanet`) |

Each network carries its own P2P magic (`FB 42 94 C0…C4`), so nodes on different networks — alphanet and
betanet included — can never handshake with each other.

### Peers

| Network | First peer |
|---------|-----------|
| `betanet` | automatic — the built-in beta seed node `163.47.9.132:4130` |
| every other network | none built in; supply one with `freebank-cli connect-peer <host>:4130` |

Peers are remembered across restarts once connected.

Then talk to it with the CLI:

```
./freebank-cli --rpc-port 6130 getblockcount
```

Run `./freebankd --help` and `./freebank-cli --help` for the full flag list.

## Verify the download

Each release ships a `SHA256SUMS` listing both the linux and macOS-arm64 tarballs:

```
sha256sum -c SHA256SUMS --ignore-missing      # macOS: shasum -a 256 -c SHA256SUMS
```

## BitWindow

FreeBank is distributed through the same channel as the C++ build (`freebank-<digits>-<arch>.tar.gz`,
no `v` prefix). From 0.3.2 the Rust FreeBank is the **latest** release, so BitWindow's automatic download
(which follows `releases/latest`) fetches it; BitWindow launches it headless with `--network betanet` on
the eCash beta. The C++ FreeBank remains available on the `master` branch and the `v0.2.x` releases.

## Licence

FreeBank's own additions are **MIT-licensed**. The underlying `plain-bitassets` chassis is used under a
written grant of MIT terms from LayerTwo Labs; as of this release the upstream `LICENSE.txt` still
reads "all rights reserved", and FreeBank makes **no** claim that that file itself says MIT. See
`NOTICE` and `LICENSE.txt` in this repository (the latter reproduced from upstream, unchanged), and
consult LayerTwo Labs for the authoritative terms of the chassis.

## Security

FreeBank is experimental, pre-audit software for test networks only. Report vulnerabilities privately
per [`SECURITY.md`](SECURITY.md) (email `mbdcdev@gmail.com`) rather than opening a public issue —
especially anything touching consensus, the two-way peg (deposits / withdrawal bundles / BMM), or
wallet key handling. Ordinary bugs are welcome as public
[issues](https://github.com/mbdrivechains/freebank/issues); the
[bug-report template](.github/ISSUE_TEMPLATE/bug_report.md) applies.
