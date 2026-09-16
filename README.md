# FreeBank (Rust) — MVP pre-release

> This file is the README for the public **`rust`** branch of
> `github.com/mbdrivechains/freebank` and for the release tarballs. It is authored here (in the
> gateway knowledge base) and copied to the orphan `rust` branch at publish time as `README.md`
> (see `RUST_PUBLISH_RUNBOOK_0.3.0.md`). The C++ `master` branch keeps its own README.

---

FreeBank is a Bitcoin **drivechain sidechain** (BIP 300/301, via the CUSF enforcer). This branch is
the **Rust** FreeBank, built on LayerTwo Labs' [`plain-bitassets`](https://github.com/LayerTwo-Labs/plain-bitassets)
chassis. The C++ FreeBank lives on the `master` branch and on the `v0.2.x` releases.

## What this is (and is not)

**This is a fresh-genesis, peg-only MVP for the eCash beta network — a pre-release.**

- **In this build:** the inherited two-way peg (deposits + withdrawal bundles) and blind-merge-mining.
- **Not in this build:** the FreeBank credit layer — bills of exchange, discount houses, notes, term
  deposits, AMM pools, settlement, and the inert-gold oracle. Those land as later `0.3.x` upgrades on
  the **same chain** (the chain identity is fixed at genesis; credit ops are added as append-only,
  activation-gated upgrades — no re-genesis).
- **Fresh genesis:** the Rust node cannot continue the C++ FreeBank chain. It starts a new chain on a
  new (beta) network. Do not point it at anything of real value.

## What's new in 0.3.1

This release adds consensus rules rejecting transactions with no inputs and re-created outputs: a
transaction must spend at least one input, an output that already exists cannot be created again, and
a block may not contain the same transaction twice. Without them a transaction could be mined twice
and a later reorg could leave nodes with different UTXO sets. The same fix is offered upstream as
[LayerTwo-Labs/plain-bitassets#61](https://github.com/LayerTwo-Labs/plain-bitassets/pull/61).

These are consensus changes: **0.3.1 cannot sync a chain started by 0.3.0** — it needs a fresh
genesis. The RPC port default also moved to `6130` (was `8454`), matching the 6000 + slot convention
of the other Rust sidechains.

## Identity (fixed at genesis)

- **Sidechain slot:** 130
- **Version:** 0.3.1
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
  --network <beta-network-name>
```

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
no `v` prefix). This Rust `0.3.1` is a **pre-release**: BitWindow follows `releases/latest`, which
excludes pre-releases, so the released BitWindow keeps fetching the C++ FreeBank. Running the Rust MVP
under BitWindow requires either the beta BitWindow that treats FreeBank as a native Rust sidechain, or
pinning `0.3.1` in the chains_config — see the project's integration notes. Until then, run the daemon
directly as shown above.

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
