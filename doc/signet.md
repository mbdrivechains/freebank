# Running FreeBank against a live signet

How to bring FreeBank up as a sidechain (slot **130**) of a BIP 300/301 signet — the
FreeBank signet behind <https://ecxfreebank.com>, or another drivechain signet such as
LayerTwo Labs'. The README's *Run (overview)* section gives the general idea; this page
is the full detail, written for someone starting from zero — every dependency is named
with a download link, and it is meant to be precise enough to hand to an AI coding agent
(Claude Code or similar) if you'd rather have the bring-up driven for you. The
project-operated FreeBank signet is the current reference network, a stopgap until
FreeBank activates on the LayerTwo Labs drivechain signet. Experimental software:
**test coins only**.

## Topology

```
  signet  <--P2P-->  bitcoind (-rest -txindex)  <--RPC/ZMQ-->  bip300301_enforcer
 (mainchain)                                                         | gRPC
                                                                     v
                                             freebankd -mainchaintransport=enforcer
                                               -enforceraddr / -mainchainrest
```

Three processes. FreeBank reaches the mainchain **only** through the enforcer's gRPC
surface plus the bitcoind REST interface — it does not join the signet P2P network.
FreeBank's own network params (magic `fb4b1845`, port 8455) govern the sidechain's own
P2P, which is separate.

## What you need (and where to get it)

Four pieces, fetched separately — nothing bundles them for you yet:

- **`freebankd` / `freebank-cli`** — the FreeBank sidechain node (this repo). Use the
  static binaries from the
  [release page](https://github.com/mbdrivechains/freebank/releases).
- **`bip300301_enforcer`** — the CUSF BIP 300/301 enforcer. It validates the drivechain
  rules on the mainchain, holds the mainchain wallet, and exposes the gRPC surface
  freebankd drives. From
  [LayerTwo-Labs/bip300301_enforcer](https://github.com/LayerTwo-Labs/bip300301_enforcer)
  (Rust; prebuilt releases, or `cargo build`). Version floor below.
- **`bitcoind`** — a signet mainchain node. Use LayerTwo Labs'
  [bitcoin-patched](https://github.com/LayerTwo-Labs/bitcoin-patched) fork of Bitcoin
  Core — it is what the enforcer is developed against (it reports itself as an ordinary
  Bitcoin Core version, e.g. `v29.x`).
- **`grpcurl`** — a generic gRPC command-line client; freebankd shells out to it at
  runtime to talk to the enforcer. From
  [fullstorydev/grpcurl](https://github.com/fullstorydev/grpcurl) or your distro's
  packages.

## Which network? (magic bytes and the challenge)

Two separate network identities are in play. Neither needs manual magic-byte
configuration, but knowing how they work explains most connection confusion:

- **Mainchain**: a signet derives its P2P network magic from its `signetchallenge`
  (BIP 325), so the challenge you pass **is** the network selector. A bare
  `bitcoind -signet` joins the public default signet — a different network entirely —
  and a wrong challenge means your node syncs the wrong chain. Beware that **all
  signets share the same hardcoded genesis hash** (Core's signet genesis is not derived
  from the challenge), so a matching genesis proves nothing; the challenge is the only
  real discriminator.
- **FreeBank**: the sidechain's own P2P uses FreeBank's compiled-in magic `fb4b1845` on
  port 8455 — distinct from Bitcoin's and every other chain's; nothing to configure.

Because the challenge is the L1's identity, freebankd **requires
`-mainchainchallenge=<hex>` outside regtest** (since v0.2.7) and refuses to start
without it; at runtime it verifies, on both the REST and enforcer channels, that the
mainchain it is talking to actually carries that challenge.

## Requirements

- **Enforcer ≥ upstream `6fdb827`** (hard requirement: adds `BlindedM6::deserialize`;
  anything older rejects FreeBank's blinded withdrawal bundles at parse time). FreeBank
  is revalidated end-to-end against upstream `135115b` (July 2026 master).
- A **dedicated enforcer instance** for FreeBank is recommended (own wallet, own gRPC
  port, pointed at your signet bitcoind). FreeBank issues *write* ops — BMM requests and
  withdrawal broadcasts — so sharing an enforcer used by other software means sharing its
  wallet and UTXOs.
- **`grpcurl` on PATH** — freebankd invokes the enforcer gRPC via `grpcurl` at runtime
  (nothing is vendored or linked).
- **Signet coins in the enforcer wallet** — BMM request transactions pay mainchain fees;
  an unfunded wallet means no BMM and a stalled sidechain.
- The signet bitcoind needs **`-rest -txindex`** (deposit transactions are fetched over
  REST).

## Mainchain node

Bring up a (drivechain-patched) signet bitcoind with your target network's challenge.

**For the FreeBank signet** — the chain this project operates, behind
<https://ecxfreebank.com> (explorer included):

```sh
bitcoind -signet -daemon -rest -txindex \
  -signetchallenge=00149048fe50778b4fee7156a5847d1d7dc1de789b3f \
  -addnode=ecxfreebank.com:38333 \
  -acceptnonstdtxn=1 -fallbackfee=0.00021 \
  -zmqpubsequence=tcp://127.0.0.1:29332 \
  -rpcuser=user -rpcpassword=pass
```

Slot 130 is already active there and the activation (M1) values are published on the
homepage, so you can skip straight to the enforcer. Two honest caveats: the block
signing key is held by the project, and this signet currently **resets daily at 09:00
UTC** (it backs the public daily-reset demo) — expect the reset drill below to apply
every day, so it is a connectivity/bring-up target, not a place to accumulate state.

**For the LayerTwo Labs signet**, check <https://drivechain.info/dev.txt> for the
current `signetchallenge` and seed nodes first — they have rotated before — and note
that slot 130 must be proposed and activated there before FreeBank can advance:

```sh
bitcoind -signet -daemon -rest -txindex \
  -signetchallenge=<current-challenge> \
  -addnode=<current-seed>:38333 \
  -acceptnonstdtxn=1 -fallbackfee=0.00021 \
  -zmqpubsequence=tcp://127.0.0.1:29332 \
  -rpcuser=user -rpcpassword=pass
```

Either way: let it sync to tip, point your enforcer at it, and confirm slot 130 shows in
the enforcer's `GetSidechains` once the FreeBank M1 proposal has activated.

## FreeBank node

Run on FreeBank's **main** network (not regtest) — the locked network params
(`fb4b1845` / 8455 / CUSF `BlindedM6` bundle format / signet-prefix mainchain addresses)
apply there:

```sh
freebankd -mainchainchallenge=<your-signet-challenge-hex> \
  -mainchaintransport=enforcer \
  -enforceraddr=127.0.0.1:<enforcer-grpc-port> \
  -mainchainrest=127.0.0.1:38332 \
  -rpcuser=user -rpcpassword=pass
```

The transport and endpoint values are the **defaults** since v0.2.1 (`enforcer`
transport, gRPC on `127.0.0.1:50051`, REST on `127.0.0.1:38332`, matching an
orchestrated BitWindow-style stack), so those flags are only needed to override. What
is **not** optional is `-mainchainchallenge` — since v0.2.7 freebankd refuses to start
outside regtest without it (see "Which network?" above); pass your target signet's
challenge, e.g. the FreeBank signet value from the mainchain section. On regtest the
transport default stays `jsonrpc` for the local-pair test harness.
Startup also probes the REST endpoint (with ~60s of retries for orchestrated
starts) and fails loud if it never answers, rather than letting a REST-less node
reject its first deposit-bearing block later.

Advance the chain with `freebank-cli refreshbmm 0.001` (typically in a loop) once the
slot is active.

## Bring-up verification, in order

1. `freebank-cli getmainchainblockcount` tracks the signet tip.
2. Slot 130 active (enforcer `GetSidechains`).
3. **BMM advances**: `refreshbmm` → a FreeBank block connects; repeat and the height
   climbs.
4. **Deposit (small)**: deposit a little signet coin to a FreeBank deposit address via
   the enforcer tooling; confirm it credits (`getbalance`). This is the M5 path.
5. **Withdrawal (small)**: `createwithdrawal` to a signet address → the bundle forms and
   broadcasts (CUSF `BlindedM6` format) → M6 pays out on the mainchain → the withdrawal
   marks Spent. Note the withdrawal ACK **threshold is a property of the enforcer's
   network config** — regtest uses short thresholds (5/10) but a real signet may run
   mainnet-scale numbers; confirm the actual threshold before promising a timeline.

## Signet resets

Test signets get wiped and restarted — on the LayerTwo Labs signet this has happened
repeatedly, and the `signetchallenge` (and therefore the network magic) rotates when it
does. Plan for the wipe:

- **Sidechain activation does not persist across a reset.** The slot-130 M1 must be
  re-proposed on the fresh chain; if you depend on the sidechain staying active, ask the
  signet operator to include it in whatever seeding batch they replay after a restart.
- **Reset drill** (run whenever the tip height drops sharply, the magic mismatches, or
  peers vanish):
  1. Re-check <https://drivechain.info/dev.txt> for the current challenge and seeds;
     update `bitcoind`'s options and delete `peers.dat` before resyncing.
  2. Start the enforcer with a **fresh datadir** — enforcer state carried across a chain
     reset can disagree with the freshly-synced bitcoind.
  3. Give freebankd a **fresh datadir** too: the old sidechain state is anchored (BMM
     commitments, deposits) to a mainchain that no longer exists.
- **Expect deep reorgs even without a full reset** — test signets are used for fork and
  reorg testing. A deep mainchain reorg is signet turbulence, not necessarily a FreeBank
  bug; check the signet operator's channels before filing one.

## Known limitations (current as of v0.2.7)

- Withdrawal mainchain destinations must be **legacy P2PKH** (an `m…`/`n…` signet
  address). Bech32/P2SH destinations are not yet decoded — a known chassis limitation,
  not a misconfiguration.
- Reserve/solvency parameters are provisional pending simulation; the chain is not for
  real value. Do not deposit anything you care about.
