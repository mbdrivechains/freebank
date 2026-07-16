# Running FreeBank against a live signet

How to bring FreeBank up as a sidechain (slot **130**) of a BIP 300/301 signet — e.g. the
LayerTwo Labs drivechain signet. Experimental software: **test coins only**.

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

## Requirements

- **Enforcer ≥ upstream `6fdb827`** (hard requirement: adds `BlindedM6::deserialize`;
  anything older rejects FreeBank's blinded withdrawal bundles at parse time). v0.2.0 is
  revalidated end-to-end against `135115b` (July 2026 master).
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

Bring up a (drivechain-patched) signet bitcoind with the network's current challenge.
For the LayerTwo Labs signet, **check <https://drivechain.info/dev.txt> for the current
`signetchallenge` and seed nodes first** — they have rotated before; the values below are
an example, not gospel:

```sh
bitcoind -signet -daemon -rest -txindex \
  -signetchallenge=<current-challenge> \
  -addnode=<current-seed>:38333 \
  -acceptnonstdtxn=1 -fallbackfee=0.00021 \
  -zmqpubsequence=tcp://127.0.0.1:29332 \
  -rpcuser=user -rpcpassword=pass
```

Let it sync to tip, point your enforcer at it, and confirm slot 130 shows in the
enforcer's `GetSidechains` once the FreeBank M1 proposal has activated.

## FreeBank node

Run on FreeBank's **main** network (not regtest) — the locked network params
(`fb4b1845` / 8455 / CUSF `BlindedM6` bundle format / signet-prefix mainchain addresses)
apply there:

```sh
freebankd -mainchaintransport=enforcer \
  -enforceraddr=127.0.0.1:<enforcer-grpc-port> \
  -mainchainrest=127.0.0.1:38332 \
  -rpcuser=user -rpcpassword=pass
```

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

## Known limitations (v0.2.0)

- Withdrawal mainchain destinations must be **legacy P2PKH** (an `m…`/`n…` signet
  address). Bech32/P2SH destinations are not yet decoded — a known chassis limitation,
  not a misconfiguration.
- Reserve/solvency parameters are provisional pending simulation; the chain is not for
  real value. Do not deposit anything you care about.
