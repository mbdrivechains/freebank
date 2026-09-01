# FreeBank Guide

**A knowledge document for people — and for their AI assistants.**

This file is meant to be *complete enough on its own* that you can hand it to an AI
assistant (paste it, attach it, or point the assistant at this URL) and ask it to walk
you through running FreeBank, standing up a bank, issuing credit, and understanding what
is happening on the chain. Every command in it was taken from a passing integration test
or from the source of the shipped release (v0.2.8 for the section-3 quick start; the current release is v0.2.10), and the quick start in
section 3 was run verbatim against the release binaries. Where something is designed but
not built, it says so.

> **Status, always:** FreeBank is experimental, pre-audit software for **test networks
> only**. Do not use it with anything of real value. Its reserve and solvency parameters
> are provisional pending simulation. It is the work of one independent operator and is
> not affiliated with or endorsed by LayerTwo Labs, eCash, or any other project. Nothing
> here is investment advice; FreeBank is not a way to make money.

---

## 0. How to use this document with an AI assistant

Give the assistant this whole file, then ask things like:

- *"Walk me through the regtest quick start in section 3, step by step."*
- *"I have a FreeBank node running. Help me register a discount house, attest its
  reserves, mint notes and redeem them."*
- *"Set up two wallets and two houses (section 4.0), then discount a bill and settle."*
- *"My house shows `effective_status: stressed`. Why, and what do I do?"*
- *"What is built and what is only designed?"*

**For the assistant.** Sections 3–4 are the command ground truth; section 7 is the
symptom → fix table; 9.1 the parameters (main and regtest columns); 9.2 the RPC signature
table. Conventions used everywhere: `$FB` = `freebank-cli` with the flags from 3.4; `$H`
= a house id; `bmm N` advances the sidechain by N blocks (3.5); `$W1`/`$W2` = two wallets
and `$H1`/`$H2` their houses (4.0); `$HOUSE`/`$HOLDER` = the wallet owning a house / a
wallet holding its notes. Section 3 was run end-to-end as one script; the section 4
recipes come from separate integration tests and are **not** one continuous script —
each states the state it assumes. A returned txid is **not** acceptance — check chain
state (`gethouse`, `getbill`, `getrawmempool`). Not in this file: the signet connection
recipe (see `doc/signet.md`). Running `freebankd` against the eCash alpha network needs
v0.2.9 or later (2.3, recipe in 5.2). If this file and `freebank-cli help <rpc>`
disagree, the binary is right; say so.

---

## 1. What FreeBank is

FreeBank is a Bitcoin-style sidechain for **free banking**: a place where anyone who
holds some base coin can open a *discount house*, post that coin as a bond, and issue
redeemable credit notes against it — and where merchants can write *bills of exchange*
(IOUs for goods sold on 30/60/90-day terms) that a house will buy at a discount, paying in
its own notes. That purchase is credit creation: new spendable money appears, backed by
the bill (whose contents the chain cannot see — what it enforces is the acceptor's escrow
bond) plus the house's bonded reserves, and it disappears again when the bill is paid and
the notes are redeemed.

Bitcoin solved self-custody of base money. FreeBank is an attempt at the other half —
self-provision of credit — using the mechanism of Scottish free banking (1716–1845, see
section 6), translated into consensus rules so that reserves are **proven on-chain instead
of trusted**. Tagline: *be your own bank, make your own credit.*

Mechanically, FreeBank is a BIP 300/301 drivechain (a C++ fork of the MIT-licensed
BitAssets sidechain chassis, itself Bitcoin Core lineage). It has **no coin of its own,
no premine, no subsidy**: the only money inside it is mainchain coin that was deposited
through the two-way peg. Everything a house issues is a liability denominated in — and
redeemable for — that pegged coin.

### The instruments, in one screen

| Instrument | What it is | Built? |
|---|---|---|
| **Bill of exchange** | A unique, stateful IOU between a drawer (seller), a drawee/acceptor (buyer, who posts an escrow bond) and a holder (current owner). Matures at a block height; endorsable; defaulted bills pay the bond to the holder; liable parties can be pursued by recourse. | Yes |
| **Discount house** | A registered, escrow-bonded, M-of-N-governed issuer of notes and term deposits. Proves its liquid reserves on-chain every ~144 blocks. Lifecycle: Open → Stressed → Deferred → Insolvent / Wound-down. | Yes |
| **Notes** | The money. Per-house credit claims minted against reserves, transferred bearer-style, redeemed at par (1 unit = 1 sat). Holders can formally demand par; houses discharge demands unilaterally; a lapsed demand can be protested. | Yes |
| **Discounting** | A house buys a bill from its holder, paying with notes minted in the same operation — the act of credit creation. Books the bill as a loan asset under a match-funding rule. | Yes |
| **Term deposits** | Time-locked loans to a house at a per-receipt rate; transferable whole; junior to notes. | Yes |
| **Clearing pool** | One constant-product AMM per house between its notes and the base coin — the secondary market that prices stressed paper. | Yes |
| **Bilateral settlement** | Two houses present each other's notes and settle the net at par ±0.5% in one co-signed transaction. | Yes (bilateral only) |
| **Gold oracle** | Bonded submitters post a gold price; the fix is a braked lower median. **Consensus-inert**: nothing in consensus reads it yet. | Yes, inert |
| **Gram display** | RPCs show a `_grams` companion beside amounts at a fixed launch scale. Presentation only — notes redeem for base coin, not gold. | Display only |
| Two-wallet bill issuance tooling, forknet L1 support (alpha/mainnet), multi-house clearing, Chaumian bearer layer, enforced gold redemption, cash-credit lines | — | **Not built** (section 8 says which are designed) |

---

## 2. Where FreeBank runs today

FreeBank runs on a **live network you can join today** — the eCash **alpha** chain (2.3), with a
beta network and then mainnet to follow. That is the front door: a real BIP 300/301 chain in slot
130, producing FreeBank blocks continuously. There is also a self-contained **regtest** you drive
yourself (2.1) — the fast lane, where the whole instrument lifecycle runs in minutes because you
mint blocks on demand. Start with the live network to join what is actually running; reach for
regtest when you want the complete bank → loan → redeem loop instantly, offline, and repeatable.
Three places, pick by what you want:

### 2.1 Your own regtest (the fast lane — full lifecycle, instant, offline)

A self-contained stack on your machine: a regtest Bitcoin node, the CUSF enforcer, and
`freebankd`. Nothing external, resets whenever you like, every instrument available. Because you
produce blocks on demand, the whole section-4 lifecycle — register a house, issue and discount a
bill, redeem a note — runs in minutes. **Section 3 is this.**

### 2.2 The public daily-reset signet

The project runs a public BIP 300/301 signet with FreeBank active in slot 130, a block
explorer, a faucet, and a live board at **https://ecxfreebank.com**. It **resets every day
at 09:00 UTC**, so it is a playground, not a place to keep anything. The connection recipe
(signet challenge, seed node, enforcer and `freebankd` flags) is in
[`doc/signet.md`](doc/signet.md) in this repository.

### 2.3 The eCash alpha network (alphanet) — activated; followable from v0.2.9, self-syncing from v0.2.10

**This is the front door: a live, public BIP 300/301 chain you can sync and take part in today.**

On **2026-08-27** FreeBank was proposed and activated as **slot 130 on the eCash alpha
network** (M1 in block 996,454, 30 of 30 acks, activated at block 996,485). Another
sidechain, in slot 24, activated in the same window. The M1 declaration carries the
v0.2.8 hash ids (section 2.4).

Be precise about what that means:

- **The slot is open.** A FreeBank node can follow the alpha chain from **v0.2.9**
  (recipe in 5.2). v0.2.8 could not: its startup identity pin assumed the mainchain was a
  *signet* and demanded a signet challenge, which a `chain=main` forknet does not have,
  and it decoded withdrawal destinations with the signet/testnet address prefix. v0.2.9
  adds `-mainchainblockpin` (pin the fork block) and derives the address prefix from the
  L1 family.
- **Blocks appear only when someone produces them.** A FreeBank block on alpha needs a
  `freebankd` posting BMM requests through an enforcer whose wallet holds alpha coins (the
  request is a paid mainchain transaction), and a miner running enforcer templates to
  include it. To see whether slot 130 is being mined, scan recent coinbases for M7
  commitments with the slot byte `0x82` (section 9.4). **As of September 2026 the network is producing FreeBank blocks continuously** — a followed node syncs a live chain; 5.3 is the fastest way to watch it happen.
- **Deposit only once you can see FreeBank blocks being produced.** A deposit is a
  mainchain transaction into the slot's escrow; it is credited by the sidechain, so with
  no blocks there is nothing to credit it — and it would be lost at the next reset
  regardless.
- **The enforcer's self-mining and self-acking are regtest/signet-only** — on alpha,
  blocks come from real hash. Obtain alpha coins by mining or from other participants.
- **Alpha is disposable.** eCash has said alpha will be followed by a beta network and
  then mainnet, each a fresh fork (see eCash's own announcements for dates). Everything on
  alpha — the activation, deposits, any chain state — is expected to vanish at the next
  reset. The project will re-propose slot 130 on the next network with the hash ids of the
  then-current release; that network's fork height and magic will differ from the alpha
  values in 5.2 and will be published here when known.

Explorer for the alpha L1: https://explorer.alpha.ecash.ninja/ (a mempool.space-style
explorer; it has no sidechain view — sidechain state comes from a synced enforcer or a
coinbase scan).

### 2.4 Verifying what you download

Releases: https://github.com/mbdrivechains/freebank/releases — Linux x86-64 and macOS
arm64 static tarballs plus `SHA256SUMS`. **Current release: v0.2.10** (adds a baked DNS seed for zero-config peer discovery, §5.3; can
follow alpha): `freebank-0.2.10-x86_64-linux-gnu.tar.gz`, sha256
`2cbba2e68552c455a134d73f72eb748ac4c44d9c411b157c7076dbaf22f397d5`; its source is the
commit the public tag `v0.2.10` points at (`git rev-parse 'v0.2.10^{commit}'`). The commands
below are written for v0.2.8 because that is what the sidechain proposal on alpha
commits to — substitute `0.2.10` to verify the current binaries the same way.

The sidechain proposal (M1) that activated slot 130 on alpha commits to v0.2.8:

| M1 field | value |
|---|---|
| slot | `130` |
| title | `FreeBank` |
| hash_id_1 | `34bee27a48d6d82135f1f477a2524abf7843bf86903f24ffdfd4e6a1ec487831` — sha256 of `freebank-0.2.8-x86_64-linux-gnu.tar.gz` |
| hash_id_2 | `c67a3ad94b6f8491d131681a0f21df3e2d5517ea` — the commit the public tag `v0.2.8` points at |

```bash
curl -LO https://github.com/mbdrivechains/freebank/releases/download/v0.2.8/freebank-0.2.8-x86_64-linux-gnu.tar.gz
curl -LO https://github.com/mbdrivechains/freebank/releases/download/v0.2.8/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing            # OK
sha256sum freebank-0.2.8-x86_64-linux-gnu.tar.gz    # 34bee27a…  = hash_id_1
tar -xzf freebank-0.2.8-x86_64-linux-gnu.tar.gz -C ~   # creates ~/freebank/bin/{freebankd,freebank-cli,freebank-tx}
git clone https://github.com/mbdrivechains/freebank freebank-src
git -C freebank-src rev-parse 'v0.2.8^{commit}'     # c67a3ad9… = hash_id_2
```

The hash ids are proposer-chosen commitments; consensus never checks them. They exist so
that you can confirm the software you run is the software the proposal named. The M1
commits only to the Linux tarball; macOS users verify their tarball against `SHA256SUMS`
and the source against hash_id_2. To read the commitment from the chain itself, decode
the coinbase of alpha block 996,454 with the snippet in 9.4. On macOS, fetch with `curl`,
not a browser, so Gatekeeper's quarantine flag never attaches to the unsigned binary.

---

## 3. Quick start on regtest (the reproducible path)

> **This is the fast lane (2.1), not the destination.** You drive block production yourself, so the
> whole instrument lifecycle in section 4 runs in minutes and repeats exactly. To do the same things
> on the **live** network, see section 5 — the commands are identical, but each operation advances
> only as your BMM blocks land, and live state is wiped at each network reset.

Three processes, all local: a regtest **Bitcoin node** (the Core build bundled with
BitWindow — currently a v31 "eCash drynet4" build; any recent Core with `-rest -txindex
-zmqpubsequence` works, which is why the enforcer is started with
`--bitcoin-core-skip-version-check`), the **CUSF enforcer** (`bip300301-enforcer`), and
**`freebankd`**. FreeBank talks to the mainchain only through the enforcer's gRPC (via
`grpcurl`) plus the node's REST interface.

The whole quick start takes about three minutes of wall-clock. It was last run verbatim
on 2026-08-28 against the v0.2.8 release binaries and the enforcer bundled with BitWindow
(v0.3.4). All snippets assume **bash**; `python3` and `xxd` are also used.

> **The one debugging fact to know before you start:** a wallet RPC that returns a txid
> has *built* a transaction, not necessarily had it *accepted* — a mempool rejection is
> logged and the txid is still returned. Check state (`gethouse`, `getbill`,
> `getrawmempool`) rather than exit status. A refused transaction leaves a phantom that
> pins its inputs; release it with `abandontransaction <txid>`.

### 3.1 Get the pieces

1. **FreeBank** — the release tarball (section 2.4). It unpacks to `freebank/bin/`.
2. **The mainchain node and the enforcer.** The simplest source is a stock
   **BitWindow** install (LayerTwo Labs' drivechain wallet, https://layertwolabs.com/download):
   it bundles both binaries. On Linux they land in
   `~/.local/share/bitwindow/assets/bin/` (`bitcoind`, `bitcoin-cli`,
   `bip300301-enforcer`). You never need to open BitWindow itself. If you cannot find
   them, download the L1 build from https://releases.drivechain.info/ and the enforcer
   from https://github.com/LayerTwo-Labs/bip300301_enforcer.
3. **`grpcurl`** on your `PATH` (https://github.com/fullstorydev/grpcurl/releases). The
   enforcer serves gRPC reflection, so no `.proto` files are needed.
4. **bash, python3, xxd.**

Set three variables for the rest of this section (adjust the paths to yours):

```bash
BIN=~/.local/share/bitwindow/assets/bin      # bitcoind / bitcoin-cli / bip300301-enforcer
FBBIN=~/freebank/bin                          # freebankd / freebank-cli from the tarball
W=~/fb-regtest && mkdir -p "$W/btc" "$W/enf" "$W/fb"
```

Ports used below (arbitrary, chosen not to collide with defaults): node RPC/REST
**19443**, node P2P **19444**, ZMQ **29332**, enforcer gRPC **50151**. `freebankd` itself
uses its regtest defaults, RPC **18457** and P2P **18456** — if anything else on the
machine uses them, pass `-rpcport`/`-port` to `freebankd` and `-rpcport` to
`freebank-cli`.

### 3.2 Start the mainchain node and the enforcer

```bash
"$BIN/bitcoind" -regtest -daemon -datadir="$W/btc" -server \
  -rpcuser=bench -rpcpassword=bench -rpcport=19443 -port=19444 \
  -zmqpubsequence=tcp://127.0.0.1:29332 -fallbackfee=0.0001 -rest -txindex

BC="$BIN/bitcoin-cli -regtest -datadir=$W/btc -rpcuser=bench -rpcpassword=bench -rpcport=19443"
until $BC getblockcount >/dev/null 2>&1; do sleep 1; done

"$BIN/bip300301-enforcer" --data-dir "$W/enf" \
  --node-rpc-addr=127.0.0.1:19443 --node-rpc-user=bench --node-rpc-pass=bench \
  --node-zmq-addr-sequence=tcp://127.0.0.1:29332 --serve-grpc-addr=127.0.0.1:50151 \
  --bitcoin-core-skip-version-check \
  --enable-wallet --wallet-sync-source=disabled --wallet-auto-create \
  > "$W/enf/enf.log" 2>&1 &

EA=127.0.0.1:50151
until grpcurl -plaintext -d '{}' $EA cusf.mainchain.v1.ValidatorService/GetChainTip >/dev/null 2>&1; do sleep 1; done
```

The enforcer needs the node's `-txindex`, `-rest` and a live `-zmqpubsequence`; it exits
if any is missing. `--wallet-sync-source=disabled` is fine on regtest because the enforcer
mines to its own wallet.

### 3.3 Mine, propose slot 130, activate

On regtest the enforcer can mine and ack for you:

```bash
# the enforcer mines to an explicit address; take one from its own wallet
MADDR=$(grpcurl -plaintext -d '{}' $EA cusf.mainchain.v1.WalletService/CreateNewAddress | python3 -c "import json,sys; print(json.load(sys.stdin)['address'])")
gen() { grpcurl -plaintext -d "{\"blocks\":$1,\"address\":\"$MADDR\"}" $EA cusf.mainchain.v1.MiningService/GenerateToAddress >/dev/null 2>&1; }

gen 101      # mature a coinbase

# the ack policy is persisted in the block producer, not passed per call
grpcurl -plaintext -d '{"ack_all":true}' $EA cusf.mainchain.v1.BlockProducerService/SetAckAllProposals >/dev/null 2>&1

HID1=$(printf 'a%.0s' {1..64}); HID2=$(printf 'b%.0s' {1..40})     # any 32 + 20 bytes will do on regtest
grpcurl -plaintext -d "{\"sidechain_id\":130,\"declaration\":{\"v0\":{\"title\":\"FreeBank\",\"description\":\"regtest\",\"hash_id_1\":{\"hex\":\"$HID1\"},\"hash_id_2\":{\"hex\":\"$HID2\"}}}}" \
  $EA cusf.mainchain.v1.BlockProducerService/SubmitSidechainProposal >/dev/null 2>&1
gen 12       # regtest activation window

grpcurl -plaintext -d '{}' $EA cusf.mainchain.v1.ValidatorService/GetSidechains | grep -q '"sidechainNumber": 130' \
  && echo "slot 130 active" || echo "slot 130 NOT active - rerun the two grpcurl calls above without >/dev/null to see the error"
```

A different enforcer build may expose these under other service names —
`grpcurl -plaintext $EA list` shows what yours serves.

### 3.4 Start freebankd

```bash
"$FBBIN/freebankd" -regtest -daemon -datadir="$W/fb" -server -rpcuser=t -rpcpassword=t \
  -mainchaintransport=enforcer -enforceraddr=$EA -mainchainrest=127.0.0.1:19443 \
  -cusfbundleformat=1 -minwithdrawal=1

FB="$FBBIN/freebank-cli -regtest -datadir=$W/fb -rpcuser=t -rpcpassword=t"
until $FB getblockcount >/dev/null 2>&1; do sleep 1; done
$FB getmainchainblockcount      # {"blockcount": 113} - the node's height after the steps above
```

Flags: `-mainchaintransport=enforcer` reaches the mainchain through the enforcer's gRPC —
it must be given explicitly on regtest, whose default transport is the legacy `jsonrpc`
mode; `-enforceraddr` is that gRPC address (default `127.0.0.1:50051`); `-mainchainrest`
is the node's REST endpoint (default `127.0.0.1:38332`; used to credit deposits);
`-cusfbundleformat=1` builds withdrawal bundles in the enforcer's layout (regtest-only
flag); `-minwithdrawal=1` lets a single withdrawal form a bundle (default 10 — v0.2.8 does
not list this flag in `freebankd -help`, but it is real). On regtest the signet-challenge
pin is not required.

v0.2.8 prints `Warning: mainchain enforcer L1 identity UNVERIFIED at startup ...` and
pauses about five seconds before continuing. On regtest that is expected and harmless —
the node carries on and `getmainchainblockcount` tracks the mainchain. (It is a bug in
the enforcer identity probe, fixed in the next release.)

### 3.5 Advancing the sidechain: the `bmm` helper

FreeBank has no miners and no `generate`. A sidechain block exists only when a mainchain
block commits to it (blind merged mining): `refreshbmm` posts a request paying a small bid;
the next mainchain block carries the commitment and the sidechain block connects. One tick
does not always land a block, and a tick that lands nothing still spends the bid — so
**always advance to a target height, never loop a fixed count**:

```bash
bmm() {   # advance the sidechain by at least $1 blocks (it can overshoot by one)
    local target=$(( $($FB getblockcount) + $1 )) tries=0
    while [ "$($FB getblockcount)" -lt "$target" ]; do
        $FB refreshbmm 0.001 >/dev/null 2>&1 || true
        gen 1; sleep 1
        tries=$((tries + 1))
        [ "$tries" -gt $(( $1 * 20 + 60 )) ] && { echo "BMM not advancing"; return 1; }
    done
    $FB refreshbmm 0.001 >/dev/null 2>&1 || true    # template a candidate for the next tick
}
```

`refreshbmm` returns non-zero on a tick with nothing to do — that is normal, hence
`|| true`.

### 3.6 Fund the sidechain (peg-in)

A deposit is a mainchain transaction into the sidechain's escrow output, built by the
enforcer's wallet. Give it a **plain** FreeBank address from `getnewaddress`:

```bash
grpcurl -plaintext -d "{\"sidechain_id\":130,\"address\":\"$($FB getnewaddress '' legacy)\",\"value_sats\":500000000,\"fee_sats\":1000000}" \
  $EA cusf.mainchain.v1.WalletService/CreateDepositTransaction     # prints {"txid": {"hex": "..."}}
gen 1        # the deposit lands on the mainchain
bmm 3        # the sidechain credits it
$FB getbalance     # 5.00 (the 0.01 fee_sats is paid by the enforcer's wallet, not deducted from the deposit)
```

Then split the balance into several coins. This matters: a house proves its reserves
coin-by-coin, and the proving coins cannot also pay the fee, so a wallet whose only
spendable coin is one big one would attest *nothing* — and that empty attestation still
succeeds and **replaces** the previous good one (`reservecapunits` drops to 0), so check
`gethouse` after every attest:

```bash
for i in 1 2 3 4 5 6; do $FB sendtoaddress "$($FB getnewaddress '' legacy)" 0.5 >/dev/null; done
bmm 3
$FB listunspent 1 | grep -c '"amount"'    # several confirmed coins
```

### 3.7 Your first bank: register → attest → mint → redeem

```bash
# registerhouse <tier 0-3> <threshold M> "<classid, 1-16 chars [a-z0-9], unique>" <denommg> "<pledges, coin amounts>" <fee>
#   denommg: a label in milligrams of gold, must be >0, consensus-inert - notes still redeem 1 unit = 1 sat
$FB registerhouse 0 1 "mybank" 1000 "[1.0]" 0.001      # prints {"txid": "..."}
bmm 6
$FB listhouses          # note the "id" of classid mybank; below it is $H
H=$($FB listhouses | python3 -c "import json,sys; print([h['id'] for h in json.load(sys.stdin) if h['classid']=='mybank'][0])")

$FB attesthouse $H 0.001       # prove this wallet's confirmed coins as the house's liquid till; prints {"txid": "..."}
bmm 4
$FB gethouse $H                # effective_status: open; reservecapunits > 0 (about 3,998,000,000 here = the ~3.998-coin till / the 10% reserve floor)

$FB mintnote $H 40000000 0.001 # 40,000,000 units (1 unit = 1 sat) - within min(capital cap, reserve cap); prints {"txid": "..."}
bmm 6
$FB listmynotes                # your notes, per house: units 40000000
$FB gethouse $H                # mintedunits: 40000000

$FB transfernote $H 10000000 0.001 "$($FB getnewaddress '' legacy)"   # bearer transfer (here to yourself); prints {"txid": "..."}
bmm 6
$FB redeemnote $H 10000000 0.001                                        # the issuing house redeems at par; prints {"txid": "..."}
bmm 6
$FB gethouse $H                # mintedunits: 30000000
```

You have registered a bank, proven its reserves, issued credit money, moved it, and
redeemed it. Every step is a consensus-validated transaction on your sidechain.

### 3.8 Peg out (optional)

```bash
$BC createwallet wd >/dev/null 2>&1 || $BC loadwallet wd >/dev/null 2>&1
DEST=$($BC -rpcwallet=wd getnewaddress '' legacy)        # destination must be a legacy P2PKH address
$FB createwithdrawal "$DEST" "$($FB getnewaddress '' legacy)" 1 0.01 0.01   # <mainchain dest> <sidechain refund addr> <amount> <sidechain fee> <mainchain fee>
bmm 4
# each round: 2 mainchain blocks (the enforcer votes on the bundle by itself) + 2 sidechain blocks;
# regtest payout needs 5 acks within 10 blocks, so 8 rounds is comfortable (it usually lands after 1-2)
for r in 1 2 3 4 5 6 7 8; do gen 2; bmm 2; done
$BC -rpcwallet=wd getreceivedbyaddress "$DEST" 0        # 1.00000000
```

### 3.9 Stop and reset

```bash
$FB stop; $BC stop; pkill -f "bip300301-enforcer.*$W/enf"
rm -rf "$W"        # start over from 3.1 whenever you like
```

---

## 4. Instrument cookbook

Every command below is exercised by the integration suite. Conventions: `$FB` is your
`freebank-cli` (section 3.4); `$H` is a house id; `bmm N` advances N sidechain blocks;
the trailing fee argument is optional on every wallet RPC that takes one (default 0.001
coin) — the examples pass it explicitly. Amounts are **coins** (decimal, e.g. `0.5`) for
pledges, escrow, bill face, discount price and fees, and **units/sats** (integers) for
notes, deposits and pool reserves.

**Two rules that apply to everything:**

1. **One state-changing operation per house per block.** A second op on the same house
   while one is pooled is refused with *"...already in the mempool - retry next block"*.
   Mine a block between operations on the same house, bill, pool or oracle submitter.
2. **A returned txid does not mean acceptance** (the callout in section 3). Assert on
   `getrawmempool` or on chain state, never on exit status.

### 4.0 Two wallets, two houses (the state the two-party recipes assume)

The recipes in 4.3, 4.4 and 4.7 need a second wallet and a second house. `freebankd` has
no `createwallet` RPC (the chassis predates it): wallets are created by restarting with
`-wallet=<name>` flags, and only the wallets you list are loaded — so list the default one
too, to keep section 3's bank:

```bash
$FB stop; sleep 2
"$FBBIN/freebankd" -regtest -daemon -datadir="$W/fb" -server -rpcuser=t -rpcpassword=t \
  -mainchaintransport=enforcer -enforceraddr=$EA -mainchainrest=127.0.0.1:19443 \
  -cusfbundleformat=1 -minwithdrawal=1 -wallet=wallet.dat -wallet=b
until $FB -rpcwallet=wallet.dat getblockcount >/dev/null 2>&1; do sleep 1; done
W1="$FB -rpcwallet=wallet.dat"    # section 3's wallet: owns house "mybank" ($H1)
W2="$FB -rpcwallet=b"             # new, empty
H1=$H

# fund the second wallet with a fresh peg-in (not from W1: draining mybank's till would shrink its reserve cap)
grpcurl -plaintext -d "{\"sidechain_id\":130,\"address\":\"$($W2 getnewaddress '' legacy)\",\"value_sats\":300000000,\"fee_sats\":1000000}" \
  $EA cusf.mainchain.v1.WalletService/CreateDepositTransaction
gen 1; bmm 3                                                       # $W2 getbalance -> 2.99999 (a 1,000-sat sidechain deposit fee goes to the block producer's coinbase - wallet.dat here; in 3.6 that was the same wallet, which is why it read 5.00)
for i in 1 2 3; do $W2 sendtoaddress "$($W2 getnewaddress '' legacy)" 0.4 >/dev/null; done; bmm 3   # its float
$W2 registerhouse 0 1 "otherbank" 1000 "[1.0]" 0.001; bmm 6
H2=$($FB listhouses | python3 -c "import json,sys; print([h['id'] for h in json.load(sys.stdin) if h['classid']=='otherbank'][0])")
$W2 attesthouse $H2 0.001; bmm 4
$W2 mintnote $H2 20000000 0.001; bmm 6

# cross-holdings: each wallet now holds some of the OTHER house's notes
$W1 transfernote $H1 5000000 0.001 "$($W2 getnewaddress '' legacy)"; bmm 6
$W2 transfernote $H2 3000000 0.001 "$($W1 getnewaddress '' legacy)"; bmm 6
$W2 listmynotes    # 17,000,000 of otherbank (20,000,000 minted - 3,000,000 sent) + 5,000,000 of mybank
$W1 listmynotes    # 25,000,000 of mybank + 3,000,000 of otherbank
# from here on, wallet RPCs need -rpcwallet: use $W1/$W2 wherever later sections show a bare $FB
```

In what follows `$HOUSE` means the wallet that owns the house in question and `$HOLDER` a
wallet holding its notes — here `$W1` is `mybank`'s house wallet and `$W2` holds 5,000,000
of `mybank`'s notes. Once two wallets are loaded, a bare `$FB` only works for node RPCs
(`listhouses`, `getbill`, `getpool`, `refreshbmm`…); run the single-wallet recipes in
4.1, 4.2, 4.4, 4.6, 4.7 and 4.9 as `$W1`, or redefine `FB="$FB -rpcwallet=wallet.dat"`
(node RPCs accept the selector too).

### 4.1 Discount houses

```bash
$FB registerhouse 0 1 "solo"    1000 "[0.5]"          0.001   # tier 0: bonded solo
$FB registerhouse 1 1 "encsolo" 1000 "[0.5]"          0.001   # tier 1: encumbered solo
$FB registerhouse 2 2 "fixed"   1000 "[0.3,0.3]"      0.001   # tier 2: restricted M-of-N, fixed partner set
$FB registerhouse 3 2 "club"    1000 "[0.3,0.3,0.3]"  0.001   # tier 3: multi-partner, open to admission
```

- Tiers set the issuance multiplier on pledged escrow: 1.0× / 1.5× / 2.0× / 3.0×. Minimum
  pledge 0.1 coin; up to 64 partners. Duplicate `classid` is refused. The fourth argument
  (`denommg`) is a recorded label only; nothing in consensus reads it.
- **Attestation.** `attesthouse <id> <fee>` publishes this wallet's confirmed coins as the
  till. An attestation proves the till *as of* a recent block (its as-of height); it must
  land within 72 blocks of that height and later than the previous attestation.
  `attestedratiobps` = attested till ÷ (`mintedunits` + `depositunits`), in basis points:
  the house is Open while ≥ 1000 bps (10%) and needs ≥ 1500 bps (15%) to recover from
  Stressed. One attestation every 144 blocks keeps a house Open; every ~72 leaves margin.
  A house that has never attested has `reservecapunits = 0` and cannot mint.
- `topuphouse <id> <partner index> <amount> <fee>` — add escrow (allowed while Stressed or
  Deferred: it is recovery capital).
- `admitpartner <id> <pledge> <fee>` (tier 3), `exitpartner <id> <partner index> <fee>`
  (tier 3; a leaving partner's pledge is tail-locked ~3 years), `winddownhouse <id> <fee>`
  (effective-Open only; refused while `mintedunits + depositunits > 0` — a chartered
  pool's note reserve still counts, so `retirepool` first), then
  `reclaimpledge <id> <partner index> <fee>`.
- Read: `listhouses`, `gethouse <id>`. `status` holds only what is stored (`open`,
  `wounddown`); **read `effective_status`**, which derives Stressed, Deferred and
  Insolvent at the tip. Other useful fields: `activeescrow`, `mintedunits`,
  `depositunits`, `mintcapunits`, `reservecapunits`, `attestedratiobps`, `brassagebps`,
  `lastattestheight`, `stress_since`, `partners[]`.

### 4.2 Bills of exchange

```bash
BODY=$(head -c 64 /dev/urandom | xxd -p -c 256)     # the (encrypted) commercial body; bill id = hash of it
NOW=$($FB getblockcount)
$FB issuebill "$BODY" 1 0.75 $((NOW + 200)) 5 0.001  # <body hex> <face coins> <escrow bond coins> <maturity height> [grace blocks=1008] [fee]; prints {"txid","bill_id"}
                                                    # (the issuing wallet must hold the bond + fees spendable: ~0.76 coin here; section 3 leaves ~2.99)
bmm 6
ID=$($FB listbills | python3 -c "import json,sys; print(json.load(sys.stdin)[-1]['id'])")
TO=$($FB getnewbillpubkey | python3 -c "import json,sys; print(json.load(sys.stdin)['pubkey'])")   # the recipient mints a fresh 33-byte pubkey
$FB endorsebill "$ID" "$TO" 0.001; bmm 6            # title moves; getbill shows endorsements[{from,to,at_height}]
$FB retirebill "$ID" 0.001; bmm 6                   # drawee pays face to the holder; bond returns; status "r"

# default path: a second bill with a short maturity, left unpaid (the issuing wallet needs ~0.76 coin spendable: bond + fees)
BODY2=$(head -c 64 /dev/urandom | xxd -p -c 256); NOW=$($FB getblockcount)
$FB issuebill "$BODY2" 1 0.75 $((NOW + 20)) 5 0.001; bmm 6
ID2=$($FB listbills | python3 -c "import json,sys; print(json.load(sys.stdin)[-1]['id'])")
bmm 30                                              # past maturity (20) + grace (5)
$FB claimbillescrow "$ID2" 0.001; bmm 6             # the holder takes the bond; status "d"
# dishonour: a liable party (drawer or a prior endorser) pays the holder and steps into the position
$FB recoursebill "$ID2" 0.001; bmm 6
```

Bill status letters: `a` active, `r` retired, `d` defaulted. In v0.2.8 `issuebill` is a
*single-wallet handshake*: the issuing wallet plays drawer, acceptor and initial holder
with fresh keys (so above, the same wallet later claims the bond). Consensus already
requires two distinct signatures (drawer and acceptor) — the tooling for two independent
wallets to draw and accept is the next item on the build queue.

### 4.3 Discounting a bill to a house (credit creation)

Two wallets from 4.0: the house (`$W1`, owning `$H1` — effectively Open, attested within
the last 144 blocks, and holding at least two confirmed coins, because `signdiscount`
proves live reserves and pays its fee from a coin outside the proof set) and the merchant
(`$W2`). The merchant draws a bill, then three messages:

```bash
$W1 attesthouse $H1 0.001; bmm 4                                    # signdiscount (like mintnote) needs an attestation <= 144 blocks old
BODY=$(head -c 64 /dev/urandom | xxd -p -c 256); NOW=$($FB getblockcount)
$W2 issuebill "$BODY" 0.5 0.4 $((NOW + 400)) 5 0.001; bmm 6         # face 0.5 coins, bond 0.4
ID=$($W2 listmybills | python3 -c "import json,sys; print(json.load(sys.stdin)[-1]['id'])")

PROP=$($W2 proposediscount $ID $H1 0.475 200 | python3 -c "import json,sys; print(json.load(sys.stdin)['proposal'])")   # seller: <bill> <house> <price in COINS <= face - despite `help` saying units> [expiry blocks, default 252, max 1008]; 5% discount
HEX=$($W1 signdiscount "$PROP" 0.001 | python3 -c "import json,sys; print(json.load(sys.stdin)['hex'])")            # house: mints the note leg, proves reserves, signs; pays the fee
$W2 completediscount "$HEX"                                                                                       # seller: re-verifies terms, signs title, broadcasts; prints {"txid": "..."}
bmm 6
$FB getbill $ID          # owner_house_id == $H1
$FB listloanbook $H1     # the bill is now a loan asset; face_matches true
$W2 listmynotes          # the seller holds 47,500,000 more of mybank's notes
```

The house must have room: `mintedunits + depositunits + price` must stay within
`mintcapunits` — which `gethouse` reports as a *total* (min of the capital cap λ·E and the
reserve cap R/ρ), not as remaining room — here 30,000,000 + 47,500,000 = 77,500,000
against a 100,000,000 capital cap — and the house re-proves live reserves for the new
total. If `signdiscount` says *"Attestation is stale"*, re-attest (7.1). Title transfer and
payment are bound in one transaction: the house cannot take the bill without paying, and the seller cannot take the
notes without conveying title. A house-held bill is retired by the drawee as usual
(`retirebill` routes to the house-side twin), or claimed by the **house** wallet after
maturity + grace; recourse is refused on house-held paper.

### 4.4 Notes: transfer, redeem, demand, protest

Signatures, not steps (section 3.7 already ran them):

```bash
$HOUSE mintnote $H 40000000 0.001                      # reserve- and capital-capped
$HOUSE transfernote $H 10000000 0.001 "<P2PKH address>" # bearer transfer; omit the address to split to yourself
$HOUSE redeemnote $H 30000000 0.001                    # the ISSUING house burns its own notes and pays par from reserves
```

- **Only the issuing house can `redeemnote`** its own notes (a house wallet holding its
  own paper uses it). A bearer in another wallet gets par by `demandnote` (below) or sells
  into the house's pool (4.6). `redeemnote`/`demandnote`/`claimnote` units must equal one
  holder-key's coins exactly — split first with a self `transfernote` if needed.
- **Formal demand (bearer redemption at par)** — with 4.0's state, `$HOLDER` = `$W2`
  holding `mybank` notes and `$HOUSE` = `$W1`:

```bash
$W2 transfernote $H1 1000000 0.001; bmm 6 # split off exactly the units to demand (the exact-match rule above)
$W2 demandnote $H1 1000000 0.001          # notes move into consensus custody with a standing payout authorisation
bmm 2
$W1 dischargedemands $H1 0.001            # the house pays the oldest demand: par exactly inside the window; {"txid","remaining"}
bmm 2
$FB gethouse $H1                          # mintedunits down by 1,000,000; $W2 now holds 4,000,000 of mybank (+ whatever 4.3 added)
```

  If the house lets a demand lapse past the demand window (1008 blocks on main, 12 on
  regtest), the holder **protests**: `$W2 protestnote $H1 0.001`. A live protest makes
  the house Stressed (`protest_open` in `gethouse`); attesting does not clear it — only
  discharging does. Demanded notes cannot be transferred.
- **Insolvency claim:** once a house is effectively Insolvent, each bearer claims pro-rata
  from the escrow pot: `claimnote $H <units> 0.001`. The first claim materialises the
  snapshot (`insolventpot`, `insolventunits`). Partners recover any residual afterwards
  with `reclaimpledge`.
- Read: `listmynotes` → per house `units`, `demanded_units`, `redeemable`, `demandable`,
  `house_status` (a single letter here — `o/s/d/i/w`; `gethouse` gives the full word).

### 4.5 The option clause (deferral)

A **Stressed** house may suspend redemption for a bounded window rather than fail:

```bash
$HOUSE deferhouse $H 0.001         # Stressed only (refused at Open); needs an attestation <= 144 blocks old and locks at least the attested till into the claim pot; effective_status: deferred
$HOUSE renewdeferral $H 0.001      # once, extends the window
# ...recover: add capital (topuphouse / a deposit from the mainchain), then
$HOUSE attesthouse $H 0.001; bmm 4  # at >= 15% the house returns to open
$HOUSE releasereserves $H 0.001     # unlocks the till again
```

While deferred: `redeemnote`, `mintnote` and `reclaimpledge` are refused; holders may
`demandnote` (queued; interest accrues at 5%/yr from the demand date); `topuphouse` is
accepted. The window is 12,960 blocks (~90 days) with one renewal. Invoking deferral
**replaces** the 1008-block Stressed → Insolvent clock with the deferral window; it does
not reset `stress_since` — only a ≥15% attestation does — and an open protest is not
cleared by it. A house that has not recovered when the window ends derives Insolvent. A
house that became Stressed by *missing* its cadence must re-attest (truthfully, below the
floor) before it can defer. A second deferral inside ~36 months, or cumulative suspension
beyond ~9 months (the renewal is refused at that point too), is barred
(`confidence_dead` in `gethouse`). To try it on regtest, advance ~290 blocks without
attesting (7.1) or restart `freebankd` with `-attestcadence=4`.

### 4.6 Term deposits

```bash
MAT=$(( $($FB getblockcount) + 80 ))
$FB originatedeposit $H 40000000 500 $MAT 0.001    # <house> <principal sats> <rate bps/yr> <absolute maturity> <fee>
$FB transferdeposit  $H 40000000 0.001              # whole receipt to a fresh key
$FB withdrawdeposit  $H 40000000 0.001              # refused before maturity; after it pays principal + accrued
$FB claimdeposit     $H 40000000 0.001              # in insolvency: after noteholders, capped at principal
```

Notes and deposits share one cap: N + D ≤ λ·E. Deposits are never redeemable early (early
liquidity means selling the receipt) and are junior to notes in the waterfall.

### 4.7 Clearing pool (AMM)

```bash
$FB createpool $H 20000000 20000000 30 0.001        # <house = pool id> <note units> <base sats> [fee bps 1..100, default 30] [fee]; one pool per house, forever
$FB getpool $H                                        # note_reserve, btx_reserve, lp_supply, fee_bps
read X Y < <($FB getpool $H | python3 -c "import json,sys; p=json.load(sys.stdin); print(p['note_reserve'], p['btx_reserve'])"); IN=1000000
OUT=$(python3 -c "x=$X; y=$Y; f=$IN*9970; print(f*y//(x*10000+f))")   # exact x·y=k quote after the 30 bps fee
$FB swapnote $H "noteforbtx" $IN $OUT 0.001          # or "btxfornote"; refused if minout exceeds the executable quote
$FB addpoolliquidity    $H 1000000 1000000 0.001
$FB removepoolliquidity $H 500000 0.001
$FB listmylp                                          # your LP position per pool
$FB retirepool $H 0.001                               # only once lp_supply is down to the 1000-unit floor
```

Every pool op except creation is ungated by house status — selling at a discount is the
legitimate exit from a stressed house. Pools never mint or burn units except at retire.
(`btx` in these field names is the base coin — the same thing the rest of this document
calls ECX or sats.)

### 4.8 Bilateral settlement-to-par

Two houses holding each other's notes — both effectively Open and attested within one
cadence (144 blocks), i.e. *par-eligible* — settle the net at par. With 4.0's state alone,
`$W2` (`otherbank`) holds 5,000,000 of `mybank`'s notes and `$W1` holds 3,000,000 of
`otherbank`'s, so `otherbank` is the net **creditor** and initiates (the responder must
itself hold presentable notes of the initiator's house, or `signsettle` refuses with
"nothing to exchange"):

```bash
$W1 attesthouse $H1 0.001; $W2 attesthouse $H2 0.001; bmm 4   # both par-eligible: Open, above the floor, attested within 144 blocks
$W2 listpresentable $H1                                   # what otherbank could present to mybank
PROP=$($W2 proposesettle $H2 $H1 | python3 -c "import json,sys; print(json.load(sys.stdin)['proposal'])")   # <own house> <counterparty> [max units] [expiry blocks]
HEX=$($W1 signsettle "$PROP"     | python3 -c "import json,sys; print(json.load(sys.stdin)['hex'])")        # debtor responds
$W2 completesettle "$HEX"                                 # initiator counter-signs and broadcasts
bmm 6
$W2 listsettlements    # (a wallet RPC) both houses' mintedunits fall by the presented units; the 2,000,000-sat net is paid to otherbank's wallet at par
# With 4.0's state alone these three calls net 2,000,000 (5,000,000 vs 3,000,000). If you ran 4.3 and
# 4.4 first, otherbank holds two coins of mybank's notes (47,500,000 + 4,000,000) and a settlement presents
# whole coins: as written it presents 47,500,000 against 3,000,000 - residual 44,500,000. Capping the
# proposal ($W2 proposesettle $H2 $H1 5000000) presents the 4,000,000 coin instead - net 1,000,000 - but
# run it INSTEAD of the uncapped proposal: once a settlement has consumed W1's otherbank notes there is
# nothing left to exchange, and a house cannot settle again for 12 blocks anyway.
```

The debtor house's wallet must hold the residual in spendable coin (here `mybank`'s
wallet pays it).

If `proposesettle` answers `"status": "consolidating"`, wait for that txid to confirm and
re-run. One settlement per **house** per cadence window (144 blocks on main, 12 on
regtest) — the stamp lives on each house record, so a house that just settled with B
cannot settle with C until its window passes; an `attesthouse` on either house displaces
a pooled settlement.

### 4.9 Gold oracle (consensus-inert)

```bash
$W1 bondoraclesubmitter 0 1.0 0.001              # [id, 0 = new] [bond coins] [fee]; one new registration per block; the id is assigned at confirmation
bmm 1
$FB listoraclesubmitters                         # re-read the id from here once the bond confirms
SUB=$($FB listoraclesubmitters | python3 -c "import json,sys; print(json.load(sys.stdin)[-1]['id'])")
$W1 submitoracleprice $SUB 800000000 0.001       # <submitter id> <milligrams of gold per 1000 ECX> <fee>; the number is an arbitrary example
$FB getgoldfix                                   # {"raw": lower median, "braked", "fixheight", "ageblocks"}; prints nothing (JSON null) before the first fix
$FB getgramrate                                  # the fixed display scale used for the _grams fields (unrelated to the oracle)
```

A fix forms only when a quorum of distinct submitter ids (3) submits in the same block.
One wallet may bond several ids (one registration per block) and submit for all of them.
Rises track immediately; falls are braked. Nothing in consensus reads the fix.

### 4.10 Withdrawal (peg-out)

See 3.8. `createwithdrawal <mainchain address> <sidechain refund address> <amount> <sidechain fee> <mainchain fee>`;
`listmywithdrawals`; `getwithdrawal <id>` (status walks `Unspent` → `Pending - in WithdrawalBundle` → `Spent`);
`createwithdrawalrefundrequest <id>` to cancel a still-Unspent withdrawal;
`refundallwithdrawals` for all of them. Destinations must be legacy P2PKH — a chassis
limitation.

---

## 5. Running against a live network

This is where you **join what is actually running** — the front door of section 2. The stack is the
same shape as section 3; what changes is that you no longer own the block clock. Two consequences
to internalise before you start:

- **Operating, not just watching.** Everything in the section-4 cookbook works here — you point the
  same `freebank-cli` RPCs at a `freebankd` on the live network. But a FreeBank block only appears
  when a BMM request wins inclusion in a mainchain block, so an operation that needs *N* sidechain
  blocks takes *N* block intervals (minutes to hours), not seconds. To *write* at all you need the
  **write path**: your own `freebankd` plus an enforcer whose wallet holds live coins, posting
  `refreshbmm` on a timer (5.2). A BitWindow-only setup (5.3) *follows* the chain — it does not by
  itself fund and post your BMM requests.
- **It is disposable.** Alpha — and the beta and mainnet forks after it — reset to fresh chains; any
  house you register or bill you issue on a live *test* network is expected to vanish at the next
  reset (2.3). Keep nothing there you are not willing to lose.

### 5.1 The public daily-reset signet

Follow [`doc/signet.md`](doc/signet.md). The shape is the same as section 3 with a signet
node instead of regtest, the project's signet challenge and seed node, and one extra
**mandatory** flag: `-mainchainchallenge=<the signet's challenge hex>`. That is FreeBank's
L1 identity pin — two custom signets share a chain name *and* a genesis hash, so the
challenge is the only thing that tells them apart. The chain resets daily at 09:00 UTC;
after a reset, give the enforcer and `freebankd` fresh datadirs and delete `peers.dat`.

### 5.2 The eCash alpha network

Followable by `freebankd` from v0.2.9 (section 2.3). The L1 side first, then the node:

- **Node:** the alphanet build of the LayerTwo Labs L1 (`L1-ecash-bitcoin-alphanet-<triplet>.zip`
  from https://releases.drivechain.info/), run as `chain=main` with `drivechain=1`,
  `txindex=1`, `rest=1`, a `zmqpubsequence` endpoint, and enough `dbcache` for your RAM.
  Fork height 963,648; network magic `eca5a104`. Sync: a full IBD from genesis takes
  days. An assumeutxo snapshot at height 935,000 is published at `data.drivechain.dev`,
  but as of Aug 2026 the file starts with the **drynet4** network magic and an
  unmodified alphanet node refuses it. The fix is one byte: patch offset **9** to `0xa1`
  (verify the offset against the current file first — a re-published corrected file needs
  no patch), then `loadtxoutset` accepts it. After loading, sync forward and pin the tip
  with `-assumevalid=<known-good tip hash>`; snapshot-plus-sync-forward is ~4.5 h versus
  days for a full IBD. (The pre-fork UTXO set is real Bitcoin's, so a `dumptxoutset`
  from any Bitcoin node at a supported height is an alternative.)
- **Enforcer:** a recent build with `--network-preset=alphanet` (v0.3.4 was the first to
  carry it), pointed at the node's RPC and ZMQ, default gRPC on `127.0.0.1:50051` (section
  3 used 50151 only to avoid collisions). Builds from mid-August 2026 on fetch only headers
  below the activation height, which lets an enforcer on an assumeutxo node reach the tip
  in minutes; older builds scan every block from genesis —
  stalling at the assumeutxo gap unless the full history is present, and growing RSS with
  the backlog until a low-memory box runs out of RAM. Then
  `grpcurl -plaintext 127.0.0.1:50051 cusf.mainchain.v1.ValidatorService/GetSidechains`
  lists slot 130 once the validator is past 996,485.
- **`freebankd` (v0.2.9 or later)** — on its `main` network (no `-regtest`), pinned to
  the alphanet fork block. This is the exact command that followed the alphanet tip on
  2026-08-28; substitute your node's RPC port and credentials:

  ```bash
  freebankd -daemon -server -rpcuser=user -rpcpassword=pass \
    -mainchaintransport=enforcer -enforceraddr=127.0.0.1:50051 -mainchainrest=127.0.0.1:18303 \
    -mainchainchain=main \
    -mainchainblockpin=963648:0000000000b360c17636b7a6c366e3effbe91a847eb5d61b7a7b29476439e924
  freebank-cli -rpcuser=user -rpcpassword=pass getmainchainblockcount   # the alpha tip
  ```

  A wrong pin hash is refused at startup with an identity-mismatch error; that is the
  point of the pin — alphanet, real Bitcoin and the next forknet are byte-identical below
  the fork height. Then run `refreshbmm 0.001` on a timer (every couple of minutes). The
  BMM request is a mainchain transaction funded by the **enforcer's wallet**, so it must
  hold alpha coins (`WalletService/CreateNewAddress` gives you an address to fund); with
  `--wallet-sync-source=disabled` the wallet only learns of coins that arrive while it is
  running. Whether your requests get mined depends on miners running enforcer templates
  — the same pools that mine the other sidechains' BMM commitments.
- **Coinbase scan:** the on-chain footprint needs no enforcer at all — see 9.4.

### 5.3 The fast path: download a release and watch it sync (via BitWindow)

Sections 5.1–5.2 build the L1 and enforcer yourself. If you already run **BitWindow** — which
bundles an eCash-alpha L1 node and an enforcer — the quickest way to see FreeBank live is to drop a
downloaded `freebankd` on top of it and let it find the network on its own. As of **September 2026 the
alpha network is producing FreeBank blocks continuously**, so there is a live chain to sync.

From **v0.2.10**, `freebankd` ships a DNS seed (`seed.ecxfreebank.com`) baked into its `main` chain
params, so it discovers a peer with **no `-addnode`** — that is the whole point of this test. (Verified
end-to-end on an Apple-Silicon Mac against a BitWindow stack.)

1. **Download and verify.** On macOS use `curl`, not a browser, so Gatekeeper's quarantine flag never
   attaches to the unsigned binary:
   ```bash
   # Linux:
   curl -LO https://github.com/mbdrivechains/freebank/releases/download/v0.2.10/freebank-0.2.10-x86_64-linux-gnu.tar.gz
   # macOS (Apple Silicon):
   curl -LO https://github.com/mbdrivechains/freebank/releases/download/v0.2.10/freebank-0.2.10-arm64-apple-darwin.tar.gz

   curl -LO https://github.com/mbdrivechains/freebank/releases/download/v0.2.10/SHA256SUMS
   sha256sum -c SHA256SUMS --ignore-missing        # macOS: shasum -a 256 -c  -> OK
   tar -xzf freebank-0.2.10-*.tar.gz               # -> freebank/bin/{freebankd,freebank-cli,freebank-tx}
   xattr -dr com.apple.quarantine freebank 2>/dev/null   # macOS only: clear quarantine if present
   ```
   `freebankd` shells out to `grpcurl` for the enforcer transport — install it (`brew install grpcurl`,
   or your package manager).

2. **Point it at BitWindow's alpha stack.** Find BitWindow's enforcer gRPC (usually `127.0.0.1:50051`)
   and its mainchain bitcoind's **REST** port. The node must have been started with `-rest` (BitWindow's
   default config includes `rest=1`) and must be on eCash alpha (`chain=main`, tip near the current alpha
   height). A **pruned** node is fine for a sync test — only deposit crediting needs `txindex`.

3. **Run `freebankd` with no `-addnode`** (create the datadir first — it refuses a missing one; replace
   `<REST_PORT>`):
   ```bash
   mkdir -p $HOME/freebank-alpha/data
   freebank/bin/freebankd -datadir=$HOME/freebank-alpha/data -server -rpcuser=fb -rpcpassword=test \
     -mainchaintransport=enforcer -enforceraddr=127.0.0.1:50051 \
     -mainchainrest=127.0.0.1:<REST_PORT> -mainchainchain=main \
     -mainchainblockpin=963648:0000000000b360c17636b7a6c366e3effbe91a847eb5d61b7a7b29476439e924 \
     -grpcurlbin=$(which grpcurl) -daemon
   ```

4. **Confirm it synced:**
   ```bash
   CLI="freebank/bin/freebank-cli -datadir=$HOME/freebank-alpha/data -rpcuser=fb -rpcpassword=test"
   $CLI getpeerinfo | grep addr     # a peer at 68.183.235.153:8455 (= seed.ecxfreebank.com), found with zero config
   $CLI getblockcount               # climbs to the live FreeBank tip
   $CLI getmainchainblockcount      # matches BitWindow's alpha tip
   ```
   Success is a peer appearing on its own **plus** `getblockcount` reaching the network height — proof of
   download → seed discovery → P2P sync → L1 validation, on a machine that built none of it. If `freebankd`
   refuses to start with an identity-mismatch error, BitWindow's node is not on eCash alpha. This path only
   *follows* the chain; to produce blocks yourself, bid via `refreshbmm` (5.2) or mine them (5.4).
### 5.4 Producing blocks yourself

§5.2 makes you a *follower* — you `refreshbmm` and bid for whoever is mining to include your
request. This makes you a *producer*: you run the mining, your coinbase carries the M7 that connects
the sidechain block, and there is no bidding war. On a network as small as alpha, a few hours of
rented SHA-256 makes you the dominant producer — the most direct way to keep slot 130 advancing (or to
watch your own `freebankd`'s blocks land).

**Block-cost math.** Alpha's difficulty is pinned at the floor (`4,294,967,296` = 2³², bits
`1900ffff`): honest hash on alpha is far below what that difficulty implies for 10-minute blocks, so
blocks arrive *slower* than ten minutes and difficulty cannot retarget any lower. Work per block is
`difficulty × 2³² = 2⁶⁴ ≈ 1.845×10¹⁹` hashes, so for a hashrate *H*:

```
expected_seconds_per_block  ≈  2^64 / H      (a Poisson mean — any single block can be much faster or slower)
```

Roughly: **~1.5 PH/s → ~3.4 h/block · ~10 PH/s → ~31 min · ~30 PH/s → ~10 min** (nominal block time,
single-handed).

**The pieces:**

1. **An enforcer configured to mine** — §5.2's flags plus:
   ```
   --enable-mempool --enable-block-template-server \
   --coinbase-recipient=<your bech32 payout address> \
   --serve-rpc-addr=<ip>:<port>         # the getblocktemplate/submitblock endpoint the pool calls
   --serve-grpc-addr=0.0.0.0:50051
   ```
   The enforcer builds the coinbase for you — your payout output **plus** the BIP300 M1/M2/M4/M7
   commitments — inside the template's `coinbasetxn`; you never construct the drivechain commitments
   yourself. (The enforcer's *self*-mine and *self*-ack are regtest/signet-only — `verify_can_mine`
   errors on a `chain=main` forknet — so on alpha the blocks come from real hash even when you are the
   producer.)

2. **A solo pool** in front of `getblocktemplate` — **simplepool**
   (`github.com/LayerTwo-Labs/simplepool`; build `master`, the Aug-2026 stratum fixes matter). Its GBT
   client must request `capabilities:["coinbasetxn"]` so the enforcer supplies the ready-made coinbase.
   Payout routing: the reward follows the **worker's stratum username** (the part before the first `.`)
   — set that to your payout address.

3. **Hashpower** pointed at the pool's stratum port. NiceHash's SHA-256 market is usually supply-starved
   (orders sit unfilled); **MiningRigRentals** is the reliable source (whole rigs, per-rig minimum
   length, priced BTC/PH/day). Two gotchas no AI's training will know: MRR shows **0 hashrate for a
   custom/solo pool** (it infers the rate from a report a solo pool never sends — trust your own
   `pool.log`, not the dashboard), and set the pool's `initial_diff` **inside the rig's advertised
   optimal range**, because vardiff only retargets on an *accepted* share — set it too high and a miner
   never lands one and appears to hang.

> **The rule that makes or breaks solo mining:** the pool passes the enforcer's `coinbasetxn` through
> **verbatim**, substituting only the reward key. **Do not strip or reorder the template's
> transactions.** The coinbase carries a witness commitment computed over the template's exact tx set —
> drop a tx and you break `bad-witness-merkle-match` *and* over-claim fees (`bad-cb-amount`); the
> network silently rejects the block **after** you have paid for the hash. Mine the template as given.



---

## 6. Why it is built this way: the Scottish lineage

Everything in this section is the project's reading of the standard accounts (Checkland,
White, Dowd and their critics); historians disagree on parts of it, and FreeBank's design
does not depend on any one of them being right.

"Free banking" has two histories. The antebellum United States — where the word
*wildcat* comes from — was a half-free system: notes had to be backed by state-approved
bonds, and — so the story goes — redemption offices were sometimes placed where holders
could not reach them. Scotland, 1716–1845, was the other kind: multiple competing
note-issuing banks, redeemable in specie, no central bank, no regulator. On the project's
reading it ran for 130 years, survived the crises that wiped out dozens of English country
banks, produced tiny public losses over the whole era, and was ended by Parliament rather
than by failure — while Scotland industrialised alongside it. FreeBank inherits the
Scottish pattern deliberately: its issuers are called *discount houses* (the project's
term for a note-issuing bank whose core business is discounting bills), not *mints*.

Each mechanism in FreeBank is a translation of a Scottish one into something a chain can
enforce:

- **Multi-issuer notes.** Bank of Scotland and Royal Bank notes circulated side by side,
  separately credible, mutually redeemable. FreeBank's per-house notes work the same way;
  on-chain reserve attestation replaces "trust the bank".
- **Settlement-to-par.** From 1771 the Scottish banks met regularly, presented each
  other's notes and settled the difference. Adverse clearings punished over-issue
  automatically, and a stressed bank's notes were still accepted — at a visible discount.
  FreeBank's principle is the same: *the discount is information, not friction.* The pools
  show a house's discount in real time; the settlement op lets two houses present and net
  at par. (Multi-house clearing sweeps are designed, not yet built.)
- **The option clause.** Scottish notes of 1730–1765 promised payment on demand *or, at
  the directors' option, six months later with 5% interest* — turning a run into an
  orderly adjustment. FreeBank builds the analogue as consensus (4.5): a 90-day window,
  one renewal, 5%/yr from the date of demand, and a confidence-death guard so it cannot
  become a way of life. The historical verdict on the clause is contested (Adam Smith
  supported its ban) and the market is expected to price it visibly.
- **Unlimited liability, translated into bonds.** Partners in the provincial and private
  Scottish banks were liable to the last penny (only the three chartered banks had limited
  liability). A chain cannot reach a personal estate, so FreeBank substitutes what it can
  enforce: pre-funded partner pledges as the sole basis of the issuance cap, more leverage
  only with more partners and more co-signing, a ~3-year tail lock on any partner who
  leaves, and full public transparency of reserves — which Scotland did not have. The
  escrow bond on every bill plays the same role for the acceptor.
- **Real bills and match-funding.** Much Scottish lending was short-dated bills tied to
  goods in transit (the other staple, the cash account, is on FreeBank's not-yet-built
  list). On the project's reading the Ayr Bank died lending long against demand notes.
  FreeBank's match-funding rule encodes the lesson: long assets cannot be funded with short
  money.

Base money stays permissionless bearer money with no identity. Credit is structurally not
permissionless — you cannot lend to someone you know nothing about — so the sidechain
layers the discipline in for those who opt in. A user who never wants credit never
touches it.

---

## 7. Gotchas — symptom, cause, fix

### 7.1 Houses and attestation

- **A house attests zero reserves from a single-coin wallet, silently.** Symptom:
  `attesthouse` returns a txid; then `reservecapunits = 0` and `mintnote` refuses. Cause: an
  attest may not spend its own proven coins, so the fee is taken from coins *outside* the
  proof set, and with one coin everything is released. Fix: keep at least two confirmed
  spendable coins in the house wallet (`sendtoaddress <own address> 0.05`, wait a block,
  check with `listunspent 1`), then run `attesthouse` again — the new attestation lands at
  a later height, which is fine; attestations only need to be monotone.
- **A house that stops attesting becomes Stressed, then Insolvent — and Insolvent cannot
  be recovered.** Cadence 144 blocks; missing two (288 blocks, ~48 h at 10-minute blocks)
  derives Stressed; 1008 blocks later (~7 days) it derives Insolvent, and from there every
  attestation is rejected (`bad-house-attest-closed`) — insolvency is absorbing by design.
  Fix: run a re-attest loop (every ~72 blocks is comfortable) and alarm on
  `effective_status != open`. The only paths out of Insolvent are the noteholder claim
  waterfall (then `claimdeposit`, then partners' `reclaimpledge`) or a new house. **On
  regtest this bites too:** any session that advances more than 288 blocks without
  re-attesting (waiting out a bill's maturity, say) derives the house Stressed — re-attest
  before continuing.
- **Attestations must be fresh and monotone.** As-of height at most 72 blocks old
  (`bad-house-attest-stale`) and strictly after the last accepted one; each attempt lands at
  a new height, so a retry costs a block.
- **"Attestation is stale - attest the house's reserves before discounting!"** (also
  refuses `deferhouse`, and `proposesettle` reports the house not par-eligible): the
  house's last attestation is more than 144 blocks old. `attesthouse`, wait a block,
  retry.
- **10% floor, 15% recovery.** A truthful below-floor attest flips the house Stressed;
  12% does not restore Open. Top up the till and re-attest at ≥15%.
- **"…already in the mempool - retry next block!"** — the one-op-per-house rule (4). Wait
  a block. A settlement takes both houses' slots; an attest is deliberately *not* guarded
  and displaces a pooled settle or discount.
- **Each house needs its own wallet** (`-wallet=<name>` on `freebankd`,
  `-rpcwallet=<name>` on the CLI), otherwise two houses would attest the same coins.
- **`getbalance` can mislead funding decisions**: unconfirmed change is not spendable. Use
  `listunspent 1`.
- **Budget in blocks, not seconds.** A house needs ~5 block-slots to stand up (register,
  attest, mint, seed a pool, create the pool); on a 10-minute chain that is a multi-hour
  job.

### 7.2 Notes and redemption

- Demanded (pre-authorised) notes cannot be transferred, and only a pre-authorised demand
  can be protested. `dischargedemands` clears one demand per call.
- The redemption spread (*brassage*) is exactly 0 while the house is Open and rises
  quadratically to 4% as the attested ratio falls toward 2.5% once impaired — a run-tax
  paid into the pot the stayers will claim from.
- Deferral: see 4.5.

### 7.3 The peg

- **Give the enforcer a plain `getnewaddress` address for deposits**, not the
  `formatdepositaddress` (`s130_…`) form — the sidechain cannot parse the wrapper and the
  deposit never credits (`invalid-deposit-missing-output` in the log).
  `getdepositaddress`/`formatdepositaddress` exist for tools that expect the wrapper; the
  enforcer wants the plain address.
- A deposit needs a mainchain block *and then* a sidechain block to credit.
- A lone withdrawal never bundles unless `-minwithdrawal=1` (default 10).
- Withdrawal destinations: legacy P2PKH only; bech32 and P2SH are not decoded.
- Payout timing is the enforcer's ack threshold (5 acks / 10 blocks on regtest), not
  FreeBank's.

### 7.4 BMM and node lifecycle

- No `generate`, `getblocktemplate` or `submitblock`; blocks come only from `refreshbmm` +
  a mainchain block. `refreshbmm` returns non-zero on an empty tick — normal.
- Poll to a target height; a bid can be spent on a mainchain block that carries no
  commitment.
- After a daemon restart the first BMM request may miss the first mainchain block; the tip
  rides the second.
- If `$FB` answers with a chain you do not recognise, another `freebankd` owns the RPC
  port: `freebankd -daemon` still returns 0, but `debug.log` says `Unable to bind any
  endpoint for RPC server`. Pick other ports (3.1).
- Operations invalidated by height alone are swept from the mempool, so a pooled op may
  not be valid next block.
- On a signet, `-mainchainchallenge` is mandatory and an identity mismatch halts the node
  with exit status 66. After a signet reset, wipe all datadirs (enforcer included) and
  `peers.dat`.
- **If you run an enforcer to *mine* (5.4)** and its `getblocktemplate` never leaves `still
  syncing`, the enforcer's mempool init-sync has wedged on a dropped ZMQ sequence message
  (the L1 node's `pubsequence` queue overran its high-water mark and the arming message was
  lost). Set `zmqpubsequencehwm=100000` on the L1 node and restart the enforcer; run it
  unattended only behind a watchdog that relaunches it when it fails to serve within a few
  minutes — a *hang* (process alive, stuck) is not cleared by a plain restart-on-exit loop.
- **Boot persistence:** if `@reboot` cron (or any `user@` systemd unit) keeps the stack up,
  run `loginctl enable-linger <user>` once — without it systemd tears the user slice down a
  few minutes after an unattended reboot and takes the node, enforcer and pool with it.
  (Testing reboot-resilience over an *open* SSH session hides this: the session keeps the
  slice alive. Test with nothing attached.)
- **Power-cut durability:** bitcoind's LevelDB is fsync'd and comes back clean from a hard
  power loss (no reindex); un-fsync'd files you write yourself (helper-script state) can
  return NUL-zeroed. fsync anything you cannot afford to lose.

### 7.5 Build and upgrade

- **v0.2.8 is a consensus change** (rejects transaction version 10; enforces
  one-payout-per-burn on withdrawals). Upgrade before the chain you follow does. No disk
  format change — a binary swap. (v0.2.7 *did* change the disk format: a datadir written
  by ≤ v0.2.6 needs a one-time `-reindex`.)
- Native builds are not portable; use the static release tarball or a `depends` static
  build. For **v0.2.8**, build the static path from `master`, not the `v0.2.8` tag: that tag is missing
  `depends/Makefile` (a gitignore accident fixed right after the release; the tag was left as-is
  so `hash_id_2` stays valid). **v0.2.9 and later tags carry the full `depends` tree** — build
  those directly.
- Re-running `./configure` can leave stale archives (`undefined reference to
  boost::system::generic_category()`): remove `src/libbitcoin_util.a` and rebuild.
- **`freebankd` has two chains of its own:** `regtest` (follows a regtest L1) and `main`
  (follows any non-regtest L1 — a signet pinned by `-mainchainchallenge`, or, from
  v0.2.9, a mainnet-family forknet such as alpha pinned by `-mainchainblockpin`). There
  is no separate testnet or signet mode. Address prefix `X…`; bech32 HRP `fbk` (`fbkrt`
  on regtest).

---

## 8. Built vs designed — as of v0.2.10

| Area | Status |
|---|---|
| Two-way peg (deposits, withdrawal bundles, payout) | Built; verified end-to-end on regtest against the enforcer (deposit and withdrawal also exercised on the project's signet) |
| Bills: issue / endorse / retire / default claim / recourse | Built |
| Bill discounting to a house, house-side retire/claim, match-funding rule | Built |
| Independent two-wallet issuance tooling (A draws on B who accepts) | **Not built** (planned next) — consensus already requires two keys; the RPC plays all roles |
| Houses: register / topup / admit / exit / wind-down / reclaim, tiers 0–3 | Built |
| Reserve attestation; Open → Stressed → Insolvent machine; claim waterfall | Built; insolvency absorbing |
| Option clause: defer / renew / release; brassage | Built; dials provisional |
| Notes: mint / transfer / redeem at par | Built |
| Bearer redemption: pre-authorised demand, unilateral discharge, protest | Built |
| Term deposits | Built |
| Clearing pools (AMM) | Built |
| Bilateral settlement-to-par | Built |
| Multi-house clearing sweeps / par-attractor | **Not built** (designed) |
| Gold oracle | Built, **consensus-inert** |
| Enforced gold redemption; gram-denominated notes | **Not built** (designed) — notes redeem 1:1 for base coin; grams are display only |
| Chaumian bearer layer over notes | **Not built** (designed; op codes reserved) |
| Cash-credit lines | **Not built** (designed) |
| Strict-DER / low-S payload signatures; L1 identity pin | Built |
| Forknet (alpha/mainnet-style L1) support in `freebankd` | Built (v0.2.9): `-mainchainblockpin` + address prefix from the L1 family; verified live on alphanet |
| Third-party audit; mutation testing | **Not done** |

Test posture: 28 end-to-end integration gates and 446 unit cases, including two-node
byte-compare convergence against a never-connected control node, reorg coverage across
every operation family, `-reindex` reproduction, and a property harness for bills. Three
inherited consensus-critical defects (from the chassis) were found and fixed in v0.2.8;
more inherited issues may exist.

**Producer caveat (the enforcer, not FreeBank):** *self-mining* a busy alpha (5.4) currently
needs a watchdog around the enforcer. Under sustained mempool churn and long uptime it can
emit a topologically-invalid block template, and a block mined from it is rejected
`bad-txns-inputs-missingorspent` — you pay for the hash and lose the block, silently. A fix
is in progress upstream; until then, cross-check `getblocktemplate` against the node's
mempool and restart the enforcer on a bad read. *Following* the chain (5.2/5.3) is unaffected.

---

## 9. Reference

### 9.1 Parameters (all PROVISIONAL pending simulation)

| Parameter | main | regtest |
|---|---|---|
| Attestation cadence | 144 blocks; Stressed after 2 missed (288) | 144 (override with `-attestcadence=<n>`, regtest only) |
| Attestation max age (as-of height) | 72 blocks | 72 |
| Reserve floor / recovery | 10% / 15% | same |
| Stressed → Insolvent window | 1008 blocks | 1008 (override `-stressedwindow=<n>`) |
| Deferral window / renewals / interest | 12,960 blocks / 1 / 5% per year from demand | 12,960 (override `-deferwindow=<n>`) |
| Demand window | 1008 blocks | 12 |
| Brassage | 0 while Open; up to 4% at a 2.5% attested ratio once impaired | same |
| Issuance multiplier by tier | 1.0 / 1.5 / 2.0 / 3.0 × active escrow | same |
| Min pledge / max partners | 0.1 coin / 64 | same |
| Partner tail lock after exit | 157,680 blocks (~3 years) | same |
| Bill grace default / cap | 1008 / 52,560 blocks | same |
| Settlement cadence per house | 144 blocks; residual band ±0.5% | 12 |
| Pool fee | 1–100 bps, default 30; 1000 LP units locked | same |
| Oracle quorum | 3 submitters in one block | 3 |
| Gram display scale | 4,822,613 sats per gram (presentation only) | 4,822,613 (override `-launchsatspergram=<n>`, regtest only) |
| Withdrawal bundle minimum | 10 (`-minwithdrawal`) | same |

### 9.2 RPC reference

`freebank-cli help <rpc>` is authoritative for each one. Fees are optional trailing
arguments (default 0.001 coin). "Wallet" RPCs run in a wallet (`-rpcwallet=<name>`);
"node" RPCs read chain state.

| RPC | side | arguments | see |
|---|---|---|---|
| `getdepositaddress` | wallet | — | 7.3 |
| `formatdepositaddress` | node | `address` | 7.3 |
| `createwithdrawal` | wallet | `address refundaddress amount fee mainchainfee` | 3.8, 4.10 |
| `createwithdrawalrefundrequest` | wallet | `id` | 4.10 |
| `refundallwithdrawals` | wallet | — | 4.10 |
| `listmywithdrawals` · `getwithdrawal` · `getwithdrawalbundle` · `rebroadcastwithdrawalbundle` | node | `getwithdrawal id` | 4.10 |
| `refreshbmm` | node | `amount [createnew] [prevblock]` | 3.5 |
| `getmainchainblockcount` · `getmainchainblockhash` | node | `getmainchainblockhash height` | 3.4 |
| `issuebill` | wallet | `bodyhex amount escrow maturityheight [graceblocks] [fee]` | 4.2 |
| `endorsebill` | wallet | `id topubkey [fee]` | 4.2 |
| `retirebill` · `claimbillescrow` · `recoursebill` | wallet | `id [fee]` | 4.2 |
| `getnewbillpubkey` | wallet | — | 4.2 |
| `listbills` · `getbill` | node | `getbill id` | 4.2 |
| `listmybills` | wallet | — (adds `roles`) | 4.3 |
| `proposediscount` | wallet | `billid houseid price [expiryblocks]` | 4.3 |
| `signdiscount` | wallet | `proposalhex [fee]` | 4.3 |
| `completediscount` | wallet | `signedhex` | 4.3 |
| `listloanbook` | node | `houseid` | 4.3 |
| `registerhouse` | wallet | `tier threshold classid denommg pledgesjson [fee]` | 3.7, 4.1 |
| `topuphouse` | wallet | `id partnerindex amount [fee]` | 4.1 |
| `admitpartner` | wallet | `id pledge [fee]` | 4.1 |
| `exitpartner` · `reclaimpledge` | wallet | `id partnerindex [fee]` | 4.1 |
| `winddownhouse` · `attesthouse` · `deferhouse` · `renewdeferral` · `releasereserves` | wallet | `id [fee]` | 4.1, 4.5 |
| `listhouses` · `gethouse` | node | `gethouse id` | 4.1 |
| `mintnote` · `redeemnote` · `claimnote` | wallet | `houseid units [fee]` | 4.4 |
| `transfernote` | wallet | `houseid units [fee] [toaddress]` | 4.4 |
| `demandnote` | wallet | `houseid units [fee] [payoutaddress]` | 4.4 |
| `protestnote` · `dischargedemands` | wallet | `houseid [fee]` | 4.4 |
| `listmynotes` | wallet | — | 4.4 |
| `originatedeposit` | wallet | `houseid principal ratebps maturityheight [fee]` | 4.6 |
| `transferdeposit` · `withdrawdeposit` · `claimdeposit` | wallet | `houseid principal [fee]` | 4.6 |
| `createpool` | wallet | `houseid noteunits btxsats [feebps] [fee]` | 4.7 |
| `swapnote` | wallet | `poolid direction amountin minout [fee]` | 4.7 |
| `addpoolliquidity` | wallet | `poolid noteunits btxsats [fee]` | 4.7 |
| `removepoolliquidity` | wallet | `poolid lpunits [fee]` | 4.7 |
| `retirepool` | wallet | `poolid [fee]` | 4.7 |
| `listmylp` | wallet | — | 4.7 |
| `listpools` · `getpool` | node | `getpool id` | 4.7 |
| `proposesettle` | wallet | `ownhouseid counterpartyid [maxunits] [expiryblocks] [fee]` | 4.8 |
| `signsettle` | wallet | `proposalhex [fee]` | 4.8 |
| `completesettle` | wallet | `signedhex` | 4.8 |
| `listpresentable` | wallet | `houseid` | 4.8 |
| `listsettlements` | wallet | — | 4.8 |
| `bondoraclesubmitter` | wallet | `[id] [bond] [fee]` | 4.9 |
| `submitoracleprice` | wallet | `submitterid price [fee]` | 4.9 |
| `getgoldfix` · `listoraclesubmitters` · `getgramrate` | node | — | 4.9 |

Retired in v0.2.8: `createasset`, `transferasset`, `transferassetcontrol` (the chassis's
colored-coin subsystem; transaction version 10 is rejected by consensus). They still
appear in `help` but refuse with "… is retired: the BitAsset subsystem (tx v10) was
removed"; the read-only `listassets` / `listmyassets` remain callable.

### 9.3 Glossary

| Term | Meaning |
|---|---|
| **ECX** | The base coin as it exists inside the sidechain — mainchain coin deposited through the peg. 1 ECX = 10⁸ sats. Not a new token. Appears as `btx` in some RPC field names (`btx_reserve`, `btxfornote`) — same thing. |
| **unit / sat / gram** | A note unit is a claim on exactly 1 sat at par. A gram is a display companion at a fixed scale. |
| **BIP 300 / 301** | The drivechain proposals: 300 = sidechain escrow, deposits and withdrawal voting on the mainchain; 301 = blind merged mining. |
| **CUSF / enforcer** | The drivechain rules running as a separate process (`bip300301_enforcer`) beside a Bitcoin node. FreeBank drives it over gRPC. |
| **BMM** | Blind merged mining: a mainchain miner commits the next sidechain block's hash in a coinbase for a fee. `refreshbmm` posts the request. |
| **CTIP** | The single mainchain UTXO holding all coins escrowed to a sidechain; every deposit and withdrawal spends and recreates it. |
| **M1–M8** | BIP 300/301 message types: M1 propose a sidechain, M2 ack it, M3 propose a withdrawal bundle, M4 ack/nack bundles, M5 deposit, M6 payout, M7 the BMM commitment (the miner's accept, in the coinbase), M8 the BMM request (the sidechain's bid transaction). |
| **slot 130** | FreeBank's sidechain number. |
| **house / partner / pledge / tier** | A discount house is a registered issuer; partners are its co-owner keys; a pledge is a partner's locked coin; the tier fixes governance shape and leverage. |
| **till** | A house's liquid reserve — the specific coins it attests. Distinct from pledged escrow (capital). |
| **attestation** | `attesthouse`: proving the till coin-by-coin against the UTXO set. |
| **Stressed / Deferred / Insolvent / Wound-down** | House statuses; the first three are derived at the tip. |
| **option clause / defer** | A Stressed house queues redemption for 90 days with interest. |
| **brassage** | The consensus redemption spread — historically the mint's coining fee. |
| **discount** | A house buying a bill below face with its own freshly minted notes. |
| **endorsement** | Transferring a bill by a signed link; each endorser becomes liable. |
| **retire / claim / recourse** | Drawee pays (bond returns) / holder takes the bond after default / a liable party pays the holder and is subrogated. |
| **demand / discharge / protest** | Formal pre-authorised request for par / the house paying it / the holder marking a lapsed demand. |
| **waterfall** | Insolvency loss order: noteholders, then term depositors, then partners' residual. |
| **presentable / settle** | Notes a house could present to their issuer; the bilateral par exchange. |
| **λ, ρ, θ** | Leverage multiplier by tier; 10% liquid-reserve floor; 2.5%, the far end of the brassage ramp. |

### 9.4 Reading a drivechain's footprint from coinbases

No sidechain API is needed to see what a drivechain-enabled mainchain has done: the
messages live in coinbase `OP_RETURN` outputs, tagged by four bytes, with the slot byte
next (`0x82` = 130):

| Message | Tag | After the slot byte |
|---|---|---|
| M1 propose sidechain | `D5E0C4AF` | the declaration blob (below) |
| M2 ack proposal | `D6E1C5DF` | the 32-byte `sha256d` of the declaration blob |
| M4 withdrawal-bundle votes | `D77D1776` | a vote vector (see the enforcer's `messages.rs`) |
| M7 BMM commitment | `D1617368` | the 32-byte sidechain block hash |

An M1's declaration blob is: version byte `0x00`, one length byte, the title, the
description, then 32 bytes `hash_id_1` and 20 bytes `hash_id_2`. Acks refer to the
proposal by `sha256d` of that blob (displayed byte-reversed, like a txid).

```bash
# list every drivechain message in one block's coinbase (any Core with the block)
BLOCKCLI="bitcoin-cli"   # with your -conf/-datadir flags
$BLOCKCLI getblock "$($BLOCKCLI getblockhash 996454)" 2 | python3 -c '
import sys, json
tags = {"d5e0c4af": "M1", "d6e1c5df": "M2", "d77d1776": "M4", "d1617368": "M7"}
cb = json.load(sys.stdin)["tx"][0]
for v in cb["vout"]:
    h = v["scriptPubKey"]["hex"]
    if not h.startswith("6a"): continue
    for tag, name in tags.items():
        i = h.find(tag)
        if i < 0: continue
        payload = bytes.fromhex(h[i + 8:])
        print(name, "slot", payload[0], "payload", payload[1:].hex())
        if name == "M1":
            blob = payload[1:]; tl = blob[1]
            print("  title", blob[2:2 + tl].decode(), "| description", blob[2 + tl:-52].decode())
            print("  hash_id_1", blob[-52:-20].hex(), "| hash_id_2", blob[-20:].hex())
'
```

---

## 10. Links, feedback, licence

- Source and releases: https://github.com/mbdrivechains/freebank
- Public demo, explorer, faucet (daily reset): https://ecxfreebank.com
- Signet connection: [`doc/signet.md`](doc/signet.md); wallet preview:
  https://github.com/mbdrivechains/freebank-gui
- Drivechain stack: https://github.com/LayerTwo-Labs/bip300301_enforcer,
  https://github.com/LayerTwo-Labs/bitcoin-patched, https://layertwolabs.com/download
- MIT licensed — see `COPYING`.

### 10.1 Reporting a problem or giving feedback

Pick the channel by what you have:

- **A concrete bug → a GitHub issue** (https://github.com/mbdrivechains/freebank/issues). A
  useful report — and enough for an AI assistant to file a complete one unaided — carries all of:
  - **Version + platform:** the full `freebankd --version` string (`vX.Y.Z-<commit>`) and
    OS/arch (Linux x86-64 or macOS arm64).
  - **Network:** regtest, the public signet, or eCash alpha — and for alpha, the L1 you
    follow and the exact `-mainchainblockpin` you started with.
  - **Repro:** the smallest ordered sequence of `freebank-cli` / `grpcurl` commands that
    triggers it, copied verbatim.
  - **Expected vs actual:** the exact error text or wrong output — copied, not paraphrased.
  - **Logs:** the relevant tail of `<datadir>/debug.log` around the failure (and the
    enforcer's stderr if it is in the path). **Redact `rpcpassword` and any keys first.**
  - **If it is a transaction:** the txid and the height it landed at (or that it never confirmed).
- **A question, an idea, or "is the network up?" → the community.** The wider BIP 300/301
  discussion — FreeBank included — happens in the **Drivechain Talk** group on Telegram: the
  fastest place for network status, design questions, and informal reports that are not yet a
  formal bug. Ideas can also go to GitHub Discussions.
- **A security vulnerability → privately, never a public issue.** Follow `SECURITY.md`, and
  describe the *class* of problem rather than a working exploit.
