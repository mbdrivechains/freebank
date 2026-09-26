# FreeBank

**Credit creation on a BIP 300/301 drivechain.** FreeBank is a Bitcoin sidechain for
free banking — *discount houses* issuing redeemable credit notes against attested
reserves, and *bills of exchange* backed by an escrow bond — in the lineage of Scottish
free banking (1716–1845), cryptographically translated. It runs as a CUSF/BIP 300–301
sidechain alongside the drivechain enforcer.

> Be your own bank. Make your own credit.

This is an exploration. It may or may not work out — but it illustrates just another
possibility that drivechains open up: not only new execution environments or scaling, but
new *monetary* arrangements settling against Bitcoin.

FreeBank is a C++ fork of the BitAssets sidechain chassis (MIT). It is **experimental,
pre-audit software** — run it on regtest/testnet/signet with test coins only.

> **New here?** Start with [`FREEBANK_GUIDE.md`](FREEBANK_GUIDE.md) — a single self-contained
> knowledge document (thesis, a verified regtest quick start, the full instrument cookbook,
> gotchas, parameters, glossary) written so you can hand it to an AI assistant and be walked
> through running your own FreeBank.

## What works today

- **BIP 300/301 sidechain**: activates into a slot, advances by blind-merged-mining (BMM),
  credits deposits (M5), produces withdrawal bundles (M3) and completes the withdrawal
  payout (M6) — the full peg-out cycle.
- **CUSF enforcer transport**: FreeBank talks to the mainchain through the CUSF
  `bip300301_enforcer` gRPC surface, invoked at runtime via `grpcurl` (nothing of the
  enforcer is vendored or linked). BMM, deposit crediting and the **full withdrawal
  peg-out** are verified end-to-end on this path (revalidated against upstream
  `135115b`, July 2026); withdrawal bundles use the enforcer's `BlindedM6` wire layout.
- **Bills of exchange** (the credit primitive): a unique, stateful instrument with
  `bill_id = sha256(encrypted_body)` as its identity (the node never decrypts the body),
  a face amount, a maturity + grace window, a consensus-enforced escrow bond posted by the
  acceptor, and ownership advanced by endorsement. Full lifecycle — issue → endorse →
  retire/default with escrow claim — runs on-chain. RPCs: `issuebill`, `endorsebill`,
  `retirebill`, `claimbillescrow`, `listbills`, `getbill`, `listmybills`.
- **Discount houses** (the issuers): registered on-chain with a pledged escrow bond and
  M-of-N partner governance; lifecycle register → top-up / admit / exit → wind-down →
  reclaim, with time-locked exit tails and a one-governance-op-per-house-per-block rule.
  RPCs: `registerhouse`, `listhouses`, `attesthouse`, and friends.
- **Credit notes** (the money): per-house redeemable credit claims. Issuance is
  **reserve-gated at mint** — a mint must prove live reserves against the cap; notes
  transfer person-to-person; the issuing house redeems at par from reserves.
- **Bearer redemption** (the holder's teeth): a note holder places a formal *demand* for
  par. Against an open house this **pre-authorises** the payout — the note coins move into
  a consensus-enforced custody script and the house **discharges** them unilaterally,
  paying par plus any in-window interest less a redemption spread, no holder signature
  needed at payout. If the house lets a demand lapse, the holder **protests** it; a live
  protest is a stress origin that turns off the house's par lamp and blocks minting, and
  if the house cannot recover it ripens into insolvency where the bearer claims the custody
  coin directly from reserves. A protest that rides through a lawful deferral re-arms at the
  recovery height rather than being cleared by it. RPCs: `mintnote`, `transfernote`,
  `redeemnote`, `demandnote`, `protestnote`, `dischargedemands`, `listmynotes`.
- **Discounting** (credit creation, the point of the whole thing): a house buys a bill of
  exchange from a holder, paying with its **own notes minted in the same operation** under
  the full reserve/leverage discipline, and books the bill as a loan asset — the Scottish
  discount-house mechanism, on-chain. Because the discount appends a real chain link,
  recourse on a defaulted bill runs holder-passive: the paying party (drawer, acceptor, or
  any prior endorser, the discount seller included) is subrogated in a fixed cascade, and a
  match-funding rule caps the book a house may build against its free escrow. Ops:
  discount, recourse, house-side retire/claim.
- **Reserve attestation and a lazy solvency machine**: houses attest their liquid till on
  a consensus cadence, proven coin-by-coin against the UTXO set. A missed cadence derives
  *Stressed*; an expired recovery window derives *Insolvent* — both computed at read time
  from on-chain heights (inherently reorg-safe). Insolvency triggers a waterfall:
  noteholders claim pro-rata from the locked escrow pot, then a whole-house residual
  settlement.
- **The option clause**, translated from the Scottish record: a stressed house may defer
  redemption for a bounded window, paying interest for the privilege, with its till locked
  into the claim pot; a consensus redemption spread (*brassage*) adds run-friction.
- **Term deposits**: time-locked deposits with a consensus interest floor and transferable
  receipts, subordinated to notes in the insolvency waterfall.
- **Clearing pools**: on-chain AMM pools between a house's notes and the base coin —
  swaps, LP shares, and orderly pool retirement. RPCs: `createpool`, `listpools`,
  `swapnote`, `addpoolliquidity`, `removepoolliquidity`, `listmylp`, `retirepool`.
- **Metric denomination (display)**: RPCs report values in grams alongside base units at
  a fixed launch scale (`getgramrate`). Presentation-only — no consensus rule reads it.

## Robustness

Consensus code is only as trustworthy as what tries to break it. Much of the work is
adversarial. The v0.2.7 line closes the two consensus issues that v0.2.6 shipped as
known-open, v0.2.7.1 closes a memory leak that fuzzing turned up, v0.2.8 closes
three consensus defects found by a line-by-line audit of the money paths inherited
from the upstream sidechain chassis, v0.2.9 makes the node able to follow a
mainnet-family L1 (the eCash alpha network) and fixes an identity check that never ran,
v0.2.11 hardens the enforcer transport against the ways a real host stack misbehaves,
v0.2.12 lets a wallet be provisioned from an external seed and ships the live fixed seed,
v0.2.13 repairs the withdrawal path for life on a shared eCash slot and opens the node to block explorers,
v0.2.14 lets block producers name their blocks and tightens the mempool to what honest wallets send,
v0.2.15 keeps deposit crediting going when an unreadable eCash transaction shares a payout's block, and
v0.2.16 lets BitWindow bid for FreeBank blocks and makes a restart with `-reindex` safe:

- **BitWindow can bid for FreeBank blocks** (v0.2.16; BitWindow's side is
  [LayerTwo Labs drivechain-frontends PR #2402](https://github.com/LayerTwo-Labs/drivechain-frontends/pull/2402),
  not yet in a BitWindow release). Three new RPCs, `get_block_template`, `connect_block` and
  `get_bmm_inclusions`, let BitWindow's blind-merged-mining engine build, bid for and connect FreeBank
  blocks. They need the enforcer transport; `get_block_template` also needs a loaded wallet (the
  coinbase pays this node). A template stays the same for one eCash round. `connect_block` answers `false` only when the block will not connect (it is invalid, or
  another block already holds its height); anything temporary is a retryable error (-40), so a paid bid
  is never abandoned by mistake. `-bmmbidder=engine` makes the engine the node's only bidder.
  `-bmmblockmaxweight` (default 300,000 weight units) caps the mempool transactions in a template;
  deposits are not capped. `setcoinbasetag` changes the coinbase tag until the next restart.
  `refreshbmm` is now refused during `-reindex`/`-loadblock` (error -10), and retries a bid the
  enforcer refused outright instead of skipping that eCash block.
- **`-reindex` no longer depends on luck** (v0.2.16). Before replaying blocks (`-reindex`,
  `-reindex-chainstate`, `-loadblock`), the node fills its eCash block cache and waits for a lagging
  enforcer. If the cache makes no progress for `-replaycachewait` seconds (default 600; 0 waits until
  shutdown), the node stops with an error; a pending `-reindex` or `-reindex-chainstate` resumes on the
  next start (`-loadblock` must be given again). Before, a replay could start with an empty cache
  and throw the chain away. The main-block and BMM cache loaders now log what they loaded.
- **Withdrawal bundles need no enforcer wallet** (v0.2.16). They go to the enforcer's
  `BlockProducerService/ProposeWithdrawalBundle`, falling back to the old wallet call only when the
  enforcer answers Unimplemented. The enforcer must serve `BlockProducerService`: run it with
  `--enable-wallet`, or without a wallet with `--enable-mempool --enable-block-template-server
  --coinbase-recipient=<address>`. An eCash reorg now checks only the newest 1,000 cached blocks
  instead of the whole cache, and `verifymainblockcache` reports where it started (`checked_from`).
  v0.2.15 and v0.2.16 have no consensus change: each is a binary swap.

- **An unreadable eCash transaction next to a withdrawal payout no longer stops deposit
  crediting** (v0.2.15). When the node looks through an L1 block for a paid bundle, it now skips
  transactions it cannot decode (an eCash version-3/TRUC transaction is one) and any that are not
  version 1 or 2, instead of halting deposit crediting for good. The payout itself is always
  version 2, so it is still found. Withdrawal bundle records also stop carrying 4 bytes of
  leftover memory. No consensus change.

- **Block producers can name their blocks** (v0.2.14). One config line, `coinbasetag=<name>` in
  `freebank.conf` (or `-coinbasetag=`), writes the producer's name into the coinbase of every block
  the node produces, after the height and the extra nonce, so explorers can credit the block to
  whoever won the BMM. 1 to 64 printable ASCII characters; the same downloaded binary for everyone.
  Without it, the [FreeBank explorer](https://explorer.ecxfreebank.com) shows the block as "unknown producer". See
  `FREEBANK_GUIDE.md` section 5.2. No consensus change: older nodes accept tagged blocks.
- **The mempool refuses deposit and withdrawal-bundle objects outside the coinbase** (v0.2.14).
  A loose transaction that carries a deposit object or a withdrawal-bundle object is refused, as
  is a withdrawal whose burn another withdrawal in the same transaction already claims (block
  validation already refuses that second claim). Honest wallets never build either. Mempool
  policy only; no consensus change.
- **Unpayable withdrawals are refused by consensus** (v0.2.13). A withdrawal whose L1 payout
  can never be paid (below the L1 dust limit, or a destination that does not decode) used to
  be accepted, and then blocked every future withdrawal bundle until its owner refunded it.
  Such withdrawals are now rejected at the mempool and in blocks, and the bundle builder skips
  any that already exist. **This is a consensus change, a soft fork active from height 0:**
  every node that validates the chain should run v0.2.13.
- **A second withdrawal bundle is possible** (v0.2.13). On the enforcer transport, the guard
  against proposing a bundle while one is pending counted every bundle the slot had ever seen,
  so after the first bundle no other could ever be proposed. It now counts only bundles L1 is
  still tracking, and refuses to propose while L1's withdrawal events cannot be read.
- **Withdrawal payouts are found by their ID, whatever the L1's opcode** (v0.2.13). eCash beta
  moved the drivechain opcode from `OP_NOP5` to `OP_NOP8`. After the first payout on such a
  network, v0.2.12 would have stopped crediting deposits. The node now identifies a paid bundle
  by recomputing the enforcer's own bundle ID from the L1 transaction, so no opcode is assumed.
- **Withdrawals to modern L1 addresses** (v0.2.13). `createwithdrawal` now accepts P2SH,
  P2WPKH, P2WSH and P2TR (taproot) L1 destinations, not only legacy P2PKH. It refuses payouts
  below the dust limit and refund addresses that are not this wallet's own legacy addresses.
  `getwithdrawal` shows the L1 form. No consensus change.
- **Explorer RPCs** (v0.2.13). `getblockstats`, `getindexinfo`, transaction `weight`, per-transaction
  `fee` in `getblock <hash> 2`, mempool `fees`, `nTx`, and a `credit` object that says what a
  FreeBank transaction did. An unmodified mempool-style explorer now runs against the node with no
  translation proxy. No consensus change.
- **The fixed seed moved to the seed's permanent address** (v0.2.13): `163.47.9.132:8455`, a
  reserved IP that survives the seed host being replaced. `seed.ecxfreebank.com` points there too.

- **Provision a wallet from a seed** (v0.2.12). `sethdseed` sets the wallet's HD seed from
  a WIF key, so every address the wallet derives is reproducible from that seed — which lets
  FreeBank be folded into a single-recovery-phrase backup the way BitWindow does its other
  sidechains (FreeBank is a legacy-wallet Core fork with no `importdescriptors`). The main
  network also now ships the live seed (`seed.ecxfreebank.com`, 68.183.235.153:8455) as a
  hardcoded bootstrap fallback beside the DNS seed. No consensus change.
- **Enforcer transport survives a host that is not quite ready** (v0.2.11). Found by
  booting freebankd under BitWindow's orchestrator on eCash alphanet. The `grpcurl`
  path is now quoted (BitWindow's macOS install dir contains a space, which split the
  command and silently disabled the transport); a failed mainchain connection check no
  longer leaves P2P network activity off until an operator runs `refreshbmm` — a
  30-second job restores it once the mainchain answers; and headers arriving while the
  mainchain is unreachable are retried rather than tripping an assertion that aborted
  the node and put a supervisor into a restart loop. No consensus change; a new
  integration gate (`enforcer_reconnect`) proves the disable → restore → resync cycle.
- **Forknet L1 identity pin** (v0.2.9). A forknet such as alphanet has no signet
  challenge and is byte-identical to Bitcoin below its fork height, so neither the
  signet pin nor the chain name can identify it. `-mainchainblockpin=<height>:<hash>`
  pins the fork block; a wrong hash refuses to start. Verified live on alphanet.
- **Withdrawal destinations follow the L1's address family** (v0.2.9). The mainchain
  address prefix used when withdrawal bundles are built and validated was fixed at the
  signet/testnet value, so no mainnet-prefix destination could be expressed. It now
  follows the L1 family the identity pin observes at startup — deterministic for every
  node on the same L1, and unchanged on every signet-following chain.
- **The enforcer identity probe verified nothing** (v0.2.9). It parsed the 80-byte
  mainchain header as the sidechain's own header type, so it always failed, every start
  warned "identity UNVERIFIED", and a wrong enforcer could never be refused. Found by
  running the public guide's quick start on the release binaries. Fixed with a plain
  SHA256d over the 80 bytes.
- **Value conservation: the vestigial colored-coin subsystem is retired** (v0.2.8).
  The chassis FreeBank was forked from shipped a generic asset-issuance feature
  (transaction version 10, `createasset`/`transferasset`) that excluded its genesis
  outputs from both halves of the value-conservation check while still crediting
  their value to the UTXO set — a raw transaction could mint base coin from nothing.
  No FreeBank instrument ever used it (bills, houses, notes, deposits, pools,
  settlement and the oracle are transaction versions 11–17), so the subsystem is
  removed outright: v10 transactions are now rejected at the transaction-check layer
  and the RPCs are gone.
- **Withdrawal burns are consumed exactly once** (v0.2.8). The burn output that
  backs a withdrawal request was inspected but never marked spent, so one burn
  could stand behind any number of withdrawal rows — and each row is a claim on the
  mainchain payout. Each burn output is now claimed at most once per transaction,
  mirroring the deposit-side fix this project shipped earlier; a withdrawal row is
  also erased if the block that created it is disconnected.
- **Withdrawal-bundle ordering is a total order** (v0.2.8). Bundle assembly sorted
  withdrawals by fee with an unstable sort, so fee ties could order differently
  between Linux (libstdc++) and macOS (libc++) — and payout order is compared
  exactly at validation, which is a cross-platform chain split waiting for a tie.
  Ties now break on the withdrawal id, which is platform-independent.
- **Sidechain-object parser fails closed** (v0.2.7.1). The parser for sidechain-object
  outputs allocated an object before deserializing into it, with no exception guard, so a
  malformed payload leaked it. Because that parser runs during mempool acceptance ahead of
  input and fee checks, and the resulting reject carried no misbehaviour score, any peer
  could repeat it for free. It now frees the object and rejects cleanly. No accept/reject
  decision changed, so a v0.2.7.1 node and a v0.2.7 node stay on the same chain.
- **Deposit reorg safety.** The deposit database's CTIP pointer is now rolled back when a
  block is disconnected, so a node that reorgs across a deposit-bearing block computes the
  same payouts as a freshly synced one. Before the fix, a reorg could strand or
  mis-pay a depositor. (Closes the last known chain-split class; advances the on-disk
  format, so an upgraded datadir re-reads once with `-reindex`.)
- **Signature canonicality.** Every operation's payload signature is now verified
  strict-DER and low-S at a single choke-point, so a keyless relayer can no longer
  re-encode a payload signature to shift an unconfirmed transaction's id.
- **Two-node convergence.** A second node boots before the first block exists and
  independently validates every block from genesis; both must match on tip, the full UTXO
  set, and every side-database (bills, houses, notes, deposits, pools, oracle) at each
  checkpoint — catching any rule written differently in the producer than the validator.
- **Reorg coverage** across every operation family, asserting disconnect is an exact
  inverse — including a deep (200+ block) reorg replayed byte-for-byte against a
  never-connected control node.
- **Recovery + format guard.** `-reindex` reproduces the chain exactly, including from a
  datadir written by an earlier version; a node reading records it cannot parse refuses to
  start and names the remedy rather than silently misparsing them.
- **Mempool-slot safety.** House-slot-taking wallet operations fail fast when another
  state-changing op for the same house is already pooled, instead of building a
  transaction the validator will reject.

28 integration gates and 446 unit tests. All must pass to merge.

## Wallet (preview)

A wallet GUI — desktop and browser (PWA) — is in development against a running
`freebankd`: notes, houses, clearing pools and bills, with balances led in grams.

![FreeBank wallet preview](doc/wallet-preview.png)

Wallet code: [mbdrivechains/freebank-gui](https://github.com/mbdrivechains/freebank-gui).

## Build

Native build (Ubuntu 24.04 shown; other platforms per standard Bitcoin Core build docs):

```sh
./autogen.sh
./configure --without-gui --with-incompatible-bdb --disable-bench
make -j"$(nproc)"
```

Binaries land in `src/`: `freebankd`, `freebank-cli`, `freebank-tx`.

> **These native binaries are NOT portable.** They link against your system's
> libraries and run only on the machine/distro that built them. The published
> release binaries are built statically (Linux via `depends`, ldd-gated to base
> libraries only; macOS via the repo's `macos-arm64` workflow) — use those, or a
> `depends` static build, for anything you intend to run on another host.

Run the unit tests:

```sh
src/test/test_bitcoin
```

## Run (overview)

FreeBank is a sidechain, so running it means running a small stack: an eCash node as the
mainchain (with `-rest=1`), the CUSF
[bip300301_enforcer](https://github.com/LayerTwo-Labs/bip300301_enforcer) watching it —
it validates the drivechain rules and can hold the mainchain wallet — and `freebankd`
driving the enforcer over gRPC (via
[grpcurl](https://github.com/fullstorydev/grpcurl)) and reading deposits from the node's
REST interface. The sidechain advances by blind-merged-mining against the mainchain:
`freebank-cli refreshbmm`, or, from v0.2.16, an engine such as BitWindow's driving
`get_block_template` and `connect_block`. FreeBank binaries come from the
[release page](https://github.com/mbdrivechains/freebank/releases).

Two things worth knowing before you start:

- **The live network is the eCash beta.** FreeBank runs as sidechain slot 130 on the eCash
  beta network, with a public seed at `seed.ecxfreebank.com` (port 8455). The beta L1 comes
  from eCash's own releases (<https://releases.ecash.com/L1-ecash-bitcoin/betanet/>; source
  [ecash-com/bitcoin](https://github.com/ecash-com/bitcoin/tree/betanet), branch `betanet`) and
  the enforcer runs with `--network-preset=betanet`. Pin the
  fork block with `-mainchainblockpin=967680:00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042`.
  The signet walkthrough below still describes the stack's shape.
- **Next to BitWindow.** A BitWindow set to the eCash network already runs the beta L1 (with
  the REST and txindex FreeBank needs) and the enforcer, and ships `grpcurl` in its `assets/bin`.
  Once both are fully synced, run the release binary beside them. It finds the seed by itself:

  ```
  freebankd -mainchaintransport=enforcer -enforceraddr=127.0.0.1:50051 \
    -mainchainrest=127.0.0.1:18302 -mainchainchain=main \
    -mainchainblockpin=967680:00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042 \
    -grpcurlbin=<BitWindow data dir>/assets/bin/grpcurl
  ```

  Don't also start FreeBank from BitWindow's Sidechains tab. Released BitWindow versions
  (0.2.231 and earlier, the current release as of 2026-09-26) launch it with the command line of
  an earlier, retired FreeBank build, and this node will not start that way.
  If you ran that earlier build, wipe its data first.
- **The full walkthrough is a separate page**: [`doc/signet.md`](doc/signet.md) —
  written for someone starting from zero, with every dependency linked, the
  network/magic-bytes pitfalls explained, and a step-by-step verification order. It is
  written for a signet: the project's public signet was retired at the end of August 2026,
  so use it for the shape of a signet stack of your own; for the live eCash beta, follow
  [`FREEBANK_GUIDE.md`](FREEBANK_GUIDE.md) sections 2.3 and 5.2. It is deliberately precise
  enough to hand to an AI coding agent — if you'd rather not drive four pieces of software by hand, pointing
  Claude Code (or another agentic assistant) at that page and asking it to do the
  bring-up with you works well.

## Verify your download

Each release lists its files' SHA-256 hashes in `SHA256SUMS`, signed with the FreeBank release key
(`SHA256SUMS.sig`). The key's public half is below and is also published as a signing key on the
maintainer's GitHub account ([mblowes](https://api.github.com/users/mblowes/ssh_signing_keys)), so you
can check it from two places:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAi2C9Lpi3gHPva6tlbLE+wdF1Cer3uUnmwZYr6SeRjR FreeBank release signing
fingerprint SHA256:1d0zm9Qb9ZtzDnQHH593fgjAkk7nPqMDG79XyWlyeeY
```

To verify (OpenSSH 8.1 or later):

```
echo 'freebank-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAi2C9Lpi3gHPva6tlbLE+wdF1Cer3uUnmwZYr6SeRjR' > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I freebank-release -n file -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

The macOS tarball is built by this repository's GitHub workflow from the tagged source, and GitHub
records a signed build attestation for it. Check it with GitHub CLI 2.49 or later, logged in
(`gh auth login`):
`gh attestation verify freebank-<version>-arm64-apple-darwin.tar.gz --repo mbdrivechains/freebank`.
Without a login, fetch the attestation from GitHub's API, take the bundle out of the wrapper the API
returns (`jq`), and pass that file with `--bundle`:

```
curl -s https://api.github.com/repos/mbdrivechains/freebank/attestations/sha256:<tarball sha256> \
  | jq '.attestations[0].bundle' > freebank.sigstore.json
gh attestation verify freebank-<version>-arm64-apple-darwin.tar.gz --repo mbdrivechains/freebank \
  --bundle freebank.sigstore.json
```

The Linux tarball is built by the maintainer. Its binaries report the maintainer's private commit
(v0.2.16: `2afa30c`), whose `src/` and `depends/` trees are identical to the public tag. Building Linux
from the public tag in CI, with an attestation, and reproducible builds so that anyone can rebuild it
byte for byte, are planned. Linux release binaries are static except for glibc and libgcc (glibc
2.38+); the macOS binaries use the system's libc++ and libSystem.

## Feedback

- **Problems / bugs** — open an [issue](https://github.com/mbdrivechains/freebank/issues)
  (the template asks for version, platform, and steps).
- **Ideas, questions, discussion** — use
  [Discussions](https://github.com/mbdrivechains/freebank/discussions).
- **Security vulnerabilities** — please email privately first: see
  [`SECURITY.md`](SECURITY.md).

## License


MIT — see [`COPYING`](COPYING). Inherited from Bitcoin Core / the BitAssets chassis.

## Status

Alpha. Consensus surfaces (bills, houses, notes and bearer redemption, discounting,
attestation/insolvency, redemption economics, term deposits, clearing pools,
deposits/withdrawals, the transport layer) have unit + integration coverage and
adversarial review; the full peg-out cycle is verified end-to-end against the CUSF
enforcer (upstream ≥ `135115b`) on regtest. Reserve and solvency parameters are
provisional pending simulation. Not yet audited; do not use with real value.

**Closed since v0.2.6.** The two consensus issues the previous release listed as
known-open are both fixed in v0.2.7: the deposit CTIP pointer is now rolled back on a
reorg (deposit reorg safety), and payload signatures are now verified strict-DER and
low-S at a single choke-point (signature canonicality). v0.2.8 closes the three
consensus defects found by an internal audit of the inherited money paths (value
conservation, withdrawal-burn consumption, withdrawal-bundle ordering — see
Robustness above). v0.2.8 is a consensus change: a v0.2.8 node rejects transaction
version 10 outright and enforces one-payout-per-burn, so upgrade before the chain
you follow does. On chains that never carried a v10 transaction or a double-claimed
burn — all known deployments — v0.2.8 revalidates the existing history unchanged.
v0.2.9 adds mainnet-family (forknet) L1 support — FreeBank is activated as slot 130 on
the eCash alpha network, and a v0.2.9 node can follow it (see `FREEBANK_GUIDE.md`
sections 2.3 and 5.2) — and fixes the enforcer identity probe, which had never
verified. On chains following a signet L1 the withdrawal-address rule is unchanged.
v0.2.13 is a consensus change (a soft fork from height 0): it refuses withdrawals that can
never be paid on L1. Chains that never carried such a withdrawal, including the eCash beta at
the time of release, revalidate unchanged; upgrade every node that validates.
v0.2.14 has no consensus change; it is a binary swap.
The standing caveats are the ones above — provisional economic parameters and no
third-party audit. Report security issues privately (see [`SECURITY.md`](SECURITY.md)).
Still test-coin software: do not use with real value.
