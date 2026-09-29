# FreeBank v0.2.16: source review (AI-assisted)

**Date:** 2026-09-26
**Reviewer:** Claude, Anthropic's AI model (model id `claude-opus-5-5`), at the maintainer's request
**Commit reviewed:** `bb427a9a52e17ea7e2c546175755ab48a6904ed1` (branch `next/v0.2.16`, `git describe` = `v0.2.15-57-gbb427a9`)
**Public release commit:** `8931edf` (public tag v0.2.16; see section 6.2 for how to confirm it carries the same code)


> **Status in v0.2.17 (added 2026-09-30, published with v0.2.17).** This review is of **v0.2.16** and is published as
> written, apart from this box and the public commit above. Its critical and high findings were **found in review
> and fixed in v0.2.17**. The box was added by the same AI assistant from the v0.2.17 source; it is a status list,
> not a new review.
>
> | ID | Status in v0.2.17 |
> |---|---|
> | C1 | **Fixed.** Every deposit record must match the enforcer's list of eCash deposits to slot 130 (outpoint, address, amount, running number), and every record must spend the treasury output of the one before it, the first included. |
> | H1 | **Fixed.** The record's destination must be the one in the eCash deposit (same check as C1). |
> | H2 | **Fixed.** `nBurnIndex` is bounds-checked before use (`CheckDepositWithL1`). |
> | M1 | **Fixed.** Only deposits owed a payout count toward the coinbase allowance. |
> | M2 | **Mostly fixed.** The enforcer is reached over a persistent HTTP connection (the Connect protocol) by default, not one `grpcurl` process per call. A header on a known parent can still cost one enforcer call. |
> | M3 | **Open.** ZeroMQ is still 4.2.2; ZMQ stays off by default. Do not expose a `-zmqpub*` socket. Planned: v0.2.18. |
> | M4 | **Mostly fixed.** `grpcurl` is no longer used by default (`-enforcertransport=grpcurl` keeps it as an option). |
> | M5, M6 | **Open** (reproducible builds). |
> | L1 | **Partly fixed.** Enforcer calls now have timeouts; the REST client is unchanged. |
> | L7 | **Fixed.** Each refund claims its own coinbase output, never one a deposit payout or another refund claimed. |
> | Other L items | Unchanged unless the v0.2.17 release notes say otherwise. |

---

## 1. What this is, and what it is not

### 1.1 What it is

This is a **read-only source review** of the FreeBank C++ node, written by an AI model (Claude) and
requested by the FreeBank maintainer. It asks four questions of the code:

1. Does the node contact anyone it should not (phone-home, telemetry, hidden listeners)?
2. How does it handle keys, wallet files, other files and external processes?
3. Can the build and its dependencies be trusted, and can a binary be tied to this source?
4. Can money on the peg (deposits, withdrawals, fees, coinbase, BMM bids) be steered to a fixed or
   hidden party, and are the peg paths sound?

The review found **one critical and two high-severity issues**, all in the deposit (peg-in) path, plus
medium and low items. They are listed in section 4 as found. The critical and high issues are known to the
maintainer. Their fixes are designed and scheduled for **v0.2.17**, so **v0.2.16 still contains them**.

### 1.2 What it is not

- **Not a guarantee.** "No finding" means "not found by this method", not "absent". An AI reviewer can miss
  things and can be wrong. Treat each finding as a claim to check. Section 6 shows how.
- **Not an audit firm's audit.** No human security firm took part. The maintainer asked for it, and the
  maintainer publishes it.
- **Not a review of the binaries.** It covers source code at one commit. Whether a downloaded binary was built
  from that source is a separate question. Section 1.3 answers it with build provenance and signed checksums,
  not with this review.
- **Not a test run.** Nothing was built, run or tested for this review (the maintainer's CI was using the
  machine at the time). Every finding comes from reading source, git history and, for the build lens,
  inspecting already-published v0.2.15 release artefacts with `strings`/`readelf`.
- **Not an economic review.** The credit layer (bills, houses, notes, pools, settlement) was checked for
  *where money goes*, not for whether the amounts and incentives are right.

**The reviewed commit is in the maintainer's private repository.** The public repository is a squashed
snapshot, so `bb427a9` cannot be resolved there. To tie the public release to the reviewed code, compare
git tree hashes. At `bb427a9` they are:

| Path | git tree/blob hash at `bb427a9` |
|---|---|
| `src/` | `cd1cbd0da66921a4808d52f58a10194513e3bd29` |
| `depends/` | `f216dc21640952731775da90583b90030f2cb13d` |
| `build-aux/` | `e58a5ea5f560352c5d17486d6b8f0550737171bf` |
| `share/` | `e3f1486df1977d37152314bce3fa5dc2832d8732` |
| `Makefile.am` | `79c06061a93e8491933456fb5089d20b8f1b078c` |
| `autogen.sh` | `27417daf7691513da832eae5541b6c5bee091551` |
| `configure.ac` | `353c41af531b68c932704e47933236c9944d51c7` (still says 0.2.15 here; the release bump changes only the version lines) |

On the public tag, `git rev-parse v0.2.16:src` (and so on for each path) should print the same hashes. The
exception is `configure.ac`, where `git diff` should show version lines only. If `src/` differs, this review
does not cover the difference. Public tag tree check: `<added at release>`.

### 1.3 Tying binaries to source (outside this review)

| Evidence | Status for v0.2.16 |
|---|---|
| Build provenance (GitHub artifact attestation) | `<added at release>` |
| `SHA256SUMS` for every release tarball | `<added at release>` |
| Signature over `SHA256SUMS` (maintainer's release key) | `<added at release>` |
| Reproducible (bit-for-bit) builds | **Not yet.** See finding M5. Guix-style reproducible builds are planned but not done. |

Until reproducible builds exist, a Linux binary can only be tied to this source by trusting the
maintainer's build machine. A macOS binary relies on GitHub's runner and Homebrew as of the build day
(finding M6). Building from source (section 6) avoids both.

---

## 2. Upstream and delta

### 2.1 Upstream base (two layers)

1. **Direct upstream: LayerTwo-Labs "BitAssets"**, a C++ BIP300/301 drivechain sidechain,
   https://github.com/LayerTwo-Labs/BitAssets (branch `BitAssets`), commit
   `ce409cbee7b11b9d8d817c455c56059849206f3d` ("Update windows & osx gitian descriptors", 2023-08-10).
   It is MIT-licensed (`COPYING` unchanged) with upstream version string 4.01.00. On 2026-09-26 this commit was
   the published tip of that branch (`git ls-remote`). **Confidence: high.** FreeBank's import commit was
   compared blob by blob with upstream `ce409cb`. All 1,552 imported files are byte-identical. The import left
   out 13 upstream files that upstream's own `.gitignore` swallows (`depends/Makefile`, 7 `depends/patches/*`,
   one `contrib/rpm` patch, three generated-dir `Makefile`s, `src/univalue/gen/gen.cpp`). A later commit
   re-added the depends and contrib ones, again byte-identical to upstream.
2. **Underneath: Bitcoin Core, 0.16.99 development line** (between v0.16.0 and v0.17.0). The newest Bitcoin
   Core commit reachable from `ce409cb` is `bf3353de9` ("Merge #12287", 2018-02-25). It was merged into the
   drivechain line in 2018, and about 605 BitAssets/drivechain commits follow it. **Confidence:
   medium-high.** This comes from merge topology and authorship in the BitAssets history, not from a tree diff
   against a Bitcoin Core checkout.

**Consequence for readers:** FreeBank carries **Bitcoin Core 0.16-era code** (P2P, wallet, RPC server) and
**2018-2023 drivechain code**. Security fixes Bitcoin Core made after early 2018 are not present unless
backported. The maintainer's earlier audits addressed some inherited issues. This review did not re-audit
the inherited base (section 5).

### 2.2 What FreeBank adds

Diff from the verbatim import to the reviewed commit: **432 files, +98,179 / -2,155 lines**. Of these,
**132 files, +33,259 / -1,635** are outside tests and documentation. Between v0.2.15 and this commit the
`src/` change is 15 files, +1,609 / -163.

| Area | Where | What changes |
|---|---|---|
| Identity / rebrand | `configure.ac`, `src/freebankd.cpp`, `src/freebank-cli.cpp`, `src/freebank-tx.cpp`, `src/util.cpp`, `src/clientversion.cpp`, `contrib/`, `doc/man/` | Binary, config, pid and datadir names (`~/.freebank`). P2P user agent `/FreeBank:<ver>/` instead of `/Satoshi:.../`. |
| Network identity, seeds | `src/chainparams.cpp`, `src/chainparamsseeds.h`, `src/chainparamsbase.cpp`, `src/consensus/params.h` | New magic, ports (P2P 8455, RPC 8454), address prefixes, bech32 HRP `fbk`, sidechain slot 130. DNS seed `seed.ecxfreebank.com`. One fixed fallback seed `163.47.9.132:8455`, run by the maintainer. Upstream fixed seeds removed. Non-configurable consensus parameters for the credit layer. Main and regtest networks only. |
| P2P handling | `src/net_processing.cpp` | Build fixes. Headers/compact blocks that fail only because the L1 is unreachable now "retry later" without penalising the peer. |
| **L1 (mainchain) client, new** | `src/l1client.cpp` (new, about 2,560 lines), `src/l1client.h`, `src/sidechainclient.*`, `src/init.cpp` | Default transport talks to the CUSF `bip300301_enforcer` over gRPC by running an external `grpcurl` binary through `popen()`, plus plain-HTTP GETs to an L1 node's REST interface. The inherited JSON-RPC transport is kept. New options: `-mainchaintransport`, `-enforceraddr`, `-grpcurlbin`, `-mainchainrest`, `-mainchainchain`, `-mainchainchallenge`, `-mainchainblockpin`, `-replaycachewait`, `-cusfbundleformat`. L1 identity pins refuse to start against the wrong L1. |
| BMM engine RPCs (v0.2.16) | `src/miner.cpp`, `src/bmmcache.*`, `src/rpc/misc.cpp`, `src/validation.cpp` | `get_block_template`, `connect_block`, `get_bmm_inclusions`, `setcoinbasetag` for an outside BMM engine. Optional coinbase tag (`-coinbasetag`, off by default). Mainchain block-cache locking and refill. |
| Consensus: new tx types | `src/primitives/transaction.*`, `src/consensus/tx_verify.cpp`, `src/validation.cpp`, `src/coins.*`, `src/undo.h`, `src/policy/policy.cpp`, `src/txmempool.cpp` | Tx versions 11-17 (bills, houses, notes, term deposits, AMM pools, settlement, gold oracle) with a txid-committed payload. Inherited v10 asset-create disabled. UTXO custody tags protect escrow outputs whose scripts are anyone-can-spend (`<id> OP_DROP OP_TRUE`), so **tag integrity is safety-critical**. Earlier peg fixes: one output cannot settle two deposits, dust deposits, CTIP baseline, withdrawal burn consumed once, total-order withdrawal sort. |
| Credit-layer modules | `src/bill.*`, `src/house.*`, `src/note.*`, `src/deposit.*`, `src/pool.*`, `src/settle.*`, `src/oracle.*`, `src/gramscale.*` | Domain logic. No new cryptographic primitives: existing secp256k1 keys and SHA-256 only. |
| Keys / signatures | `src/pubkey.*`, `src/wallet/wallet.cpp` (about +6,800), `src/wallet/rpcwallet.cpp` (about +2,700) | Strict-DER/low-S check for payload signatures. About 50 new wallet RPCs. `sethdseed` (set HD master key from a WIF). |
| Wallet file handling | `src/wallet/db.cpp`, `src/wallet/rpcdump.cpp` | Boost-version portability and help text only. |
| On-disk DBs | `src/txdb.*`, `src/init.cpp` | New LevelDB stores under `<datadir>/blocks/{Houses,Bills,Pools}`. Disk-format version gate. |
| Addresses | `src/mainchainaddress.*`, `src/bech32.*`, `src/base58.cpp`, `src/sidechain.*` | L1 withdrawal-address parser (P2PKH/P2SH/P2WPKH/P2WSH/P2TR). bech32m port. |
| Read RPCs | `src/rpc/blockchain.cpp`, `src/rpc/misc.cpp`, `src/rpc/rawtransaction.cpp`, `src/core_write.cpp` | `getblockstats` backport, `getindexinfo`, read RPCs for credit-layer state. |
| Build / depends | `depends/packages/libevent.mk`, `src/support/lockedpool.cpp` | libevent 2.1.8 -> 2.1.12. GCC 13 include fix. **All other depends definitions, build scripts and vendored libraries (secp256k1, leveldb, univalue, crypto) are byte-identical to upstream.** |
| CI | `.github/workflows/linux.yml`, `.github/workflows/macos.yml` | Build and test on push. Tag job re-runs the portable build. macOS release artefact built here. |
| Tests, docs | `src/test/`, `test/`, `doc/`, `README.md`, `SECURITY.md` | Not in shipped binaries. |

---

## 3. Scope and method

Each lens was run by a separate Claude instance on the reviewed commit. A final pass (this document)
re-checked the critical and high findings and the header-flood finding against the source.

| Lens | What was concretely checked |
|---|---|
| **1. Network / phone-home** | Grepped all non-vendored `src/` and the added diff lines for URLs, IP literals, hostnames and `.onion`. Grepped for every process-spawn and outbound-socket primitive (`popen`/`system`/`exec*`/`fork`, Boost.Asio sockets, evhttp client, Qt network). Confirmed the inherited network stack (`net.cpp`, `netbase.*`, `addrman`, `torcontrol.*`, `httpserver.cpp`, `httprpc.cpp`, `rest.cpp`, `zmq/`, `protocol.*`) is **unchanged** from the import. Read the `grpcurl` shell-out, REST client and JSON-RPC client line by line, including every request-body construction site. Checked that no RPC or runtime path can change `-enforceraddr`/`-grpcurlbin`/`-mainchainrest`. Listed every new RPC and confirmed it sits behind the normal RPC auth. Traced peer-triggered L1 traffic from `headers` messages end to end. |
| **2. Keys, wallet, files, processes** | Every process-spawn site. Every `grpcurl` request body (10 sites). Secret logging (added `LogPrint`/`strprintf`/`error()` lines near key, seed, WIF, password material). Key material copied out of secure storage. Every new RPC for key export or filesystem paths. `EnsureWalletIsUnlocked` present in all 41 new write RPCs. `sethdseed` and HD seed derivation. What the wallet checks before counter-signing a transaction another party built (`SignDiscount`, `CompleteDiscount`, `CompleteSettle`). Domain separation of payload-signature digests. Every file written by new code. The wallet-path containment check. |
| **3. Build and supply chain** | All 33 `depends/packages/*.mk` compared with upstream (identical except libevent). The depends fetch/verify logic (sha256 checked before use, fallback mirror under the same hash). libevent 2.1.12 source compared file by file with the official release asset (202/202 common files identical). The autotools delta. Committed binaries (none executable). Secret scan of tracked files. `.github/workflows/*`. The maintainer's Linux release script. The published v0.2.15 Linux and macOS binaries: linked libraries, hardening flags, embedded library versions and commit ids. |
| **4. Peg and money paths (malice lens)** | Searched for hard-coded addresses, keys, long hex constants and hostnames. Read coinbase construction and the coinbase value limit, the BMM bid request, the deposit builder and validator, the withdrawal bundle builder/validator and refunds, value conservation in `CheckTxInputs` (no early return before in >= out), every credit-layer consensus-mandated payout script and fee sink, every wallet-builder output. Searched for admin / kill-switch / pause / blacklist / time-bomb patterns. Checked that consensus-parameter overrides refuse to start off regtest. |

Severity scale used below:
**Critical** = a party without special privilege can create or take coins.
**High** = the same with a narrower precondition, or a network-wide crash/divergence.
**Medium** = a real weakness with a precondition or a trust gap users should know about.
**Low** = hardening or a narrow edge case.
**Info** = a fact worth stating, often benign.

---

## 4. Findings

"Block producer" means whoever wins a sidechain block through BMM. That is anyone willing to pay the L1
bid, not a fixed party. Line numbers are at `bb427a9`.

### 4.1 Critical and high

| ID | Sev. | Where | What | Evidence summary |
|---|---|---|---|---|
| C1 | **Critical** | `src/validation.cpp:7659-7731` (deposit check in `ConnectBlock`); `src/l1client.cpp:1399-1416` (`VerifyDeposit`) | **Deposit records are not bound to a real deposit into slot 130.** A block producer can credit itself coins with no L1 backing. (a) While no deposit baseline exists yet (no deposit has ever been accepted), the CTIP-input check is skipped and `amountPrev = 0`. `VerifyDeposit` only confirms that *some* transaction sits at index `nTx` of the named L1 block. Nothing checks that output `nBurnIndex` pays the sidechain's treasury. So the first record can name any real L1 transaction and output and be credited at full value. (b) Only the first record in a block is checked to spend the previous CTIP. Later records in the same block are not chained to it. | `payout = d.dtx.vout[d.nBurnIndex].nValue - amountPrev` is compared only with the record's own `amtUserPayout`. `VerifyDeposit` returns `vTxid[nTx] == txid` and nothing more. Re-checked in the final pass. The maintainer's v0.2.17 rule design records this and a regtest reproduction that minted about 99 billion sat. **Fix scheduled for v0.2.17, not in v0.2.16.** |
| H1 | **High** | `src/validation.cpp:7715-7730`; `src/sidechain.cpp:331-352` | **A real deposit can be redirected to the block producer.** The validator requires a coinbase output paying the record's own `strDest`, which the producer writes. Nothing compares `strDest` with the destination the depositor committed to in the L1 transaction. Honest producers copy it from the enforcer's event, but validators never re-derive it. | `GetDepositPayoutOutput` decodes `deposit.strDest`; `ClaimDepositPayoutOutput` matches that script. No other use of `strDest` in validation. The maintainer's design notes record a redirect that connected on v0.2.14. **Fix scheduled for v0.2.17.** |
| H2 | **High** (lens rated medium; raised in the final pass) | `src/validation.cpp:7704` | **`nBurnIndex` from a producer-written deposit record is used as a vector index without a bounds check.** An out-of-range value is undefined behaviour in *every validating node*: a crash, or different nodes reading different garbage (divergence). An in-range value pointing at a non-treasury output changes the credited amount (feeds C1). The builder checks the bound; the validator does not. | `CAmount burn = d.dtx.vout[d.nBurnIndex].nValue;` with no preceding size check. Confirmed in the final pass: no earlier bound check on the block-validation path. **Fix scheduled for v0.2.17.** |

The maintainer states that on 2026-09-26 slot 130 on the beta network held no treasury and no deposits yet,
so C1/H1/H2 had no funds to act on. This review did not verify that. FreeBank's `SECURITY.md` already
states it is pre-audit software for test networks only.

### 4.2 Medium

| ID | Where | What | Evidence summary |
|---|---|---|---|
| M1 | `src/validation.cpp:7642`, `:8581`; `src/sidechain.cpp:341-350` | **The coinbase allowance counts deposits that are not paid out.** Dust deposits (<= 1,000 sat) and deposits with an undecodable destination are added to `nDepositPayout`, but no payout output is required for them. A producer may pay that value to itself. The honest builder does not. | `nDepositPayout += deposit->amtUserPayout;` for every record; `blockReward = nFees + nDepositPayout + nRefundPayout`; `if (!GetDepositPayoutOutput(d, required)) continue;`. Scheduled for v0.2.17. |
| M2 | `src/validation.cpp:10379-10383`, `:12741-12751`; `src/l1client.cpp:650-656`, `:1554-1561`; `src/net_processing.cpp:1321-1339` | **A remote peer can make the node run one `grpcurl` process per header it sends, under `cs_main`, with no penalty.** `AcceptBlockHeader` calls `CheckMainchainConnection()` for every non-genesis header *before* the duplicate-header early return. On the default enforcer transport this is an uncached `popen(grpcurl ... GetChainTip)`. A peer can resend up to 2,000 already-known headers per message, repeatedly. That stalls RPC and block processing. If any call fails (for example an enforcer timeout under load), the node disables *all* networking until a 30-second re-check. Inherited call pattern (upstream made one local HTTP call per header); FreeBank's process-per-call transport makes it much heavier. | Code reading only; not reproduced. Re-checked in the final pass: the connection check sits above `mapBlockIndex.find(hash)`. `MAX_HEADERS_RESULTS = 2000`. |
| M3 | `depends/packages/zeromq.mk` (inherited, unchanged); shipped Linux `freebankd` | **The static Linux release embeds ZeroMQ 4.2.2, affected by CVE-2019-6250** (remote code execution by a peer that connects to the ZMQ socket; fixed in 4.3.1). ZMQ is **off by default**: only a node started with `-zmqpub*=tcp://<reachable address>` is exposed. The macOS build does not link ZMQ. | `strings` on the v0.2.15 Linux binary shows `zmq::v2_decoder_t::size_ready`. Remedy: bump zeromq (Core uses 4.3.x) or configure releases with `--disable-zmq`. **Until then: do not enable `-zmqpub*` on a non-loopback address.** |
| M4 | `src/l1client.cpp:577-587` | **The node runs an external, unverified binary (`grpcurl`) and trusts its output as L1 truth** (deposits, BMM, withdrawal events). It is taken from `-grpcurlbin`, by default the first `grpcurl` on `PATH`. It is not shipped, pinned or hash-checked. It belongs in the node's trust base next to the enforcer and the L1 node. This is a trust-statement item more than a code defect. | `std::string strBin = gArgs.GetArg("-grpcurlbin", "grpcurl");` `popen(strCommand.c_str(), "r")`. Tested against grpcurl v1.9.1 only. |
| M5 | Linux release script (maintainer's machine, not in the public repo); `.github/workflows/linux.yml:73-129` | **The Linux release binary cannot be reproduced by a third party.** It is built on the maintainer's machine with the host toolchain (no pinned container or Guix). The tarball mtime is the build date. The binary embeds absolute build paths. The toolchain version is not recorded. The CI tag job builds an independent tarball, but its hash is never compared with the shipped one, so it proves portability, not provenance. The release script is not in the public repo. | Build lens read the script and the shipped v0.2.15 binary. Cheap partial steps: fixed `SOURCE_DATE_EPOCH`/mtime from the tag, `-ffile-prefix-map`, record toolchain versions, publish the CI tarball hash beside the shipped one, publish the release script. |
| M6 | `.github/workflows/macos.yml:16,35-42` | **The macOS release is built from unpinned Homebrew packages** (boost@1.85, libevent, openssl@3 at whatever version is current that day) on a GitHub-hosted runner and statically linked. It cannot be rebuilt byte-for-byte later. There is no codesigning or notarization step. | `brew install ... boost@1.85 libevent ...`. The v0.2.15 mac binary embeds `openssl@3/3.6.3` paths. No `codesign`/`notarytool` in the workflow. |

### 4.3 Low

| ID | Where | What |
|---|---|---|
| L1 | `src/l1client.cpp:780-845` (`RestGet`), `:2384-2455` (`SendRequestToMainchain`) | The REST and JSON-RPC L1 clients have **no timeout and no response-size cap**. An endpoint that accepts and never answers hangs the calling thread (deposit checks run inside block validation). One that streams without end grows memory. Defaults are loopback, so this matters when `-mainchainrest` points at a host you do not control. The `grpcurl` path is bounded by `-max-time 15`. |
| L2 | `src/l1client.cpp:2386-2429`, `:1798-1803` | With `-mainchaintransport=jsonrpc` (default on regtest only), the node sends **its own `-rpcuser:-rpcpassword`** as HTTP Basic auth to whatever listens on `127.0.0.1:8332` (18443 on regtest), including an unrelated process that bound the port first. Those credentials control the FreeBank wallet. Inherited upstream behaviour. With cookie auth nothing is sent. |
| L3 | `src/l1client.cpp:1755-1761`, `:571-587` | `grpcurl` runs through `/bin/sh`. **`-enforceraddr` is inserted unquoted and unvalidated.** `-grpcurlbin` is wrapped in double quotes, which still allow `$(...)`, backticks and `$VAR`; the only check is "no double quote". Whoever writes `freebank.conf`/the command line or controls `PATH` can run commands as the node user. That is the same trust level as the inherited `-blocknotify`, and no RPC or peer can set these options. It becomes a real injection risk if a wrapper (GUI, installer, hosted service) ever fills them from untrusted input. Request bodies cannot inject: they contain only integers, hex and base64, and a single quote is refused. The full command line (public data only) is visible to local users via `ps`. Fix: validate the address as `host:port`, reject shell metacharacters in the path, or use `fork`/`execvp` with an argv array. |
| L4 | `src/l1client.cpp:587`; no `FD_CLOEXEC` in `net.cpp`, `netbase.cpp`, `httpserver.cpp`, leveldb, `wallet/db.cpp` | The `grpcurl` child **inherits every open descriptor** of `freebankd` (sockets, LevelDB files, wallet DB environment), as the inherited `-*notify` children do. It is the operator's own binary as the same user, so it gains no new access, but a substituted `grpcurl` gets live wallet descriptors, and the node now spawns a child on every L1 call. |
| L5 | `src/wallet/rpcwallet.cpp:2347-2415`; `src/wallet/wallet.cpp:1483-1508` | `sethdseed` takes the HD master key as a WIF parameter. It is not logged. When passed on a `freebank-cli` command line it lands in the process list and shell history (like `importprivkey`). The new seed is stamped "created now", so restoring a previously used seed does **not** rescan: past funds appear only after `rescanblockchain`, and the help text does not say so. Otherwise correct: requires unlock, refuses non-HD wallets and duplicate keys, stores the key encrypted if the wallet is encrypted. |
| L6 | `src/wallet/wallet.cpp:7023-7110` (`CompleteSettle`) | **Plausible, not confirmed.** When counter-signing a settlement another party built, the wallet checks less than it does for a discount. In one mode it checks only `vout[0]`; in the other it signs (`SIGHASH_ALL`) without inspecting the outputs itself. Safety then rests on the consensus settle rules, which no lens traced to confirm they fully pin the output set. The inputs at stake are note-dust coins. |
| L7 | `src/validation.cpp:8546-8578` vs `:7727` | Refund payout matching counts coinbase outputs by (script, amount) without the claimed-output set that deposits use. One output can satisfy both a deposit payout and a refund with the same script and amount, and the producer keeps the difference. It needs a coincidental match. Scheduled for v0.2.17. |
| L8 | `depends/packages/openssl.mk` (inherited); shipped Linux binary | The Linux release embeds **OpenSSL 1.0.1k (2015)**. In this daemon it is used only as one RNG input (`OPENSSL_no_config`, no TLS; ECDSA uses libsecp256k1; key generation mixes OpenSSL, OS and hardware RNG through SHA-512). No reachable exploit path is known. The macOS build uses OpenSSL 3.6.3. |
| L9 | `depends/packages/libevent.mk:3-5` | The libevent pin uses GitHub's auto-generated `/archive/` tarball (sha256 `7180a979...`), not the signed release asset Bitcoin Core pins (`92e6de1b...`). A commit message calls it "Core's own pin", which is inaccurate. Contents verified identical (202/202 common files). Risk is availability: archive bytes have changed before, which would fail the hash check and block the build (safely). |
| L10 | inherited `depends/packages/*.mk` | Several primary download URLs are dead (boost on bintray) or plain `http://`. Integrity is unaffected (every fetch is sha256-checked). In practice the build depends on the `bitcoincore.org/depends-sources` fallback mirror for availability. |
| L11 | `.github/workflows/*.yml` | Actions are pinned by mutable tag (`@v4`), not commit SHA, and no `permissions:` block limits the token. No secrets and no `pull_request_target`, so exposure is small. The macOS artefact users download is built by these workflows. |
| L12 | Linux release script | The script does not enforce a clean tree or that HEAD is the release tag. Partial safeguard: the version string embeds the commit and a `-dirty` suffix for modified tracked files (untracked files are not detected). The v0.2.15 Linux binary shows a clean commit. |

### 4.4 Info (facts worth stating; mostly benign)

| ID | Where | What |
|---|---|---|
| I1 | `src/chainparams.cpp:149-153`; `src/chainparamsseeds.h` | **The only contact with infrastructure the maintainer runs is peer discovery.** The DNS seed is `seed.ecxfreebank.com`, and the one fixed fallback seed is `163.47.9.132:8455`. Resolving or connecting reveals your IP (or your DNS resolver's) to that operator, the same exposure as Bitcoin Core's DNS seeds. Standard controls work unchanged: `-dnsseed=0`, `-connect`, `-proxy`, `-onlynet`. Regtest has no seeds. An older release (v0.2.12) shipped a different fixed seed IP. If that address is ever reassigned, those old nodes would try a stranger's host, but only as an ordinary P2P peer. |
| I2 | `src/` (whole tree) | **No telemetry, analytics, crash reporting, update check or phone-home found.** Outside the three L1 client functions in `src/l1client.cpp`, nothing in compiled code opens sockets or starts processes, apart from the inherited P2P, Tor control, HTTP-RPC server, `freebank-cli` client and the operator-configured `-blocknotify`/`-walletnotify`/`-alertnotify`. |
| I3 | `src/httprpc.cpp:235-238` | **No hidden listener, no unauthenticated RPC.** The only HTTP handlers are the inherited JSON-RPC ones. Every new RPC (the BMM-engine RPCs, credit-layer reads, about 50 wallet RPCs) is in the normal table behind cookie/`rpcuser` auth. |
| I4 | `src/torcontrol.*`, `src/net.h`, `configure.ac` | Inherited Bitcoin Core 0.16 defaults, unchanged: P2P listens on all interfaces (port 8455). **If a local Tor daemon allows it, the node automatically creates an onion service** (`-listenonion=1` default; disable with `-listenonion=0`). UPnP is off and not compiled into the Linux release. REST is off by default. ZMQ only with `-zmqpub*`. RPC binds to localhost unless `-rpcbind`/`-rpcallowip` are set. |
| I5 | `src/l1client.cpp`; `src/init.cpp:994-1060` | **L1 links are plaintext and unauthenticated.** gRPC to the enforcer at `-enforceraddr` (default `127.0.0.1:50051`) and HTTP GET to `-mainchainrest` (default `127.0.0.1:38332`). They carry hashes, heights, amounts, BMM bids and withdrawal bundles. No wallet secrets travel on them. The node credits deposits and validates BMM from what these endpoints report, so **pointing them at a remote host means trusting that host's L1 data over an unencrypted link**. Off regtest, startup refuses to run without an L1 identity pin. |
| I6 | `src/rpc/misc.cpp` (`refreshbmm`); `src/l1client.cpp:1474-1525` | On the enforcer transport, any authenticated `freebankd` RPC caller can make the **enforcer's L1 wallet** spend on a BMM bid (no upper cap in `freebankd`). The FreeBank RPC password therefore also carries L1 spending authority, bounded by the enforcer wallet balance. Inherited semantics. |
| I7 | `src/miner.cpp:213-218, 506`; `src/validation.cpp:2658` | **No developer fee or fixed payee in block production.** The coinbase pays the producing node's own wallet (or a caller-supplied script): fees plus the inherited 1,000-sat per-deposit fee. The block subsidy is 0 and genesis pays 0. |
| I8 | `src/l1client.cpp:1474-1526, 2056-2110` | **BMM bids name no recipient in FreeBank code.** Only sidechain id, value, height and hashes are sent. The L1-side wallet builds the transaction, so whether the bid reaches only the L1 miner is decided there (outside this review). Default bid is 10,000 sat. |
| I9 | `src/validation.cpp:12277-12440` | **Withdrawals cannot be redirected by a producer.** Every validator rebuilds the bundle from its own withdrawal DB and requires a byte-identical transaction. Refunds need a signature by the user's refund-address key. |
| I10 | `src/consensus/tx_verify.cpp:420-712, 1164-1176`; `src/validation.cpp:3448-3458` | **No admin bypass in the credit layer.** Escrow guards compare only against payload-derived scripts, house approvers or fixed positions. Value conservation (in >= out) applies to every tx version with no early exit. House registration is permissionless. No kill switch, pause, blacklist or wall-clock time bomb found. Consensus-parameter overrides refuse to start off regtest. |
| I11 | `src/house.cpp:325-346`; `src/pool.cpp:638-660`; `src/validation.cpp:5176-5186` | Credit-layer fees go to the house's own escrow (brassage), the pool's reserves (swap fee), the house's own key (pool retire) or the block producer (tx fees). None goes to a protocol or developer address. |
| I12 | `src/consensus/tx_verify.cpp:562-588, 697-705` | **Oracle bonds cannot be withdrawn in this version.** No unbond operation exists; a bond can only be consolidated into an equal or larger bond. Funds are not redirected, but they are locked until a later release adds the operation. |
| I13 | `src/sidechain.h:87-89`; `src/validation.h:242-243` | Three inherited upstream key constants (`feeKey`, `SIDECHAIN_CHANGE_KEY`, `SIDECHAIN_TEST_SCRIPT_HEX`) are defined but **never referenced**. They are byte-identical to upstream, and no money path uses them. Removing them would simplify future reviews. Other hard-coded hashes are inherited Bitcoin Core constants that do nothing here; `defaultAssumeValid` is FreeBank's own genesis, so no signature checks are skipped. |
| I14 | `src/wallet/wallet.cpp:7282-7690` | Positive: the discount flow does not sign blindly. The wallet re-derives the proposal from on-chain records and checks price, payee, title output and input before signing. |
| I15 | `src/bill.cpp`, `src/house.cpp`, `src/note.cpp`, `src/deposit.cpp`, `src/pool.cpp` | Payload signatures reuse wallet keys over tagged double-SHA256 digests (`"FreeBankBill/issue"`, `"FreeBankReserveProof"`, ...). They are domain-separated from each other and not practically confusable with Bitcoin sighashes. Non-collision was not proven for every digest. |
| I16 | `src/wallet/rpcdump.cpp`, `src/wallet/rpcwallet.cpp`, `src/wallet/db.cpp:289` | The only RPCs taking filesystem paths are inherited (`dumpwallet` refuses to overwrite; `backupwallet` overwrites; `importwallet` reads). None of the new RPCs takes a path. The rewritten wallet-filename check is equivalent for traversal cases. |
| I17 | `src/clientversion.cpp`; `src/miner.cpp:873-915` | Public data: the user agent identifies the node as FreeBank. By default the coinbase carries only height and extra nonce. An operator tag goes into blocks only when `-coinbasetag`/`setcoinbasetag` is set. |
| I18 | `configure.ac:4-7`; release binaries | Version metadata. At the reviewed commit `configure.ac` still says 0.2.15 (to be bumped at release). `_CLIENT_VERSION_IS_RELEASE` is false (inherited), so every build shows the pre-release warning. For v0.2.15, the Linux binary embeds a private-repo commit id (`843ccae`) and the macOS binary the public tag commit (`b6e01eb`). Their build inputs were checked byte-identical, so the public tag is the right source for both, but `freebankd --version` on Linux names a commit you cannot find on GitHub. |
| I19 | `contrib/gitian-descriptors/`, `contrib/gitian-build.sh`, `contrib/verifybinaries/` | Inherited reproducible-build and verification tooling **does not apply to FreeBank**. It still builds `bitassets` from LayerTwo-Labs and verifies against bitcoincore.org. Do not mistake it for a FreeBank verification path. |
| I20 | depends, build-aux, vendored libs; shipped Linux binary | Benign: build system and vendored crypto/DB libraries unchanged from upstream except libevent. No new build-time download or code generation. The v0.2.15 Linux binary is PIE, full RELRO, non-exec stack, fortified. Dynamic deps are glibc/libm/libgcc_s only. No executables, archives or credentials are committed to the repository. |

---

## 5. Not checked, and limits

- **Nothing was run.** No build, test, daemon, packet capture or `strace`. The header-flood finding (M2) and the
  deposit findings were not reproduced for this review. The deposit reproductions cited come from the
  maintainer's own test notes, which are not in the public repo.
- **The binaries of v0.2.16.** Only already-published v0.2.15 binaries and a v0.2.16 development build's version
  string were inspected. Whether the v0.2.16 release tarballs match this source is for section 1.3.
- **The inherited base.** Bitcoin Core 0.16-era code (P2P, wallet, BDB, crypter, RPC server, cookie auth) and the
  2018-2023 BitAssets code were only confirmed unchanged relative to the import. They were not re-audited, and
  no check was made for Bitcoin Core CVEs fixed after early 2018. The Core base identity (section 2.1, layer 2) was
  not tree-diffed against a Bitcoin Core checkout.
- **Vendored and depends libraries** (secp256k1, leveldb, univalue, boost, BDB, OpenSSL, libevent, ZeroMQ) were not
  audited. Only their identity with upstream was checked, and only libevent's contents were compared with its
  official release. No upstream GPG signatures were verified. No CVE database was queried beyond the ones named.
- **The consensus and economic correctness of the credit layer** (solvency, note waterfall, AMM invariants,
  settlement arithmetic, custody-tag integrity end to end). Lens 4 checked only where money goes. L6 needs a
  consensus-level confirmation.
- **About 50 new wallet builder functions** were checked by grep for key access, logging and unlock guards. Only the
  discount, settlement and `sethdseed` paths were read in full.
- **Other peer-driven L1 traffic.** Only the header path was traced end to end. Whether blocks, compact blocks or
  deposit-bearing blocks can also drive large numbers of L1 calls was not traced, nor which callers hold
  `cs_main` during the untimed REST reads.
- **External components the node trusts:** the `grpcurl` binary, the LayerTwo-Labs `bip300301_enforcer` (which
  holds the wallet that funds BMM bids and reports deposits), the L1 node, and BitWindow (the outside BMM engine).
  Whether BMM bids pay only the L1 miner, and whether deposits and withdrawals are reported honestly, are
  decided there.
- **Live infrastructure:** what `seed.ecxfreebank.com` and `163.47.9.132` actually return or run.
- **GitHub itself:** Actions runs, repository permissions, who can push tags or releases, and whether the release
  assets on GitHub equal the maintainer's archived copies.
- **The macOS build** beyond `strings` (no macOS tools were available). No Windows build exists.
- **The Qt GUI** (`src/qt/`). It is not in the release binaries (`--without-gui`) and was only grepped.
- **Earlier Rust-era content** in the public repository's history (v0.3.x tags) was not reviewed.

---

## 6. How to verify this yourself

### 6.1 Confirm the upstream base and see exactly what FreeBank changed

```sh
git clone https://github.com/LayerTwo-Labs/BitAssets upstream-bitassets
git -C upstream-bitassets checkout ce409cbee7b11b9d8d817c455c56059849206f3d
git clone <FreeBank public repo> freebank && git -C freebank checkout <release tag>

# Everything FreeBank added or changed relative to upstream:
diff -ruN upstream-bitassets freebank -x .git > freebank-vs-upstream.diff

# Things this review says are unchanged (should print nothing, apart from depends/packages/libevent.mk):
for p in depends build-aux autogen.sh src/secp256k1 src/leveldb src/univalue src/crypto; do
  diff -r upstream-bitassets/$p freebank/$p
done
```

Expect differences under `depends/` only in `packages/libevent.mk`, plus the 13 gitignored files
described in section 2.1. The inherited network stack (`src/net.cpp`, `src/netbase.*`, `src/addrman.*`,
`src/torcontrol.*`, `src/httpserver.cpp`, `src/httprpc.cpp`, `src/rest.cpp`, `src/zmq/`, `src/protocol.*`)
should show no diff.

### 6.2 Confirm the release is the reviewed code

Compare `git rev-parse <tag>:src` and the other paths with the table in section 1.2.

### 6.3 Build from source (Linux, static, as the releases are built)

```sh
cd freebank
make -C depends -j"$(nproc)" NO_QT=1 NO_UPNP=1       # every source tarball is sha256-checked
D="$PWD/depends/x86_64-pc-linux-gnu"
./autogen.sh
./configure --prefix="$D" --without-gui --disable-bench --with-incompatible-bdb \
  --with-boost="$D" CPPFLAGS="-I$D/include" LDFLAGS="-L$D/lib -static-libstdc++" \
  PKG_CONFIG_PATH="$D/lib/pkgconfig"
# Optional, recommended until ZeroMQ is bumped (finding M3): add --disable-zmq
make -j"$(nproc)"
src/test/test_bitcoin          # unit tests
```

Your binary will not be byte-identical to the published one (finding M5). Building it yourself means you do
not need to trust the published binary.

### 6.4 Check the specific claims

- **Phone-home / endpoints:** `grep -rnE 'https?://|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' src --include=*.cpp --include=*.h | grep -v -e src/leveldb -e src/secp256k1 -e src/univalue -e src/test -e src/qt/locale`
  and `grep -rnE '\bpopen\(|\bsystem\(|\bexecv|\bfork\(' src`. Compare with I1, I2 and L3.
- **Deposit issues:** read `src/validation.cpp` around the "Verify new deposit payouts" comment and
  `EnforcerL1Client::VerifyDeposit` in `src/l1client.cpp` (C1, H1, H2, M1).
- **Header path:** `AcceptBlockHeader` in `src/validation.cpp`. The mainchain check sits above the
  duplicate-header lookup (M2).
- **grpcurl command:** `BuildGrpcurlCommand` and `RunGrpcurl` in `src/l1client.cpp` (L3, L4, M4).
- **Coinbase and fees:** `CreateNewBlock` in `src/miner.cpp`, `GetBlockSubsidy` and the `blockReward` check in
  `src/validation.cpp` (I7, M1).
- **Build pins:** `depends/packages/*.mk` (M3, L8-L10); `.github/workflows/*.yml` (M6, L11).

Report problems as `SECURITY.md` describes: privately by email for anything touching consensus, the peg or keys,
public issues for the rest.

---

*This report was written by an AI model and may contain errors. It was published by the FreeBank maintainer
alongside the release's provenance and checksums. It is one input to your judgement, not a certificate.*
