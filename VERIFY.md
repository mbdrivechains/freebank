# Verifying a FreeBank release

This page is for anyone, or anyone's AI assistant, who wants to answer two questions before running FreeBank:

1. **Is the source safe?** Does it contain exploits, backdoors, phone-home code or a way to steer coins?
2. **Was the published binary built from that source,** and from nothing else?

From **v0.2.18**, you can answer the second question yourself, byte for byte, for the Linux x86_64 release. The
first question can only be answered by reviewing the code. This page shows how to do both, and what neither of them
proves.

## What you can and cannot check

| Claim | How you check it | Holds for |
|---|---|---|
| The source at the tag is what you reviewed | `git checkout <tag>` | every release |
| The Linux binary was built from that source | rebuild with Guix, compare the sha256 (step 3) | v0.2.18 and later |
| The Linux binary is the one GitHub built from the public tag | GitHub attestation (step 4) | v0.2.18 and later |
| The macOS binary is the one GitHub built from the public tag | GitHub attestation (step 4) | releases built by the `macos-arm64` workflow (check with step 4) |
| The files are the ones the maintainer published | signed `SHA256SUMS` (step 4) | every release since signing began |
| The code is free of exploits | nobody can prove this; review reduces the risk (step 2) | |

FreeBank is **experimental, pre-audit software**. A clean review, by an AI or a person, is evidence, not a
guarantee.

## Step 1: get the source at the release tag

```sh
git clone https://github.com/mbdrivechains/freebank
cd freebank
git checkout v0.2.18            # the release you are checking
git rev-parse HEAD              # note the commit; from v0.2.18 the binaries report it (freebankd -version)
```

## Step 2: review the source

FreeBank is a fork of LayerTwo-Labs' **BitAssets** sidechain (MIT, commit `ce409cbee7b11b9d8d817c455c56059849206f3d`),
which sits on **Bitcoin Core 0.16-era** code. Most of the tree is inherited. A review is far more useful when it
concentrates on what FreeBank changed:

- [`doc/SOURCE_REVIEW_V0216.md`](doc/SOURCE_REVIEW_V0216.md), section 2.2, maps FreeBank's changes up to v0.2.16
  by area and file; for later changes, `git diff v0.2.16 <tag>`. Section 6.1 gives the commands to diff this tree
  against the BitAssets commit (from v0.2.18 that diff also shows `depends/packages/zeromq.mk`, which drops
  libtool `.la` files, and the new `contrib/guix/`). Section 6.4 lists greps for specific claims (network
  endpoints, process spawning, coinbase and fees, the deposit checks).
- The areas that matter most: the mainchain client (`src/l1client.*`), deposits and withdrawals (`src/sidechain.*`,
  `src/validation.cpp`), the miner and coinbase (`src/miner.cpp`), the credit layer (`src/bill.*`, `src/house.*`,
  `src/note.*`, `src/deposit.*`, `src/pool.*`, `src/settle.*`, `src/oracle.*`), and the wallet
  (`src/wallet/wallet.cpp`, `src/wallet/rpcwallet.cpp`).
- **Third-party libraries** are built from source tarballs pinned by sha256 in `depends/packages/*.mk` (at
  v0.2.17: Boost 1.64.0, OpenSSL 1.0.1k, Berkeley DB 4.8.30, libevent 2.1.12, ZeroMQ 4.2.2; the `.mk` files at
  your tag are authoritative). They are compiled into the binary
  as published upstream. Review them or trust their upstreams. Several are old; see findings M3 (ZeroMQ; it is off
  unless you pass a `-zmqpub*` option) and L8-L10 (build pins) in the source review, and the release notes.
- Earlier reviews and their findings are in `doc/`. The [`SECURITY.md`](SECURITY.md) file says how to report a
  problem.

### A prompt for an AI reviewer

Give your assistant the checked-out tree and something like this:

> You are reviewing the FreeBank node, a C++ Bitcoin sidechain (BIP 300/301), at commit `<commit>`, for a person
> deciding whether to run it. It is a fork of LayerTwo-Labs BitAssets commit
> ce409cbee7b11b9d8d817c455c56059849206f3d (Bitcoin Core 0.16-era). Focus on the code FreeBank added or changed
> (doc/SOURCE_REVIEW_V0216.md section 2.2 lists it; diff against the BitAssets commit to confirm). Look for:
> (1) any network contact other than the documented peers, seeds and the user-configured mainchain enforcer;
> (2) private keys, seeds or wallet data leaving the wallet, being logged or written outside the datadir;
> (3) hard-coded addresses, keys or amounts that could steer deposits, withdrawals, fees, the coinbase or BMM bids
> to anyone; (4) consensus rules that let someone create or take coins; (5) external processes, shell commands or
> file paths built from untrusted input; (6) anything in the build files (`configure.ac`, `Makefile.am`,
> `depends/`, `contrib/guix/`) that downloads or injects code not pinned by hash. For each finding give the file
> and line, what an attacker needs, and the impact. Say plainly what you did not check.

## Step 3: rebuild the Linux binary and compare (v0.2.18 and later)

You need Linux x86_64, Docker, about 25 GB free under Docker's data directory and a network connection. The first
run builds a pinned toolchain and can take hours; it is cached for later runs. Note that `run.sh` runs the tree's
own build scripts inside a `docker run --privileged` container (Guix needs it to create its build sandbox), so
read `contrib/guix/docker/` first if that matters to you.

```sh
contrib/guix/docker/run.sh                         # or JOBS=8 contrib/guix/docker/run.sh
sha256sum guix-build-*/output/x86_64-linux-gnu/freebank-*-x86_64-linux-gnu.tar.gz
```

The hash must equal the `x86_64-linux-gnu` line in the release's `SHA256SUMS`. If it does, the published Linux
binary was built from exactly the source you checked out: same compiler, same libraries, same bytes. If it does
not, please open an issue with your hash, the commit and your Docker and OS versions. If cloning Guix fails, set
`GUIX_URL=https://codeberg.org/guix/guix.git` (the same history as the default savannah URL).

How this works: [`contrib/guix`](contrib/guix/README.md) (adapted from Bitcoin Core's) builds inside
[Guix](https://guix.gnu.org), pinned to one Guix commit, so every builder uses the same compiler and libraries,
themselves built from pinned, hashed sources. The Docker image is designed not to change the output: it runs only
the Guix daemon and `guix time-machine`, and the build uses the Guix commit pinned in
`contrib/guix/libexec/prelude.bash`. By default Guix downloads already-built toolchain packages from its own
servers, after checking their signatures. To use none of them, start from fresh volumes and build everything
from source (this takes a day or more):

```sh
docker volume rm freebank-guix-1.5.0-gnu freebank-guix-1.5.0-var freebank-guix-cache   # if they exist
ADDITIONAL_GUIX_COMMON_FLAGS=--no-substitutes contrib/guix/docker/run.sh
```

You then still trust the Guix 1.5.0 release binary that starts the build (its sha256 is pinned in the Dockerfile)
and Guix's own bootstrap seeds.

## Step 4: check the signature and GitHub's attestation

- **Signature:** `SHA256SUMS` is signed with the FreeBank release key. The key and the commands are in the
  README under [Verify your download](README.md#verify-your-download).
- **GitHub attestation:** this repository's `guix-linux` (Linux) and `macos-arm64` (macOS) workflows build each
  release tag on GitHub, and GitHub records a signed attestation naming the workflow, the commit and the file's
  hash. With GitHub CLI 2.49 or later, logged in (`gh auth login`; without a login, use the `--bundle` route in
  the README's Verify your download section):

  ```sh
  gh attestation verify freebank-<version>-x86_64-linux-gnu.tar.gz --repo mbdrivechains/freebank \
    --signer-workflow mbdrivechains/freebank/.github/workflows/guix.yml
  gh attestation verify freebank-<version>-arm64-apple-darwin.tar.gz --repo mbdrivechains/freebank
  ```

  Every Linux release is built on two different machines, GitHub's runner and the maintainer's, with the same
  scripts. If the attestation verifies and the hash matches `SHA256SUMS`, GitHub built exactly these bytes from
  the tag. Your own build is the independent one.

## What this does not cover

- **Releases before v0.2.18** were built by the maintainer and cannot be rebuilt byte for byte. Their source can
  still be reviewed, or built yourself (doc/SOURCE_REVIEW_V0216.md section 6.3).
- **macOS** builds come from GitHub's workflow (step 4) but are not yet reproducible: you trust GitHub's macOS
  runner for them.
- **Other software you run with FreeBank** (the eCash node, the CUSF enforcer, BitWindow, `grpcurl`) is not
  covered here.
- **Review limits:** inherited Bitcoin Core 0.16 and BitAssets code has not been fully re-audited, and security
  fixes Bitcoin Core made after early 2018 are only present where backported.
