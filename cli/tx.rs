//! `freebank-tx` — companion binary listed alongside `freebankd` / `freebank-cli`.
//!
//! In the C++ FreeBank / Bitcoin Core lineage, `*-tx` is a standalone raw-transaction
//! construction/editing tool. The Rust (plain-bitassets) chassis builds and signs
//! transactions inside the node and `freebank-cli`, so there is no separate raw-tx
//! tool in this build. This stub exists only so the release tarball ships the file
//! BitWindow lists as a companion of `freebankd` (see docs-local/BITWINDOW_LAUNCH_CONTRACT.md).
//! It prints one explanatory line and exits successfully.

fn main() {
    println!(
        "freebank-tx: raw-transaction tooling is not part of the Rust FreeBank build; \
use freebank-cli and freebankd to build and sign transactions."
    );
}
