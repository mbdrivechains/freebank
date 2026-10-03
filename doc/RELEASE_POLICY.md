# How FreeBank releases are made

1. **Source.** Every release is a tag on this repository. The tag's commit is the source of every binary.
2. **Linux builds are reproducible.** The Linux x86_64 tarball is built with Guix from the tag, on GitHub and by the
   maintainer, and is released only when both builds are identical byte for byte. Anyone can rebuild it and compare
   (VERIFY.md, step 3).
3. **macOS builds** are built by GitHub Actions from the tag and carry a GitHub build attestation.
4. **Signed checksums.** `SHA256SUMS` lists every tarball and is signed with the FreeBank release key
   (`SHA256SUMS.sig`; fingerprint `SHA256:1d0zm9Qb9ZtzDnQHH593fgjAkk7nPqMDG79XyWlyeeY`). The key is kept on the
   maintainer's machine, protected by a passphrase.
5. **Consensus changes wait, from the mainnet launch.** A release that changes consensus rules is published as a
   pre-release first, with notes
   that say so and say what an operator must do (for example, restart once with `-reindex`). It becomes `latest`
   (what BitWindow and other tools install by default) no sooner than **7 days** after publication, unless it fixes a
   flaw that is being exploited. Releases that change no consensus rule may become `latest` at once, and so may every release before the mainnet
   launch (beta).
6. **Notes.** Every release lists what changed, whether consensus changed, what an operator must do, and known issues.
