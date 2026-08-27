# Packaging

## The release contract

`installer/install.sh` downloads a signed release by default, so the names and
the signatures below are load-bearing: change one of them without changing the
installer and every `curl … | sudo bash` in the world stops working. The
installer half of this contract lives in `release_tarball_name`,
`release_base_url` and `verify_checksum`.

A release of tag `vX.Y.Z` publishes, as GitHub release assets:

```
ferrum-X.Y.Z-x86_64-linux.tar.gz     the three binaries, top level or one dir down
ferrum-X.Y.Z-aarch64-linux.tar.gz
SHA256SUMS                           sha256sum(1) format, one line per tarball
SHA256SUMS.minisig                   minisign signature over SHA256SUMS
```

Note where the `v` goes: the *tag* carries it, the *filename* does not.

Each tarball contains `ferrum-agentd`, `ferrum-web` and `ferrum` — nothing else
is looked at. `ferrum-web` must be built after `ui/` so the interface is
embedded in it.

Only `SHA256SUMS` is signed. That is deliberate and it is the whole reason the
chain holds: the installer verifies the signature on the checksum file first,
and only then checks the tarball against it. Signing each tarball separately
would work too, but signing nothing and shipping a bare checksum file — the
common shape — proves only that the file matched itself.

## Cutting a release

1. Build both architectures, assemble the tarballs, and write `SHA256SUMS`
   with the tarball basenames only (no directory components — the installer
   matches by basename, and a signed file that names the same artefact twice is
   refused rather than resolved).
2. Sign it:

   ```bash
   minisign -S -s ~/.minisign/ferrum-release.key -m SHA256SUMS
   ```

3. Rewrite the placeholder in the installer with the matching public key —
   the 56-character `RW…` line from `ferrum-release.pub`, not the file:

   ```bash
   sed -i "s|PLACEHOLDER-REPLACE-AT-RELEASE|$(sed -n 2p ferrum-release.pub)|" \
     installer/install.sh
   ```

   `tests/gates/installer.sh` asserts that placeholder appears exactly once, so
   this substitution can never quietly rewrite the check along with the key.
   Until it is replaced the installer refuses to download anything at all,
   which is what stops a fork from installing unverified binaries by accident.

4. Attach all four files to the release.

The secret key never leaves the release signer. Nothing in CI holds it, and
nothing in this repository can produce a signature without it.

## Still to come (Phase 1+)

- `cargo-deb` and `cargo-generate-rpm` metadata for `.deb` and `.rpm` builds.
- Self-update (spec §5.5), which verifies the same ed25519/minisign signature
  before swapping a binary and rolls back if the new version fails its health
  check within 60 seconds. It shares this contract; changing the artefact names
  means changing it too.
- Our own package repository, which is where prebuilt dynamic nginx modules
  (brotli, ModSecurity) will come from, since we never compile on a customer's
  server.

## Building without a release

```bash
sudo installer/install.sh --from-source            # build here, then install
sudo installer/install.sh --from ./target/release  # install an existing build
```

Neither path downloads anything, so neither needs a signing key.
