# Packaging

Signed tarballs exist. `.github/workflows/release.yml` builds
`unihelm-<version>-{x86_64,aarch64}.tar.gz` from a `v*` tag, signs them with
minisign, and drafts a GitHub release; `docs/releasing.md` is the procedure and
the key-handling rules. The public key is `minisign.pub` at the repository root.

Still to come here:

- `cargo-deb` and `cargo-generate-rpm` metadata for `.deb` and `.rpm` builds,
- the self-update client — the signatures the release workflow produces are the
  ones it will verify before swapping a binary, rolling back if the new version
  fails its health check within 60 seconds (spec §5.5),
- the repository metadata for our own package repo, which is where prebuilt
  dynamic nginx modules (brotli, ModSecurity) will come from, since we never
  compile on a customer's server.

`installer/install.sh --from ./target/release` still installs from a local
build, which is what you want on a distribution older than the one the release
tarballs are linked against (see the glibc note in `docs/releasing.md`).

## The release contract

`installer/install.sh` downloads a signed release by default, so the names and
the signatures below are load-bearing: change one of them without changing the
installer and every `curl … | sudo bash` in the world stops working. The
installer half of this contract lives in `release_tarball_name`,
`release_base_url` and `verify_checksum`.

A release of tag `vX.Y.Z` publishes, as GitHub release assets:

```
unihelm-X.Y.Z-x86_64.tar.gz     a complete installer: bin/, install.sh,
unihelm-X.Y.Z-aarch64.tar.gz    preflight.sh, config.toml.example, systemd/
SHA256SUMS                      sha256sum(1) format, one line per tarball
SHA256SUMS.minisig              minisign signature over SHA256SUMS
```

Each tarball unpacks to a directory of the same name as the file, minus
`.tar.gz`.

Note where the `v` goes: the *tag* carries it, the *filename* does not.

Each tarball contains `unihelm-agentd`, `unihelm-web` and `unihelm`, and
`unihelm-web` must be built after `ui/` so the interface is embedded in it.

The rest of the tarball is not padding. `curl … | sudo bash` has no files on
disk — no `preflight.sh`, no `config.toml.example`, no unit files — and fetching
those loose from the raw content host would put unsigned files on a server,
which is the one thing this whole chain exists to prevent. So a piped run
verifies this tarball and then runs the `install.sh` inside it. That makes
`install.sh`, `preflight.sh`, `config.toml.example` and `systemd/*.service`
part of the release contract too: drop one and the piped install stops working,
because `locate_installer_root` refuses a tarball that is missing any of them.

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
   minisign -S -s ~/.minisign/unihelm-release.key -m SHA256SUMS
   ```

3. Rewrite the placeholder in the installer with the matching public key —
   the 56-character `RW…` line from `unihelm-release.pub`, not the file:

   ```bash
   sed -i "s|PLACEHOLDER-REPLACE-AT-RELEASE|$(sed -n 2p unihelm-release.pub)|" \
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
