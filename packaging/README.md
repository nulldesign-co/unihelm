# Packaging

Signed tarballs exist. `.github/workflows/release.yml` builds
`ferrum-<version>-{x86_64,aarch64}.tar.gz` from a `v*` tag, signs them with
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
