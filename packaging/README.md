# Packaging

Empty until Phase 1. It will hold:

- `cargo-deb` and `cargo-generate-rpm` metadata for `.deb` and `.rpm` builds,
- the release signing setup — self-update verifies an ed25519 (minisign)
  signature before swapping a binary, and rolls back if the new version fails
  its health check within 60 seconds (spec §5.5),
- the repository metadata for our own package repo, which is where prebuilt
  dynamic nginx modules (brotli, ModSecurity) will come from, since we never
  compile on a customer's server.

Until then, `installer/install.sh --from ./target/release` installs from a local
build.
