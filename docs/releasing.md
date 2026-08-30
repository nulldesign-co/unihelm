# Releasing Unihelm

A release is one signed tag. Everything after that is
[`.github/workflows/release.yml`](../.github/workflows/release.yml): it builds
the UI once, builds three binaries for two architectures, refuses anything over
the 25 MB budget, packages per-architecture tarballs, signs them with minisign,
and leaves a **draft** release for a human to publish.

Publishing stays manual on purpose. Self-update follows *published* releases and
swaps binaries on every server that runs Unihelm (spec §5.5), so an accidental
tag must not be able to reach them.

---

## Before the first release ever runs

The repository ships [`minisign.pub`](../minisign.pub) as a placeholder so the
file exists and the tarball layout is right from day one. It is not a key. The
workflow **fails** while the word `PLACEHOLDER` is still in that file, so the
placeholder cannot be shipped by accident — but that also means the first
release does not run until the steps below are done.

### 1. Generate the signing key

On a machine you trust, offline if you can:

```bash
minisign -G -W -p minisign.pub -s minisign.key
```

`-W` writes the secret key without a password. That is deliberate and it is a
trade-off worth understanding rather than copying:

- GitHub Actions has no terminal, so a password-protected key cannot be typed
  in. Feeding a password on stdin means storing the password as a second secret
  next to the key it protects, which buys nothing.
- So the protection is not a passphrase, it is *custody*: the secret key exists
  in exactly two places — an encrypted vault (password manager) and the
  `MINISIGN_SECRET_KEY` repository secret — and it is rotated on any suspicion.

If you would rather hold a passphrase-protected key, keep one and sign releases
by hand from a workstation; do not try to make CI type a passphrase.

### 2. Store the two halves

| Half | Where it goes | Where it must never go |
|---|---|---|
| `minisign.pub` | committed to the repository, shipped in every tarball, quoted in the release notes | — |
| `minisign.key` | password manager (as a file/secure note) **and** GitHub → Settings → Secrets and variables → Actions → `MINISIGN_SECRET_KEY` | the repository, a laptop's home directory, chat, a CI log, an artifact |

Paste the **entire** two-line contents of `minisign.key` into the secret —
comment line included. The workflow writes it to `$RUNNER_TEMP/minisign.key`
under `umask 077`, uses it in one step, and removes it in an `if: always()`
step. It is never written into the checked-out tree, so it cannot be swept up
by an artifact upload.

`.gitignore` covers `minisign.key`, because `minisign -G` writes it right next
to the public key in whatever directory you happen to be in — which is usually
a clone. `tests/gates/release.sh` asserts that ignore entry is still there.

### 3. Commit the public key

```bash
git add minisign.pub
git commit -m "Release signing key"
```

Say in the commit message, or in an announcement, what the key's ID is
(the trailing text of the `untrusted comment:` line). People who verify Unihelm
should learn the key from somewhere other than the artifact they are verifying.

---

## Cutting a release

### 1. Bump the version

The workspace version is the version. `Cargo.toml`:

```toml
[workspace.package]
version = "0.2.0"
```

The workflow reads the tag, strips the `v`, and compares it with this field
before it builds anything; if they disagree the release stops in about ten
seconds. It then checks again at the end, by running `--version` on each
packaged binary. A binary that reports a version its tag disagrees with is
worse than a failed release: it makes every later bug report ambiguous.

### 2. Check what a release will actually contain

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
bash tests/gates/no-shell.sh
bash tests/gates/installer.sh
bash tests/gates/release.sh

cd ui && npm ci && npm run build && cd ..
cargo build --release
bash tests/gates/budgets.sh
```

CI runs all of this on `main` already; running it locally before tagging just
means finding out now rather than after the tag exists.

### 3. Tag and push

```bash
git commit -am "Unihelm 0.2.0"
git tag -s v0.2.0 -m "Unihelm 0.2.0"
git push origin main
git push origin v0.2.0
```

`-s` signs the tag with your own git/GPG key. That is separate from the
minisign release key and does a different job: the git signature says who cut
the release, the minisign signature says the binaries are the ones that tag
produced.

### 4. Watch the workflow

It runs four jobs:

| Job | What it proves |
|---|---|
| `Version` | the tag and `Cargo.toml` agree |
| `UI bundle` | `npm ci` + `npm run build` on node 20, initial route still under 350 KB gzipped |
| `x86_64` / `aarch64` | the binaries build, are each under 25 MB, unpack, and report the right version on their own architecture |
| `Sign and draft the release` | checksums, minisign signatures, signatures verify against the committed public key, draft created |

The UI is built once and downloaded by both build jobs, because `unihelm-web`
embeds `crates/unihelm-web/ui-dist` with `rust-embed` **at compile time**
(`crates/unihelm-web/src/ui.rs`). A build job that starts without that directory
populated still succeeds and still produces a running binary — one that serves
an empty page. The workflow therefore fails outright if `ui-dist/assets` is
missing after the download, rather than trusting it.

### 5. Publish

Open the draft release, read the notes, and press publish.

Check before you do:

- both tarballs are attached, plus `SHA256SUMS`, `SHA256SUMS.minisig`, and a
  `.minisig` per tarball,
- the public key quoted in the notes is the one you expect,
- the glibc floor in the notes is one your supported distributions meet
  (see the caveat below).

### Re-running a release

`workflow_dispatch` takes an existing tag and rebuilds it. The job deletes and
recreates the *draft* (never the tag), so re-running does not leave two
generations of assets on one release.

If the release for that tag is already **published**, the workflow stops with an
error instead. Deleting a published release would take its download URLs out
from under everyone who has them and unpublish the release self-update is
following (spec §5.5). A published tag is immutable: the fix for a bad published
release is `v0.2.1`, not a rebuild of `v0.2.0`.

The tarballs are byte-reproducible, so a rebuild of the same tag on the same
runner image produces the same checksums — file order, ownership, mtimes and the
gzip header timestamp are all pinned. That is what makes "re-run it and compare"
a meaningful check rather than a guess. It holds across re-runs of the same
runner image, not across a runner image that ships a different `tar` or `gzip`.

---

## What operators do with the signature

```bash
curl -fsSLO https://github.com/farzam-seyedhashem/unihelm/releases/download/v0.2.0/unihelm-0.2.0-x86_64.tar.gz
curl -fsSLO https://github.com/farzam-seyedhashem/unihelm/releases/download/v0.2.0/unihelm-0.2.0-x86_64.tar.gz.minisig

minisign -Vm unihelm-0.2.0-x86_64.tar.gz -P 'RW…'   # key from the repo, not the download
tar -xzf unihelm-0.2.0-x86_64.tar.gz
cd unihelm-0.2.0-x86_64 && sudo ./install.sh --from ./bin
```

Two signature layers exist because they answer different questions:

- **`SHA256SUMS.minisig`** — one signature over the checksum file. A human
  verifies it once and then `sha256sum -c SHA256SUMS` covers every artifact.
- **`unihelm-<version>-<arch>.tar.gz.minisig`** — a signature on each tarball on
  its own. Self-update fetches one file and must be able to decide whether it is
  genuine without also fetching and parsing a checksum list (spec §5.5).

Every tarball also carries a copy of `minisign.pub`. That copy is for verifying
the *next* release; it proves nothing about the download it came in.

---

## Rotating the signing key

Rotate on a schedule you decide, and immediately if any of these is true: the
secret key was on a machine that was compromised, it was pasted anywhere other
than the vault and the repository secret, a maintainer with access to the
repository secret leaves, or you simply do not know where all the copies are.

The awkward part of rotating a release key is that anything already deployed
trusts the old one. So the order matters:

1. **Generate the new key** — `minisign -G -W -p minisign-new.pub -s minisign-new.key`.
2. **Announce it, signed by the old key.** Write a short statement naming the
   new public key, sign it with the *old* secret key
   (`minisign -Sm KEYROTATION.txt -s minisign.key`), and publish both on the
   previous release and wherever else you announce. This is the only step that
   makes the rotation verifiable rather than an unexplained key change.
3. **Replace the repository secret** with the new secret key.
4. **Commit the new `minisign.pub`** over the old one, in the same commit as the
   version bump for the release that will use it. The workflow verifies every
   signature it makes against the committed public key, so a half-done rotation
   — new secret in CI, old public key in the repository — fails the release
   instead of shipping artifacts nobody can verify.
5. **Cut a release with the new key.** Its notes quote the new key.
6. **Destroy the old secret key** everywhere: vault entry, any local copy. Keep
   the old *public* key in the announcement so old artifacts stay verifiable.
7. **Update anything pinned to the old key**, including self-update's trusted
   key, and treat servers still pinned to the old key as needing a manual step
   — a rotation that silently breaks self-update is a rotation that strands
   every server that has not updated yet.

Never reuse a key ID, and never "un-rotate" back to an old key. If step 2 is
impossible because the old secret key is already gone or compromised, say so
plainly in the announcement: an unsigned rotation notice is weak, and pretending
otherwise is worse than admitting it.

---

## Known gap: the glibc floor

The build runs on `ubuntu-24.04`, which links against glibc 2.39. Spec §7.1 also
promises Debian 12 (glibc 2.36) and AlmaLinux 9 (glibc 2.34), and a binary built
against a newer glibc does not run on an older one — it dies at startup with
`version 'GLIBC_2.38' not found`.

The workflow does not hide this: each build job computes the highest `GLIBC_`
symbol version its binaries need and puts it in the release notes, so the
requirement is stated rather than discovered. But until the build moves, the
tarballs are for glibc ≥ 2.39 distributions.

Two ways to close it, when someone picks it up:

- **Build in an older container** — run the cargo step inside `almalinux:9`
  (or `debian:12`), which is the oldest glibc in the support matrix. Keeps
  dynamic linking, needs a container step per architecture.
- **Build `*-unknown-linux-musl`** — statically linked, runs on anything.
  Costs binary size and swaps in musl's allocator, so re-measure against the
  25 MB budget and the RSS budget (spec §3) before committing to it.

Until then, `installer/preflight.sh` reports the OS but does not check glibc, and
building from source (`cargo build --release`) is the supported path on the older
distributions.
