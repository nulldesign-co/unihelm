# Security policy

## Supported versions

None yet. Ferrum is pre-release: there are no published versions, no binary
downloads, and no deployment we support. Until the first tagged release, the
only supported response to a security problem is a fix on `main`.

| Version | Supported |
|---|---|
| (no releases yet) | — |

Once releases exist, this table will name which ones receive fixes.

## Reporting a vulnerability

Email **farzam.seyedhashem@gmail.com** (the address on every commit). Please
do not open a public issue for anything exploitable.

Include what you would want to receive: the affected code path, a reproduction
or proof of concept, and your assessment of impact. Since there is no release,
"affected version" is a commit hash.

This is a small pre-release project without a security team or a bounty
program; what you will get is an honest reply, credit if you want it, and a
fix that lands with a regression test named after the hole it closes.

## Threat model, in brief

Ferrum is a control panel that runs privileged operations on a server hosting
mutually untrusting tenants. The design assumes three hostile parties, in
increasing order of access:

**An attacker on the network.** Faces `ferrum-web` only: argon2id password
hashing, session cookies stored as SHA-256 digests, CSRF tokens on mutations,
rate limiting, and a default configuration that listens on loopback until the
operator decides otherwise.

**A hostile tenant.** Owns a Linux account and can run PHP. Each site runs in
its own FPM pool as its own user, `open_basedir` confined to the site,
dangerous functions disabled via `php_admin_value` (which `ini_set()` cannot
widen), home directories mode 0710 with a single traversal group. This
isolation is not assumed from configs — it was verified from inside a tenant's
PHP on a live server: `/etc/passwd` unreadable, `/home` unlistable,
`shell_exec` absent.

**A compromised web process.** The design's central assumption is that
`ferrum-web` — the internet-facing half — will one day be compromised, and the
damage must be bounded. It runs unprivileged and holds no capabilities.
Everything privileged crosses a 0700 Unix socket (peer-credential-checked on
accept) into `ferrum-agentd`, which treats the web process as untrusted:
operations must exist in a whitelist registry, the caller's rights are
re-derived from the database rather than believed from the frame, and inputs
must deserialize into validated newtypes. A compromised web process can ask
for privileged work — but only work on the list, only within rights the
database grants that account, only with inputs that survive validation, and
every request is audited.

Two classes of attack are removed structurally rather than defended against:

- **Shell injection** cannot occur because nothing is ever executed through a
  shell — every command is an argv array, enforced by a CI gate
  (`tests/gates/no-shell.sh`).
- **Malicious upstream packages** from a spoofed repository cannot install
  because every repository's signing key is pinned by full fingerprint in the
  source and verified in-process against the key actually downloaded, before
  any repo file is written.

Secrets at rest (ACME account keys, and every credential to come) are sealed
with XChaCha20-Poly1305 under a master key in `/etc/ferrum/secret.key` (0600);
the key refuses to load from a file with wider permissions.

**Out of scope:** an attacker who is already root on the host, kernel
vulnerabilities, physical access, and the security of the tenant applications
themselves — Ferrum bounds what a hacked WordPress can reach, but cannot make
it unhackable.

A longer treatment of the boundary and its enforcement points is in
[docs/architecture.md](docs/architecture.md).
