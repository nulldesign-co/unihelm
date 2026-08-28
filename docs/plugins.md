# Plugins — the sidecar contract

Spec §6 does not leave this open:

> Do NOT let plugins run in-process as root.

Everything on this page follows from that one sentence. A Ferrum plugin is **a
separate process**, started by the agent under a **dedicated unprivileged system
account**, inside a systemd unit carrying the same hardening the panel's own
`ferrum-web` unit does, speaking the panel's **existing length-prefixed JSON
framing** over **its own** Unix socket.

There is no dynamic library, no ABI, no `dlopen`, and no code path from a plugin
into the agent's address space. A plugin that segfaults, hangs or leaks is one
unit that systemd restarts.

---

## 1. What a plugin can extend

Five extension points, each owning one method namespace on the sidecar
protocol:

| Point | Namespace | What it provides |
|---|---|---|
| `app_store` | `app.*` | New installable application definitions (spec §11.14) |
| `dns_provider` | `dns.*` | A DNS-01 provider beside Cloudflare (spec §11.13) |
| `backup_target` | `backup.*` | A restic-compatible destination (spec §11.10) |
| `notifier` | `notify.*` | An alert notification channel (spec §11.11) |
| `ui_panel` | `ui.*` | A micro-frontend mount point under `/plugins/<path>` |

**The manifest is the routing authority.** A plugin declares its points at
install time; the panel stores that list and routes only the calls those points
cover. Nothing ever asks the running sidecar what it thinks it provides, so a
plugin cannot widen its own reach at runtime. A plugin that declared `notifier`
and is asked for `dns.present` is refused *before a socket is opened*.

### What a plugin can never do

**Register an operation.** The operation registry is built from a fixed list in
Rust (`crates/ferrum-ops/src/registry.rs`). Nothing in the plugin system inserts
into it, and that is load-bearing rather than incidental: the registry is where
the permission check lives, so an extension point that could add an operation
would be an extension point that could add an unchecked one. Plugins are reached
*through* operations, never as them — the permission is checked on the panel's
own operation, and only then does the agent consult a plugin.

**Get a writable path.** The install directory is root-owned; the plugin account
may read and execute, never write. The unit sets `ProtectSystem=strict` with no
`ReadWritePaths` at all. Anything a plugin needs to persist goes through an
extension-point call to the agent, which is the whole reason the extension
points exist.

**See who the caller is.** The sidecar request envelope carries a method and
params, and nothing else. It is deliberately *not* the panel's own
`RequestFrame`, which carries an `AuthContext` — a plugin has no business
knowing which account triggered a call, let alone what permissions it holds.

---

## 2. The payload

A plugin is a directory. At its root:

```
plugin.toml            the manifest
plugin.toml.minisig    a detached minisign signature over plugin.toml
bin/plugin             the entry point, and whatever else the manifest lists
```

### `plugin.toml`

```toml
slug        = "acme-dns"          # [a-z0-9][a-z0-9-]* , 1–19 characters
name        = "ACME DNS provider"
version     = "1.2.3"
entry       = "bin/plugin"        # relative to this directory
api_version = 1
extensions  = ["dns_provider"]

# Optional, and only with `ui_panel` declared above.
[ui]
path     = "acme"                 # mounts at /plugins/acme
label_en = "ACME DNS"
label_fa = "دی‌ان‌اس ای‌سی‌ام‌ای"

# Every file in the payload, by path, with its lowercase hex SHA-256.
[files]
"bin/plugin" = "9f2c…"
```

Rules the panel enforces, and why each one exists:

- **`slug`** is `[a-z0-9]`, then up to 18 more of `[a-z0-9-]`, ending
  alphanumeric. That alphabet is the intersection of three things the slug
  becomes: a systemd unit-name component, a Unix account name
  (`ferrum-plug-<slug>`, which must fit in 32 characters), and a path component.
  No dots — a dot in a unit name changes what systemd thinks the unit *is*.
- **`entry`** must be relative and traversal-free, and must contain no character
  systemd would read as syntax in `ExecStart=` — no space (which would split the
  command), no `%` (a specifier expanded before anything else reads the line),
  no quote or `$`. Refused rather than escaped: a binary whose path needs
  quoting is a packaging mistake worth naming.
- **`api_version`** must equal the protocol this panel speaks (**1**). A
  mismatch is refused at install time rather than discovered as a parse error on
  a socket at three in the morning.
- **`extensions`** must be non-empty and free of duplicates. A plugin that
  extends nothing is a service, not a plugin.
- **`[ui]`** requires `ui_panel` in `extensions`, and `path` must be a single
  slug-shaped segment. A plugin does not get to name a route outside its own
  namespace.
- **`[files]`** must list every file in the payload, and must *not* list
  `plugin.toml` or `plugin.toml.minisig` — a file cannot carry its own digest.
  The entry point must appear in it: an unlisted file is an unverified file.

---

## 3. Trust: how a payload is verified

Two independent checks, in this order.

**Authenticity — a minisign signature over `plugin.toml`.** The panel verifies
`plugin.toml.minisig` against the public keys in the `plugins.trusted_keys`
setting (a JSON array of the `RW…` strings `minisign -p` prints). This is the
same ed25519/minisign format the installer already verifies releases with
(spec §5.5), so a publisher signs a plugin with the tool they already have:

```sh
minisign -Sm plugin.toml -t "acme-dns 1.2.3"
```

Verification is done **in process**, not by shelling out to `minisign`: the
binary is an EPEL package on the RHEL family and may simply not be installed,
and a verification that silently degrades to "skipped" when a tool is missing is
not a verification. Both the payload signature *and* the global signature over
the trusted comment are checked — skipping the second is the classic minisign
implementation bug, and it leaves the field whose whole name promises it is
trustworthy freely editable by anyone holding the file.

**Integrity — the `[files]` digest table.** Every listed file must exist with
the listed SHA-256, **and every file in the tree must be listed**. The second
direction is the one that matters: a checker that only verifies what the
manifest mentions is defeated by shipping a second binary the manifest does not
mention, and the signature over the manifest would still verify perfectly.
Symlinks are refused anywhere in the tree — a symlink has no content to hash,
and one pointing at `/etc/shadow` inside a directory the agent is about to copy
is the oldest trick there is.

Together these give the same shape as the release pipeline's `SHA256SUMS` +
minisign: one signed document that vouches for a set of digests.

### Unsigned plugins, and why they are refused by default

`plugins.allow_unsigned` defaults to **false**, and installing a plugin with no
`plugin.toml.minisig` fails with a refusal that names the setting.

The reasoning is not ceremony. A plugin is code the agent **starts as a service
on a machine full of other people's websites**. It runs beside the panel, on the
same host as every tenant's files and every tenant's database. "I downloaded it
from somewhere" is not a trust decision a control panel should make on an
operator's behalf, and a default of "install whatever" would mean the first
plugin most people ever install is installed without anybody having decided to
trust its author.

Turning the setting on is legitimate — you are developing a plugin, or you build
your own and do not sign it. It is a decision, so it is spelled as one, it is
recorded on the row (`signature = "unsigned"`) rather than forgotten, and the
install log carries a warning. The row keeps that answer for the months-later
question of *how did this get here*.

Note that the digest table is enforced **either way**. Turning off signature
checking removes authenticity, not integrity: an unsigned plugin still cannot
contain a file nobody listed.

---

## 4. Installing, enabling, removing

```
POST   /api/plugins                     { "source": "/opt/staged/acme-dns" }
POST   /api/plugins/{slug}/enable
POST   /api/plugins/{slug}/disable
DELETE /api/plugins/{slug}
GET    /api/plugins
```

**The panel does not fetch anything.** `plugin.install` takes a path to a tree
already staged on the server; a marketplace client (spec §14 Phase 6) belongs
above this layer and would stage a tree exactly like this one. The source path
must be absolute and canonical, and it may not be under `/home` — a tree a
tenant can rewrite between the moment it is verified and the moment it is copied
would make the whole signature check theatre.

**Installing is not starting.** A freshly installed plugin is **disabled**: the
unit is written, the account exists, the tree is in place, and nothing is
running. An operator can read the manifest the panel accepted before any of that
code executes. Enabling is a separate, audited decision.

**There is no in-place upgrade.** Installing over an existing slug is a conflict;
remove and install. An in-place upgrade has to reconcile a running sidecar, a
changed manifest and a changed extension set, and getting that half-right is
worse than not offering it.

**Removing leaves the account behind**, and says so in the result. `userdel` on
a system account that might still own a file somewhere is how a uid gets
recycled onto files nobody meant to hand over.

---

## 5. What the sidecar has to implement

### The unit the panel writes

```ini
[Service]
Type=simple
User=ferrum-plug-<slug>
WorkingDirectory=/var/lib/ferrum/plugins/<slug>
ExecStart=/var/lib/ferrum/plugins/<slug>/<entry>
Environment=FERRUM_PLUGIN_SOCKET=/run/ferrum/plugins/<slug>/plugin.sock
Environment=FERRUM_PLUGIN_SLUG=<slug>
Environment=FERRUM_PLUGIN_API=1
RuntimeDirectory=ferrum/plugins/<slug>
RuntimeDirectoryMode=0750
…NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, PrivateDevices,
   ProtectKernel*, ProtectControlGroups, ProtectClock, ProtectHostname,
   ProtectProc=invisible, RestrictRealtime, RestrictSUIDSGID,
   RestrictNamespaces, RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6,
   LockPersonality, MemoryDenyWriteExecute, SystemCallArchitectures=native,
   SystemCallFilter=@system-service, CapabilityBoundingSet= (empty),
   AmbientCapabilities= (empty), MemoryMax=128M, TasksMax=64…
```

`PrivateNetwork` is deliberately **not** set: a DNS provider or a backup target
exists to talk to a remote API. `RestrictAddressFamilies` keeps that to the
families a network client actually needs.

### The socket

Bind a `SOCK_STREAM` Unix socket at `$FERRUM_PLUGIN_SOCKET` and accept
connections. `systemd` creates the parent directory, owns it to your account and
removes it when the unit stops, so there is never a stale socket to clean up.
The agent dials exactly that path and nothing else — a plugin that binds
elsewhere is simply unreachable.

### The framing

The same wire format as the panel's own IPC (spec §5.3), and deliberately so —
`crates/ferrum-ipc/src/codec.rs` is the reference implementation:

> **A 4-byte big-endian length, then that many bytes of UTF-8 JSON.**

One request per connection, one response, then the agent closes. A reply may not
exceed **1 MiB** — extension-point answers are DNS records, repository listings
and notification receipts.

**Request** (agent → plugin):

```json
{ "v": 1, "id": "3f0a…", "method": "dns.present", "params": { … } }
```

`id` is a correlation string; echo it or ignore it, the agent only ever logs it.

**Response** (plugin → agent), tagged on `result`:

```json
{ "result": "ok",  "data": { … } }
{ "result": "err", "message": "the zone is not delegated to this account" }
```

An `err` message reaches an operator's screen, so write it for one; it is
truncated at 500 characters. The agent waits **15 seconds** for a reply — a
plugin call happens inside an operation somebody is waiting on, so a plugin that
hangs must not become a panel that hangs.

### A minimal sidecar

```python
import json, os, socket, struct

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(os.environ["FERRUM_PLUGIN_SOCKET"])
sock.listen(8)

def read_frame(conn):
    (n,) = struct.unpack(">I", conn.recv(4))
    buf = b""
    while len(buf) < n:
        buf += conn.recv(n - len(buf))
    return json.loads(buf)

while True:
    conn, _ = sock.accept()
    with conn:
        try:
            request = read_frame(conn)
            if request["method"] == "dns.present":
                reply = {"result": "ok", "data": {"record_id": "abc"}}
            else:
                reply = {"result": "err", "message": "unsupported method"}
        except Exception as e:                      # never die on one caller
            reply = {"result": "err", "message": str(e)}
        body = json.dumps(reply).encode()
        conn.sendall(struct.pack(">I", len(body)) + body)
```

---

## 6. Settings

| Key | Default | Meaning |
|---|---|---|
| `plugins.allow_unsigned` | `false` | Whether a payload with no `plugin.toml.minisig` may be installed. See §3. |
| `plugins.trusted_keys` | `[]` | JSON array of minisign public keys (`RW…`) that plugin manifests may be signed with. Empty means this panel trusts nobody's plugins. |

A *signed* plugin installed while `plugins.trusted_keys` is empty is refused,
and the refusal names the setting: a signature nobody has said they trust is not
better than no signature, it is just longer.
