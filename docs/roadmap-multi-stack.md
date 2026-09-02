# Making Unihelm a panel for any server

Written after a night's work on the parts that were reachable, and an honest
account of the parts that were not. The request was: every language, every web
server, every database, a database GUI, mail DNS into Cloudflare, domain
attachment, themes, and full Docker management.

Several of those already existed and needed connecting rather than building.
Several are weeks of work each and are described here rather than half-built,
because a control panel that half-manages a production server is worse than one
that admits it only reads.

## What landed

| | |
|---|---|
| `sites.discover` | Reads vhosts nginx already serves. php / static / proxy / redirect, with root, upstream, certificate and source file. |
| `runtime.list` | Node, Python, PHP, Ruby, Go, Deno, Bun — every installed version with its absolute path. |
| `mail.dns.publish` | Writes the SPF advisory into the configured provider's zone. Dry run by default; never overwrites. |
| catchall yields | The panel's default server steps aside where one already exists, instead of failing `nginx -t` and rolling back. |
| `http2 on;` gated | Ubuntu 24.04 ships nginx 1.24, where that directive is a hard error. Every vhost the panel rendered was invalid there. |

The last one was not on the list and matters more than most things that were:
site creation was broken on a distribution this project tests on every release.

## What already existed

Worth knowing before building anything: the panel already has `app.*` for Node
applications, `db.*` for MySQL/MariaDB/Postgres including **Adminer** as a
database GUI, `dns.provider.set` with a working Cloudflare client that creates
and deletes records, `panel.tls.issue` for putting the panel on a domain, and
`branding.*` for the look of it.

So "a GUI to manage databases" is `db.adminer.enable`, and "attach a domain
later" is `unihelm cert panel <domain>`. Both need surfacing in the UI, not
building.

---

## 1. Apache and LiteSpeed alongside nginx

**Where the architecture already helps.** `Validator` and `Reloader` are traits
(`unihelm-config/src/apply.rs`), and the apply engine takes them per request. A
second web server plugs in there without touching the engine.

**Where it does not.** 28 files under `unihelm-ops` and `unihelm-config` name
nginx, and 32 sites wire `NginxValidator` or `UnitReloader::nginx` directly. The
site model has no server field. The templates are nginx syntax throughout, and
the WAF integration is ModSecurity-for-nginx.

**The shape of the work.**

1. A `WebServer` enum on the site, defaulting to nginx, stored per site rather
   than per server — an operator migrating one site at a time is the normal
   case, not the exotic one.
2. `templates/apache/` and `templates/litespeed/` beside `templates/nginx/`, and
   a template name resolved from the site's server rather than hardcoded.
3. `ApacheValidator` (`apachectl configtest`) and `LitespeedValidator`, both
   trivial against the existing trait.
4. Port arbitration. Two web servers cannot both own :80. Either one is the
   front and the other is disabled, or nginx fronts and Apache listens on 8080
   as a backend — which is the classic and probably the right default for the
   "PHP with .htaccess" case that drives this request at all.
5. The catchall and default-server logic already written for the nginx survey
   generalises: whichever server is in front owns the default.

**Risk.** High. This touches every site the panel manages. It must be per-site
and reversible, and it needs the drift detection extended or a switched site
will silently diverge.

**Estimate.** Two to three weeks to do properly. A week to do badly.

## 2. Runtimes beyond discovery

`runtime.list` reads what is installed. Two things follow.

**Pinning.** `nodeapp.rs` resolves one absolute `node` at create time and its own
header says per-app pinning "changes only which path that is". So: a
`runtime_version` column on `node_apps`, resolved through `runtimes::survey()` at
create and at update, written into the unit's `ExecStart`. Small and contained —
this is the next thing to build.

**Installing.** Harder, and the reason it is not done. Installing a Node version
means either a version manager (fnm/nvm, per-user, invisible to systemd unless
the absolute path is captured) or a distribution repository (NodeSource,
one line per major version, signed). The project's own rule — spec §11.1,
install only from official upstream repos pinned by full fingerprint — points at
the second. `unihelm_distro::repos` exists for exactly this and is where it goes.

**Beyond Node.** A Python or Ruby app is the same shape as a Node app: a process,
a port, a unit file, a proxy vhost. `nodeapp.rs` is 80% of a generic
`app` module — the Node-specific parts are the binary name, the entry file
convention and `NODE_ENV`. Generalising it is a day's work and unlocks Python,
Ruby, Go and Bun at once.

## 3. More databases

Today: MySQL/MariaDB and Postgres, through `db.*`.

The honest shape of "a store where you install what you want" is a
`DatabaseEngine` enum, a per-engine trait for create/drop/grant/user, and the
distro repo definitions for installing each. Redis, MongoDB and SQLite are all
different enough in their access model that a shared `db.user.create` across all
of them would be a lie — Redis has no users in the same sense before ACLs, SQLite
has no server at all.

Suggested order: Redis first (widely wanted, simple), then MongoDB. SQLite needs
no management and should be left out.

## 4. Docker

Nothing exists today. This is its own product: images, containers, volumes,
networks, compose files, logs, exec, and a registry credential store. It also
overlaps the panel's security model in a way nothing else does — a container with
the docker socket mounted is root on the host, so "manage Docker from the panel"
means the panel can be used to bypass every boundary it enforces elsewhere.

If it is built, it should start read-only: list containers, images, volumes,
show logs and stats. That is most of the value and none of the risk. Start/stop
next. Anything that runs a new container needs a considered answer to the socket
question first.

## 5. The small ones

**Attach a domain from settings.** `panel.tls.issue` does the work; the UI needs
a form that takes a domain, calls it, and then tells the operator to change
`listen` back to loopback because nginx is now in front. Half a day.

**Themes.** `branding.*` already stores colours. A theme is a named set of those
values plus a picker. A day, mostly UI.

**Mail DNS into Cloudflare.** Done tonight.

**Database GUI.** `db.adminer.enable` exists. It needs a button and a link in the
databases page rather than a CLI call. Half a day.

---

## What to build next, in order

1. **Runtime pinning for Node apps.** Small, contained, immediately useful, and
   the model already anticipates it.
2. **Generalise `nodeapp` into `app`.** Unlocks Python, Ruby, Go and Bun for one
   day's work.
3. **Surface what exists in the UI** — Adminer, `cert panel`, `sites.discover`,
   `runtime.list`. Several of the requests above are already answered by code
   nobody can reach from the panel.
4. **Apache as a backend behind nginx.** The `.htaccess` case, without the port
   war.
5. **Docker, read-only.**

Everything above 4 is a week of work in total. Items 4 and 5 are the ones worth
thinking about before starting.
