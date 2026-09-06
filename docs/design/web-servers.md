# More than one web server

Nginx, Apache and OpenLiteSpeed, switchable, with every site the panel serves
following the switch. The catalogue has offered all three since 0.2; only nginx
has ever been able to serve a site, because a vhost is a rendered template and
there has only ever been one.

## What is already settled

[`containerised-runtimes.md`](containerised-runtimes.md) put the web server on
the host and every runtime in a container, and said why that makes this
tractable: the FPM containers do not know what is in front of them, and only the
connection to the socket changes.

    nginx        fastcgi_pass unix:/run/unihelm/fpm/<site>-php83.sock
    Apache       SetHandler proxy:unix:/run/unihelm/fpm/<site>-php83.sock|fcgi://
    LiteSpeed    an external app pointed at the same socket

So the runtime half of this is done and shipped. What is left is the vhost half,
and the vhost half is where the danger is.

## The danger

`nginx/site.conf.j2` is 216 lines and most of them are load-bearing. Two are
worth naming outright because they are the difference between a hosting panel
and an incident:

    try_files $uri =404;   # inside the .php location

Without it a request for `/uploads/avatar.png/evil.php` reaches PHP with
`PATH_INFO` set, and an upload directory is remote code execution. Apache's
`SetHandler proxy:...|fcgi://` does not have this shape at all — the equivalent
protection is `AcceptPathInfo Off` plus never handing a non-existent path to the
handler — which is exactly the kind of "the same thing, spelled differently"
that a second backend gets wrong quietly.

    location ~ /\.(?!well-known)   # dotfiles
    location ~* \.(?:sql|bak|env|...)$

A second backend that renders 95% of the first one is not 95% as good. It is a
panel that serves `.env` on Tuesdays.

## Feature parity is not a detail, it is the design

Three things this panel offers per site have no equivalent in Apache's base
modules. Verified rather than assumed:

| Feature | nginx | Apache | OpenLiteSpeed |
|---|---|---|---|
| request rate limiting | `limit_req_zone` | **none in base** — `mod_ratelimit` is bandwidth in KiB/s, not requests; requests need `mod_qos` or `mod_evasive`, neither of which ships enabled | per-vhost throttling, built in |
| HTTP/3 | `listen 443 quic` | **none in production** — `mod_http3` is experimental, on a patched httpd | built in |
| connection limiting | `limit_conn` | `mod_qos` again | built in |

An operator who has rate limiting on a site, switches to Apache, and is not told
has lost a control they chose and still believes they have. That is the same
class of failure as every serious bug this project has had: **the panel telling
somebody a thing is true when it is not.**

So the switch is not "render the other template". It is:

1. Survey every site for features the target cannot do.
2. Refuse, naming the sites and the features, unless the operator says to drop
   them — and record what was dropped, per site, so the panel keeps saying so
   afterwards rather than quietly presenting a rate-limit field that does
   nothing.
3. Only then render.

The refusal is the feature. Everything else is templates.

## Order of work

Each step is a release, and each leaves the panel working.

**1. The seam.** *(Shipped in 0.7.0.)* One place decides which web server is active, and the two vhost
call sites in `site.rs` ask it instead of naming `nginx/site.conf`,
`NginxValidator` and `UnitReloader::nginx` literally. No behaviour changes:
nginx is the only answer the seam can give. This is the step that is safe to get
wrong, so it goes first and alone.

**2. Apache.** *(0.7.0, corrected in 0.7.1 — see below.)* The vhost template, `apachectl configtest` as the validator, the
modules it needs (`proxy_fcgi`, `ssl`, `rewrite`, `headers`, `expires`,
`deflate`), and the parity survey above. Apache first because it shares the FPM
socket contract exactly and has a real config validator, which is what the
apply engine's snapshot → write → validate → roll back cycle is built on.

**3. The switch.** *(0.7.0, corrected in 0.7.1.)* `webserver.switch`, which re-renders every site, validates
the whole configuration with the target's own tool, starts it and stops the
incumbent — and puts the incumbent back on any failure. Not per-site: a machine
half on Apache is a machine with two things fighting over port 80.

### What the building actually taught

Steps 2 and 3 shipped as 0.7.0 and the release stayed a draft, because an
adversarial review of that diff — seven independent readers over the switch, the
templates, the modules, the survey, the rest of the codebase and the wiring —
found that **it could not have served a single page**. The plan above is not
wrong; it is incomplete in a way that only reading the whole system exposes.

**The permission model is the feature, not the templates.** Every one of the
panel's tenant boundaries is one group. A site directory is
`tenant:<web server group>` at `0710` so the server can traverse it and nobody
else can; each FPM socket is `0660` with the same group. Apache runs as
`www-data`, which is in none of it — so a switched machine answers 403 for every
static file and 503 for every PHP page with a configuration that is otherwise
perfect. Nothing about a vhost template can reveal this. The arriving server is
added to that group before anything is written.

**A missing Apache module is not a syntax error.** `configtest` passes, Apache
starts, every page loads, and the directives that needed the module are silently
inert. nginx has no equivalent hazard: its features are compiled in and an
unknown directive fails `nginx -t` loudly. So the switch enables what the vhosts
need and then *verifies* it against Apache's own `-M` output. The enable is a
best effort; the verification is not. The first list had eight modules and
missed six more, all of them default-enabled — which is exactly why they were
left out, and exactly why they belong in a check that exists for the machine
that is *not* in its default state.

**Validation that cannot see the files it is validating is worse than none.**
Every `paths::apache_*` is Debian's `/etc/apache2`. On EL, Apache is `httpd` and
reads `/etc/httpd/conf.d`, so the vhosts would be written correctly and read by
nothing — and `apachectl configtest` would still *pass*, because httpd would be
checking its own stock configuration. The switch's own safety check would have
reported success while taking the machine to the distribution's default page.
That is a refusal, not a warning, until the paths resolve against the family.

**A task cannot refuse.** `webserver.switch` answers 202 and a task id long
before it has looked at a site, so the refusal listing what a switch would cost
never reaches that call. The page read the list off the switch's own error,
which meant the confirm-then-accept flow could never complete: the first click
always succeeded, cleared the pending state, and `accept_gaps` was unsendable.
Any operation whose refusal is part of its interface has to be able to answer
that question separately — `webserver.gaps` is that, behind `server_read`.

**Two features are server-wide and nginx-only.** The WAF's rules are loaded by
nginx's ModSecurity connector; Adminer is served from an nginx vhost. Both would
have gone quiet while the panel went on reporting them as enabled, which is the
failure this whole document is about. They are gaps now, reported before the
switch runs.

The lesson under all five: **the templates were the easy half, and the half that
looks like the work.** Everything that actually broke lived somewhere else — in
a group, a path, an execution mode, a module list, a feature two pages away.

**4. OpenLiteSpeed.** Not started. Last because its configuration is a different shape — a
`virtualhost` block in `httpd_config.conf` plus a per-vhost file, with listeners
mapping domains to vhosts — and because its validation story needs to be
established before anything depends on it. The apply engine will not write a
file it cannot validate, and that rule does not bend for a third web server.

## What does not change

Sites, tenants, FPM pools, sockets, certificates, DNS, backups. A site's row in
the database says what it serves, not what serves it. That is why this is a
switch and not a migration.

---

Sources for the parity table:
[mod_ratelimit](https://httpd.apache.org/docs/2.4/mod/mod_ratelimit.html) ·
[mod_http3 status](https://codeit.guru/2026/08/mod_http3-0-0-52-for-apache-httpd-2-4-68-is-available-for-testing/)
