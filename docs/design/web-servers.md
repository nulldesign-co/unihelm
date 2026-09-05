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

**1. The seam.** One place decides which web server is active, and the two vhost
call sites in `site.rs` ask it instead of naming `nginx/site.conf`,
`NginxValidator` and `UnitReloader::nginx` literally. No behaviour changes:
nginx is the only answer the seam can give. This is the step that is safe to get
wrong, so it goes first and alone.

**2. Apache.** The vhost template, `apachectl configtest` as the validator, the
modules it needs (`proxy_fcgi`, `ssl`, `rewrite`, `headers`, `expires`,
`deflate`), and the parity survey above. Apache first because it shares the FPM
socket contract exactly and has a real config validator, which is what the
apply engine's snapshot → write → validate → roll back cycle is built on.

**3. The switch.** `webserver.switch`, which re-renders every site, validates
the whole configuration with the target's own tool, starts it and stops the
incumbent — and puts the incumbent back on any failure. Not per-site: a machine
half on Apache is a machine with two things fighting over port 80.

One thing turned up in the building that the plan above did not have, and it is
the sharpest edge in the whole feature: **a missing Apache module is not a
syntax error.** `configtest` passes, Apache starts, every page loads, and the
directives that needed the module are silently inert — and without
`mod_proxy_fcgi` that means serving the source of every `.php` file on the
machine as plain text. nginx has no equivalent hazard, because its features are
compiled in and an unknown directive fails `nginx -t` loudly. So the switch
enables the eight modules the vhosts need and then *verifies* them against
Apache's own `-M` output before writing anything. The enable is a best effort;
the verification is not.

**4. OpenLiteSpeed.** Last because its configuration is a different shape — a
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
