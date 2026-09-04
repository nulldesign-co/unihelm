# One container per tool and version

The agreed shape, in the owner's words: install a tool and you get a container;
install a second version of it and you get a second container; every site that
names that version points at that one container. Not a container per site.

## Why the earlier objection was wrong

I argued against PHP in Docker on memory grounds, having costed one container
per site — a hundred sites, a hundred containers, gigabytes. That is not the
architecture. PHP-FPM already multiplexes: one master process holds a pool per
site, each pool running as its own Linux user with its own `open_basedir`. Move
that master into a container and the hundred pools go with it. Two PHP versions
in use means two containers, not two hundred.

The same reasoning that made the objection wrong also answers the security
question. Host FPM already runs as one process tree with access to every tenant
home; the pools are what separate them, by uid and `open_basedir`. In a
container the pools are unchanged. The boundary does not move.

## The model

| | |
|---|---|
| `unihelm-php-8.3` | one container, every 8.3 site's pool inside it |
| `unihelm-php-7.4` | a second version is a second container |
| `unihelm-mariadb-11.8` | one container |
| `unihelm-redis` | one container |
| nginx / Apache / LiteSpeed | **on the host** |

A site records the version it wants. That name resolves to a container. Nothing
about a site's own configuration changes.

### Why the web server stays on the host

It terminates TLS, reads certificates the panel renews, serves static files out
of tenant homes, and the panel writes its vhosts. Containerising it buys
isolation from nothing — it is the thing everything else is behind — and costs a
bind mount of every path it already needs.

This is also what makes switching web servers tractable. The FPM containers do
not know or care what is in front of them; only the connection changes:

    nginx        fastcgi_pass unix:/run/unihelm/fpm/<site>-php83.sock
    Apache       SetHandler proxy:unix:/run/unihelm/fpm/<site>-php83.sock|fcgi://
    LiteSpeed    an external app pointed at the same socket

One socket per site, in a directory the container and the host share. Every web
server can reach it, and the runtime side is identical for all three.

## The two things that must be right

**uids must agree.** `uh_abc123` is uid 1007 on the host; inside the container
the pool must run as 1007 too, or the files it opens have the wrong owner. The
container therefore does not create users: the host's `/etc/passwd` and
`/etc/group` are bind-mounted read-only, and pools name the same accounts they
name today.

**The socket directory is the contract.** `/run/unihelm/fpm` is bind-mounted into
every FPM container. The host's tmpfiles entry already recreates it across
reboots — the comment in `paths.rs` explains what happens when it does not, which
is every PHP site answering 502 while the panel reports healthy.

Tenant homes are bind-mounted as well, because that is where the code is.

## What this fixes that the host model could not

Installing PHP 8.3 took a production site offline last week: retiring the stock
pool left FPM with nothing to run and it would not start. In this model a
version is an image. Installing one cannot disturb another, removing one is
removing a container, and there is no shared `/etc/php` for two versions to
disagree over.

## Node, Python and Ruby are not the same shape

PHP has a multiplexer; these do not. One Node container cannot host four Node
applications the way one FPM hosts four sites — each application is its own
process with its own port and lifetime.

So for applications the container is per application, built from the version's
image: `unihelm-app-<user>-<name>` on `node:22`. That keeps the property the
owner asked for — installing Node 22 means every app that names 22 runs the same
image — without pretending a runtime has a pool model it does not have.

## Order of work

1. Databases and caches. Self-contained, no uid mapping, no socket sharing, and
   it removes the MySQL/MariaDB port collision entirely.
2. Applications. One container per app, image chosen by the pinned version.
3. PHP-FPM. Last, because uid mapping and the shared socket directory are the
   parts that can break a running server, and they should be built on a path
   already exercised by the first two.

Each ships on its own so it can be tested before the next begins.
