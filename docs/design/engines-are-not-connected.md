# The containerised engines were never connected

0.3.0 moved every database and cache into a container, one per tool and version.
The containers are built, started, health-checked, sealed with a generated root
password, and recorded in an engine registry. Then nothing uses any of it.

Two operations that an operator reaches in their first hour are wrong because of
it, and they are the same defect seen from two ends.

## What is actually broken

**The Stack page reports a running container as "Not installed".** `stack.install`
claims and settles the *host* row key even when what it installed was a
container. `stack.status` then asks the package manager whether that slug is
present, gets `false`, and rewrites the row to `absent` — the arm that exists to
catch somebody removing a package by hand. `ComponentView` carries no `runtime`
field at all, so even a correct row could not say which of the two it was. The
`/api/engines` endpoint that would list the containers exists and the UI never
calls it. And `engine.remove` writes a *different* row key — the container name —
so removing the container cannot correct the host row either.

**`db.create` fails on the default install path.** `db.rs` only ever builds a
socket client:

    mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock
    psql -h /var/run/postgresql

There is no socket, because there is no host install. The operator installs
MariaDB from the Stack page, the panel says it worked, the Stack page then says
MariaDB is not installed, and creating a database fails with a missing client.
Three surfaces disagreeing about one machine.

## The tell

`engine::root_connection` carries a doc comment naming it *"the entry point
`db.rs` calls"*.

It has no callers anywhere in the tree.

That is the third time this exact shape has shipped here. `repos::litespeed` was
written, its signing key confirmed against a live `Release.gpg`, merged — and
never wired into the match that turns a catalogue slug into a repository, so
OpenLiteSpeed sat permanently greyed out. The `runtime` field the Stack page
sends was read by nobody, so "run it on the server" was silently discarded. Each
time, the piece that does the work was correct and the wire to it was missing,
and each time the tests passed because they tested the piece.

**A function whose doc comment describes its caller, and has none, is a bug.**
Worth a lint if one is cheap to write; worth naming here regardless, because the
next one will look exactly like this.

## The shape of the fix

The two halves need different things and must not be conflated.

### One row key, honestly derived

A component's identity in `stack_components` has to be the same string whichever
runtime it landed on, or claim/settle/remove cannot agree. Today install writes
one and remove writes another.

Status must then report `runtime` per row, cross-checked against Docker rather
than the package manager — a stopped container is *installed and down*, which is
a different sentence from *absent*, and telling them apart is the whole reason
an operator opens the page. That check is also what stops the panel reporting a
container that somebody removed by hand as still there.

### One connection, chosen by where the engine actually is

`db.rs` needs a second execution path, not a rewrite. When the registry says an
engine is a container, run the client inside it; otherwise use the socket, which
is still right for a host install and must keep working.

The root password is sealed in the engine record and **must not reach argv** —
`/proc` is readable by every local account, which is the boundary the sealing
exists to hold. The clients take it from the environment (`MYSQL_PWD`,
`PGPASSWORD`), which is the route to use.

`require_engine_ready` currently asks about `mariadb` and `postgresql` by slug.
It has to ask the registry instead, and cover `mysql` as well — that slug is in
the catalogue and reaches the same code.

### What must not change

The SQL itself. Identifier quoting, the `LIKE`-metacharacter escaping in a
GRANT, the privilege cleanup after a `DROP DATABASE` — all of that is correct and
hard-won, and it is the same whether the server is in a container or not. This
is a change to *how the client is invoked*, and nothing below that line.

## Order

1. **The row key and `runtime` on the wire.** Nothing renders differently until
   the UI reads it, so this is safe to get wrong on its own.
2. **The Stack page reading it**, including a stopped container reported as down
   rather than missing.
3. **`db.rs`'s second path**, behind the registry lookup, with the socket path
   untouched for host installs.

Step 3 is the one that makes `db.create` work on a default install, and it is
last on purpose: it depends on the registry being the thing everything asks, and
steps 1 and 2 are what prove that it is.
