# Architecture

## Two processes, one hard boundary

```
  Browser ── HTTPS ──▶  ferrum-web        user: ferrum, no capabilities
  CLI ────── UDS ────▶   • REST API + SSE
                         • sessions, RBAC, rate limiting
                         • embedded React UI
                                │
                                │  length-prefixed JSON over /run/ferrum/agent.sock
                                ▼
                        ferrum-agentd     user: root
                         • operation registry (a whitelist)
                         • task queue and scheduler
                         • package / service / firewall backends
                                │
                                ▼
                        nginx · php-fpm · mariadb · postgres · redis · docker
```

`ferrum-web` faces the internet and holds nothing. It cannot restart a service,
write a config file, or read a tenant's home directory. When it needs something
done, it names an operation and sends a frame.

`ferrum-agentd` is root and does exactly four things with a request:

1. looks the name up in the registry — an unknown name is `FER-1504`, not a
   fallback;
2. re-derives the caller's rights from the database, ignoring what the frame
   claimed;
3. deserializes the input into a typed struct, where every field is a validated
   newtype or an enum;
4. runs the operation, through argv arrays only.

A compromised web process can therefore ask for privileged work, but only work
that is already on the list, only within the rights the database says that
account has, and only with inputs that survive validation.

## Why the panel going down is not an outage

Nothing in the serving path — nginx, php-fpm, the databases — depends on either
daemon at runtime. They are ordinary systemd units with ordinary configuration
files. Stop both Ferrum processes and every hosted site keeps serving.

That is a design constraint, not a happy accident, and it is why the panel can
afford to be crash-only: both daemons restart unconditionally, keep no state
that matters in memory, and reconcile whatever was in flight on the way back up.

## State

One SQLite file in WAL mode. No external database, because a panel that needs
MariaDB running in order to tell you why MariaDB is down has its dependency
arrow pointing the wrong way.

Writers are kept apart on purpose: the agent owns tasks and metrics, the web
process owns sessions and audit. That is what avoids lock contention under load
rather than hoping WAL absorbs it.

## Tasks

Anything slower than about 300 ms becomes a Task: a row, a live log, and a
terminal state with a human-readable reason. The UI shows them in a drawer that
reads like a CI run — because "the button did something, probably" is the worst
part of using other panels.

Task output goes to two places at once: `task_logs`, which survives a
disconnect, and an event stream, which is what makes the drawer live. The
persisted copy is authoritative; a viewer that falls behind loses lines from the
stream, never from the record.

## Where OS differences live

`ferrum-distro`, and nowhere else. Four traits — packages, services, firewall,
security module — with an implementation per family. A feature module that knows
whether it is on Debian or RHEL is a bug: unit names, package names and firewall
syntax all resolve behind those traits.

Adding a distribution is implementing the traits and adding a CI image.
