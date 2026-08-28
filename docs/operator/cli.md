# The `ferrum` command line

`ferrum` reaches everything the web panel does (spec §11.20). It is not a
parallel API: it opens the same Unix socket `ferrum-web` opens, sends the same
typed operations, and the root agent re-derives the acting account's rights from
the database before it does anything. There is no CLI-only privilege and no
CLI-only endpoint.

It has to run on the panel host, as root: it reads the panel database to find an
active administrator account and connects to the agent socket, and both are
root-only by design.

## The shape of a command

```
ferrum [--config PATH] [--dev DIR] [--json] [--follow] <group> <verb> [args]
```

| Flag | What it does |
|------|--------------|
| `--json` | Print the agent's reply verbatim instead of a table. Works everywhere, including on failures. |
| `--follow`, `-f` | When the operation becomes a task, stream its log and exit with the task's outcome. |
| `--config PATH` | Read a different `config.toml`. Defaults to `/etc/ferrum/config.toml`. |
| `--dev DIR` | Operate on a development instance rooted at `DIR`. |

Both `--json` and `--follow` are global, so they work before *or* after the
subcommand: `ferrum site list --json` and `ferrum --json site list` are the same
command.

## Exit codes

A CLI that only ever says `1` cannot be branched on, so the failure's class is
in the exit status and the exact reason is printed:

| Exit | Meaning |
|------|---------|
| `0` | success |
| `1` | the CLI never got as far as asking — no config, no database, no administrator account |
| `2` | usage error (clap) |
| `10` | generic / internal failure |
| `11` | authentication |
| `12` | input validation |
| `13` | authorization, RBAC, quota |
| `14` | resource state — not found, already exists, conflict |
| `15` | the agent: unreachable, timed out, protocol mismatch |
| `16` | system, packages, services |
| `17` | task engine — including a followed task that failed or was cancelled |
| `18` | config management — drift, validation, rollback |

The digit pair is the block of the `FER-1xxx` code from the error taxonomy
([error codes](../api/errors.md)), so `FER-1402 domain_already_exists` exits
`14` and an agent that is not running exits `15`. The full code is always
printed:

```console
$ ferrum site create shop.example
error: FER-1402 domain_already_exists: shop.example is already served here
$ echo $?
14
```

With `--json` the same failure goes to **stdout**, so a script reads one stream:

```console
$ ferrum --json site create shop.example
{
  "error": {
    "code": "FER-1402",
    "slug": "domain_already_exists",
    "detail": "shop.example is already served here",
    "field": null
  }
}
```

Without `--json` errors go to stderr, so a human piping the output still sees
them.

## Long operations

Anything that installs packages, talks to a CA or runs restic comes back as a
task id:

```console
$ ferrum php install 8.3
task 6a3f… started
follow it with: ferrum task logs 6a3f… --follow
```

`--follow` on the original command does the same thing in one step, and makes
the exit code the task's:

```console
$ ferrum php install 8.3 --follow
…
task 6a3f… ok
```

`ferrum task list`, `ferrum task show <id>` and `ferrum task logs <id>` read the
task table directly, so they still work when the agent is down — which is
exactly when you want to know why the last task failed. `ferrum task cancel`
needs the agent, and reports the task's actual state rather than assuming the
request was honoured: a task that did not opt in to cancellation cannot be
cancelled, and the CLI says so instead of printing "cancelled".

## Secrets

No command takes a secret as an argument. A token typed as `--token hunter2` is
readable in `/proc/<pid>/cmdline` by every account on the machine for as long as
the command runs, and stays in the shell history for ever after. Secrets arrive
on stdin, or from an environment variable:

```console
$ printf '%s\n' "$CF_TOKEN" | ferrum dns provider-set --label cloudflare --token-stdin
$ FERRUM_S3_SECRET_ACCESS_KEY=… ferrum backup repo init --kind s3 \
    --label offsite --path s3.example.com/backups --s3-access-key-id AKIA…
```

| Command | stdin flag | Environment variable |
|---------|-----------|----------------------|
| `dns provider-set` | `--token-stdin` | `FERRUM_DNS_TOKEN` |
| `backup repo init` | `--s3-secret-stdin` | `FERRUM_S3_SECRET_ACCESS_KEY` |
| `sftp enable` | `--password-stdin` | `FERRUM_SFTP_PASSWORD` |
| `user create-admin` | `--password-stdin` | — (generated and printed once) |

## What each group covers

`ferrum --help` lists the groups and `ferrum <group> --help` the verbs; both are
generated from the same tree the binary parses with, so neither can go stale.

- `site` — create, list, update, delete, and check a vhost for drift
- `php`, `stack` — install and remove nginx, PHP, MariaDB, PostgreSQL
- `db` — databases, database users, grants, and Adminer
- `cert`, `dns` — HTTP-01 certificates, the panel's own certificate, DNS checks,
  provider credentials, DNS-01 wildcards
- `backup` — repositories, runs, schedules, restores
- `cron` — scheduled jobs
- `firewall` — ports, bans, and Sentinel's settings
- `app` — Node.js applications
- `wordpress` — installs, core and plugin updates, and an allowlisted `wp` CLI
- `plan`, `subscription` — plans, assignment, suspension
- `waf`, `security` — ModSecurity, and the posture scan
- `alert`, `quota`, `sftp`, `svc` — alert rules and channels, disk quotas,
  chrooted SFTP, managed units
- `task` — list, show, follow, cancel

`ferrum firewall settings-set` reads the current settings, applies the flags you
gave and writes the whole struct back, so changing one knob cannot silently
reset the other four.

To see exactly which operation a command reaches:

```console
$ ferrum ops list
count: 82

operation               command
alert.channels.delete   alert channels-delete 1
alert.channels.list     alert channels
…
```

That listing is generated from the same table `tests/gates/cli-parity.sh`
checks against the operation registry, so it is the mapping, not a description
of it. (It is deliberately not restated here: the operations themselves are
documented in [operations.md](../operations.md), and duplicating the list would
let a new operation look documented just because somebody pasted its name into
two places.)

## Shell completions

Generated from the same command tree, by a hidden subcommand:

```console
# ferrum completions bash > /usr/share/bash-completion/completions/ferrum
# ferrum completions zsh  > /usr/share/zsh/site-functions/_ferrum
# ferrum completions fish > /usr/share/fish/vendor_completions.d/ferrum.fish
```

A subcommand cannot exist without being completable, because the script is
rendered from the parser rather than written by hand.

## When something is wrong

`ferrum doctor` checks the pieces in the order they depend on each other — the
system, the database, the agent socket, disk space — so the first failure it
reports is usually the real one. It exits non-zero only on failures, never on
warnings, so it is safe in a monitoring cron.
