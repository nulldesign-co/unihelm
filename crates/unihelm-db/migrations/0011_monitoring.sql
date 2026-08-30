-- Migration 0011 (Phase 2): alert rules, notifier channels and alert events
-- (spec §11.11, §10.2).
--
-- The interesting table is `alert_events`, because it is where alert *state*
-- lives. A monitoring system that re-evaluates its rules every minute and
-- notifies whenever a threshold is exceeded sends one message per minute for as
-- long as the condition lasts, which trains every operator who receives it to
-- filter the channel. So an event here is a span, not a point: it is opened
-- when the condition first holds, stays open (silently) while it keeps holding,
-- and is closed when the condition clears. Only the two *transitions* notify.
--
-- The partial unique index below is what enforces that at the storage layer
-- rather than in application logic — two evaluation passes racing (an agent
-- restart while a tick is in flight) still cannot open two events for the same
-- thing.

CREATE TABLE alert_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT    NOT NULL CHECK (kind IN (
                   'disk_pct', 'mem_pct', 'load', 'service_down', 'cert_expiry_days'
               )),
    -- What, within the kind, the rule watches: a mount point for `disk_pct`, a
    -- managed unit name for `service_down`. NULL means "every subject of this
    -- kind" — one `disk_pct` rule then covers every mounted filesystem, which
    -- is what an operator actually wants and what the seeded default does.
    --
    -- Not in the original column sketch, but `service_down` is unusable
    -- without it: the seeded default is "service_down for nginx", and there is
    -- nowhere else to put "nginx".
    target     TEXT,
    -- REAL because thresholds are compared against percentages and load
    -- averages. `service_down` carries 1.0 — the rule is boolean, and storing a
    -- sentinel keeps the column NOT NULL.
    threshold  REAL    NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

-- One rule per (kind, target). SQLite treats NULLs as distinct in a unique
-- index, so a plain UNIQUE (kind, target) would happily allow twenty
-- "every disk over 90%" rules — and each one would raise its own event for the
-- same disk. COALESCE collapses the NULLs onto one key. (Same trick, same
-- reason, as `plans_owner_name_uq` in migration 0006.)
CREATE UNIQUE INDEX alert_rules_kind_target_uq
    ON alert_rules (kind, COALESCE(target, ''));

CREATE TABLE notify_channels (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT    NOT NULL CHECK (kind IN ('webhook', 'telegram')),
    label         TEXT    NOT NULL,
    -- The whole channel configuration, sealed with the MasterKey
    -- (XChaCha20-Poly1305, see ferrum_db::secrets) — spec §12 rule 6.
    --
    -- The *entire* config is sealed, not just the obvious secret: a Telegram
    -- bot token is plainly a credential, but so is a webhook URL, because the
    -- common shape (`https://hooks.example/services/T00/B00/XXXX`) carries its
    -- authorization in the path. Storing it in the clear would put a working
    -- credential in every database backup.
    config_sealed TEXT    NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

-- Labels are how an operator tells two webhooks apart in the UI and in the
-- "delivery failed" log line, so they have to be distinct.
CREATE UNIQUE INDEX notify_channels_label_uq ON notify_channels (label);

CREATE TABLE alert_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER NOT NULL REFERENCES alert_rules (id) ON DELETE CASCADE,
    -- The specific thing that breached, within the rule: `/var`, `nginx`,
    -- `example.com`. Also not in the original sketch, and also load-bearing —
    -- without it a single "any disk over 90%" rule could only ever have one
    -- open event, so a second filesystem filling up would be silently swallowed
    -- by the first one's debounce.
    subject     TEXT    NOT NULL,
    message     TEXT    NOT NULL,
    -- The reading that opened the event, kept for the UI and for after-the-fact
    -- questions ("how full was it when this fired?").
    value       REAL,
    raised_at   TEXT    NOT NULL,
    -- NULL = still happening. This column is the state machine.
    resolved_at TEXT,
    -- How many state-transition notifications have been dispatched for this
    -- event: 1 after the raise was delivered, 2 after the resolve. It is the
    -- ledger that makes "did anybody actually get told?" answerable, and it is
    -- what the debounce tests assert against.
    notified    INTEGER NOT NULL DEFAULT 0
);

-- The debounce, enforced by the database: at most one open event per
-- (rule, subject).
CREATE UNIQUE INDEX alert_events_open_uq
    ON alert_events (rule_id, subject) WHERE resolved_at IS NULL;

-- The alert history page reads newest-first; the evaluator reads the open set.
CREATE INDEX alert_events_raised_idx ON alert_events (raised_at DESC);
CREATE INDEX alert_events_open_idx ON alert_events (rule_id) WHERE resolved_at IS NULL;

-- Defaults, enabled, so a fresh install is already watching the three things
-- that actually take servers down (spec §11.11). An operator who disagrees can
-- disable or re-threshold them; an operator who never opens the alerts page is
-- still covered.
--
-- `strftime` here formats exactly as `ferrum_db::to_sql_time` does
-- (RFC 3339, seconds, Z), so these rows are indistinguishable from ones the
-- panel wrote.
INSERT INTO alert_rules (kind, target, threshold, enabled, created_at, updated_at)
VALUES
    -- A disk over 90% is the single most common way a hosting server dies.
    ('disk_pct',         NULL,    90.0, 1,
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- Fourteen days is a week after the thirty-day renewal window opens: by
    -- then automatic renewal has had a fortnight of attempts and something is
    -- genuinely wrong.
    ('cert_expiry_days', NULL,    14.0, 1,
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- nginx down means every site on the box is down.
    ('service_down',     'nginx',  1.0, 1,
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
