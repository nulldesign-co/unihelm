-- Migration 0012 (Phase 2): firewall intent and Sentinel bans (spec §11.9).
--
-- The organising idea: **the backend is the truth, this table is the intent.**
-- firewalld, ufw and nftables each own a live ruleset that an operator can
-- change from a shell at three in the morning, and a panel that treats its own
-- table as authoritative would happily report a port open that nothing is
-- serving. So `fw_rules` records only what the panel was *asked* to do; every
-- read (`fw.rules`) lists the backend as well and reports the difference as
-- drift. That is also why there is no `active` column: "is it live?" is a
-- question for `FwBackend::list_rules`, not for SQLite.

CREATE TABLE fw_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    proto      TEXT    NOT NULL CHECK (proto IN ('tcp', 'udp')),
    -- A literal address or CIDR, never a hostname: a rule whose meaning depends
    -- on DNS at apply time is a rule nobody can audit. NULL is "from anywhere",
    -- which the UI marks as the decision it is.
    source     TEXT,
    comment    TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL
);

-- One record per (port, proto, source). `COALESCE` because SQL NULLs are
-- distinct from each other in a UNIQUE index, so without it "port 443 from
-- anywhere" could be recorded an unbounded number of times and every one of
-- them would show as its own row against the single backend rule.
CREATE UNIQUE INDEX fw_rules_uq ON fw_rules (port, proto, COALESCE(source, ''));

-- Every ban Sentinel (or an operator) ever placed, including the lifted ones.
--
-- History is the point. A ban list that forgets cannot answer "why could this
-- customer not reach their site last Tuesday", which is the single most common
-- support question a brute-force defence generates. Rows are therefore closed
-- by setting `lifted_at`, never deleted.
CREATE TABLE sentinel_bans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL,
    -- Free text for the operator: "6 ssh auth failures in 10m", "manual".
    reason     TEXT    NOT NULL,
    banned_at  TEXT    NOT NULL,
    -- NULL means permanent — only ever an operator's deliberate choice.
    -- Sentinel's own bans always carry a TTL, because a brute-force defence
    -- that accumulates permanent bans eventually bans a customer's office.
    expires_at TEXT,
    -- Set when the ban was removed early (unban) or reaped after expiry.
    lifted_at  TEXT
);

CREATE INDEX sentinel_bans_ip_idx     ON sentinel_bans (ip, banned_at DESC);
-- The reaper's query: still-standing bans, oldest expiry first.
CREATE INDEX sentinel_bans_active_idx ON sentinel_bans (lifted_at, expires_at);

-- Sentinel's settings (`sentinel.enabled`, `sentinel.ssh_threshold`,
-- `sentinel.window_minutes`, `sentinel.ban_minutes`, `sentinel.allowlist`) live
-- in the existing `settings` table. They are deliberately *not* seeded here:
-- an absent key reads as the code's default, and `sentinel.enabled` defaults to
-- false so a fresh install cannot lock its operator out of a server they have
-- not configured yet (spec §11.9, and see `ferrum_ops::fwops`).
