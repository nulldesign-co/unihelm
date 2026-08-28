-- Migration 0015 (Phase 4, ModSecurity WAF): per-site policy and the rule
-- exclusion list (spec §11.9).
--
-- These two tables are the *whole* input to `/etc/ferrum/waf/main.conf`. That
-- is the organising idea: the rules file is a pure render of this state, so
-- "why is this rule not firing on that site" is answerable from two SELECTs
-- rather than from reading a generated file. A row here is intent; whether
-- ModSecurity is actually loaded and enforcing is a question only `nginx -t`
-- and `waf.status` can answer, exactly as `fw_rules` (0012) records intent and
-- the firewall backend holds the truth.
--
-- Nothing here is seeded. An absent `waf_sites` row means "this site runs the
-- server-wide default", which is what a site should do the moment it is
-- created — a new site inheriting somebody's older per-site relaxations would
-- be a security hole created by a default.

-- One row per site that has a policy of its own.
CREATE TABLE waf_sites (
    -- Also the primary key: a site has one WAF policy, not a history of them.
    -- `ON DELETE CASCADE` because a policy for a deleted site could only ever
    -- render into a rule matching a hostname nothing serves.
    site_id        INTEGER PRIMARY KEY REFERENCES sites (id) ON DELETE CASCADE,
    -- `off`    — ModSecurity is switched off for this site's traffic entirely.
    -- `detect` — rules run and log; nothing is blocked (spec §11.9 asks for a
    --            log-only mode first, and this is it).
    -- `block`  — the CRS anomaly score is enforced.
    mode           TEXT    NOT NULL CHECK (mode IN ('off', 'detect', 'block')),
    -- CRS paranoia level. 1 is the default and the only level suitable for a
    -- site whose traffic nobody has studied; 4 will reject legitimate requests
    -- on most real applications. The CHECK is the whole validation: a level
    -- outside 1–4 sets CRS variables no rule reads, which would silently mean
    -- "paranoia level 1" rather than failing.
    paranoia_level INTEGER NOT NULL CHECK (paranoia_level BETWEEN 1 AND 4),
    updated_at     TEXT    NOT NULL
) WITHOUT ROWID;

-- Rules the operator has decided not to run, server-wide or for one site.
--
-- A WAF without an exclusion list is a WAF that gets turned off. The first
-- false positive on a customer's checkout page is answered either by removing
-- one rule id or by disabling the whole thing, and only one of those keeps the
-- other 900 rules working.
CREATE TABLE waf_exclusions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- NULL means server-wide. A site-scoped exclusion renders as a
    -- `ctl:ruleRemoveById` action on that site's own phase-1 rule, so it
    -- applies to that site's traffic and no one else's.
    site_id    INTEGER          REFERENCES sites (id) ON DELETE CASCADE,
    -- The CRS rule id, e.g. 942100 (the libinjection SQL rule that most often
    -- fires on a page with a code editor in it). Bounded because it is
    -- rendered into a rules file: a value ModSecurity cannot parse would fail
    -- `nginx -t` and roll back every other pending change with it.
    rule_id    INTEGER NOT NULL CHECK (rule_id BETWEEN 1 AND 2147483647),
    -- Why. Not decoration: an exclusion outlives the person who added it, and
    -- an unexplained hole in a WAF is indistinguishable from an attacker's.
    reason     TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);

-- One exclusion per (scope, rule). `COALESCE` because SQL NULLs are distinct
-- from each other in a UNIQUE index, so without it the same server-wide
-- exclusion could be stored an unbounded number of times and every copy would
-- render another `SecRuleRemoveById` line. 0 is safe as the sentinel: `sites`
-- ids come from AUTOINCREMENT and start at 1.
CREATE UNIQUE INDEX waf_exclusions_uq
    ON waf_exclusions (COALESCE(site_id, 0), rule_id);

-- The render reads every site's exclusions grouped by site.
CREATE INDEX waf_exclusions_site_idx ON waf_exclusions (site_id);

-- The server-wide switch (`waf.enabled`), the default engine mode
-- (`waf.default_mode`), the default paranoia level (`waf.default_paranoia`)
-- and the installed Core Rule Set version (`waf.crs_version`) live in the
-- existing `settings` table, for the same reason Sentinel's do: an absent key
-- must read as the code's default, and seeding rows at install time would mean
-- a later release could never change a default it had already written into
-- every database. See `ferrum_ops::waf`.
