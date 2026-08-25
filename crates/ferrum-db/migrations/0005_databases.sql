-- Migration 0005 (Phase 2, db-mgmt): tenant databases and database users
-- (spec §11.4, §9).
--
-- These tables are METADATA ONLY. No database-user password — plain, hashed or
-- encrypted — is ever stored here or anywhere else in the panel. A password is
-- generated at creation time, handed to the caller exactly once in the
-- operation's direct response, and from then on exists only inside the engine's
-- own authentication tables (mysql.global_priv / pg_authid). The panel never
-- needs it again: "I forgot the password" is answered by issuing a new one, not
-- by reading an old one back. A copy we do not hold is a copy that cannot leak
-- through a backup, a log line or a compromised web process (spec §12 rule 6:
-- store secrets only when something has to be *replayed*, which a password
-- never is).
--
-- Names are stored exactly as validated by the `DbName` newtype — `[A-Za-z0-9_]`,
-- starts with a letter or underscore, engine-reserved names refused — so they
-- are safe to interpolate as bare SQL identifiers. There is no forced tenant
-- prefix (the spec does not mandate one); server-wide uniqueness comes from the
-- UNIQUE indexes below plus an engine-level existence check before creation, so
-- a panel-managed database can never collide with — or silently adopt — one
-- that already exists on the engine.

CREATE TABLE dbs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER NOT NULL REFERENCES subscriptions (id) ON DELETE RESTRICT,
    engine          TEXT    NOT NULL CHECK (engine IN ('mysql', 'postgres')),
    name            TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

-- One namespace across both engines: a MySQL `shop` and a PostgreSQL `shop`
-- would be two different databases that every list, backup label and Adminer
-- link then has to disambiguate. Cheaper to refuse the collision up front.
CREATE UNIQUE INDEX dbs_name_uq         ON dbs (name);
CREATE INDEX dbs_subscription_idx       ON dbs (subscription_id);

CREATE TABLE db_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER NOT NULL REFERENCES subscriptions (id) ON DELETE RESTRICT,
    engine          TEXT    NOT NULL CHECK (engine IN ('mysql', 'postgres')),
    username        TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

-- Server-wide for the same reason as dbs_name_uq — and because MySQL account
-- names and PostgreSQL role names each live in a single engine-wide namespace
-- anyway, so per-subscription uniqueness would only defer the conflict to the
-- CREATE USER statement.
CREATE UNIQUE INDEX db_users_username_uq   ON db_users (username);
CREATE INDEX db_users_subscription_idx     ON db_users (subscription_id);
