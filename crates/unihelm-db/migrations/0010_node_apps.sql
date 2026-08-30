-- Migration 0010 (Phase 3, node-apps): tenant Node.js applications
-- (spec §11.6, §6.3).
--
-- One row per app. The row is the panel's record of three things that must
-- agree: a systemd unit on disk, a TCP port nothing else may take, and the
-- subscription whose slice and Linux account the app runs inside.
--
-- Why the port lives here rather than being discovered at start time: the
-- reverse-proxy vhost has to name a port *before* the app has ever run, and
-- two apps that both "found a free port" at boot would race into the same one.
-- Allocation is therefore a database fact — `port INTEGER NOT NULL UNIQUE`
-- makes a duplicate impossible to store even if two allocations race, and the
-- CHECK keeps the panel inside the range documented for tenant apps (20000 to
-- 25000, unprivileged and clear of the ephemeral range). Deleting an app frees
-- its port for the next allocation; see `ferrum_db::node_apps` for why reuse
-- is deliberate.
--
-- `site_id` is the optional reverse-proxy vhost in front of the app. ON DELETE
-- SET NULL rather than CASCADE: deleting the site should stop the app being
-- *published*, not delete the tenant's application.
--
-- What is deliberately NOT stored: environment variables and the memory cap.
-- Both are rendered into the unit file at create time, and the unit file is
-- the single source of truth the operator reads and systemd enforces. Storing
-- a second copy here would create a pair that can silently disagree, and env
-- values are exactly the place where secrets show up (spec §12 rule 6: store a
-- secret only when something must replay it — nothing replays these).

CREATE TABLE node_apps (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER NOT NULL REFERENCES subscriptions (id) ON DELETE RESTRICT,
    -- The reverse-proxy site published in front of this app, if any.
    site_id         INTEGER          REFERENCES sites (id) ON DELETE SET NULL,
    -- Validated by `ferrum_core::AppName`: [a-z0-9][a-z0-9_-]{0,31}. Safe to
    -- paste into a unit name and a path with no quoting.
    name            TEXT    NOT NULL,
    -- Tenant-home-relative path to the JS entry point (`ferrum_core::TenantPath`).
    entry           TEXT    NOT NULL,
    port            INTEGER NOT NULL UNIQUE CHECK (port BETWEEN 20000 AND 25000),
    node_env        TEXT    NOT NULL DEFAULT 'production'
                            CHECK (node_env IN ('production', 'development', 'test')),
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

-- Per tenant, not server-wide: two customers may each have an app called
-- `blog`. The unit name that carries both (`ferrum-app-<linux_user>-<name>`)
-- is unique because `subscriptions.linux_user` is.
CREATE UNIQUE INDEX node_apps_subscription_name_uq ON node_apps (subscription_id, name);
CREATE INDEX node_apps_subscription_idx            ON node_apps (subscription_id);
CREATE INDEX node_apps_site_idx                    ON node_apps (site_id);
