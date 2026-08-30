-- Migration 0014 (Phase 4, wordpress): the WordPress toolkit's inventory
-- (spec §11.12 — the spec numbers the toolkit 11.12; the wave-5 task sheet
-- calls it §11.14, which is the App Store).
--
-- One row per WordPress installation the panel knows about. The row is
-- deliberately *thin*: WordPress's own truth lives in `wp-config.php` and in
-- its database, and WP-CLI can read all of it. What cannot be re-derived
-- cheaply is the panel's own bookkeeping — which site an install belongs to,
-- which managed database backs it, and whether the operator asked for
-- unattended core updates.
--
-- `site_id ... ON DELETE CASCADE` is the containment rule. Every wp.* operation
-- resolves its install *through the site*, and the site is resolved through the
-- caller's `TenantScope`; a customer therefore cannot name an install id that
-- belongs to someone else and learn anything but `not_found`. Cascading on
-- delete keeps that true after the fact: a site row that is gone must not leave
-- an install row behind whose scope can no longer be computed. (Contrast
-- `node_apps.site_id`, which is SET NULL — there the site is a *publishing*
-- decision in front of an app that exists on its own. Here the site IS the
-- install: the files live in its document root.)
--
-- `path` is the install directory as an absolute path, not a tenant-relative
-- one. It is derived by the panel from `sites.root_dir` (plus an optional
-- subdirectory) and never accepted from a caller, so storing the resolved form
-- means every later operation reads the same directory the install was created
-- in even if the site's root is later changed underneath it — a mismatch the
-- panel can then *report* instead of silently operating somewhere else.
--
-- `db_id ... ON DELETE SET NULL` because the reverse is worse: dropping the
-- database of a WordPress site must not delete the panel's record that the
-- site is a WordPress site. The install is then visibly broken, which is the
-- honest state, rather than invisible.
--
-- `version` is a cache of what `wp core version` last reported, NULL until
-- something has asked. It is never used to decide anything — every operation
-- that needs the real version asks WP-CLI — it exists so a list page can be
-- rendered without spawning one PHP process per row.
--
-- What is deliberately NOT stored: the database password. It is written once
-- into `wp-config.php` (owned by the tenant, mode 0640) and returned once by
-- the create response, exactly like `db.user.create` (spec §12 rule 6: store a
-- secret only when something must replay it — nothing here replays it).

CREATE TABLE wp_installs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     INTEGER NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    -- Absolute directory containing wp-config.php and wp-load.php.
    path        TEXT    NOT NULL,
    -- Last observed core version, e.g. `6.8.2`. NULL = never observed.
    version     TEXT,
    -- The managed database backing this install, when the panel created it.
    db_id       INTEGER          REFERENCES dbs (id) ON DELETE SET NULL,
    auto_update INTEGER NOT NULL DEFAULT 0 CHECK (auto_update IN (0, 1)),
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

-- One install per directory, server-wide. Two rows pointing at one wp-config.php
-- would let two sites' update policies fight over the same files.
CREATE UNIQUE INDEX wp_installs_path_uq   ON wp_installs (path);
CREATE INDEX wp_installs_site_idx         ON wp_installs (site_id);
CREATE INDEX wp_installs_db_idx           ON wp_installs (db_id);
