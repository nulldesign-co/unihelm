-- Migration 0006 (Phase 2): plans, and the suspension timestamp (spec §6.2, §6.4).
--
-- `subscriptions.plan_id` and `suspended_reason` already exist: migration 0002
-- created them ahead of time precisely so Phase 2 would not have to reshape the
-- table. SQLite's ALTER TABLE cannot retrofit a foreign key onto an existing
-- column, so the plan reference is enforced at the repository layer instead: a
-- plan id only ever lands in `subscriptions.plan_id` through `Db::assign_plan`
-- after a tenant-scoped lookup proved the plan exists and is visible to the
-- assigner, and `plans` rows refuse deletion while any subscription still
-- points at them.

CREATE TABLE plans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- NULL marks an admin-global plan, visible to (and assignable by) every
    -- reseller. A reseller's own plans carry the reseller's user id (spec §6.2).
    owner_user_id INTEGER REFERENCES users (id) ON DELETE RESTRICT,
    name          TEXT    NOT NULL,
    max_sites     INTEGER NOT NULL CHECK (max_sites >= 0),
    max_dbs       INTEGER NOT NULL CHECK (max_dbs >= 0),
    storage_mb    INTEGER NOT NULL CHECK (storage_mb >= 0),
    -- Feature flags (spec §6.2). Integer bools, like every other flag column.
    can_ssh       INTEGER NOT NULL DEFAULT 0 CHECK (can_ssh IN (0, 1)),
    can_cron      INTEGER NOT NULL DEFAULT 1 CHECK (can_cron IN (0, 1)),
    can_node_apps INTEGER NOT NULL DEFAULT 0 CHECK (can_node_apps IN (0, 1)),
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

-- One name per owner. A plain UNIQUE (owner_user_id, name) would not do it:
-- SQLite treats NULLs as distinct in unique indexes, so two admin-global plans
-- could share a name. User id 0 is the system actor and can never be a real
-- account (AUTOINCREMENT starts at 1), so it is safe as the NULL stand-in.
CREATE UNIQUE INDEX plans_owner_name_uq ON plans (COALESCE(owner_user_id, 0), name);

-- The delete-refusal check ("is any subscription still on this plan?") and the
-- future reseller allocation reconciliation (spec §6.2) both scan by plan.
CREATE INDEX subscriptions_plan_idx ON subscriptions (plan_id);

-- When the suspension happened — shown in the UI next to the reason, and the
-- clock the delete grace period runs from (spec §6.4: delete = suspend +
-- grace period + final backup).
ALTER TABLE subscriptions ADD COLUMN suspended_at TEXT;
