-- Migration 0013 (Phase 2): per-tenant disk quotas (spec §6.2, §6.3).
--
-- Two pieces:
--
-- 1. The limits themselves live on the subscription, because that is the unit
--    a plan is applied to and the unit that owns exactly one Linux account.
--    They are stored in megabytes and NULL means "no quota set" — distinct
--    from 0, which would be "a quota of nothing".
--
-- 2. `quota_projects` maps a subscription to an XFS project id. XFS project
--    quotas are keyed by a numeric id the administrator invents, not by uid,
--    so somebody has to be the allocator of record — and it has to be durable,
--    because handing tenant B the id that still carries tenant A's usage
--    accounting would bill one tenant for another's files. The id is the
--    PRIMARY KEY so the same number can never back two subscriptions, and the
--    UNIQUE on subscription_id keeps one tenant from accumulating several ids.
--    Rows go away with their subscription (ON DELETE CASCADE), which is what
--    makes an id reusable after a tenant is deleted: the kernel-side limits
--    are cleared when the next tenant's `limit -p` overwrites them.
--
-- ext4 user quotas and the du fallback need no table: they key off the Linux
-- account name, which `subscriptions.linux_user` already owns.

ALTER TABLE subscriptions ADD COLUMN quota_soft_mb INTEGER;
ALTER TABLE subscriptions ADD COLUMN quota_hard_mb INTEGER;

CREATE TABLE quota_projects (
    -- The XFS project id passed to `xfs_quota -x -c 'project ...'`. Allocation
    -- starts at 100 (see `unihelm_db::quota`) so ids an operator assigned by
    -- hand in /etc/projid before installing the panel stay out of our range.
    project_id      INTEGER PRIMARY KEY,
    subscription_id INTEGER NOT NULL UNIQUE
                            REFERENCES subscriptions (id) ON DELETE CASCADE,
    -- The directory the project was applied to, recorded so a moved or
    -- re-provisioned home is detectable as drift rather than silently split
    -- across two trees.
    path            TEXT    NOT NULL,
    created_at      TEXT    NOT NULL
);
