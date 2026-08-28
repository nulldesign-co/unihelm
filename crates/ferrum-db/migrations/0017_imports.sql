-- Migration 0017 (Phase 4, migration importers): the stored dry-run plan
-- (spec §11.15).
--
-- This table exists for one reason, and it is a security reason as much as a
-- usability one: **`import.apply` must never re-scan.** If "apply" meant "read
-- the cPanel tarball again and do whatever it says now", then the thing the
-- operator reviewed and the thing that ran would be two different objects, and
-- a tarball that changed in between (or a `/www/wwwroot` that did) would be
-- applied unseen. So `import.plan` writes the complete plan here, verbatim, and
-- hands back an id; `import.apply` takes an id and executes *that JSON*, never
-- the source. The source is opened once more only to fetch payload bytes, and
-- only after `source_fingerprint` proves it is the same bytes the plan was
-- derived from.
--
-- The plan is stored as JSON rather than shredded into relational tables on
-- purpose. It is a *document the operator approved* — the exact mapping, the
-- renames, and the explicit "does not map" list — and its value comes from
-- being byte-identical to what was shown. Normalising it would make the
-- reviewed artifact unreconstructable, and every column would need a migration
-- each time an importer learns to recognise one more kind of cPanel cruft.
-- Nothing queries inside it; the panel only ever reads a whole plan by id.

CREATE TABLE import_plans (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Which importer produced it. The CHECK is load-bearing: `import.apply`
    -- dispatches the payload fetch on this value, and a third source that
    -- forgot to teach the applier would otherwise store a plan nothing can
    -- execute.
    source_kind        TEXT    NOT NULL CHECK (source_kind IN ('cpanel', 'aapanel')),
    -- The tarball (cPanel) or the aaPanel installation root that was scanned,
    -- as an absolute server path.
    source_path        TEXT    NOT NULL,
    -- What the source looked like when the plan was made:
    --   * cPanel  — SHA-256 of the whole tarball.
    --   * aaPanel — SHA-256 of its own inventory database
    --               (`<root>/server/panel/data/default.db`), which is what the
    --               mapping was read out of; there is no single artifact to
    --               hash, and the site files it points at are on this server
    --               and are re-read at apply time anyway.
    -- `import.apply` recomputes it and refuses on a mismatch. Not a security
    -- boundary against a *hostile* source — every guard still runs on apply —
    -- but the difference between "the operator approved this" and "the operator
    -- approved something that used to be here".
    source_fingerprint TEXT    NOT NULL,
    -- Where the import lands. RESTRICT, not CASCADE: a subscription with plans
    -- pointing at it is one somebody may be mid-migration into, and deleting
    -- it out from under a half-applied import should require dealing with the
    -- import first. (`sites.subscription_id` uses RESTRICT for the same
    -- reason.)
    subscription_id    INTEGER NOT NULL REFERENCES subscriptions (id) ON DELETE RESTRICT,
    -- The `ImportPlan`, serialised. The reviewed artifact; see the header.
    plan_json          TEXT    NOT NULL,
    -- Who ran the dry run. Kept for the audit trail even after the account is
    -- gone, hence SET NULL rather than CASCADE — deleting an administrator must
    -- not delete the record of what they planned to import.
    created_by         INTEGER          REFERENCES users (id) ON DELETE SET NULL,
    created_at         TEXT    NOT NULL,
    -- NULL until `import.apply` has consumed this plan. A second apply of the
    -- same id is refused on this column: applying twice would try to create the
    -- same sites and databases again, and the second attempt's failures would
    -- be indistinguishable from a genuine conflict.
    applied_at         TEXT,
    -- The task the apply ran as, so the plan links to its own log.
    applied_task_id    TEXT,
    -- What actually happened, as JSON: the ids created and the steps that
    -- failed. Written once, when the apply finishes (successfully or not) — an
    -- import that half-worked is the case the operator most needs to read.
    outcome_json       TEXT
);

-- The list page is "recent plans, newest first", optionally for one
-- subscription.
CREATE INDEX import_plans_created_idx      ON import_plans (created_at DESC);
CREATE INDEX import_plans_subscription_idx ON import_plans (subscription_id);
