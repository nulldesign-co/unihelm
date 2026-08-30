-- Migration 0007 (Phase 3, cron): per-subscription scheduled commands
-- (spec §11.8).
--
-- One row per job. The rows are the panel's *intent*; the tenant's crontab is
-- a rendering of them (`unihelm_ops::cron::render_crontab`), regenerated in
-- full on every change rather than patched line by line. That direction is
-- deliberate: a crontab edited in place has no identity for a line, so an
-- update would have to find "the line that used to be this job" by string
-- matching — and a job whose command changed is exactly the case where that
-- fails. Rendering from the table makes the file a pure function of the rows.
--
-- ON DELETE CASCADE, unlike `node_apps`' RESTRICT: a cron job owns nothing
-- outside the crontab, so removing a subscription may take its jobs with it.
-- Spec §11.8 AC ("removing subscription removes crontab entries") is half
-- satisfied here and half in the account teardown that removes the crontab
-- file itself; the rows must not be what keeps a deleted tenant alive.
--
-- `schedule` and `command` are stored as the *canonical* text the validator
-- produced, not as the caller typed it: `unihelm_ops::cron` collapses a
-- schedule to five single-space-separated fields before it is stored, so two
-- spellings of one schedule cannot render two different crontabs. SQLite
-- cannot express either rule as a CHECK, so the renderer validates every row
-- again on the way out and refuses to render one that does not pass: a
-- hand-edited database gets a named error, never a crontab line nobody
-- vouched for.
--
-- `last_error` is the *apply* error, not the job's exit status: it records why
-- the crontab could not be installed the last time this subscription's jobs
-- were rendered, and is cleared by the next successful install. Per-job run
-- history (exit code, duration, output tail — spec §11.8) needs a runner that
-- captures output and is not part of this table.

CREATE TABLE cron_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER NOT NULL REFERENCES subscriptions (id) ON DELETE CASCADE,
    -- Five whitespace-separated fields, canonicalised. Never `@reboot` or an
    -- `@alias`: see `unihelm_ops::cron` for why a tenant may not have one.
    schedule        TEXT    NOT NULL,
    -- The command line cron hands to the user's shell. Validated to hold no
    -- control characters at all — a newline here would append a second job to
    -- the crontab, which is the injection this feature exists to not have.
    command         TEXT    NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    -- Why the last crontab install for this subscription failed, or NULL.
    last_error      TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

-- Every read is "this subscription's jobs": the list operation, the render
-- that rebuilds a crontab, and the per-subscription cap.
CREATE INDEX cron_jobs_subscription_idx ON cron_jobs (subscription_id);
