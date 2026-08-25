-- Migration 0003: the internal scheduler (spec §10.2).
--
-- Persisted rather than in-memory, for the same reason the task queue is: the
-- agent is `Restart=always`, and a schedule that lives only in a process is a
-- schedule that silently stops after a crash. Storing the next run time also
-- means a job that fell due while the agent was down runs on the way back up
-- instead of being skipped.

CREATE TABLE scheduler_jobs (
    name             TEXT    PRIMARY KEY,
    interval_seconds INTEGER NOT NULL CHECK (interval_seconds > 0),
    -- Every schedule is jittered, so a hundred panels installed from the same
    -- image do not all hit Let's Encrypt in the same second (spec §10.2).
    jitter_seconds   INTEGER NOT NULL DEFAULT 0 CHECK (jitter_seconds >= 0),
    enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),

    last_run_at      TEXT,
    next_run_at      TEXT    NOT NULL,
    last_status      TEXT    CHECK (last_status IS NULL OR last_status IN ('ok', 'failed')),
    last_error       TEXT,
    last_duration_ms INTEGER,
    run_count        INTEGER NOT NULL DEFAULT 0,
    failure_count    INTEGER NOT NULL DEFAULT 0,

    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL
) WITHOUT ROWID;

CREATE INDEX scheduler_jobs_due_idx ON scheduler_jobs (next_run_at) WHERE enabled = 1;

-- When a certificate may next be attempted.
--
-- Let's Encrypt allows five failed validations per identifier per hour, so a
-- site with a broken DNS record must back off rather than retry in a loop.
-- Kept on the certificate because the backoff is per certificate, not per job.
ALTER TABLE certificates ADD COLUMN next_attempt_at TEXT;
