-- Migration 0009 (Phase 3, backups): restic repositories, schedules and runs
-- (spec §11.10).
--
-- Three tables, one per question an operator asks: *where do backups go*,
-- *when do they happen*, and *what happened*.
--
-- # Why the repository password is stored at all
--
-- A restic repository is encrypted, and its password is the only key. Storing
-- it sealed here is what lets the scheduler run an unattended 03:00 backup
-- without a human present. The consequence is stated plainly in
-- `ferrum_ops::backup`'s module documentation and repeated in the operator
-- docs: a panel-scope backup whose password exists *only* inside the panel
-- database cannot be restored after the panel is lost, because the password
-- is inside the thing that burned down. `backup.repo.init` therefore returns
-- the generated password exactly once, at creation, for the operator to store
-- off-server. There is no second chance and no recovery path through the
-- panel — by design, since a panel that could re-derive the password would be
-- a panel whose compromise hands over every backup.
--
-- `password_sealed` and `credentials_sealed` hold `MasterKey` ciphertext
-- (XChaCha20-Poly1305, hex) exactly like `acme_accounts.private_key_sealed`
-- (spec §12 rule 6). Reading this table with `sqlite3` during an incident
-- reveals nothing; the master key lives at /etc/ferrum/secret.key, 0600.
--
-- WITHOUT ROWID is deliberately *not* used: every one of these tables has a
-- synthetic autoincrementing id, which is the rowid, so there is no natural
-- key to organise around.

CREATE TABLE backup_repos (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    -- The two backends this build drives. SFTP and WebDAV are named in the
    -- spec as later targets; adding one means a new CHECK value and a new
    -- `RESTIC_REPOSITORY` prefix, nothing more.
    kind               TEXT    NOT NULL CHECK (kind IN ('local', 's3')),
    -- What the operator calls it. Unique so a UI list, an alert and a task log
    -- can all name a repository the same way without carrying its id.
    label              TEXT    NOT NULL UNIQUE,
    -- A filesystem path for `local`; an endpoint URL like
    -- `s3.example.com/bucket/prefix` for `s3`. Never interpolated into a
    -- command line — it reaches restic through RESTIC_REPOSITORY in the
    -- environment (see the module docs for why).
    path_or_url        TEXT    NOT NULL,
    -- Sealed JSON: the S3 access key id, secret access key and optional
    -- region. NULL for a local repository, which needs no credentials.
    credentials_sealed TEXT,
    password_sealed    TEXT    NOT NULL,
    created_at         TEXT    NOT NULL,
    updated_at         TEXT    NOT NULL
);

-- When backups happen, and how much history to keep.
--
-- ON DELETE CASCADE from the repository: a schedule pointing at a repository
-- that no longer exists could only ever fail, once a minute, forever.
CREATE TABLE backup_schedules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id         INTEGER NOT NULL REFERENCES backup_repos (id) ON DELETE CASCADE,
    scope           TEXT    NOT NULL CHECK (scope IN ('panel', 'subscription')),
    subscription_id INTEGER          REFERENCES subscriptions (id) ON DELETE CASCADE,
    -- Five-field cron (`m h dom mon dow`), evaluated by
    -- `ferrum_ops::backup::cron`. Stored as text rather than parsed columns so
    -- an operator sees back what they typed.
    cron            TEXT    NOT NULL,
    -- restic's `forget --keep-daily/--keep-weekly/--keep-monthly`. Zero means
    -- "keep none at that granularity"; the CHECKs stop a negative from
    -- reaching an argv where restic would read it as a flag.
    keep_daily      INTEGER NOT NULL DEFAULT 7  CHECK (keep_daily   >= 0),
    keep_weekly     INTEGER NOT NULL DEFAULT 4  CHECK (keep_weekly  >= 0),
    keep_monthly    INTEGER NOT NULL DEFAULT 6  CHECK (keep_monthly >= 0),
    enabled         INTEGER NOT NULL DEFAULT 1  CHECK (enabled IN (0, 1)),

    -- The scope and its subject have to agree. A 'subscription' schedule with
    -- no subscription would be a job with nothing to back up, and a 'panel'
    -- schedule carrying one would silently ignore it.
    CHECK ((scope = 'subscription' AND subscription_id IS NOT NULL)
        OR (scope = 'panel'        AND subscription_id IS NULL))
);

CREATE INDEX backup_schedules_repo_idx    ON backup_schedules (repo_id);
CREATE INDEX backup_schedules_enabled_idx ON backup_schedules (enabled);

-- What happened. One row per attempt, including the failures — a backup
-- history that records only successes cannot answer "when did this stop
-- working", which is the question that matters (spec §11.10 AC: a corrupted
-- target produces an alert, not silent success).
--
-- `schedule_id` is NULL for a run somebody started by hand, and ON DELETE SET
-- NULL rather than CASCADE: deleting a schedule must not erase the evidence of
-- what it did. `repo_id` is RESTRICT for the same reason — the history is the
-- record of which snapshots exist, and dropping it silently would leave
-- snapshots in a bucket nobody can account for.
CREATE TABLE backup_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id     INTEGER          REFERENCES backup_schedules (id) ON DELETE SET NULL,
    repo_id         INTEGER NOT NULL REFERENCES backup_repos (id)     ON DELETE RESTRICT,
    scope           TEXT    NOT NULL CHECK (scope IN ('panel', 'subscription')),
    subscription_id INTEGER          REFERENCES subscriptions (id) ON DELETE SET NULL,
    started_at      TEXT    NOT NULL,
    finished_at     TEXT,
    status          TEXT    NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    -- restic's snapshot id, from the `--json` summary. NULL while running and
    -- on failure, and also on success against a restic old enough not to emit
    -- a summary — the run still succeeded, we just cannot name the snapshot.
    snapshot_id     TEXT,
    bytes           INTEGER,
    -- The failure, in restic's own words. NULL unless status = 'failed'.
    error           TEXT,

    -- A finished run has an end; a running one does not yet.
    CHECK ((status = 'running' AND finished_at IS NULL)
        OR (status <> 'running' AND finished_at IS NOT NULL))
);

-- The scheduler's hot query is "when did this schedule last run", answered
-- from here rather than from a `last_run_at` column on the schedule: two
-- copies of that fact can disagree, and the one on the schedule would be the
-- one that silently stops being written.
CREATE INDEX backup_runs_schedule_idx ON backup_runs (schedule_id, started_at DESC);
CREATE INDEX backup_runs_repo_idx     ON backup_runs (repo_id, started_at DESC);
CREATE INDEX backup_runs_sub_idx      ON backup_runs (subscription_id, started_at DESC);
