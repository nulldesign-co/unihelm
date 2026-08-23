-- Ferrum panel schema, migration 0001 (Phase 0).
--
-- Naming follows spec §9 exactly; later phases extend it with new migrations
-- and never by editing this file.
--
-- Conventions:
--   * timestamps are RFC 3339 UTC strings, so the database is readable with
--     plain `sqlite3` during an incident;
--   * anything ending in `_json` holds a JSON document validated by serde on the
--     way in and out;
--   * secrets are stored either hashed (passwords, tokens) or sealed
--     (TOTP seeds) — never in the clear.

CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    role            TEXT    NOT NULL CHECK (role IN ('admin', 'reseller', 'customer')),
    email           TEXT    NOT NULL,
    username        TEXT    NOT NULL,
    pass_hash       TEXT    NOT NULL,
    -- libsodium sealed box under the master key in /etc/ferrum/secret.key.
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
    status          TEXT    NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'suspended', 'locked')),
    -- The reseller this account belongs to; NULL for admins and direct customers.
    reseller_id     INTEGER REFERENCES users (id) ON DELETE RESTRICT,
    -- Per-account permission overrides; may only narrow the role's defaults.
    permissions_json TEXT   NOT NULL DEFAULT 'null',
    full_name       TEXT,
    locale          TEXT    NOT NULL DEFAULT 'en',
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    last_login_at   TEXT
);

CREATE UNIQUE INDEX users_username_uq ON users (username);
CREATE UNIQUE INDEX users_email_uq    ON users (email);
CREATE INDEX users_reseller_idx       ON users (reseller_id);

-- Sessions store the SHA-256 of the cookie value, never the value itself: a
-- leaked database backup must not be a set of live logins.
CREATE TABLE sessions (
    id              TEXT    PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf            TEXT    NOT NULL,
    ip              TEXT,
    user_agent      TEXT,
    -- Set when an admin is operating as somebody else (spec §6.1).
    impersonator_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
    created_at      TEXT    NOT NULL,
    last_seen_at    TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
);

CREATE INDEX sessions_user_idx    ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    hash         TEXT    NOT NULL,
    scopes_json  TEXT    NOT NULL DEFAULT '[]',
    created_at   TEXT    NOT NULL,
    expires_at   TEXT,
    last_used_at TEXT,
    revoked      INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
);

CREATE UNIQUE INDEX api_tokens_hash_uq ON api_tokens (hash);
CREATE INDEX api_tokens_user_idx       ON api_tokens (user_id);

-- Every state-changing call lands here (spec §10.3).
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              TEXT    NOT NULL,
    actor_user_id   INTEGER REFERENCES users (id) ON DELETE SET NULL,
    actor_username  TEXT    NOT NULL,
    impersonator_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
    ip              TEXT,
    action          TEXT    NOT NULL,
    target          TEXT,
    detail_json     TEXT    NOT NULL DEFAULT '{}',
    request_id      TEXT,
    -- Denormalised so a tenant's audit trail survives their user row being
    -- reassigned, and so scoped queries need no join.
    subscription_id INTEGER
);

CREATE INDEX audit_at_idx     ON audit_log (at DESC);
CREATE INDEX audit_actor_idx  ON audit_log (actor_user_id, at DESC);
CREATE INDEX audit_tenant_idx ON audit_log (subscription_id, at DESC);
CREATE INDEX audit_action_idx ON audit_log (action, at DESC);

-- The task engine (spec §10.1). Interrupted tasks are reconciled at agent start,
-- which is what makes the crash-only design safe.
CREATE TABLE tasks (
    id              TEXT    PRIMARY KEY,
    op              TEXT    NOT NULL,
    input_json      TEXT    NOT NULL DEFAULT '{}',
    actor_user_id   INTEGER REFERENCES users (id) ON DELETE SET NULL,
    subscription_id INTEGER,
    status          TEXT    NOT NULL DEFAULT 'queued'
                            CHECK (status IN ('queued', 'running', 'ok', 'failed', 'cancelled')),
    progress        INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    -- Stable FER-xxxx code plus a human-readable reason; both set iff failed.
    error_code      TEXT,
    error_detail    TEXT,
    cancellable     INTEGER NOT NULL DEFAULT 0 CHECK (cancellable IN (0, 1)),
    -- Only tasks marked idempotent are ever retried automatically.
    idempotent      INTEGER NOT NULL DEFAULT 0 CHECK (idempotent IN (0, 1)),
    request_id      TEXT,
    created_at      TEXT    NOT NULL,
    started_at      TEXT,
    finished_at     TEXT
);

CREATE INDEX tasks_status_idx  ON tasks (status, created_at DESC);
CREATE INDEX tasks_tenant_idx  ON tasks (subscription_id, created_at DESC);
CREATE INDEX tasks_actor_idx   ON tasks (actor_user_id, created_at DESC);

CREATE TABLE task_logs (
    task_id TEXT    NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    seq     INTEGER NOT NULL,
    at      TEXT    NOT NULL,
    line    TEXT    NOT NULL,
    PRIMARY KEY (task_id, seq)
) WITHOUT ROWID;

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
) WITHOUT ROWID;

-- Feeds per-IP and per-account rate limiting, and later the Sentinel jail for
-- panel logins (spec §11.9).
CREATE TABLE login_attempts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT    NOT NULL,
    ip       TEXT    NOT NULL,
    username TEXT    NOT NULL,
    success  INTEGER NOT NULL CHECK (success IN (0, 1))
);

CREATE INDEX login_attempts_ip_idx   ON login_attempts (ip, at DESC);
CREATE INDEX login_attempts_user_idx ON login_attempts (username, at DESC);
