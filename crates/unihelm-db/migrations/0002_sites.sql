-- Migration 0002 (Phase 1): sites, certificates and the config revision store.
--
-- `subscriptions` arrives here rather than in Phase 2 because a PHP-FPM pool
-- needs a Linux user to run as, and inventing a per-site owner now would mean
-- regrouping it under a subscription later. Phase 2 adds plans, quotas and
-- cgroup slices on top of this table; it does not reshape it.

CREATE TABLE subscriptions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    -- Plans are Phase 2. Until then a subscription is simply an owner and a
    -- Linux account.
    plan_id          INTEGER,
    -- `uh_<short-id>`; the account PHP-FPM pools and cron jobs run as.
    linux_user       TEXT    NOT NULL,
    home_dir         TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active', 'suspended', 'pending_delete')),
    suspended_reason TEXT,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL
);

CREATE UNIQUE INDEX subscriptions_linux_user_uq ON subscriptions (linux_user);
CREATE INDEX subscriptions_customer_idx        ON subscriptions (customer_id);

CREATE TABLE sites (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id      INTEGER NOT NULL REFERENCES subscriptions (id) ON DELETE RESTRICT,
    domain               TEXT    NOT NULL,
    site_type            TEXT    NOT NULL
                                 CHECK (site_type IN ('php', 'static', 'proxy', 'redirect')),
    -- Set only for php sites; the CHECK below keeps the two in step.
    php_version          TEXT,
    root_dir             TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'provisioning'
                                 CHECK (status IN ('provisioning', 'active', 'suspended', 'failed')),

    -- www policy: leave alone, redirect apex to www, or www to apex.
    www_policy           TEXT    NOT NULL DEFAULT 'none'
                                 CHECK (www_policy IN ('none', 'add', 'strip')),
    force_https          INTEGER NOT NULL DEFAULT 1 CHECK (force_https IN (0, 1)),
    http3                INTEGER NOT NULL DEFAULT 0 CHECK (http3 IN (0, 1)),
    maintenance_mode     INTEGER NOT NULL DEFAULT 0 CHECK (maintenance_mode IN (0, 1)),
    client_max_body_size TEXT    NOT NULL DEFAULT '64m',

    -- First-class escape hatches (spec §10.4 rule 3), so people rarely need to
    -- edit a rendered file by hand.
    custom_nginx_snippet TEXT,
    php_ini_overrides    TEXT,

    rate_limit_enabled   INTEGER NOT NULL DEFAULT 0 CHECK (rate_limit_enabled IN (0, 1)),
    rate_limit_rps       INTEGER NOT NULL DEFAULT 20,
    rate_limit_burst     INTEGER NOT NULL DEFAULT 40,
    conn_limit           INTEGER NOT NULL DEFAULT 20,

    proxy_port           INTEGER,
    redirect_target      TEXT,
    redirect_code        INTEGER NOT NULL DEFAULT 301 CHECK (redirect_code IN (301, 302, 307, 308)),

    created_at           TEXT    NOT NULL,
    updated_at           TEXT    NOT NULL,

    -- A php site without a version, or a proxy site without a port, would render
    -- a vhost that cannot work. Catch it at the storage layer too.
    CHECK (site_type <> 'php' OR php_version IS NOT NULL),
    CHECK (site_type <> 'proxy' OR proxy_port IS NOT NULL),
    CHECK (site_type <> 'redirect' OR redirect_target IS NOT NULL)
);

CREATE UNIQUE INDEX sites_domain_uq      ON sites (domain);
CREATE INDEX sites_subscription_idx      ON sites (subscription_id);
CREATE INDEX sites_status_idx            ON sites (status);

CREATE TABLE site_aliases (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id    INTEGER NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    domain     TEXT    NOT NULL,
    -- When set, the alias 301s to the primary domain instead of serving it.
    redirect   INTEGER NOT NULL DEFAULT 0 CHECK (redirect IN (0, 1)),
    created_at TEXT    NOT NULL
);

CREATE UNIQUE INDEX site_aliases_domain_uq ON site_aliases (domain);
CREATE INDEX site_aliases_site_idx         ON site_aliases (site_id);

CREATE TABLE certificates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    -- NULL for the panel's own certificate and the default self-signed one.
    site_id      INTEGER REFERENCES sites (id) ON DELETE CASCADE,
    kind         TEXT    NOT NULL CHECK (kind IN ('le', 'custom', 'self_signed')),
    domains_json TEXT    NOT NULL,
    issuer       TEXT,
    not_before   TEXT,
    not_after    TEXT,
    auto_renew   INTEGER NOT NULL DEFAULT 1 CHECK (auto_renew IN (0, 1)),
    status       TEXT    NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'active', 'expired', 'failed', 'revoked')),
    -- The last renewal failure, so the UI can explain why a certificate is
    -- about to expire instead of only warning that it is.
    last_error   TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    cert_dir     TEXT    NOT NULL,
    issued_at    TEXT,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);

CREATE INDEX certificates_site_idx   ON certificates (site_id);
-- Drives the renewal scheduler: cheapest possible "what expires soon" query.
CREATE INDEX certificates_expiry_idx ON certificates (not_after) WHERE auto_renew = 1;

-- Every activation, so any change can be undone in one click (spec §10.4 rule 5).
CREATE TABLE config_revisions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    path             TEXT    NOT NULL,
    sha256           TEXT    NOT NULL,
    content          TEXT    NOT NULL,
    rendered_by_task TEXT,
    -- Exactly one revision per path is the one currently on disk.
    active           INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at       TEXT    NOT NULL
);

CREATE INDEX config_revisions_path_idx   ON config_revisions (path, created_at DESC);
CREATE UNIQUE INDEX config_revisions_active_uq ON config_revisions (path) WHERE active = 1;

-- What the Stack Manager has installed (spec §11.1).
CREATE TABLE stack_components (
    slug              TEXT    PRIMARY KEY,
    installed_version TEXT,
    status            TEXT    NOT NULL DEFAULT 'absent'
                              CHECK (status IN ('absent', 'installing', 'installed', 'failed', 'removing')),
    last_error        TEXT,
    last_task_id      TEXT,
    installed_at      TEXT,
    updated_at        TEXT    NOT NULL
) WITHOUT ROWID;

-- The panel's ACME account. The private key is sealed under the master key in
-- /etc/unihelm/secret.key and never appears in an API response (spec §12 rule 6).
CREATE TABLE acme_accounts (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    directory_url         TEXT    NOT NULL,
    contact_email         TEXT    NOT NULL,
    credentials_encrypted TEXT    NOT NULL,
    created_at            TEXT    NOT NULL
);

CREATE UNIQUE INDEX acme_accounts_directory_uq ON acme_accounts (directory_url);
