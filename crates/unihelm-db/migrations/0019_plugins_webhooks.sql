-- Migration 0019 (Phase 6, extensibility): outbound webhooks and the plugin
-- registry (spec §9 `webhooks`, §6 note on plugins, §14 Phase 6).
--
-- Two features, one migration, because they are the same promise from two
-- sides: spec §2.4 says "no billing/invoicing — expose a clean API + webhooks
-- so WHMCS/FOSSBilling can integrate later", and §14 Phase 6 says "third
-- parties can extend Unihelm without patching the core". Webhooks are how the
-- panel talks *out*; plugins are how somebody else's code talks *in*.
--
-- ---------------------------------------------------------------------------
-- webhooks
-- ---------------------------------------------------------------------------
--
-- The column list comes straight from spec §9, with three additions that the
-- delivery loop cannot work without and that the spec's one-line sketch could
-- not have anticipated:
--
--   * `secret_sealed` rather than `secret` — the signing key is a secret at
--     rest like the ACME account key and the Cloudflare token, so it is sealed
--     with the panel master key (spec §12 rule 6). A plaintext HMAC key in a
--     database file that gets backed up to S3 is a forgeable signature.
--   * `disabled_reason` — a hook the panel switched off must be able to say
--     why. "active = 0" with no explanation is a support ticket.
--   * `last_status` — the HTTP status of the most recent attempt, so the UI can
--     distinguish "your endpoint answers 401" from "your endpoint is gone"
--     without opening the delivery table.
--
-- `failure_count` counts *consecutive* failures, not lifetime ones: a hook that
-- has failed twice a year for five years is healthy, and a counter that never
-- resets would eventually disable it. Any success sets it back to zero.
--
-- Owned by a user, not by a subscription. A webhook is a property of an
-- *account* — a reseller integrating their billing system wants one hook for
-- everything they own, not one per subscription — and the tenant-scope filter
-- in `unihelm_db::webhooks` resolves ownership through `users.reseller_id` the
-- same way the user repository does.

CREATE TABLE webhooks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Validated to http:// or https:// with no control characters before it is
    -- stored (`unihelm_ops::webhook::validate_url`). SQLite cannot express that
    -- as a CHECK, so the delivery loop validates again on the way out and
    -- refuses a row it would not have accepted — a hand-edited database gets a
    -- named error, never a request nobody vouched for.
    url              TEXT    NOT NULL,
    -- The HMAC-SHA256 signing key, sealed with the panel master key. Never
    -- serialised out of the database: `webhook.set` shows it once, at creation.
    secret_sealed    TEXT    NOT NULL,
    -- JSON array of event names. `["*"]` means every event.
    events_json      TEXT    NOT NULL,
    active           INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    last_delivery_at TEXT,
    last_status      INTEGER,
    -- Consecutive failures. Reset to 0 by any 2xx.
    failure_count    INTEGER NOT NULL DEFAULT 0,
    -- Why the panel switched this hook off, or NULL if a human did.
    disabled_reason  TEXT,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL
);

-- Every read is either "this account's hooks" (the list operation) or "every
-- active hook" (the fan-out on an event).
CREATE INDEX webhooks_owner_idx ON webhooks (owner_user_id);
CREATE INDEX webhooks_active_idx ON webhooks (active);

-- ---------------------------------------------------------------------------
-- webhook_deliveries
-- ---------------------------------------------------------------------------
--
-- One row per (event, hook) pair, created at emit time and retried by the
-- scheduler. The queue is in the database rather than in memory for the same
-- reason the scheduler's own jobs are: an agent restart must not silently drop
-- the "backup failed" notification that was mid-retry.
--
-- At-least-once, never exactly-once. The row is marked delivered only after a
-- 2xx is seen, so a response lost on the wire produces a second POST with the
-- **same** `id` — which is why that id travels in the `X-Unihelm-Delivery`
-- header and why the docs tell receivers to de-duplicate on it.
--
-- `payload_json` is frozen at emit time rather than re-derived at send time.
-- A retry that reported the *current* state instead of the state at the moment
-- of the event would be a different message wearing the same name, and the one
-- guarantee a webhook consumer needs is that a redelivery is a redelivery.

CREATE TABLE webhook_deliveries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id      INTEGER NOT NULL REFERENCES webhooks (id) ON DELETE CASCADE,
    event           TEXT    NOT NULL,
    -- The exact bytes that were signed and POSTed, kept verbatim so a retry is
    -- byte-identical and the signature over it stays verifiable.
    payload_json    TEXT    NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    -- When the delivery loop may next pick this row up. Bounded exponential
    -- backoff (`unihelm_ops::webhook::backoff`).
    next_attempt_at TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'delivered', 'failed')),
    last_error      TEXT,
    response_status INTEGER,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

-- The delivery loop's only query: pending rows whose time has come, oldest
-- first. A composite index on exactly that predicate keeps the tick cheap on a
-- panel whose queue has grown a backlog behind a dead endpoint.
CREATE INDEX webhook_deliveries_due_idx
    ON webhook_deliveries (status, next_attempt_at);
CREATE INDEX webhook_deliveries_hook_idx ON webhook_deliveries (webhook_id);

-- ---------------------------------------------------------------------------
-- plugins
-- ---------------------------------------------------------------------------
--
-- A plugin is a *sidecar*: a separate process, started under a dedicated
-- unprivileged account, speaking the panel's existing length-prefixed JSON
-- framing over its own UDS. Spec §6 is explicit — "Do NOT let plugins run
-- in-process as root" — so nothing in this table is a code path into the
-- agent. The row records where the plugin lives, who it runs as, and which
-- extension points the agent will route to it; the routing table is *this*
-- row, not anything the plugin says at runtime.
--
-- `slug` is the primary key and the table is WITHOUT ROWID: the natural key is
-- the identity (a plugin is installed once, by name), it is what every lookup
-- uses, and there is no second candidate.
--
-- `signature` records how the payload was trusted at install time, and it is
-- kept rather than discarded because it is the answer to "how did this get
-- here" months later. `unsigned` is only ever written when the operator has
-- turned `plugins.allow_unsigned` on; the setting defaults to off and the
-- reasoning is in docs/plugins.md.

CREATE TABLE plugins (
    -- `[a-z0-9][a-z0-9-]{1,31}`, validated by `unihelm_ops::plugin::PluginSlug`.
    -- It becomes part of a unit name, a Unix account name and a socket path, so
    -- its alphabet is the intersection of what all three accept.
    slug             TEXT    NOT NULL PRIMARY KEY,
    name             TEXT    NOT NULL,
    version          TEXT    NOT NULL,
    -- The manifest exactly as it was validated at install time. Kept whole so
    -- an upgrade can diff what changed, and so the agent never has to re-read a
    -- file the plugin's own account could have rewritten since.
    manifest_json    TEXT    NOT NULL,
    -- JSON array of the extension points the agent will route to this plugin.
    -- Derived from the manifest at install time; the authority for routing.
    extensions_json  TEXT    NOT NULL,
    -- Where the payload was unpacked. Root-owned; the plugin account may read
    -- and execute, never write.
    install_dir      TEXT    NOT NULL,
    -- The dedicated system account the sidecar runs as: `unihelm-plug-<slug>`.
    run_user         TEXT    NOT NULL,
    signature        TEXT    NOT NULL CHECK (signature IN ('minisign', 'unsigned')),
    enabled          INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    -- Why the sidecar last failed to start or answer, or NULL.
    last_error       TEXT,
    installed_at     TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL
) WITHOUT ROWID;

-- "Which plugins should be running" is the enable/disable sweep's only query.
CREATE INDEX plugins_enabled_idx ON plugins (enabled);
