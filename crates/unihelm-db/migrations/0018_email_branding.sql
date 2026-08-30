-- Migration 0018 (Phase 5 groundwork): the outbound SMTP relay and
-- white-label branding (spec §11.18, §11.19).
--
-- Two unrelated features share one migration because they are the two halves
-- of "what a reseller's customer sees": the mail their sites send, and the
-- panel they log in to. Nothing here is seeded — an absent row means "no relay
-- configured" and "the panel's own branding", both of which are the correct
-- state for a fresh install.
--
-- What this migration deliberately does NOT create: mailboxes, domains,
-- aliases, or anything else a mail *server* would need. v1 is relay-only
-- (spec §11.18); the full Stalwart stack is Phase 5 and optional, and a schema
-- that pretended otherwise would be a promise the code does not keep.

-- ---------------------------------------------------------------------------
-- The outbound SMTP relay
-- ---------------------------------------------------------------------------

-- Exactly one relay, server-wide.
--
-- `CHECK (id = 1)` rather than a settings key because of `password_sealed`:
-- the credential has to live in a column somebody can see the shape of, next
-- to the host it belongs to, so an operator reading the schema can tell that
-- the panel stores an SMTP password at all. A JSON blob in `settings` hides
-- that.
--
-- Server-wide and not per-tenant on purpose. PHP's `mail()` runs as the tenant
-- (§5), so whatever credential the shim holds is readable by that tenant; a
-- per-tenant credential would multiply the number of secrets on disk without
-- changing who can read the one that matters to them. One relay, one
-- credential, and a loud note in the docs that it is send-only by design.
CREATE TABLE mail_relay (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    -- Hostname or IP of the submission server. Validated as a `RelayHost`
    -- newtype before it gets here; the CHECK is the second line of defence,
    -- because this string is rendered into a config file the MTA reads.
    host            TEXT    NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    -- 587 (submission, STARTTLS) or 465 (implicit TLS) in practice. 25 is
    -- allowed for a relay on the same private network and nothing else.
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    -- `none` — plaintext, only sane to a relay on localhost or a private LAN.
    -- `starttls` — connect in the clear, upgrade, and refuse to continue if
    --              the upgrade fails (see unihelm_ops::mail::smtp).
    -- `implicit` — TLS from the first byte (SMTPS, port 465).
    tls_mode        TEXT    NOT NULL CHECK (tls_mode IN ('none', 'starttls', 'implicit')),
    -- NULL means an unauthenticated relay: legitimate for a relay that
    -- authorises by source IP, which is how most in-datacentre relays work.
    username        TEXT,
    -- Sealed with the panel master key (spec §12 rule 6), never stored or
    -- logged in the clear, and never returned by any operation. `mail.relay.get`
    -- reports whether one is set, not what it is.
    password_sealed TEXT,
    -- The envelope sender every site's mail goes out as. Relays reject mail
    -- from a domain they are not authorised for, so this is the single field
    -- most likely to be the reason mail bounces — which is why it is required
    -- rather than derived from the site.
    from_address    TEXT    NOT NULL,
    from_name       TEXT,
    -- An operator can switch the relay off without discarding the credential.
    -- Disabling re-renders every pool with `sendmail_path` removed, so PHP
    -- falls back to whatever the system has (usually nothing, which is the
    -- honest answer).
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    updated_at      TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- White-label branding
-- ---------------------------------------------------------------------------

-- One row per reseller, plus row 0 for the panel default.
--
-- `reseller_id = 0` is a sentinel, not a foreign key: user ids are
-- `INTEGER PRIMARY KEY AUTOINCREMENT` and therefore start at 1, so 0 can never
-- collide with a real account. The alternative — a nullable column with a
-- partial unique index — makes every lookup a two-branch query for no gain,
-- and a WITHOUT ROWID table cannot have a NULL primary key anyway.
--
-- No `REFERENCES users (id)` for the same reason. The cost is that deleting a
-- reseller leaves an orphan branding row; the branding repository resolves by
-- id and simply never finds it again, which is cheaper than a foreign key that
-- would reject the sentinel row.
CREATE TABLE branding (
    reseller_id   INTEGER PRIMARY KEY CHECK (reseller_id >= 0),
    -- Every field is nullable and every NULL means "inherit". A reseller who
    -- has set only a logo gets the panel's name, colour and support URL, and
    -- changing the panel default changes theirs too. That is the behaviour a
    -- white-label feature has to have: partial branding is the common case.
    panel_name    TEXT,
    support_url   TEXT,
    -- `#rrggbb`, validated before it is stored. It reaches the browser inside a
    -- CSS custom property, so an unvalidated value here is a stylesheet
    -- injection; the CHECK is the schema's share of stopping that.
    primary_color TEXT    CHECK (primary_color IS NULL OR primary_color GLOB '#[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'),
    -- The hostname this reseller's customers reach the panel on (spec §11.19
    -- "custom login domain"). It is how `GET /api/branding` — the one endpoint
    -- that answers without a session, because the login page needs it — decides
    -- whose branding to serve. Lowercased and port-stripped before storage.
    login_host    TEXT,
    updated_at    TEXT    NOT NULL
) WITHOUT ROWID;

-- One reseller per login host. A second reseller claiming a host would make
-- the pre-session lookup ambiguous, and "whichever row SQLite returned first"
-- is not an answer.
CREATE UNIQUE INDEX branding_login_host
    ON branding (login_host)
    WHERE login_host IS NOT NULL;

-- The uploaded images.
--
-- A rowid table, unlike almost everything else in this schema with a natural
-- key: SQLite's WITHOUT ROWID tables store the whole row inside the B-tree
-- page chain, which is the wrong shape for a multi-hundred-kilobyte BLOB. The
-- natural key survives as a unique index instead.
--
-- Blobs in the database rather than files on disk, deliberately: branding has
-- to survive a restore (§11.10 backs up the panel database), it has to be
-- readable by the *web* process — which is unprivileged and has no business
-- reading a directory the agent writes — and it is bounded to three small
-- images per reseller.
CREATE TABLE branding_assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    reseller_id  INTEGER NOT NULL CHECK (reseller_id >= 0),
    -- `logo`, `favicon` or `login_background`.
    kind         TEXT    NOT NULL CHECK (kind IN ('logo', 'favicon', 'login_background')),
    -- The type the panel *sniffed*, not one a client claimed. Constrained to
    -- the raster formats the upload path accepts: SVG is refused outright
    -- (see unihelm_ops::branding::sniff_image for why), so no value here can
    -- ever name a document format a browser would script.
    content_type TEXT    NOT NULL CHECK (content_type IN (
                     'image/png', 'image/jpeg', 'image/gif',
                     'image/webp', 'image/x-icon'
                 )),
    bytes        BLOB    NOT NULL,
    -- Serves the ETag, so a browser that already has the logo does not refetch
    -- it on every login page load.
    sha256       TEXT    NOT NULL,
    size_bytes   INTEGER NOT NULL CHECK (size_bytes > 0),
    updated_at   TEXT    NOT NULL
);

-- One asset per (reseller, kind): uploading a new logo replaces the old one.
-- Keeping a history of logos would be a slow leak of megabytes into the panel
-- database for no feature anybody asked for.
CREATE UNIQUE INDEX branding_assets_owner ON branding_assets (reseller_id, kind);
