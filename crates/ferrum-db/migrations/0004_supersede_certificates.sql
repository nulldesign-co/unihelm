-- Migration 0004: retire duplicate certificates.
--
-- Every issuance inserts a row, and until now nothing retired the row it
-- replaced. A live test server ended up with three rows for one domain, all
-- marked active — which meant the renewal scheduler would have opened three
-- ACME orders for that one name on every cycle, against a CA that rate-limits
-- by domain.
--
-- `certificate_issued` now supersedes the older rows in the same transaction.
-- This migration adds the status it uses and backfills what was already stored.
--
-- SQLite cannot alter a CHECK constraint, so the table is rebuilt. The twelve
-- steps of the documented safe-rebuild procedure reduce to this because the
-- only inbound reference is `certificates.site_id -> sites.id`; nothing points
-- at `certificates`, so no foreign key needs re-pointing.

PRAGMA foreign_keys = OFF;

CREATE TABLE certificates_new (
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
                         CHECK (status IN ('pending', 'active', 'superseded',
                                           'expired', 'failed', 'revoked')),
    -- The last renewal failure, so the UI can explain why a certificate is
    -- about to expire instead of only warning that it is.
    last_error   TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    cert_dir     TEXT    NOT NULL,
    issued_at    TEXT,
    -- Added by migration 0003: when a failing certificate may be tried again.
    next_attempt_at TEXT,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);

INSERT INTO certificates_new
    (id, site_id, kind, domains_json, issuer, not_before, not_after, auto_renew,
     status, last_error, failure_count, cert_dir, issued_at, next_attempt_at,
     created_at, updated_at)
SELECT
     id, site_id, kind, domains_json, issuer, not_before, not_after, auto_renew,
     status, last_error, failure_count, cert_dir, issued_at, next_attempt_at,
     created_at, updated_at
FROM certificates;

DROP TABLE certificates;
ALTER TABLE certificates_new RENAME TO certificates;

CREATE INDEX certificates_site_idx   ON certificates (site_id);
CREATE INDEX certificates_expiry_idx ON certificates (not_after) WHERE auto_renew = 1;

-- Backfill: keep only the newest issuance per site live. That is the one nginx
-- is actually serving, so it is the one worth renewing.
UPDATE certificates
SET status = 'superseded',
    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE site_id IS NOT NULL
  AND status IN ('active', 'pending', 'expired')
  AND id != (
      SELECT c2.id FROM certificates c2
      WHERE c2.site_id = certificates.site_id
        AND c2.status IN ('active', 'pending', 'expired')
      -- Newest first; a row that was never issued has no issued_at and loses.
      ORDER BY c2.issued_at IS NULL, c2.issued_at DESC, c2.id DESC
      LIMIT 1
  );

PRAGMA foreign_keys = ON;
