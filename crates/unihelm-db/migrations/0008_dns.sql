-- Migration 0008 (Phase 2): DNS provider credentials (spec §11.13).
--
-- v1 is the *provider-integration* model: the panel does not run authoritative
-- DNS, it holds an API credential for somebody who does (spec §11.13, own
-- authoritative DNS is Phase 5). Cloudflare is the only provider this build
-- speaks, and the CHECK constraint says so rather than leaving a `kind` column
-- that quietly accepts `route53` and then fails at runtime with a message about
-- an unknown enum. Adding deSEC or RFC2136 later means widening this CHECK in a
-- migration, which is exactly the review moment a new provider deserves.
--
-- `credentials_sealed` holds a **Cloudflare API Token**, sealed with the panel
-- master key (XChaCha20-Poly1305, see `unihelm_db::MasterKey`) exactly the way
-- `acme_accounts.credentials_encrypted` holds the ACME account key. It is never
-- stored, logged or returned in the clear (spec §12 rule 6), and the column name
-- says `sealed` so a reader of the schema knows the value is not a password to
-- be compared but a ciphertext to be opened.
--
-- Never a Global API Key. That distinction is the whole security story of this
-- table and it is argued at length in `unihelm_ops::dns`: a Global Key
-- authenticates every action on every zone in the account (and the account's
-- billing), while a token can be scoped to Zone:Read + DNS:Edit on one zone. A
-- panel that stores the first has taken the customer's entire Cloudflare account
-- hostage on the strength of its own disk encryption.

CREATE TABLE dns_providers (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    kind               TEXT NOT NULL CHECK (kind = 'cloudflare'),
    -- The operator's own name for this credential ("acme-corp zone token").
    -- Shown in the UI; it is the only handle they have on a value they can
    -- never read back.
    label              TEXT NOT NULL,
    credentials_sealed TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

-- Unique on (kind, label), not on kind alone.
--
-- The scoping advice above only works if an operator can hold more than one
-- token: a token restricted to `example.com`'s zone cannot touch
-- `other-customer.net`, so a server hosting both needs two. `dns.provider.set`
-- upserts on this key, so re-running it with the same label rotates that
-- credential rather than accumulating dead rows, and issuance walks every
-- provider looking for one whose zone list covers the name.
CREATE UNIQUE INDEX dns_providers_label_uq ON dns_providers (kind, label);
