/**
 * The DNS record editor's API client (spec §11.13).
 *
 * Separate from `api.ts` for the same reason `files-api.ts` and
 * `databases-api.ts` are: an area with a dozen shapes of its own should not
 * push them all into the file every screen imports.
 *
 * Two things here are not arbitrary.
 *
 * **The provider read returns metadata, never the token.** `GET
 * /api/dns/provider` answers with the label, the Cloudflare accounts, the zones
 * and whether the credential still answers Cloudflare. There is no field on
 * `DnsStoredProvider` that could carry a secret, and the page below never has
 * one in memory after a save.
 *
 * **Nothing here polls.** Every call in this file is a live Cloudflare request
 * made by the agent, and Cloudflare rate-limits per token. So the queries that
 * use these have `refetchOnWindowFocus` off and a stale time measured in
 * minutes: the page fetches when a zone is chosen and when a write lands, and
 * otherwise leaves the budget alone.
 */

import { api } from "@/lib/api";

/** One stored credential, described by everything except its secret. */
export interface DnsStoredProvider {
  id: number;
  kind: string;
  label: string;
  /**
   * Did the token answer Cloudflare just now?
   *
   * Checked live, not remembered: a token revoked in the Cloudflare dashboard
   * is still a row in the panel's table, and showing that row as active would
   * be a claim about the credential every renewal depends on that is untrue.
   */
  reachable: boolean;
  /** Why it did not, in Cloudflare's own words. */
  error: string | null;
  accounts: string[];
  /** Every zone the token administers — its blast radius if it is stolen. */
  zones: string[];
}

export interface DnsProviderStatus {
  providers: DnsStoredProvider[];
}

export interface DnsZone {
  id: string;
  name: string;
  account: string | null;
  provider_label: string;
}

export interface DnsZonesResponse {
  zones: DnsZone[];
  /** Credentials that could not be asked, so the zone list may be short. */
  unreachable: string[];
}

export interface DnsRecord {
  id: string;
  kind: string;
  name: string;
  content: string;
  /** `1` is Cloudflare's automatic. */
  ttl: number;
  /** `null` for a type Cloudflare cannot proxy. */
  proxied: boolean | null;
  priority: number | null;
  comment: string | null;
  /** The content is one of this server's own public addresses. */
  points_here: boolean;
  /**
   * What changing or removing this record would cost, in whole sentences.
   *
   * The server's, deliberately. Deciding "is this record load-bearing" needs
   * the panel's own site list and this server's addresses, and a second copy of
   * that decision in the browser is the copy that goes stale — which here means
   * a confirm dialog that stays quiet while somebody deletes a live site.
   */
  impact: string[];
}

export interface DnsRecordsResponse {
  zone: string;
  zone_id: string;
  provider_label: string;
  records: DnsRecord[];
  server_addresses: string[];
  /** The zone holds more records than this list carries. */
  truncated: boolean;
  /** The types the agent will write. Sent, so the picker cannot drift from it. */
  record_types: string[];
  /** Of those, the ones that can go behind Cloudflare's proxy. */
  proxyable_types: string[];
}

/** A create, or an update with the two fields that say what was on screen. */
export interface DnsRecordRequest {
  zone: string;
  kind: string;
  name: string;
  content: string;
  ttl: number | null;
  proxied: boolean | null;
  priority: number | null;
  confirm_name?: string;
  confirm_content?: string;
}

export interface DnsRecordWriteResponse {
  zone: string;
  /** As Cloudflare stored it — not as it was sent. */
  record: DnsRecord;
  previous: DnsRecord | null;
}

export interface DnsRecordDeleteResponse {
  zone: string;
  deleted: DnsRecord;
}

export const dnsApi = {
  provider: () => api.get<DnsProviderStatus>("/api/dns/provider"),
  zones: () => api.get<DnsZonesResponse>("/api/dns/zones"),
  records: (zone: string) =>
    api.get<DnsRecordsResponse>(`/api/dns/records?zone=${encodeURIComponent(zone)}`),
  createRecord: (body: DnsRecordRequest) =>
    api.post<DnsRecordWriteResponse>("/api/dns/records", body),
  updateRecord: (id: string, body: DnsRecordRequest) =>
    api.put<DnsRecordWriteResponse>(`/api/dns/records/${encodeURIComponent(id)}`, body),
  /**
   * Remove a record, saying which record was on screen when Delete was pressed.
   *
   * The confirmations are not ceremony: a record id addresses whatever now sits
   * under it, and if somebody edited that record in the Cloudflare dashboard
   * since this table was drawn, deleting by id alone removes something nobody
   * chose. The agent re-reads the record and refuses when it is not this one.
   */
  deleteRecord: (id: string, zone: string, record: Pick<DnsRecord, "name" | "content">) => {
    const query = new URLSearchParams({
      zone,
      confirm_name: record.name,
      confirm_content: record.content,
    });
    return api.del<DnsRecordDeleteResponse>(
      `/api/dns/records/${encodeURIComponent(id)}?${query.toString()}`,
    );
  },
};

/** Cloudflare's "automatic" TTL, and the only one a proxied record may carry. */
export const TTL_AUTOMATIC = 1;

/** The TTLs the form offers. Anything outside 60–86400 the agent refuses. */
export const TTL_CHOICES = [TTL_AUTOMATIC, 60, 300, 1800, 3600, 86400] as const;

/** The types that carry a priority. Everything else is refused with one. */
export const PRIORITY_TYPES = ["MX", "SRV"];
