/**
 * Site aliases and re-provisioning (spec §11.2).
 *
 * Both of these were missing rather than broken. A site's extra domains could
 * only ever be set by the `with_www` checkbox on the create form, so attaching
 * `www.example.com` — or a second brand, or a subdomain — to a site that
 * already existed meant deleting the site, its files and its certificate and
 * building it again. And a site whose provisioning stopped halfway sat in the
 * list as a red `failed` row with no button on it at all.
 *
 * Kept out of `lib/api.ts` on purpose: that file is the shared client every
 * page imports, and this is one page's surface.
 *
 * Everything here answers 202 with a task id. Adding a name re-renders the
 * vhost and reloads the web server, which is past the immediate budget, so the
 * caller watches the task rather than trusting the response.
 */

import { api, type TaskAccepted } from "@/lib/api";

export const sitesApi = {
  /**
   * Attach another domain.
   *
   * No `redirect` flag: the column exists in the database and no template
   * renders it, and the panel does not accept settings it cannot honour.
   */
  addAlias: (siteId: number, domain: string) =>
    api.post<TaskAccepted>(`/api/sites/${siteId}/aliases`, { domain }),
  /**
   * Detach one.
   *
   * The name is a path segment, so it is encoded even though `aliasProblem`
   * has already refused anything that would need encoding — the check and the
   * URL are two different pieces of code, and only one of them is looking.
   */
  removeAlias: (siteId: number, alias: string) =>
    api.del<TaskAccepted>(`/api/sites/${siteId}/aliases/${encodeURIComponent(alias)}`),
  /**
   * Run a site's provisioning again.
   *
   * Every step converges — the account, the directories, the pool, the vhost —
   * and the tenant's own files are left alone, so this repairs a half-made site
   * instead of replacing it.
   */
  reprovision: (siteId: number) => api.post<TaskAccepted>(`/api/sites/${siteId}/reprovision`),
};

// ---------------------------------------------------------------------------
// The agent's domain rules, mirrored for the field label
// ---------------------------------------------------------------------------

/**
 * Normalise a typed domain the way `unihelm_core::Domain::parse` does.
 *
 * Lowercase, trimmed, and with *every* trailing dot removed — Rust's
 * `trim_end_matches('.')` strips them all, so `example.com..` and `example.com`
 * are one name there and must be one name here. This matters beyond tidiness:
 * the alias is stored as the agent normalised it and the remove route matches
 * on that spelling, so a client that sent `Example.COM.` and then displayed it
 * unchanged would have a remove button that could not find its own row.
 */
export function normalizeDomain(raw: string): string {
  return raw.trim().replace(/\.+$/, "").toLowerCase();
}

export type AliasProblem =
  | "required"
  | "needsDot"
  | "tooLong"
  | "labelTooLong"
  | "charset"
  | "hyphen"
  | "ipAddress"
  | "sameAsSite"
  | "alreadyAttached";

/**
 * Why this cannot be an alias of this site, or `null`.
 *
 * A mirror, not a boundary: `site.alias.add` refuses all of it again, and the
 * cross-tenant collision check — the one that stops a name being taken from
 * another customer — can only be made against the database and is deliberately
 * not guessed at here. What this buys is a message under the field instead of a
 * task that fails a second later, and it is worth having because the two rules
 * an operator actually trips over are local ones: typing the site's own name,
 * and typing a name that is already in the list in front of them.
 */
export function aliasProblem(
  raw: string,
  site: { domain: string; aliases: string[] },
): AliasProblem | null {
  const value = normalizeDomain(raw);
  if (value === "") return "required";
  if (value.length > 253) return "tooLong";

  const labels = value.split(".");
  if (labels.length < 2) return "needsDot";
  for (const label of labels) {
    // An empty label is `a..b` — not a length problem, and the agent calls it
    // one of its own, but "needs a dot" is the message that fits what was
    // typed.
    if (label === "") return "needsDot";
    if (label.length > 63) return "labelTooLong";
    if (label.startsWith("-") || label.endsWith("-")) return "hyphen";
    // ASCII only: an IDN has to be punycoded before it can be a `server_name`,
    // because what nginx serves has to be exactly what DNS resolves.
    if (!/^[a-z0-9-]+$/.test(label)) return "charset";
  }
  // An all-digit last label means somebody pasted an IP address.
  if (/^\d+$/.test(labels[labels.length - 1]!)) return "ipAddress";

  if (value === normalizeDomain(site.domain)) return "sameAsSite";
  if (site.aliases.some((alias) => normalizeDomain(alias) === value)) return "alreadyAttached";
  return null;
}
