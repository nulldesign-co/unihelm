/**
 * Plans and suspension API client (spec §6.2, §6.4).
 *
 * # The gap this file works around
 *
 * The panel exposes `POST /api/subscriptions/{id}/suspend` and its inverse, but
 * there is **no endpoint that lists subscriptions** — no `GET
 * /api/subscriptions`, and no `subscription.list` operation behind one. So the
 * subscriptions the page offers to suspend are derived from the sites the
 * caller can already see (`GET /api/sites`, whose rows carry
 * `subscription_id`).
 *
 * Two consequences, both surfaced in the UI rather than hidden:
 *
 * - A subscription with no sites does not appear. Suspending one is still
 *   possible, by id, which is why the page keeps a by-id path.
 * - **Suspension state is not knowable here.** Suspending flips
 *   `subscriptions.status` and re-renders each vhost onto the maintenance
 *   page; it deliberately does not touch the sites' own rows (so unsuspend can
 *   restore each site's stored settings), and the site row is all this client
 *   gets to see. The page therefore says "unknown" instead of guessing, and
 *   offers both directions — both operations are idempotent, so neither is a
 *   trap.
 */

import { api, type SiteView, type TaskAccepted } from "@/lib/api";

// ---------------------------------------------------------------------------
// Wire shapes (mirrors unihelm-ops `plan`)
// ---------------------------------------------------------------------------

export interface PlanView {
  id: number;
  /** null = admin-global; a number = the reseller who owns it (spec §6.2). */
  owner_user_id: number | null;
  name: string;
  max_sites: number;
  max_dbs: number;
  storage_mb: number;
  can_ssh: boolean;
  can_cron: boolean;
  can_node_apps: boolean;
  created_at: string;
  updated_at: string;
  /** Subscriptions currently on this plan; deletion is refused above zero. */
  subscriptions: number;
}

export interface PlansResponse {
  plans: PlanView[];
}

/** The plan fields an operator edits. Limits are counts; storage is megabytes. */
export interface PlanLimits {
  max_sites: number;
  max_dbs: number;
  storage_mb: number;
  can_ssh: boolean;
  can_cron: boolean;
  can_node_apps: boolean;
}

export interface CreatePlanRequest extends PlanLimits {
  name: string;
}

export type UpdatePlanRequest = Partial<CreatePlanRequest>;

export interface AssignResult {
  subscription_id: number;
  plan_id: number;
  plan_name: string;
  /** The subscription already holds more sites than the new plan allows. */
  over_limit: boolean;
}

export const plansApi = {
  list: () => api.get<PlansResponse>("/api/plans"),
  create: (body: CreatePlanRequest) => api.post<{ plan: PlanView }>("/api/plans", body),
  update: (id: number, body: UpdatePlanRequest) =>
    api.patch<{ plan: PlanView }>(`/api/plans/${id}`, body),
  remove: (id: number) => api.del<{ plan_id: number }>(`/api/plans/${id}`),
  assign: (planId: number, subscriptionId: number) =>
    api.post<AssignResult>(`/api/plans/${planId}/assign`, { subscription_id: subscriptionId }),
  /** 202 + a task id: one nginx reload per site is past the immediate budget. */
  suspend: (subscriptionId: number, reason: string) =>
    api.post<TaskAccepted>(`/api/subscriptions/${subscriptionId}/suspend`, { reason }),
  unsuspend: (subscriptionId: number) =>
    api.post<TaskAccepted>(`/api/subscriptions/${subscriptionId}/unsuspend`),
};

// ---------------------------------------------------------------------------
// Subscriptions, derived from what the API does expose
// ---------------------------------------------------------------------------

/** One subscription as this page can see it: an id and the sites under it. */
export interface DerivedSubscription {
  id: number;
  /**
   * Domains that are serving today, so they are the ones suspension actually
   * switches to the maintenance page — `subscription.suspend` skips any site
   * that is not `active`, because a provisioning site has no vhost yet and a
   * failed one may have nothing valid on disk.
   */
  liveDomains: string[];
  /** Domains of sites in any other state; listed, but not promised to go dark. */
  otherDomains: string[];
}

/**
 * Group the visible sites into subscriptions.
 *
 * Sorted by id, and the domains within each sorted alphabetically, so the
 * confirmation dialog reads the same way twice and an operator can check it
 * against what they expected before they click.
 */
export function subscriptionsFromSites(sites: SiteView[]): DerivedSubscription[] {
  const byId = new Map<number, DerivedSubscription>();
  for (const site of sites) {
    let entry = byId.get(site.subscription_id);
    if (!entry) {
      entry = { id: site.subscription_id, liveDomains: [], otherDomains: [] };
      byId.set(site.subscription_id, entry);
    }
    (site.status === "active" ? entry.liveDomains : entry.otherDomains).push(site.domain);
  }
  const out = [...byId.values()];
  for (const entry of out) {
    entry.liveDomains.sort();
    entry.otherDomains.sort();
  }
  out.sort((a, b) => a.id - b.id);
  return out;
}

// ---------------------------------------------------------------------------
// Client-side mirrors of the agent's rules (messages, not boundaries)
// ---------------------------------------------------------------------------

export type ReasonProblem = "required" | "tooLong" | "control";

/**
 * The suspension reason, checked the way the agent checks it: 1–500 characters
 * of plain text.
 *
 * Mandatory is a product decision, not a validation accident — the reason is
 * what the customer is shown next to the maintenance page, and "suspended for
 * no recorded reason" helps nobody (spec §6.4). Checking it here only saves the
 * round trip; `subscription.suspend` refuses the same input.
 */
export function reasonProblem(raw: string): ReasonProblem | null {
  const value = raw.trim();
  if (value === "") return "required";
  // `chars().count()`, not bytes: the agent counts characters, and a Farsi
  // reason must get the same 500 the English one gets. Spreading the string
  // yields code points, which is what Rust's `chars()` iterates.
  if ([...value].length > 500) return "tooLong";
  // Rust's `char::is_control` is the Unicode Cc category, exactly these two
  // ranges. Written as escapes rather than literals so the rule survives an
  // editor that eats invisible bytes.
  if (/[\u0000-\u001F\u007F-\u009F]/.test(value)) return "control";
  return null;
}

export type LimitProblem = "required" | "notANumber" | "tooLarge";

/**
 * A plan limit, checked against what the wire type accepts.
 *
 * The request fields are `u32`, so a negative or fractional value is refused by
 * serde before `plan.create` runs at all — which produces a whole-request
 * parse error rather than a field-level one. Catching it here is what keeps the
 * message attached to the field the operator got wrong.
 */
export const MAX_PLAN_LIMIT = 4_294_967_295;

export function limitProblem(raw: string): LimitProblem | null {
  const value = raw.trim();
  if (value === "") return "required";
  if (!/^\d+$/.test(value)) return "notANumber";
  if (Number(value) > MAX_PLAN_LIMIT) return "tooLarge";
  return null;
}

/** Only the fields that actually changed, so a PATCH says what it means. */
export function planDiff(before: PlanView, after: CreatePlanRequest): UpdatePlanRequest {
  const diff: UpdatePlanRequest = {};
  if (after.name !== before.name) diff.name = after.name;
  if (after.max_sites !== before.max_sites) diff.max_sites = after.max_sites;
  if (after.max_dbs !== before.max_dbs) diff.max_dbs = after.max_dbs;
  if (after.storage_mb !== before.storage_mb) diff.storage_mb = after.storage_mb;
  if (after.can_ssh !== before.can_ssh) diff.can_ssh = after.can_ssh;
  if (after.can_cron !== before.can_cron) diff.can_cron = after.can_cron;
  if (after.can_node_apps !== before.can_node_apps) diff.can_node_apps = after.can_node_apps;
  return diff;
}
