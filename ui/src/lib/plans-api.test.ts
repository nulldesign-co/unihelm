/**
 * Behaviour tests for the plans and suspension client logic (spec §6.2, §6.4).
 *
 * Suspension is the destructive action on this page: it takes live domains off
 * the air. The claims worth pinning down are therefore about the confirmation
 * dialog telling the truth — that the domains it promises will go dark are
 * exactly the ones the agent switches — and about the reason field refusing the
 * same input the agent refuses, since a rejected suspension after the operator
 * has already committed is the worst of both worlds.
 */

import { describe, expect, it } from "vitest";

import type { SiteState, SiteView } from "./api";
import {
  limitProblem,
  planDiff,
  reasonProblem,
  subscriptionsFromSites,
  type PlanView,
} from "./plans-api";

function site(subscriptionId: number, domain: string, status: SiteState = "active"): SiteView {
  // Only the three fields the derivation reads are meaningful; the rest exist
  // so the object is a real `SiteView` rather than a shape that drifts from it.
  return {
    id: 1,
    subscription_id: subscriptionId,
    domain,
    site_type: "php",
    php_version: "8.4",
    root_dir: `/home/uh_x/${domain}`,
    status,
    force_https: true,
    http3: false,
    maintenance_mode: false,
    client_max_body_size: "64m",
    custom_nginx_snippet: null,
    php_ini_overrides: null,
    rate_limit_enabled: false,
    aliases: [],
    linux_user: "uh_x",
    has_certificate: true,
  };
}

function plan(overrides: Partial<PlanView> = {}): PlanView {
  return {
    id: 1,
    owner_user_id: null,
    name: "Starter",
    max_sites: 3,
    max_dbs: 1,
    storage_mb: 1024,
    can_ssh: false,
    can_cron: true,
    can_node_apps: false,
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-01T00:00:00Z",
    subscriptions: 0,
    ...overrides,
  };
}

describe("subscriptionsFromSites", () => {
  it("groups sites under their own subscription and never mixes two tenants", () => {
    const derived = subscriptionsFromSites([
      site(7, "a.example"),
      site(9, "b.example"),
      site(7, "c.example"),
    ]);
    expect(derived).toEqual([
      { id: 7, liveDomains: ["a.example", "c.example"], otherDomains: [] },
      { id: 9, liveDomains: ["b.example"], otherDomains: [] },
    ]);
  });

  it("promises only the serving domains, because only those are switched", () => {
    // `subscription.suspend` skips any site that is not active — a provisioning
    // site has no vhost yet, a failed one may have nothing valid on disk. The
    // confirmation must not claim they go dark.
    const [derived] = subscriptionsFromSites([
      site(7, "live.example", "active"),
      site(7, "half.example", "provisioning"),
      site(7, "broken.example", "failed"),
      site(7, "already.example", "suspended"),
    ]);
    expect(derived!.liveDomains).toEqual(["live.example"]);
    expect(derived!.otherDomains).toEqual([
      "already.example",
      "broken.example",
      "half.example",
    ]);
  });

  it("orders subscriptions and domains the same way twice, so a reread checks out", () => {
    const first = subscriptionsFromSites([site(9, "z.example"), site(2, "b.example")]);
    const second = subscriptionsFromSites([site(2, "b.example"), site(9, "z.example")]);
    expect(first).toEqual(second);
    expect(first.map((s) => s.id)).toEqual([2, 9]);
  });

  it("returns nothing rather than a phantom row when no site is visible", () => {
    expect(subscriptionsFromSites([])).toEqual([]);
  });
});

describe("reasonProblem", () => {
  it("refuses a blank reason, because the reason is what the customer is shown", () => {
    expect(reasonProblem("")).toBe("required");
    expect(reasonProblem("   \n\t ")).toBe("required");
  });

  it("refuses control characters the agent would refuse", () => {
    // `char::is_control` is the Unicode Cc category: both the C0 range and the
    // C1 range that a paste from a rich-text editor can smuggle in.
    expect(reasonProblem("unpaid\u0000invoice")).toBe("control");
    expect(reasonProblem("unpaid\u001Binvoice")).toBe("control");
    expect(reasonProblem("unpaid\u007F")).toBe("control");
    expect(reasonProblem("unpaid\u009Dinvoice")).toBe("control");
  });

  it("counts characters, not bytes, so a Farsi reason gets the same 500", () => {
    const farsi = "ت".repeat(500);
    expect(farsi.length).toBe(500);
    expect(reasonProblem(farsi)).toBeNull();
    expect(reasonProblem("ت".repeat(501))).toBe("tooLong");
  });

  it("accepts an ordinary reason in either language", () => {
    expect(reasonProblem("Invoice 3 months overdue")).toBeNull();
    expect(reasonProblem("صورت‌حساب 3 ماه معوق")).toBeNull();
  });
});

describe("limitProblem", () => {
  it("refuses what the u32 wire type would refuse, before the round trip", () => {
    expect(limitProblem("-1")).toBe("notANumber");
    expect(limitProblem("1.5")).toBe("notANumber");
    expect(limitProblem("ten")).toBe("notANumber");
    expect(limitProblem("4294967296")).toBe("tooLarge");
  });

  it("accepts zero, because a plan that allows nothing is a real plan", () => {
    expect(limitProblem("0")).toBeNull();
    expect(limitProblem("4294967295")).toBeNull();
  });

  it("refuses an empty field rather than silently sending zero", () => {
    expect(limitProblem("")).toBe("required");
  });
});

describe("planDiff", () => {
  it("sends only what moved, so the audit row says what actually happened", () => {
    const before = plan({ max_sites: 3, can_ssh: false });
    expect(
      planDiff(before, {
        name: before.name,
        max_sites: 5,
        max_dbs: before.max_dbs,
        storage_mb: before.storage_mb,
        can_ssh: false,
        can_cron: before.can_cron,
        can_node_apps: before.can_node_apps,
      }),
    ).toEqual({ max_sites: 5 });
  });

  it("carries a flag that was switched off, which a truthiness check would drop", () => {
    const before = plan({ can_cron: true });
    const diff = planDiff(before, {
      name: before.name,
      max_sites: before.max_sites,
      max_dbs: before.max_dbs,
      storage_mb: before.storage_mb,
      can_ssh: before.can_ssh,
      can_cron: false,
      can_node_apps: before.can_node_apps,
    });
    expect(diff).toEqual({ can_cron: false });
  });

  it("sends an empty patch when nothing changed", () => {
    const before = plan();
    expect(
      planDiff(before, {
        name: before.name,
        max_sites: before.max_sites,
        max_dbs: before.max_dbs,
        storage_mb: before.storage_mb,
        can_ssh: before.can_ssh,
        can_cron: before.can_cron,
        can_node_apps: before.can_node_apps,
      }),
    ).toEqual({});
  });
});
