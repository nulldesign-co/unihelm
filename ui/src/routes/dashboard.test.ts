/**
 * What the dashboard calls a problem (spec §11.2).
 *
 * The amber banner at the top of the page is the panel's answer to "is
 * anything broken?", and an operator reads every line in it as something on
 * their server that needs them. That makes the list a promise rather than a
 * summary: everything in it has to be a condition on the machine, and
 * everything in it has to be actionable. This pins the one entry that was
 * neither — the panel's own memory against a build-time regression gate — and
 * the ones that are, so removing it cannot quietly take them with it.
 */

import { describe, expect, it } from "vitest";

import type { Metrics, Overview, ServicesResponse } from "@/lib/api";

import { collectProblems } from "./dashboard";

/** Keys, not sentences: what is asserted here is which problems are raised. */
const t = (key: string) => key;

const metrics = (over: Partial<Metrics> = {}): Metrics => ({
  at: "2026-09-06T12:00:00Z",
  uptime_seconds: 86_400,
  load: { one: 0.2, five: 0.3, fifteen: 0.3 },
  cpu: { cores: 4, usage_pct: 6 },
  memory: {
    // A small VPS, and still nearly a hundred times the panel's budget.
    total_bytes: 8 * 1024 * 1024 * 1024,
    used_bytes: 2 * 1024 * 1024 * 1024,
    available_bytes: 6 * 1024 * 1024 * 1024,
    swap_total_bytes: 0,
    swap_used_bytes: 0,
  },
  disks: [{ mount: "/", total_bytes: 100, used_bytes: 40, available_bytes: 60, filesystem: "/dev/vda1" }],
  network: { rx_bytes: 0, tx_bytes: 0, rx_bytes_per_sec: 0, tx_bytes_per_sec: 0 },
  panel: { web_rss_bytes: null, agent_rss_bytes: null, total_rss_bytes: 40 * 1024 * 1024 },
  ...over,
});

/** A healthy server: the banner over this one has to be green. */
const overview = (over: Partial<Overview> = {}): Overview => ({
  agent_online: true,
  panel_version: "0.7.2",
  panel_uptime_seconds: 3_600,
  metrics: metrics(),
  system: {
    agent_version: "0.7.2",
    distro: "Ubuntu 24.04",
    family: "debian",
    arch: "aarch64",
    package_backend: "apt",
    firewall_backend: "nftables",
    security_module: "apparmor",
  },
  ...over,
});

const noServices: ServicesResponse = { services: [] };

function problems(over: Partial<Overview> = {}, openAlertCount: number | null = 0) {
  return collectProblems({
    t,
    locale: "en",
    overview: overview(over),
    services: noServices,
    openAlertCount,
  });
}

describe("the attention banner", () => {
  it("does not put the panel's own memory budget in front of an operator", () => {
    // The defect, exactly: an 80 MB CI regression gate was compared against the
    // panel's resident memory and pushed into the amber "needs attention"
    // banner. A non-technical operator who had just uploaded a login background
    // read "the panel is over budget" as their server running out of memory —
    // on a machine with gigabytes free — and there was no page anywhere that
    // could act on it, because there is nothing for them to do. It belongs on
    // the footprint card, stated against the memory the machine actually has.
    const fat = metrics({
      panel: {
        web_rss_bytes: 140 * 1024 * 1024,
        agent_rss_bytes: 60 * 1024 * 1024,
        total_rss_bytes: 200 * 1024 * 1024,
      },
    });
    expect(problems({ metrics: fat })).toEqual([]);
  });

  it("still names everything that is the operator's to fix", () => {
    // The other half of the change: the banner keeps counting the conditions
    // that are real, and each of those still points at the page that acts on
    // it. A list emptied of everything is no better than one crying wolf.
    const full = metrics({
      disks: [
        { mount: "/", total_bytes: 100, used_bytes: 96, available_bytes: 4, filesystem: "/dev/vda1" },
      ],
    });
    const raised = problems({ metrics: full, system: undefined }, 2);
    expect(raised.map((p) => p.id)).toEqual(["alerts", "disk-/"]);
    expect(raised.find((p) => p.id === "alerts")?.to).toBe("/alerts");
  });

  it("offers no link on a problem with nowhere to send anybody", () => {
    // Every entry is drawn as a link with a chevron unless it says otherwise,
    // and a link to the page the reader is already standing on does nothing at
    // all when it is clicked. A full disk has no page in this panel, and
    // neither does an agent that is not answering — the callout under the
    // banner is where that one is explained.
    const offline = problems({ agent_online: false });
    expect(offline.map((p) => p.id)).toEqual(["agent"]);
    expect(offline[0]!.to).toBeNull();
  });
});
