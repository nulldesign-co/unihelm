/**
 * What the dashboard says about a restart the machine is waiting for.
 *
 * A kernel update replaces files and leaves the running system on the old ones.
 * The panel read neither Debian's `/var/run/reboot-required` nor the EL
 * family's `needs-restarting -r`, so an operator who applied updates was told
 * the work succeeded and had no way to learn their kernel patch was not the
 * code executing on that machine.
 *
 * Two promises are pinned here. A pending restart reaches the attention banner
 * and names what asked for it — and a restart state that could not be
 * established reaches it too, because the banner's empty face says "nothing on
 * this server needs your attention right now" and that claim must not rest on a
 * check nobody could run.
 */

import { describe, expect, it } from "vitest";

import type { Metrics, Overview } from "@/lib/api";

import { collectProblems, type RebootStatus } from "./dashboard";

/** Keys, not sentences: what is asserted here is which problems are raised. */
const t = (key: string) => key;

const metrics = (): Metrics => ({
  at: "2026-09-08T12:00:00Z",
  uptime_seconds: 86_400,
  load: { one: 0.2, five: 0.3, fifteen: 0.3 },
  cpu: { cores: 4, usage_pct: 6 },
  memory: {
    total_bytes: 8 * 1024 * 1024 * 1024,
    used_bytes: 2 * 1024 * 1024 * 1024,
    available_bytes: 6 * 1024 * 1024 * 1024,
    swap_total_bytes: 0,
    swap_used_bytes: 0,
  },
  disks: [{ mount: "/", total_bytes: 100, used_bytes: 40, available_bytes: 60, filesystem: "/dev/vda1" }],
  network: { rx_bytes: 0, tx_bytes: 0, rx_bytes_per_sec: 0, tx_bytes_per_sec: 0 },
  panel: { web_rss_bytes: null, agent_rss_bytes: null, total_rss_bytes: 40 * 1024 * 1024 },
});

/** A server with nothing else wrong with it, so the reboot entry stands alone. */
const overview = (): Overview => ({
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
});

const status = (requirement: RebootStatus["requirement"]): RebootStatus => ({
  requirement,
  hostname: "web-01",
  sites: ["example.com"],
  site_count: 1,
});

function problems(reboot?: RebootStatus) {
  return collectProblems({
    t,
    locale: "en",
    overview: overview(),
    services: { services: [] },
    openAlertCount: 0,
    reboot,
  });
}

describe("a restart the server is waiting for", () => {
  it("reaches the attention banner and names the package that asked for it", () => {
    // The defect, exactly: this entry did not exist, so a server running a
    // kernel it had already patched looked identical to one that was current.
    const raised = problems(
      status({
        state: "required",
        packages: ["linux-image-6.8.0-45-generic", "linux-base"],
        evidence: "/var/run/reboot-required exists",
      }),
    );
    expect(raised.map((p) => p.id)).toEqual(["reboot"]);
    expect(raised[0]!.label).toBe("dashboard.health.rebootRequiredForMany");
  });

  it("does not count a remainder that is not there", () => {
    // One package has no "and N others" to add, and `{{count}}` of 0 takes
    // English's *plural* branch — which is how "and 0 more packages" would have
    // reached an operator.
    const raised = problems(
      status({ state: "required", packages: ["linux-base"], evidence: "marker" }),
    );
    expect(raised[0]!.label).toBe("dashboard.health.rebootRequiredFor");
  });

  it("still says so when the system named no packages", () => {
    // The marker file can exist with no package list beside it. Dropping the
    // entry because the detail is missing would lose the only signal there is.
    const raised = problems(
      status({ state: "required", packages: [], evidence: "/var/run/reboot-required exists" }),
    );
    expect(raised.map((p) => p.id)).toEqual(["reboot"]);
    expect(raised[0]!.label).toBe("dashboard.health.rebootRequired");
  });

  it("says it could not tell rather than letting the banner go green", () => {
    // A Debian install without `update-notifier-common` never grows the marker
    // file, so its absence proves nothing. Staying silent would let "nothing on
    // this server needs your attention" be said on evidence nobody gathered.
    const raised = problems(status({ state: "unknown", reason: "no notify-reboot-required" }));
    expect(raised.map((p) => p.id)).toEqual(["reboot-unknown"]);
  });

  it("offers no link, because the notice that can act on it is on this page", () => {
    const raised = problems(
      status({ state: "required", packages: ["linux-base"], evidence: "marker" }),
    );
    expect(raised[0]!.to).toBeNull();
  });

  it("says nothing on a server that does not need restarting", () => {
    expect(problems(status({ state: "not_required" }))).toEqual([]);
  });

  it("says nothing while the answer has not arrived", () => {
    // An in-flight query is not evidence of anything, and guessing "required"
    // from a pending request would put an alarm on a healthy server.
    expect(problems(undefined)).toEqual([]);
  });
});
