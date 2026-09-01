/**
 * Behaviour tests for the firewall page's own judgement (spec §11.9).
 *
 * The lockout guard itself lives in `src/lib/ip.ts` and is tested there. What
 * is pinned here is the rest of what this page decides before it talks to the
 * agent: the port form's rules, and Sentinel's bounds — the numbers that decide
 * whether the brute-force defence protects the operator or bans them.
 */

import { describe, expect, it } from "vitest";

import { ApiError, type SentinelSettings } from "@/lib/api";

import { isRouteMissing, portProblem, sentinelProblems } from "./firewall";

describe("the open-port form", () => {
  it("accepts the shapes a real rule takes", () => {
    expect(portProblem("22", "")).toBeNull();
    expect(portProblem("8080", "203.0.113.0/24")).toBeNull();
    expect(portProblem("65535", "2001:db8::/32")).toBeNull();
    expect(portProblem(" 443 ", " 198.51.100.7 ")).toBeNull();
  });

  it("refuses a port number that is not one", () => {
    for (const bad of ["", "0", "65536", "99999", "-1", "80.5", "http", "08"]) {
      expect(portProblem(bad, ""), bad).toBe("port");
    }
  });

  it("refuses a hostname as a source, because a rule that depends on DNS cannot be audited", () => {
    // The agent takes a literal address or CIDR only; accepting a name here
    // would offer a rule the firewall will never hold (docs/operations.md,
    // `fw.port.open`).
    for (const bad of ["office.example.com", "localhost", "203.0.113.0/33", "203.0.113"]) {
      expect(portProblem("22", bad), bad).toBe("source");
    }
  });
});

const settings = (over: Partial<SentinelSettings> = {}): SentinelSettings => ({
  enabled: true,
  ssh_threshold: 6,
  window_minutes: 10,
  ban_minutes: 60,
  allowlist: [],
  ...over,
});

describe("Sentinel's bounds", () => {
  it("accepts the shipped defaults, which are the ones an operator sees first", () => {
    expect(sentinelProblems(settings({ enabled: false }))).toEqual([]);
    expect(sentinelProblems(settings())).toEqual([]);
  });

  it("refuses a threshold of zero, which would ban every address in the log including yours", () => {
    expect(sentinelProblems(settings({ ssh_threshold: 0 }))).toContain("ssh_threshold");
    expect(sentinelProblems(settings({ ssh_threshold: -1 }))).toContain("ssh_threshold");
    expect(sentinelProblems(settings({ ssh_threshold: 1 }))).toEqual([]);
  });

  it("keeps the scan window between a minute and a day", () => {
    expect(sentinelProblems(settings({ window_minutes: 0 }))).toContain("window_minutes");
    expect(sentinelProblems(settings({ window_minutes: 1441 }))).toContain("window_minutes");
    expect(sentinelProblems(settings({ window_minutes: 1440 }))).toEqual([]);
  });

  it("keeps a ban between a minute and a year", () => {
    expect(sentinelProblems(settings({ ban_minutes: 0 }))).toContain("ban_minutes");
    expect(sentinelProblems(settings({ ban_minutes: 525_601 }))).toContain("ban_minutes");
    expect(sentinelProblems(settings({ ban_minutes: 525_600 }))).toEqual([]);
  });

  it("refuses a fractional knob rather than letting the server round it silently", () => {
    expect(sentinelProblems(settings({ ssh_threshold: 6.5 }))).toContain("ssh_threshold");
    // An empty numeric field parses to NaN in the browser; it must read as a
    // problem, not as zero.
    expect(sentinelProblems(settings({ window_minutes: Number.NaN }))).toContain("window_minutes");
  });

  it("refuses a typo in the allowlist instead of storing an entry that covers nothing", () => {
    expect(sentinelProblems(settings({ allowlist: ["203.0.113.0/24", "office-lan"] }))).toContain(
      "allowlist",
    );
    expect(sentinelProblems(settings({ allowlist: ["203.0.113.0/24", "::1"] }))).toEqual([]);
  });

  it("reports every bad field at once so the form does not fix them one round trip at a time", () => {
    expect(sentinelProblems(settings({ ssh_threshold: 0, ban_minutes: 0 }))).toEqual([
      "ssh_threshold",
      "ban_minutes",
    ]);
  });
});

describe("telling a missing route apart from a refusal", () => {
  it("recognises the bare 404 an unregistered axum route answers with", () => {
    // No JSON body, so the client synthesises `unexpected_response`. This is a
    // build without `/api/firewall`, not a firewall that said no.
    const bare = new ApiError(404, {
      code: "HTTP-404",
      slug: "unexpected_response",
      message: "Not Found",
    });
    expect(isRouteMissing(bare)).toBe(true);
  });

  it("does not mistake the panel's own not_found for a missing API", () => {
    const real = new ApiError(404, {
      code: "UNI-0404",
      slug: "not_found",
      message: "no such ban",
    });
    expect(isRouteMissing(real)).toBe(false);
    expect(isRouteMissing(new Error("network"))).toBe(false);
  });
});
