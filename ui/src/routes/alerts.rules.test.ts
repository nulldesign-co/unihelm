/**
 * The rules card's own judgement (spec §11.11).
 *
 * A separate file from `alerts.test.ts` — that one pins the channel and history
 * behaviour — because these three claims arrived together and each was a real
 * defect an operator hit on a fresh install:
 *
 * - the edit dialog locked kind, target and threshold, so opening Edit on a
 *   `service_down` rule gave a form where nothing could be changed and Save did
 *   nothing at all. The fields are editable now, and a changed `(kind, target)`
 *   is honestly a replace, because that pair is the rule's identity;
 * - a rule that could not be edited could not be deleted either, so the label a
 *   replace has to name has to be exactly the one the server uses;
 * - the target list was a hardcoded copy of the agent's whitelist that had gone
 *   stale, and it offered services the machine does not have.
 */

import { describe, expect, it } from "vitest";

import type { AlertRule, ServiceStatus, ServiceTargetOption } from "@/lib/api";

import {
  normalizeTarget,
  ruleLabel,
  ruleToReplace,
  serviceAvailability,
  serviceChoices,
} from "./alerts";

const rule = (over: Partial<AlertRule> = {}): AlertRule => ({
  id: 3,
  kind: "service_down",
  target: "nginx",
  threshold: 1,
  enabled: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  ...over,
});

const option = (over: Partial<ServiceTargetOption> = {}): ServiceTargetOption => ({
  target: "nginx",
  display_name: "Nginx",
  unit: "nginx.service",
  ...over,
});

const status = (unit: string, state: ServiceStatus["state"]): ServiceStatus => ({
  display_name: unit,
  unit,
  state,
  sub_state: "dead",
  enabled: null,
  main_pid: null,
  memory_bytes: null,
  since: null,
});

describe("editing a rule", () => {
  it("saves in place when the kind and target are untouched", () => {
    expect(ruleToReplace(rule(), "service_down", "nginx")).toBeNull();
  });

  it("treats an empty target and a null target as the same rule", () => {
    // The every-filesystem disk rule stores NULL and the form holds "". A
    // replace here would delete the rule it had just written back.
    expect(ruleToReplace(rule({ kind: "disk_pct", target: null }), "disk_pct", "")).toBeNull();
    expect(ruleToReplace(rule({ kind: "disk_pct", target: null }), "disk_pct", "   ")).toBeNull();
  });

  it("reports the rule left behind when the target changes", () => {
    // `(kind, target)` is the identity, so saving `mariadb` over `nginx` writes
    // a second rule; the old one has to be named so it can be removed.
    expect(ruleToReplace(rule(), "service_down", "mariadb")).toEqual({
      kind: "service_down",
      target: "nginx",
    });
  });

  it("reports the rule left behind when the kind changes", () => {
    expect(ruleToReplace(rule({ kind: "mem_pct", target: null }), "load", "")).toEqual({
      kind: "mem_pct",
      target: null,
    });
  });

  it("never replaces anything when the rule is new", () => {
    expect(ruleToReplace(null, "disk_pct", "/var")).toBeNull();
  });

  it("names a rule the way the server does, so the two halves of a replace match", () => {
    expect(ruleLabel({ kind: "service_down", target: "nginx" })).toBe("service_down:nginx");
    expect(ruleLabel({ kind: "disk_pct", target: null })).toBe("disk_pct");
    expect(normalizeTarget("  /var  ")).toBe("/var");
    expect(normalizeTarget("   ")).toBeNull();
  });
});

describe("choosing a service to watch", () => {
  it("calls a unit the server reports as not_found missing", () => {
    const services = [status("nginx.service", "not_found")];
    expect(serviceAvailability(option(), services)).toBe("missing");
  });

  it("calls a unit in any other state installed", () => {
    for (const state of ["active", "inactive", "failed", "activating"] as const) {
      expect(serviceAvailability(option(), [status("nginx.service", state)])).toBe("installed");
    }
  });

  it("says nothing about a unit the services endpoint does not cover", () => {
    // The dashboard probes six units; a rule may name more. Claiming "not
    // installed" for one nobody asked about would be the panel asserting
    // something it has not checked.
    expect(serviceAvailability(option({ target: "sshd", unit: "ssh.service" }), [])).toBe("unknown");
    expect(serviceAvailability(option(), undefined)).toBe("unknown");
  });

  it("keeps a target that is not on the agent's list so the select can show it", () => {
    // `php_fpm:8.3` is set from the CLI and is not one of the fixed choices. A
    // <select> with no option for its value shows the first entry instead, and
    // saving would then move the rule to a service nobody picked.
    const choices = serviceChoices([option()], "php_fpm:8.3");
    expect(choices.map((c) => c.target)).toEqual(["php_fpm:8.3", "nginx"]);
    // And it carries no unit, so nothing claims to know whether it is installed.
    expect(serviceAvailability(choices[0]!, [status("nginx.service", "active")])).toBe("unknown");
  });

  it("leaves the list alone when the current target is on it or empty", () => {
    const options = [option()];
    expect(serviceChoices(options, "nginx")).toBe(options);
    expect(serviceChoices(options, "")).toBe(options);
  });
});
