/**
 * What the Databases page decides before it talks to the agent (spec §11.4).
 *
 * One decision on that page is worth pinning: whether Adminer's Enable button
 * is armed. Adminer is a PHP application, and the agent installs it on the
 * highest PHP version the Stack Manager has — on a server with none it refuses,
 * and it refuses *inside a task*, which is the least visible place a refusal
 * can land. So the button has to know beforehand, and it has to be careful
 * about what "does not know" means: a wrong refusal on this card is a feature
 * the operator cannot reach and is given no reason for.
 */

import { describe, expect, it } from "vitest";

import type { AdminerStatus } from "@/lib/databases-api";

import { adminerEnableBlocked } from "./databases";

/**
 * `db.adminer.status` as it arrives, with the PHP answer left out by default —
 * which is exactly what an agent older than this panel sends.
 */
const status = (
  over: Partial<AdminerStatus & { php_available?: boolean }> = {},
): AdminerStatus & { php_available?: boolean } => ({
  enabled: false,
  url: null,
  php_version: null,
  adminer_version: "6.0.1",
  pin_provenance: "single-source",
  ...over,
});

describe("whether Adminer can be enabled at all", () => {
  it("refuses the click the agent would refuse, before it is spent", () => {
    // The defect this exists for: on a fresh server the button was armed, the
    // click came back 202, and the task behind it refused with "no PHP version
    // is installed" where nothing on the page showed it. From the operator's
    // side the click worked and then nothing happened, over and over.
    expect(adminerEnableBlocked(status({ php_available: false }))).toBe(true);
  });

  it("stands out of the way once there is a PHP to run it on", () => {
    expect(adminerEnableBlocked(status({ php_available: true }))).toBe(false);
  });

  it("does not refuse on an agent older than this panel", () => {
    // The field is optional on the wire, and a missing field is not an agent
    // reporting no PHP. Reading it as one would disable Enable on a server
    // holding three versions and give no way to find out why — worse than the
    // defect, because the refusal it invents is not even true.
    expect(adminerEnableBlocked(status())).toBe(false);
  });

  it("says nothing before the status has been read", () => {
    // The button carries the query's own loading state; there is nothing to
    // refuse yet.
    expect(adminerEnableBlocked(undefined)).toBe(false);
  });

  it("never blocks turning Adminer off", () => {
    // The button is Disable while Adminer is enabled, and disabling removes a
    // vhost and a pool file — no interpreter required. A server whose PHP was
    // taken out from under a running Adminer is precisely the one that has to
    // be able to press it.
    expect(adminerEnableBlocked(status({ enabled: true, php_available: false }))).toBe(false);
  });
});
