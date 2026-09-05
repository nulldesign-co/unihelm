/**
 * Behaviour tests for the Node apps page's client-side checks (spec §11.10).
 *
 * The agent is the security boundary — it re-parses `TenantPath` and re-applies
 * the systemd rules whatever this file does. What is pinned here is that the
 * form's copy of those rules does not *disagree* with the server's: a path the
 * agent would refuse must not sail through the form and come back as a failed
 * task, and a perfectly ordinary entry file must not be blocked by a check the
 * server never made.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { en } from "@/i18n/en";
import type { AppView, StackComponentView } from "@/lib/api";

import { entryProblem, modeOf, modeUnavailable, offersVersion, unitState } from "./apps";

describe("the entry path check", () => {
  it("refuses the traversal payloads that never become a TenantPath", () => {
    for (const hostile of [
      "../../etc/passwd",
      "apps/../../etc/shadow",
      "/etc/passwd",
      "/home/other/apps/x.js",
      "..",
    ]) {
      expect(entryProblem(hostile), hostile).toBe(true);
    }
  });

  it("refuses what systemd would read as syntax in ExecStart", () => {
    // A space splits ExecStart into two arguments; `%` is a specifier expanded
    // before the line is used; a quote unbalances it. The agent refuses each of
    // these rather than escaping them, so the form has to as well.
    for (const hostile of [
      "apps/my blog/server.js",
      "apps/blog/%h.js",
      'apps/blog/"server".js',
      "apps/blog/serv'er.js",
      "apps/blog/$(id).js",
      "apps/blog/`id`.js",
      "apps/blog/back\\slash.js",
    ]) {
      expect(entryProblem(hostile), hostile).toBe(true);
    }
  });

  it("accepts the ordinary shapes a Node entry point actually has", () => {
    for (const fine of [
      "apps/blog/server.js",
      "apps/blog/dist/index.mjs",
      "server.js",
      "apps/my-blog/src/main.cjs",
      "apps/blog_2/server.js",
      "  apps/blog/server.js  ",
    ]) {
      expect(entryProblem(fine), fine).toBe(false);
    }
  });

  it("treats an empty path as a problem so the field is required either way", () => {
    expect(entryProblem("")).toBe(true);
    expect(entryProblem("   ")).toBe(true);
  });

  it("does not mistake a dotfile or a version for a traversal", () => {
    // `..` is only a traversal as a whole path segment; `.env.js` and
    // `v1..2` are not, and refusing them would be a check the agent never makes.
    expect(entryProblem("apps/blog/.hidden/server.js")).toBe(false);
    expect(entryProblem("apps/blog/server..js")).toBe(false);
  });
});

/**
 * How an app runs, as the page reads it.
 *
 * Two questions the page answers before the agent gets a chance to, and both
 * are wrong in a way nobody would notice from a screenshot: a row that says
 * "In a container" over a systemd unit sends an operator to `docker logs` for a
 * journal, and a Create button disabled because the catalogue has not answered
 * yet locks containers out of a server that has been running them for months.
 */
describe("where an application runs", () => {
  // Through `unknown` on purpose: one of the cases below is a mode this build
  // has never heard of, which is exactly what an agent newer than this panel
  // sends and what the type says cannot happen.
  const app = (mode?: string): AppView =>
    ({ ...(mode === undefined ? {} : { mode }) }) as unknown as AppView;

  it("reads an app with no mode at all as running on the host", () => {
    // Every app made before this field existed, and every app reported by an
    // agent older than this panel. They are systemd units, all of them.
    expect(modeOf(app())).toBe("host");
  });

  it("reads only the exact string as a container", () => {
    expect(modeOf(app("container"))).toBe("container");
    expect(modeOf(app("host"))).toBe("host");
    // A mode this build has never heard of is not a container: the row would
    // claim an isolation the app does not have.
    expect(modeOf(app("podman"))).toBe("host");
  });

  const component = (over: Partial<StackComponentView>): StackComponentView =>
    ({ component: "docker", status: "installed", ...over }) as StackComponentView;

  it("blocks a container when the server has no container runtime", () => {
    expect(modeUnavailable("container", [])).toBe(true);
    expect(modeUnavailable("container", [component({ status: "absent" })])).toBe(true);
    expect(modeUnavailable("container", [component({ component: "nginx" })])).toBe(true);
  });

  it("counts a Docker somebody installed by hand", () => {
    expect(modeUnavailable("container", [component({ status: "unmanaged" })])).toBe(false);
    expect(modeUnavailable("container", [component({ status: "installed" })])).toBe(false);
  });

  it("never blocks the host, which needs nothing installed to run", () => {
    expect(modeUnavailable("host", [])).toBe(false);
    expect(modeUnavailable("host", undefined)).toBe(false);
  });

  it("lets the click through while the catalogue is still unknown", () => {
    // An unanswered query is not the same answer as "no Docker". Reading it as
    // one disables Create on a machine that would have taken the app.
    expect(modeUnavailable("container", undefined)).toBe(false);
  });
});

/**
 * The state badge, which is the one thing on a row worth looking at twice.
 *
 * A container has more ways to be not-running than systemd does, and the row
 * renders `state` straight into a colour table and a translation key. The
 * failure this pins is the quiet one: a container that exited on its first
 * second must not come back as a badge that says anything but "not running",
 * and must never come back as a raw `service.exited` on a customer's screen.
 */
describe("naming a unit state", () => {
  it("passes through every state this build knows", () => {
    for (const known of [
      "active",
      "inactive",
      "failed",
      "activating",
      "deactivating",
      "not_found",
      "unknown",
    ] as const) {
      expect(unitState(known), known).toBe(known);
    }
  });

  it("does not claim a state it cannot name is running", () => {
    // What `docker inspect` says about a container that died immediately. None
    // of these is a UnitState, and every one of them means "not running".
    for (const containerish of ["exited", "created", "restarting", "dead", "paused", ""]) {
      expect(unitState(containerish), containerish).toBe("unknown");
    }
  });

  it("does not mistake a prototype member for a state", () => {
    // `state in TONE` would wave these through, and `t("service.constructor")`
    // is a raw key rendered at whoever is reading the page.
    for (const inherited of ["constructor", "toString", "hasOwnProperty", "__proto__"]) {
      expect(unitState(inherited), inherited).toBe("unknown");
    }
  });
});

/**
 * Whether the change dialog offers a version to pin.
 *
 * The version list this page has is `runtime.list` — the interpreters installed
 * on this server. For a container app that list is wrong twice: pinning one of
 * its entries points an image-built app at a host install, and on a Docker-only
 * machine it is empty, so the dialog tells somebody to install a runtime on a
 * live host to fix an app that needs nothing installed there. That advice is
 * the shape of an outage this project has already had.
 */
describe("offering a version to pin", () => {
  it("offers one for an interpreted app on the host", () => {
    for (const runtime of ["node", "python", "ruby", "bun", "deno"] as const) {
      expect(offersVersion("host", runtime), runtime).toBe(true);
    }
  });

  it("offers none for Go, which has no interpreter to point at", () => {
    expect(offersVersion("host", "go")).toBe(false);
  });

  it("offers none in a container, whatever the language", () => {
    for (const runtime of ["node", "python", "ruby", "bun", "deno", "go"] as const) {
      expect(offersVersion("container", runtime), runtime).toBe(false);
    }
  });
});

/**
 * Every translation key this page asks for, resolved against the bundle.
 *
 * `t("apps.modeHint.container")` is just a string: a key that was never added
 * ships as the raw key rendered on screen, and this page now builds eight
 * families of them from a template literal where no typo is visible. The
 * i18n coverage test next door is scoped to two other pages on purpose — "not
 * a trap for the next page somebody adds" — so the claim is made here, beside
 * the page that makes it.
 */
describe("translation coverage for the apps page", () => {
  const source = readFileSync(fileURLToPath(new URL("./apps.tsx", import.meta.url)), "utf8");

  function lookup(key: string): unknown {
    return key
      .split(".")
      .reduce<unknown>(
        (node, part) =>
          typeof node === "object" && node !== null
            ? (node as Record<string, unknown>)[part]
            : undefined,
        en,
      );
  }

  it("resolves every literal key the page asks for", () => {
    const keys = [...source.matchAll(/\bt\(\s*"([^"]+)"/g)].map((m) => m[1]!);
    // A page that suddenly asks for nothing means the scan broke, not that the
    // page stopped needing translations.
    expect(keys.length).toBeGreaterThan(20);
    for (const key of keys) {
      expect(typeof lookup(key), `en: ${key}`).toBe("string");
    }
  });

  it("resolves the keys built from a template literal, which no scan can see", () => {
    const families = [
      // `service.${state}` — every state `unitState` can return.
      ...["active", "inactive", "failed", "activating", "deactivating", "not_found", "unknown"].map(
        (s) => `service.${s}`,
      ),
      // `apps.envName.${node_env}`
      ...["production", "development", "test"].map((e) => `apps.envName.${e}`),
      // Everything keyed by mode. Both arms of each, because the page renders
      // whichever one the app happens to be.
      ...[
        "modeName",
        "modeHint",
        "modeStays",
        "deleteHint",
        "logsHint",
        "logsEmpty",
        "changeRuntimeRestart",
      ].flatMap((family) => [`apps.${family}.container`, `apps.${family}.host`]),
    ];
    for (const key of families) {
      expect(typeof lookup(key), `en: ${key}`).toBe("string");
    }
  });
});
