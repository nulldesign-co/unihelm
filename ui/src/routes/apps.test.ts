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

import { describe, expect, it } from "vitest";

import { entryProblem } from "./apps";

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
