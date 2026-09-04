/**
 * What the Stack page decides before it talks to the agent (spec §11.1).
 *
 * The agent is the boundary — it looks every slug and version up in the
 * catalogue and refuses anything else. What is pinned here is the part of the
 * page the agent cannot protect the operator from: whether a click reads as
 * "add a version" or "take the running database out and put a different one in",
 * and whether an end-of-life version can end up under the button without anyone
 * choosing it.
 *
 * The last block is a different kind of guard. Every string on this page is a
 * `t("...")` lookup, so a key that does not exist ships as the raw key rendered
 * on screen — twice in one week, at the time of writing. This resolves every key
 * the page can ask for, including the families built from template literals that
 * no static scan can see.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import type { CatalogueEntry, CatalogueVersion, StackComponentView } from "@/lib/api";

import { en } from "../i18n/en";

import {
  defaultRuntimeFor,
  defaultVersionFor,
  groupByCategory,
  hostHoldsEntry,
  planFor,
  runtimeOf,
  sideBySideIn,
  supportFor,
} from "./stack";

const version = (over: Partial<CatalogueVersion> & { version: string }): CatalogueVersion => ({
  note: "",
  source: "vendor",
  eol: false,
  recommended: false,
  ...over,
});

/** PHP as the catalogue has it: many versions, all at once. */
const php: CatalogueEntry = {
  slug: "php",
  display_name: "PHP",
  category: "language",
  summary: "Versions run side by side; each site picks its own.",
  side_by_side: true,
  // Host packages, until the FPM step lands: uid mapping and the shared socket
  // directory are what containerising PHP needs and neither exists yet.
  install: { runtimes: ["host"], default_runtime: "host" },
  versions: [
    version({ version: "8.5" }),
    version({ version: "8.4" }),
    version({ version: "8.3", recommended: true }),
    version({ version: "8.2", eol: true }),
    version({ version: "7.4", eol: true }),
  ],
};

/**
 * MariaDB as the catalogue has it.
 *
 * On the host: one port, one data directory, one version. As containers: a
 * version each, side by side, which is the whole reason the mode is a choice.
 * The catalogue prefers the container, so a fresh machine gets the shape the
 * design settled on without anybody going looking for it.
 */
const mariadb: CatalogueEntry = {
  slug: "mariadb",
  display_name: "MariaDB",
  category: "database",
  summary: "The default engine.",
  side_by_side: false,
  install: { runtimes: ["host", "container"], default_runtime: "container" },
  versions: [
    version({ version: "11.8", recommended: true, note: "long-term support" }),
    version({ version: "11.4", note: "long-term support" }),
    version({ version: "10.11" }),
  ],
};

const nginx: CatalogueEntry = {
  slug: "nginx",
  display_name: "Nginx",
  category: "web_server",
  summary: "The web server Unihelm renders vhosts for.",
  side_by_side: false,
  // Stays on the host: it terminates TLS, reads the certificates the panel
  // renews and serves files out of tenant homes.
  install: { runtimes: ["host"], default_runtime: "host" },
  versions: [version({ version: "stable", recommended: true })],
};

/** The row every container-backed install depends on. */
const docker: CatalogueEntry = {
  slug: "docker",
  display_name: "Docker",
  category: "container",
  summary: "The container runtime.",
  side_by_side: false,
  install: { runtimes: ["host"], default_runtime: "host" },
  versions: [version({ version: "stable", recommended: true })],
};

/**
 * One row as `stack.status` sends it.
 *
 * `slug` is the agent's own row key and is versioned only where several
 * versions coexist — `php8.3` but plain `mariadb`. It is built here rather than
 * passed in, so no fixture can quietly agree with a page that groups on the
 * wrong field.
 */
const row = (
  over: Partial<StackComponentView> & { component: string; version: string },
): StackComponentView => {
  const sideBySide = over.component === "php" || over.component === "node";
  return {
    slug: sideBySide ? `${over.component}${over.version}` : over.component,
    display_name: over.component,
    category: "language",
    status: "installed",
    installed_version: null,
    last_error: null,
    unit_state: "active",
    unit_active: true,
    // Host unless a case says otherwise, which is what every row on every
    // machine that has ever run this panel is.
    runtime: "host",
    ...over,
  };
};

/** Docker on the machine, so a container-backed install has somewhere to go. */
const dockerInstalled = row({ component: "docker", version: "stable" });

describe("grouping the catalogue", () => {
  it("keeps the server's order and does not invent a category list of its own", () => {
    // A category this build has never heard of still has to get a heading in the
    // place the catalogue put it, rather than being filtered out by a hard-coded
    // list — that filtering is what made the old page a second, staler copy of
    // the catalogue.
    const groups = groupByCategory([
      nginx,
      php,
      mariadb,
      { ...php, slug: "node", display_name: "Node.js" },
      { ...nginx, slug: "quantum", category: "quantum" as CatalogueEntry["category"] },
    ]);
    expect(groups.map((g) => g.category)).toEqual([
      "web_server",
      "language",
      "database",
      "quantum",
    ]);
    expect(groups[1]!.entries.map((e) => e.slug)).toEqual(["php", "node"]);
  });
});

describe("which version the chooser opens on", () => {
  it("opens a one-at-a-time engine on the version it already has", () => {
    // Anything else arms the Replace path the moment the page loads, on a row
    // the operator was only reading.
    const rows = [row({ component: "mariadb", version: "11.8", installed_version: "11.8.2" })];
    expect(defaultVersionFor(mariadb, rows)).toBe("11.8");
  });

  it("opens a side-by-side runtime on the best version it does not have", () => {
    // The recommended one is already here, so the menu moves on to the newest
    // supported version that is not — the catalogue is newest-first — rather
    // than sitting on a choice whose Install button does nothing.
    const rows = [row({ component: "php", version: "8.3", installed_version: "8.3.14" })];
    expect(defaultVersionFor(php, rows)).toBe("8.5");
  });

  it("never opens on an end-of-life version, even when nothing else is left", () => {
    // 7.4 is on the menu because somebody migrating an old application needs it.
    // It is not what the button is pointing at while they read the summary.
    const rows = ["8.5", "8.4", "8.3"].map((v) => row({ component: "php", version: v }));
    expect(defaultVersionFor(php, rows)).toBe("8.3");
  });

  it("recommends the recommended version on an empty machine", () => {
    expect(defaultVersionFor(php, [])).toBe("8.3");
    expect(defaultVersionFor(mariadb, [])).toBe("11.8");
  });
});

describe("what a row offers", () => {
  it("offers neither install nor remove for something the panel did not install", () => {
    // Install would add a vendor repository over a running nginx and replace a
    // configuration that is serving sites; Remove would stop it serving at all.
    const rows = [row({ component: "nginx", status: "unmanaged", version: "stable" })];
    const plan = planFor(nginx, rows, "stable");
    expect(plan.unmanaged).toBe(true);
    expect(plan.action).toBe("none");
    expect(plan.replaces).toBeNull();
    // The chip for that row must not carry a Remove either.
    expect(plan.rows.every((r) => r.status !== "installed")).toBe(true);
  });

  it("calls a different version of a one-at-a-time engine a replacement, and names what goes", () => {
    const rows = [row({ component: "mariadb", version: "11.8", installed_version: "11.8.2" })];
    const plan = planFor(mariadb, rows, "11.4");
    expect(plan.action).toBe("replace");
    expect(plan.replaces).toBe("11.8");
  });

  it("calls a second version of a side-by-side runtime an ordinary install", () => {
    const rows = [row({ component: "php", version: "8.3" })];
    const plan = planFor(php, rows, "7.4");
    expect(plan.action).toBe("install");
    expect(plan.replaces).toBeNull();
  });

  it("does not offer to install a version that is already there", () => {
    const rows = [row({ component: "php", version: "8.3" })];
    expect(planFor(php, rows, "8.3").action).toBe("held");
    expect(planFor(php, rows, "8.3").offered.map((v) => v.version)).toEqual([
      "8.5",
      "8.4",
      "8.2",
      "7.4",
    ]);
  });

  it("offers a second go at the version that failed, and only that one", () => {
    const rows = [row({ component: "php", status: "failed", version: "8.4", last_error: "404" })];
    expect(planFor(php, rows, "8.4").action).toBe("retry");
    expect(planFor(php, rows, "8.5").action).toBe("install");
  });

  it("treats a version being removed as still present, so nothing offers to install over it", () => {
    const rows = [row({ component: "mariadb", status: "removing", version: "11.8" })];
    const plan = planFor(mariadb, rows, "11.8");
    expect(plan.working).toBe(true);
    expect(plan.action).toBe("held");
  });

  it("ignores rows belonging to another entry", () => {
    const rows = [
      row({ component: "php", version: "8.3" }),
      row({ component: "mariadb", version: "11.8" }),
    ];
    expect(planFor(php, rows, "8.4").replaces).toBeNull();
    expect(planFor(php, rows, "8.4").rows.map((r) => r.slug)).toEqual(["php8.3"]);
  });

  it("finds a side-by-side runtime's rows even though the agent keys them `php8.3`", () => {
    // The row key in `stack_components` carries the version where versions
    // coexist, so it is not the catalogue slug and never matches one. A page
    // that groups on `slug` finds nothing for PHP, prints "Not installed" over a
    // machine serving sites, and arms Install — which is how installing PHP from
    // the panel took a production site down once already.
    const rows = [row({ component: "php", version: "8.3" })];
    expect(rows[0]!.slug).toBe("php8.3");
    expect(planFor(php, rows, "8.5").rows).toHaveLength(1);
    expect(planFor(php, rows, "8.3").action).toBe("held");
  });

  it("drops the absent rows the agent sends for everything it could install", () => {
    // `stack.status` emits a row per catalogue entry whether or not it is on the
    // machine. An absent row counted as present would put a Remove button on
    // something that was never installed.
    const rows = [
      row({ component: "php", status: "absent", version: "8.5" }),
      row({ component: "php", version: "8.3" }),
    ];
    const plan = planFor(php, rows, "8.5");
    expect(plan.rows.map((r) => r.version)).toEqual(["8.3"]);
    expect(plan.action).toBe("install");
  });
});

// ---------------------------------------------------------------------------
// Host packages or a container
// ---------------------------------------------------------------------------

describe("where an install goes", () => {
  it("reads a row from an older agent as host packages, not as a container", () => {
    // An agent that predates this sends no `runtime` at all. Reading the gap as
    // "container" would put a Remove beside an apt package and send the agent
    // off to delete a container that never existed.
    // No cast: `runtime` is optional on the wire type precisely because rows
    // written before the field existed are still in the table. A cast here
    // would let that stop being true without a test noticing.
    const { runtime: _absent, ...legacy } = row({ component: "mariadb", version: "11.8" });
    expect(runtimeOf(legacy)).toBe("host");
  });

  it("reads an entry with no install block as host-only, so no mode menu appears", () => {
    // Same skew, the other direction: an older agent's catalogue says nothing
    // about where things run, and everything it can install runs on the host.
    // A menu drawn on that guess offers a mode the agent will refuse.
    const { install: _absent, ...legacy } = nginx;
    expect(supportFor(legacy as CatalogueEntry)).toBe("host");
    expect(supportFor(mariadb)).toBe("either");
    expect(supportFor({ ...mariadb, install: { runtimes: ["container"], default_runtime: "container" } })).toBe("container");
  });

  it("opens on the mode of what is already installed, not on the catalogue's preference", () => {
    // The catalogue prefers containers for MariaDB. This server has one on the
    // host, and a row that loads pointing at "container" is proposing a
    // migration the operator did not ask for and may not notice they accepted.
    const rows = [row({ component: "mariadb", version: "11.8" })];
    expect(defaultRuntimeFor(mariadb, rows)).toBe("host");
  });

  it("opens on the catalogue's preference when nothing is installed", () => {
    expect(defaultRuntimeFor(mariadb, [])).toBe("container");
  });

  it("never opens on a mode the entry does not offer", () => {
    expect(defaultRuntimeFor(nginx, [])).toBe("host");
    // Even against a catalogue that contradicts itself: what may be chosen
    // wins over what is preferred, because only the first is installable.
    const containerOnly: CatalogueEntry = {
      ...mariadb,
      install: { runtimes: ["container"], default_runtime: "host" },
    };
    expect(defaultRuntimeFor(containerOnly, [])).toBe("container");
  });

  it("stops calling a second version a replacement once it is a container", () => {
    // The point of the whole change. On the host these two want one port and
    // one data directory, so the first goes to make room for the second. As
    // containers they do not, and telling an operator their running database is
    // about to be replaced when it is not is how a migration gets postponed for
    // no reason.
    const rows = [dockerInstalled, row({ component: "mariadb", version: "11.8", runtime: "container" })];
    const asContainer = planFor(mariadb, rows, "11.4", "container");
    expect(asContainer.action).toBe("install");
    expect(asContainer.replaces).toBeNull();

    // Same entry, same two versions, on the host: still a replacement.
    const onHost = [row({ component: "mariadb", version: "11.8" })];
    expect(planFor(mariadb, onHost, "11.4", "host").action).toBe("replace");
    expect(sideBySideIn(mariadb, "host")).toBe(false);
    expect(sideBySideIn(mariadb, "container")).toBe(true);
  });

  it("does not offer to remove a host install by putting a container beside it", () => {
    // Presence is an answer about one mode. A host MariaDB is not what a new
    // container replaces — it keeps its port, its data directory and its
    // packages — so nothing here may name it as the version that goes.
    const rows = [dockerInstalled, row({ component: "mariadb", version: "11.8" })];
    const plan = planFor(mariadb, rows, "11.4", "container");
    expect(plan.replaces).toBeNull();
    // The host row is still on the page: the operator has to see everything
    // that is installed, whichever mode the chooser is on.
    expect(plan.rows.map((r) => r.version)).toEqual(["11.8"]);
  });

  it("does not offer a container the agent will refuse because the host holds the engine", () => {
    // The agent refuses this outright: a host MariaDB and a container MariaDB
    // give `db.create` two engines to pick between, and the wrong pick writes a
    // tenant's data where nothing will look for it again. The page draws the
    // button, so the page has to know — otherwise the operator picks the mode
    // the design recommends, presses a live Install and gets a red task
    // explaining a rule the row could have stated first.
    const rows = [dockerInstalled, row({ component: "mariadb", version: "11.8" })];
    expect(planFor(mariadb, rows, "11.4", "container").hostIncumbent).toBe(true);
    // Not on the host path — that is a replacement, which the row already says.
    expect(planFor(mariadb, rows, "11.4", "host").hostIncumbent).toBe(false);
  });

  it("counts only the host copies the agent itself counts", () => {
    // The agent's test is `status == Installed`. A copy somebody else put there
    // is not that — and blocking on one would refuse the container over a row
    // the panel also refuses to remove, which is a dead end with no way out.
    expect(hostHoldsEntry([row({ component: "mariadb", version: "11.8" })])).toBe(true);
    expect(
      hostHoldsEntry([row({ component: "mariadb", status: "unmanaged", version: "11.8" })]),
    ).toBe(false);
    expect(
      hostHoldsEntry([row({ component: "mariadb", status: "failed", version: "11.8" })]),
    ).toBe(false);
    // Nor is a container the panel already runs: reinstalling one is idempotent
    // and must not be refused as though it were a second engine.
    expect(
      hostHoldsEntry([row({ component: "mariadb", version: "11.8", runtime: "container" })]),
    ).toBe(false);
  });

  it("chooses the opening version per mode", () => {
    // 11.4 is a container already, so the container menu moves past it to the
    // recommended version. The host has nothing, so it opens on the recommended
    // one too — and the deliberately unrecommended container version is what
    // makes that second assertion mean something: a shared answer would open
    // the host menu on 11.4, the version the host does not have.
    const rows = [row({ component: "mariadb", version: "11.4", runtime: "container" })];
    expect(defaultVersionFor(mariadb, rows, "container")).toBe("11.8");
    expect(defaultVersionFor(mariadb, rows, "host")).toBe("11.8");
  });

  it("does not call the host install of a containerised version 'already installed'", () => {
    // The mode-scoped half of the same rule, and the one that decides whether a
    // button is disabled. 11.8 is on this machine as a container; the host has
    // nothing. A row reading the container as presence puts "Installed" on the
    // button, greys it out, and leaves an operator who wants the engine in
    // packages with no way to say so and no reason given.
    const rows = [dockerInstalled, row({ component: "mariadb", version: "11.8", runtime: "container" })];
    expect(planFor(mariadb, rows, "11.8", "host").action).toBe("install");
    expect(planFor(mariadb, rows, "11.8", "container").action).toBe("held");
  });

  it("does not tell the host there is nothing left to install because containers hold it all", () => {
    // "Every version this panel offers is already installed" is drawn from
    // `offered`, and it is a sentence about one mode. Every version being a
    // container says nothing about the host, and printing it there strands the
    // operator on a row with no chooser and no button.
    const rows = [
      dockerInstalled,
      ...mariadb.versions.map((v) =>
        row({ component: "mariadb", version: v.version, runtime: "container" }),
      ),
    ];
    expect(planFor(mariadb, rows, "11.8", "container").offered).toEqual([]);
    expect(planFor(mariadb, rows, "11.8", "host").offered).toHaveLength(mariadb.versions.length);
  });

  it("does not read a failed host install as a failed container one", () => {
    // The retry button is "go again at the thing that broke". A container
    // install that has never run is an install, and offering Retry for it
    // suggests the panel knows something about it that it does not.
    const rows = [
      dockerInstalled,
      row({ component: "mariadb", status: "failed", version: "11.4", last_error: "404" }),
    ];
    expect(planFor(mariadb, rows, "11.4", "host").action).toBe("retry");
    expect(planFor(mariadb, rows, "11.4", "container").action).toBe("install");
  });

  it("refuses a container install on a server with no Docker, and only that mode", () => {
    // Nothing can run as a container until the runtime is there. Letting the
    // click through gets a failed task and a red row; saying so on the row that
    // makes the choice gets Docker installed.
    const plan = planFor(mariadb, [], "11.8", "container");
    expect(plan.dockerMissing).toBe(true);
    expect(planFor(mariadb, [], "11.8", "host").dockerMissing).toBe(false);
  });

  it("counts Docker installed outside the panel", () => {
    // The panel already drives containers it did not create. Refusing this one
    // because a different tool ran the install would be a rule with no reason.
    const byHand = [row({ component: "docker", status: "unmanaged", version: "stable" })];
    expect(planFor(mariadb, byHand, "11.8", "container").dockerMissing).toBe(false);
    expect(planFor(mariadb, [dockerInstalled], "11.8", "container").dockerMissing).toBe(false);
  });

  it("does not report Docker missing on a row that offers no choice at all", () => {
    // An unmanaged row carries neither chooser nor button, so nothing on it is
    // waiting on Docker. The entry has to be one that *could* have gone into a
    // container for this to test anything: on nginx the mode is host whatever
    // the branch does, and the assertion would pass with the rule deleted.
    const byHand = [row({ component: "mariadb", status: "unmanaged", version: "11.8" })];
    expect(planFor(mariadb, byHand, "11.8").runtime).toBe("container");
    expect(planFor(mariadb, byHand, "11.8").dockerMissing).toBe(false);
    // And the same row on an entry that has nowhere else to run.
    const nginxByHand = [row({ component: "nginx", status: "unmanaged", version: "stable" })];
    expect(planFor(nginx, nginxByHand, "stable").dockerMissing).toBe(false);
  });

  it("keeps Docker's own row on the host, so it cannot wait on itself", () => {
    const plan = planFor(docker, [], "stable");
    expect(plan.runtime).toBe("host");
    expect(plan.support).toBe("host");
    expect(plan.dockerMissing).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Translation coverage
// ---------------------------------------------------------------------------

/** Every key the page can build from a template literal, spelled out. */
const DYNAMIC_KEYS = [
  ...["web_server", "language", "database", "cache", "container"].flatMap((category) => [
    `stack.category.${category}`,
    `stack.categoryHint.${category}`,
  ]),
  ...["distro", "vendor"].map((source) => `stack.source.${source}`),
  ...["host", "container"].map((runtime) => `stack.runtime.${runtime}`),
  ...["absent", "unmanaged", "installing", "installed", "failed", "removing"].map(
    (state) => `stack.state.${state}`,
  ),
];

function lookup(bundle: unknown, key: string): unknown {
  return key
    .split(".")
    .reduce<unknown>(
      (node, part) =>
        typeof node === "object" && node !== null
          ? (node as Record<string, unknown>)[part]
          : undefined,
      bundle,
    );
}

describe("translation coverage for the stack page", () => {
  const source = readFileSync(fileURLToPath(new URL("./stack.tsx", import.meta.url)), "utf8");

  it("resolves every key the page names outright", () => {
    // Every `"stack.…"` and `"common.…"` literal in the file, not only the ones
    // written directly inside `t(` — half of this page's keys are chosen by a
    // ternary and passed in as an argument.
    const keys = [...source.matchAll(/"((?:stack|common)\.[A-Za-z0-9_.]+)"/g)].map((m) => m[1]!);
    // A page that suddenly asks for nothing means the scan broke, not that the
    // page stopped needing translations.
    expect(keys.length).toBeGreaterThan(15);
    for (const key of keys) {
      expect(typeof lookup(en, key), `en: ${key}`).toBe("string");
    }
  });

  it("resolves the key families built from the catalogue's own values", () => {
    for (const key of DYNAMIC_KEYS) {
      expect(typeof lookup(en, key), `en: ${key}`).toBe("string");
    }
  });
});
