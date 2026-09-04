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

import { defaultVersionFor, groupByCategory, planFor } from "./stack";

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
  versions: [
    version({ version: "8.5" }),
    version({ version: "8.4" }),
    version({ version: "8.3", recommended: true }),
    version({ version: "8.2", eol: true }),
    version({ version: "7.4", eol: true }),
  ],
};

/** MariaDB as the catalogue has it: one port, one data directory, one version. */
const mariadb: CatalogueEntry = {
  slug: "mariadb",
  display_name: "MariaDB",
  category: "database",
  summary: "The default engine.",
  side_by_side: false,
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
    ...over,
  };
};

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
// Translation coverage
// ---------------------------------------------------------------------------

/** Every key the page can build from a template literal, spelled out. */
const DYNAMIC_KEYS = [
  ...["web_server", "language", "database", "cache", "container"].flatMap((category) => [
    `stack.category.${category}`,
    `stack.categoryHint.${category}`,
  ]),
  ...["distro", "vendor"].map((source) => `stack.source.${source}`),
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
