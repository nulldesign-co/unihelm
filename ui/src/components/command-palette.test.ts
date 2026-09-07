/**
 * Behaviour tests for what ⌘K can find (spec §4.2).
 *
 * The palette used to be a substring match over sixteen nav labels, so the only
 * way to reach a page was to already know what it was called. "restore" — typed
 * by somebody whose site is down — matched nothing, because the page is called
 * Backups. Neither did "ssl", "certificate" or "php". What is pinned here is
 * that the words an operator actually types lead somewhere, that a query which
 * genuinely matches nothing still says so, and that the best answer is the row
 * Enter runs.
 */

import { describe, expect, it } from "vitest";

import { scoreCommand, searchCommands, type Command } from "./command-palette";

const noop = () => {};

const COMMANDS: Command[] = [
  { id: "dashboard", label: "Dashboard", keywords: ["home", "overview", "cpu"], run: noop },
  {
    id: "sites",
    label: "Sites",
    group: "Hosting",
    keywords: ["domain", "ssl", "tls", "certificate", "https"],
    run: noop,
  },
  {
    id: "databases",
    label: "Databases",
    group: "Hosting",
    keywords: ["db", "mysql", "mariadb", "postgres"],
    run: noop,
  },
  {
    id: "backups",
    label: "Backups",
    group: "Operations",
    keywords: ["restore", "snapshot", "restic"],
    run: noop,
  },
  {
    id: "stack",
    label: "Stack",
    group: "Operations",
    keywords: ["php", "nginx", "redis", "versions"],
    run: noop,
  },
  { id: "branding", label: "Branding", group: "Administration", keywords: ["logo"], run: noop },
];

/** The commands a query returns, flattened into the order they render in. */
function found(query: string): string[] {
  return searchCommands(COMMANDS, query).flatMap((group) => group.commands.map((c) => c.id));
}

describe("searching the palette", () => {
  it("finds a page by a word the operator would type for it, not only by its name", () => {
    // Every one of these returned nothing when the match was a substring of the
    // label — and each is a page somebody reaches for under pressure.
    expect(found("restore")).toContain("backups");
    expect(found("ssl")).toContain("sites");
    expect(found("certificate")).toContain("sites");
    expect(found("php")).toContain("stack");
    expect(found("db")).toContain("databases");
    expect(found("mysql")).toContain("databases");
  });

  it("still finds a page by its own label, the way it always did", () => {
    expect(found("backup")).toContain("backups");
    expect(found("Databases")).toContain("databases");
  });

  it("tolerates a few letters left out or typed out of order", () => {
    // "dbse" is Databases with letters missing; "backup restore" is two words
    // in the order they occur to somebody, not the order we wrote them in.
    expect(found("dbse")).toContain("databases");
    expect(found("restore backup")).toContain("backups");
    expect(found("backup restore")).toContain("backups");
  });

  it("puts the strongest match first, because Enter runs the first row", () => {
    expect(found("backups")[0]).toBe("backups");
    expect(found("restore")[0]).toBe("backups");
    expect(found("ssl")[0]).toBe("sites");
  });

  it("requires every word to land somewhere, so a nonsense query says nothing", () => {
    // A palette that answers everything is as useless as one that answers
    // nothing: "no results" is information.
    expect(found("zzzzz")).toEqual([]);
    expect(found("backup docker")).toEqual([]);
    expect(scoreCommand(COMMANDS[0]!, "zzzzz")).toBe(0);
  });

  it("does not let two letters scatter-match half the menu", () => {
    // "d" then "b" occur in that order in "Branding" and in "Dashboard". A
    // two-letter query that returned both would bury the answer it has.
    expect(found("db")).not.toContain("branding");
    expect(found("db")).not.toContain("dashboard");
  });

  it("shows everything, in the order it was given, when nothing is typed", () => {
    expect(found("")).toEqual(COMMANDS.map((command) => command.id));
    expect(found("   ")).toEqual(COMMANDS.map((command) => command.id));
  });
});

describe("the group headings", () => {
  it("gathers results under the heading each command belongs to", () => {
    const groups = searchCommands(COMMANDS, "");
    expect(groups.map((group) => group.label)).toEqual([
      null,
      "Hosting",
      "Operations",
      "Administration",
    ]);
  });

  it("leads with the group holding the best match, and never splits a group", () => {
    // "restore" is a Backups keyword; Operations therefore comes first, and
    // Stack — which matches nothing here — is simply absent rather than left
    // behind under a second "Operations" heading further down.
    const groups = searchCommands(COMMANDS, "restore");
    expect(groups[0]?.label).toBe("Operations");
    expect(groups.filter((group) => group.label === "Operations")).toHaveLength(1);
  });

  it("keeps the flattened order identical to the rendered order", () => {
    // The arrow keys walk a flat list while the eye reads grouped rows; if the
    // two disagree, Enter runs a command the operator is not looking at.
    const groups = searchCommands(COMMANDS, "s");
    const flat = groups.flatMap((group) => group.commands);
    expect(new Set(flat).size).toBe(flat.length);
    expect(flat.length).toBe(groups.reduce((n, group) => n + group.commands.length, 0));
  });
});
