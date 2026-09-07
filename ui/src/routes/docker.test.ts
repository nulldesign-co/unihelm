/**
 * The containers table's column geometry.
 *
 * Which pixel a column lands on is CSS and not testable here; what is testable
 * is the class list the page composes, and that is where the bug was. The first
 * body cell asked for `w-full` while Container and Image were the only headers
 * without a width, so the name column took every spare pixel and Image was left
 * with the remainder — and with `break-all` on that cell, "the remainder" was a
 * repository name broken mid-token down a column a few characters wide. Ports
 * was shredded the same way.
 *
 * The arithmetic below is the part that would not have been caught by looking:
 * a table is only allowed to scroll once it is too narrow for its columns, so a
 * `min-w` smaller than the widths add up to does not scroll — auto layout
 * answers the shortfall by shrinking columns instead, which is the original
 * defect wearing different numbers. The first attempt at this fix declared
 * 1072px of columns behind a 1040px `min-w` and put the ports column back to
 * 388px at every other column's expense.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const source = readFileSync(fileURLToPath(new URL("./docker.tsx", import.meta.url)), "utf8");

/** The body of a named function in the page, so an assertion can be scoped. */
function functionBody(name: string): string {
  const start = source.indexOf(`function ${name}(`);
  expect(start, `${name} is no longer declared — this scan is reading nothing`).toBeGreaterThan(-1);
  const end = source.indexOf("\nfunction ", start + 1);
  return source.slice(start, end === -1 ? undefined : end);
}

/** Tailwind's spacing scale is quarter-rem, so `w-56` is 224 CSS pixels. */
function widthPx(token: string): number {
  const bracketed = /^w-\[(\d+)px\]$/.exec(token);
  if (bracketed) return Number(bracketed[1]);
  const step = /^w-(\d+)$/.exec(token);
  return step ? Number(step[1]) * 4 : Number.NaN;
}

/** Every `min-w-[Npx]` the containers table and its loading ghost declare. */
function containerTableMinWidths(): number[] {
  return [...source.matchAll(/<Table className="min-w-\[(\d+)px\]">\s*\n\s*<ContainerHead \/>/g)].map(
    (m) => Number(m[1]),
  );
}

describe("the containers table's columns", () => {
  it("gives every header an explicit width, so no column is left to take the remainder", () => {
    const head = functionBody("ContainerHead");
    const headers = [...head.matchAll(/<Th className="([^"]*)"/g)].map((m) => m[1]!);
    const bare = [...head.matchAll(/<Th>/g)];

    expect(headers.length, "five columns, five widths").toBe(5);
    expect(bare.length, "a header with no className has no width either").toBe(0);
    for (const className of headers) {
      const width = className.split(" ").map(widthPx).find(Number.isFinite);
      expect(width, `no width in "${className}"`).toBeGreaterThan(0);
    }
  });

  it("never lets the first body cell claim the row, which is what starved Image", () => {
    const section = functionBody("ContainerSection");
    expect(section).not.toContain('<Td className="w-full"');
  });

  it("scrolls the card rather than shrinking the columns when the space runs out", () => {
    const head = functionBody("ContainerHead");
    const declared = [...head.matchAll(/<Th className="([^"]*)"/g)]
      .map((m) => m[1]!.split(" ").map(widthPx).find(Number.isFinite) ?? 0)
      .reduce((sum, w) => sum + w, 0);

    const minWidths = containerTableMinWidths();
    // The real table and the ghost that stands in for it while it loads, which
    // must agree or the rows land at a different width than they were drawn at.
    expect(minWidths.length, "the real table and its skeleton").toBe(2);
    expect(new Set(minWidths).size, `ghost and table disagree: ${minWidths.join(" vs ")}`).toBe(1);
    expect(minWidths[0], `columns add up to ${declared}px`).toBeGreaterThanOrEqual(declared);
  });

  it("breaks an image name between its parts and never breaks a port mapping", () => {
    const section = functionBody("ContainerSection");
    const image = /<Td className="([^"]*)">\{row\.image\}<\/Td>/.exec(section)?.[1] ?? "";
    // `break-all` cuts `ghcr.io/owner/app:v1` at whatever character the column
    // ends on; `break-words` leaves the name setting its own minimum width.
    expect(image.split(" ")).toContain("break-words");
    expect(image.split(" ")).not.toContain("break-all");

    // A mapping is one fact — host, port, direction, target, protocol — and a
    // wrap between the arrow and its target is how "published on every
    // interface" gets read as "published on localhost".
    const ports = /<Td className="([^"]*)">\s*\n\s*\{row\.ports\.trim\(\)/.exec(section)?.[1] ?? "";
    expect(ports.split(" ")).toContain("whitespace-nowrap");
    expect(ports.split(" ")).not.toContain("break-all");
  });
});
