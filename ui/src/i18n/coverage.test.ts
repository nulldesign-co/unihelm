/**
 * Translation coverage for the databases, plans and Docker pages (spec §4.2).
 *
 * `t("plans.reasonProblem.control")` is just a string, so a typo or a renamed
 * key ships as the raw key rendered on screen. This reads the pages back and
 * resolves every key they ask for.
 *
 * Docker joined the list after that shipped: the page asked for eight keys the
 * bundle did not have, so a stopped container's only button read `docker.start`
 * and a failed action printed `docker.actionFailed` in place of what the server
 * had said. Nothing caught it, because the scan named two files by hand. The
 * list is still explicit rather than a glob — a page whose keys are not covered
 * should be added deliberately — but "we only claimed those two" stopped being
 * a reason the moment a real install rendered a key as a label.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { en } from "./en";

const PAGES = [
  "../routes/databases.tsx",
  "../routes/plans.tsx",
  "../routes/docker.tsx",
  // Added after the Docker page shipped eight raw keys as button labels, and
  // the cron dialog nearly did the same: a page that is not in this list can
  // lose a key with nothing failing.
  "../routes/cron.tsx",
  "../routes/alerts.tsx",
  "../routes/files.tsx",
];

/** Every `t("literal")` in a file. Template-literal keys are handled below. */
function literalKeys(source: string): string[] {
  return [...source.matchAll(/\bt\(\s*"([^"]+)"/g)].map((m) => m[1]!);
}

/**
 * Key families built from a template literal, which no static scan can see.
 * Each entry is every key the page can actually produce for that family.
 */
const DYNAMIC_KEYS = [
  "databases.engine.mysql",
  "databases.engine.postgres",
  "databases.nameProblem.required",
  "databases.nameProblem.tooLong",
  "databases.nameProblem.start",
  "databases.nameProblem.charset",
  "databases.nameProblem.reserved",
  "plans.nameProblem.required",
  "plans.nameProblem.tooLong",
  "plans.limitProblem.required",
  "plans.limitProblem.notANumber",
  "plans.limitProblem.tooLarge",
  "plans.reasonProblem.required",
  "plans.reasonProblem.tooLong",
  "plans.reasonProblem.control",
  "plans.justAction.suspended",
  "plans.justAction.reinstated",
  // One dialog wears three sets of words, chosen by `docker.confirm.${action}`.
  // A missing one renders as the raw key in the title of the pause standing in
  // front of a stop, a restart or a removal — the last place an operator should
  // have to guess what they are agreeing to.
  "docker.confirm.stop.title",
  "docker.confirm.stop.hint",
  "docker.confirm.stop.confirm",
  "docker.confirm.stop.body",
  "docker.confirm.restart.title",
  "docker.confirm.restart.hint",
  "docker.confirm.restart.confirm",
  "docker.confirm.restart.body",
  "docker.confirm.remove.title",
  "docker.confirm.remove.hint",
  "docker.confirm.remove.confirm",
  "docker.confirm.remove.body",
];

/** i18next pluralises by appending `_other`; both forms must exist. */
const PLURAL_KEYS = ["plans.subscriptionsOn", "plans.liveCount", "plans.goDark"];

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

function pageSources(): { file: string; source: string }[] {
  return PAGES.map((relative) => ({
    file: relative,
    source: readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8"),
  }));
}

describe("translation coverage for the databases, plans and docker pages", () => {
  it("resolves every literal key the pages ask for", () => {
    for (const { file, source } of pageSources()) {
      const keys = literalKeys(source);
      // A page that suddenly asks for nothing means the scan broke, not that
      // the page stopped needing translations.
      expect(keys.length, file).toBeGreaterThan(20);
      for (const key of keys) {
        expect(typeof lookup(en, key), `en: ${key} (${file})`).toBe("string");
      }
    }
  });

  it("resolves the keys built from template literals, which no scan can see", () => {
    for (const key of DYNAMIC_KEYS) {
      expect(typeof lookup(en, key), `en: ${key}`).toBe("string");
    }
  });

  it("carries both plural forms, so a count of two does not render the raw key", () => {
    for (const key of PLURAL_KEYS) {
      expect(typeof lookup(en, key), key).toBe("string");
      expect(typeof lookup(en, `${key}_other`), `${key}_other`).toBe("string");
    }
  });
});
