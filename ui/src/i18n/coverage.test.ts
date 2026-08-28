/**
 * Translation coverage for the databases and plans pages (spec §4.2).
 *
 * `Translations` makes a *missing* Farsi key a compile error, but nothing
 * typechecks the other direction: `t("plans.reasonProblem.control")` is just a
 * string, so a typo or a renamed key ships as the raw key rendered on screen —
 * and on the Farsi page an English fallback is the same defect wearing a
 * disguise.
 *
 * So this reads the two pages back and resolves every key they ask for. The
 * scan is deliberately limited to those two files: it is this task's claim to
 * make, not a trap for the next page somebody adds.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { en } from "./en";
import { fa } from "./fa";

const PAGES = ["../routes/databases.tsx", "../routes/plans.tsx"];

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

describe("translation coverage for the databases and plans pages", () => {
  it("resolves every literal key the pages ask for, in both languages", () => {
    for (const { file, source } of pageSources()) {
      const keys = literalKeys(source);
      // A page that suddenly asks for nothing means the scan broke, not that
      // the page stopped needing translations.
      expect(keys.length, file).toBeGreaterThan(20);
      for (const key of keys) {
        expect(typeof lookup(en, key), `en: ${key} (${file})`).toBe("string");
        expect(typeof lookup(fa, key), `fa: ${key} (${file})`).toBe("string");
      }
    }
  });

  it("resolves the keys built from template literals, which no scan can see", () => {
    for (const key of DYNAMIC_KEYS) {
      expect(typeof lookup(en, key), `en: ${key}`).toBe("string");
      expect(typeof lookup(fa, key), `fa: ${key}`).toBe("string");
    }
  });

  it("carries both plural forms, so a count of two does not fall back to English", () => {
    for (const key of PLURAL_KEYS) {
      for (const bundle of [en, fa] as const) {
        expect(typeof lookup(bundle, key), key).toBe("string");
        expect(typeof lookup(bundle, `${key}_other`), `${key}_other`).toBe("string");
      }
    }
  });

  it("does not leave a Farsi string identical to its English source", () => {
    // The one honest exception is a product name: MariaDB and PostgreSQL are
    // spelled the same in both languages, as is the Adminer heading.
    const SAME_ON_PURPOSE = new Set([
      "databases.engine.mysql",
      "databases.engine.postgres",
      "databases.adminerTitle",
    ]);
    const suspects: string[] = [];
    for (const section of ["databases", "plans"] as const) {
      walk(en[section], fa[section], section, (key, english, farsi) => {
        if (english === farsi && !SAME_ON_PURPOSE.has(key)) suspects.push(key);
      });
    }
    expect(suspects).toEqual([]);
  });
});

function walk(
  english: unknown,
  farsi: unknown,
  prefix: string,
  visit: (key: string, en: string, fa: string) => void,
) {
  if (typeof english === "string" && typeof farsi === "string") {
    visit(prefix, english, farsi);
    return;
  }
  if (typeof english !== "object" || english === null) return;
  for (const [name, value] of Object.entries(english)) {
    walk(value, (farsi as Record<string, unknown> | null)?.[name], `${prefix}.${name}`, visit);
  }
}
