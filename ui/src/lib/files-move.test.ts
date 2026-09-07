/**
 * Behaviour tests for Move's destination rules and the directory chain a folder
 * upload has to build (spec §11.7).
 *
 * Both are here because the panel had neither. Moving a file meant copying it
 * and deleting the original — twice the disk and a window where the wrong
 * duplicate can be edited — and a folder could not be uploaded at all, because
 * `fs.mkdir` makes exactly one level and nothing walked the chain.
 *
 * The refusals are the interesting half. The server does stop both mistakes,
 * but as `already exists` and as an errno from `rename(2)`; neither sentence
 * says "those files are already in that folder" or "that folder is inside the
 * one you are moving", which is the only thing an operator can act on.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "./api";
import { ancestorDirs, ensureDir, filesApi, isWithin, moveRefusal } from "./files-api";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("isWithin", () => {
  it("counts the home root as containing everything, including itself", () => {
    expect(isWithin("", "public_html/index.php")).toBe(true);
    expect(isWithin("", "")).toBe(true);
  });

  it("counts a folder as containing itself and everything under it", () => {
    expect(isWithin("site", "site")).toBe(true);
    expect(isWithin("site", "site/css")).toBe(true);
    expect(isWithin("site", "site/css/vendor/a.css")).toBe(true);
  });

  it("does not mistake a shared name prefix for containment", () => {
    // The bug this shape produces is a refusal, not a corruption: `site-backup`
    // is a sibling of `site`, and moving into it must stay allowed.
    expect(isWithin("site", "site-backup")).toBe(false);
    expect(isWithin("site", "sites/a")).toBe(false);
    expect(isWithin("site/css", "site")).toBe(false);
  });
});

describe("moveRefusal", () => {
  const dir = (path: string) => ({ path, kind: "dir" as const });
  const file = (path: string) => ({ path, kind: "file" as const });

  it("lets an ordinary move through", () => {
    expect(moveRefusal([file("public_html/a.php")], "backup")).toBeNull();
    expect(moveRefusal([dir("site")], "backup/old")).toBeNull();
    // Out of a folder and up to the home root is a move like any other.
    expect(moveRefusal([file("site/a.php")], "")).toBeNull();
  });

  it("names the folder the items are already in, which the server calls a name clash", () => {
    expect(moveRefusal([file("site/a.php"), file("site/b.php")], "site")).toBe("sameFolder");
    expect(moveRefusal([file("a.php")], "")).toBe("sameFolder");
  });

  it("refuses a folder moved inside itself, which the server calls errno 22", () => {
    expect(moveRefusal([dir("site")], "site")).toBe("intoItself");
    expect(moveRefusal([dir("site")], "site/css")).toBe("intoItself");
    expect(moveRefusal([dir("site")], "site/css/vendor")).toBe("intoItself");
  });

  it("refuses when any one of a multi-select would be the one to fail", () => {
    // The whole selection is refused rather than half-moved: the sequential
    // rename would otherwise move two items and then stop on the third.
    expect(moveRefusal([file("other/a.php"), dir("site")], "site/css")).toBe("intoItself");
  });

  it("does not apply the folder rule to a symlink, which moves as the link", () => {
    // Renaming a link moves the link itself; there is no inside to fall into,
    // and refusing it would take away the only way to tidy one up.
    expect(moveRefusal([{ path: "site", kind: "symlink" }], "site/css")).toBeNull();
  });
});

describe("ancestorDirs", () => {
  it("names every level from the home root down, shallowest first", () => {
    expect(ancestorDirs("site/css/vendor")).toEqual(["site", "site/css", "site/css/vendor"]);
    expect(ancestorDirs("site")).toEqual(["site"]);
  });

  it("has nothing to make for the home root itself", () => {
    expect(ancestorDirs("")).toEqual([]);
    expect(ancestorDirs("/")).toEqual([]);
  });

  it("cleans a hostile relative path before naming a level after it", () => {
    // A dropped folder's paths come from the browser, and `..` in one must
    // never become a directory the panel walks up into.
    expect(ancestorDirs("a/../../b")).toEqual(["a", "a/b"]);
    expect(ancestorDirs("//a///b/")).toEqual(["a", "a/b"]);
  });
});

describe("ensureDir", () => {
  const refusal = (slug: string, message: string) =>
    new ApiError(409, { code: "UNI-1401", slug, message });

  it("makes each level in turn, because the endpoint makes exactly one", async () => {
    const made: string[] = [];
    vi.spyOn(filesApi, "mkdir").mockImplementation(async (path: string) => {
      made.push(path);
    });

    await ensureDir("site/css/vendor");

    expect(made).toEqual(["site", "site/css", "site/css/vendor"]);
  });

  it("treats a level that is already there as done", async () => {
    const made: string[] = [];
    vi.spyOn(filesApi, "mkdir").mockImplementation(async (path: string) => {
      // The common case for the second file of a folder upload, and for every
      // file after that: the parent was made by the one before it.
      if (path === "site") throw refusal("already_exists", "`site` already exists");
      made.push(path);
    });

    await expect(ensureDir("site/css")).resolves.toBeUndefined();
    expect(made).toEqual(["site/css"]);
  });

  it("stops on any other refusal rather than uploading into a folder that is not there", async () => {
    vi.spyOn(filesApi, "mkdir").mockRejectedValue(
      refusal("quota_exceeded", "the account is over its disk quota"),
    );

    await expect(ensureDir("site/css")).rejects.toThrow("over its disk quota");
  });
});
