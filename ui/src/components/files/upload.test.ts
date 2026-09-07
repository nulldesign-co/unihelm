/**
 * Behaviour tests for what a drop on the file manager turns out to contain
 * (spec §11.7).
 *
 * The handler used to call `webkitGetAsEntry()` only to `continue` past
 * anything that came back a directory, so dragging a folder onto the panel
 * enqueued nothing, said nothing, and looked exactly like a drop that had been
 * accepted. Silent loss is the worst shape this defect has, so every case below
 * checks the same thing twice: what came out, and that nothing vanished on the
 * way.
 */

import { describe, expect, it } from "vitest";

import { filesFromDrop, filesFromPicker } from "./upload";

// ---------------------------------------------------------------------------
// Fakes for the drag-and-drop entry API, which exists in no test environment
// ---------------------------------------------------------------------------

function fileEntry(name: string, content = "x"): FileSystemEntry {
  return {
    isFile: true,
    isDirectory: false,
    name,
    file: (resolve: (file: File) => void) => resolve(new File([content], name)),
  } as unknown as FileSystemEntry;
}

function dirEntry(
  name: string,
  children: FileSystemEntry[],
  options: { batchSize?: number; unreadable?: boolean } = {},
): FileSystemEntry {
  const batchSize = options.batchSize ?? 100;
  return {
    isFile: false,
    isDirectory: true,
    name,
    createReader: () => {
      let at = 0;
      return {
        readEntries: (
          resolve: (entries: FileSystemEntry[]) => void,
          reject: (error: unknown) => void,
        ) => {
          if (options.unreadable) {
            reject(new Error("SecurityError"));
            return;
          }
          const batch = children.slice(at, at + batchSize);
          at += batch.length;
          resolve(batch);
        },
      };
    },
  } as unknown as FileSystemEntry;
}

/** A drop from a browser with the entry API — every modern one. */
function dropOf(entries: FileSystemEntry[]): DataTransfer {
  return {
    items: entries.map((entry) => ({
      kind: "file",
      webkitGetAsEntry: () => entry,
      getAsFile: () => null,
    })),
    files: [],
  } as unknown as DataTransfer;
}

/** A drop from a browser that has no entry API at all. */
function legacyDropOf(files: File[]): DataTransfer {
  return {
    items: files.map((file) => ({ kind: "file", getAsFile: () => file })),
    files,
  } as unknown as DataTransfer;
}

/**
 * What a directory looks like when the entry API is missing: a zero-byte `File`
 * that throws the moment anything reads a byte of it.
 */
function directoryShapedFile(name: string): File {
  return {
    name,
    size: 0,
    slice: () => ({ arrayBuffer: () => Promise.reject(new Error("NotFoundError")) }),
  } as unknown as File;
}

// ---------------------------------------------------------------------------

describe("filesFromDrop", () => {
  it("walks a dropped folder and keeps each file's path relative to it", async () => {
    const tree = dirEntry("site", [
      fileEntry("index.php"),
      dirEntry("css", [fileEntry("app.css"), dirEntry("vendor", [fileEntry("reset.css")])]),
    ]);

    const { uploads, unreadable } = await filesFromDrop(dropOf([tree]));

    expect(uploads.map((u) => u.relativePath)).toEqual([
      "site/index.php",
      "site/css/app.css",
      "site/css/vendor/reset.css",
    ]);
    expect(unreadable).toEqual([]);
  });

  it("reads every batch, because readEntries answers with at most a hundred at a time", async () => {
    // Chromium caps a `readEntries` call at 100 children and signals the end
    // with an empty batch. Reading it once loses everything past the hundredth
    // file — the same defect as losing all of them, only harder to notice.
    const many = Array.from({ length: 250 }, (_, i) => fileEntry(`f${i}.txt`));
    const { uploads } = await filesFromDrop(dropOf([dirEntry("bulk", many, { batchSize: 100 })]));

    expect(uploads).toHaveLength(250);
    expect(uploads[249]?.relativePath).toBe("bulk/f249.txt");
  });

  it("names a folder it could not read instead of accepting the drop in silence", async () => {
    const { uploads, unreadable } = await filesFromDrop(
      dropOf([dirEntry("private", [fileEntry("a.txt")], { unreadable: true })]),
    );

    expect(uploads).toEqual([]);
    expect(unreadable).toEqual(["private"]);
  });

  it("still takes the folders it could read when one of them fails", async () => {
    const { uploads, unreadable } = await filesFromDrop(
      dropOf([
        dirEntry("good", [fileEntry("a.txt")]),
        dirEntry("bad", [], { unreadable: true }),
      ]),
    );

    expect(uploads.map((u) => u.relativePath)).toEqual(["good/a.txt"]);
    expect(unreadable).toEqual(["bad"]);
  });

  it("reports a folder with no files in it, which no upload path would ever name", async () => {
    const { uploads, emptyDirs } = await filesFromDrop(
      dropOf([
        dirEntry("app", [
          fileEntry("boot.php"),
          dirEntry("storage", [dirEntry("logs", [])]),
        ]),
      ]),
    );

    expect(uploads.map((u) => u.relativePath)).toEqual(["app/boot.php"]);
    // Deepest first: making `app/storage/logs` makes `app/storage` on the way.
    expect(emptyDirs).toEqual(["app/storage/logs", "app/storage"]);
  });

  it("takes loose files with their own names, folder or no folder", async () => {
    const { uploads, emptyDirs, unreadable } = await filesFromDrop(
      dropOf([fileEntry("notes.txt"), fileEntry("photo.png")]),
    );

    expect(uploads.map((u) => u.relativePath)).toEqual(["notes.txt", "photo.png"]);
    expect(emptyDirs).toEqual([]);
    expect(unreadable).toEqual([]);
  });

  it("refuses a folder that arrives as a zero-byte File where there is no entry API", async () => {
    // Uploading it would create an empty file wearing the folder's name and
    // then report success — a worse answer than saying it cannot be read.
    const { uploads, unreadable } = await filesFromDrop(
      legacyDropOf([directoryShapedFile("assets")]),
    );

    expect(uploads).toEqual([]);
    expect(unreadable).toEqual(["assets"]);
  });

  it("does not mistake a genuinely empty file for a folder", async () => {
    const { uploads, unreadable } = await filesFromDrop(legacyDropOf([new File([], ".gitkeep")]));

    expect(uploads.map((u) => u.relativePath)).toEqual([".gitkeep"]);
    expect(unreadable).toEqual([]);
  });
});

describe("filesFromPicker", () => {
  function picked(name: string, relative: string): File {
    const file = new File(["x"], name);
    Object.defineProperty(file, "webkitRelativePath", { value: relative });
    return file;
  }

  it("keeps the tree a webkitdirectory picker hands back", () => {
    const uploads = filesFromPicker([
      picked("index.php", "site/index.php"),
      picked("app.css", "site/css/app.css"),
    ] as unknown as FileList);

    expect(uploads.map((u) => u.relativePath)).toEqual(["site/index.php", "site/css/app.css"]);
  });

  it("falls back to the bare name for the plain picker, which sets no relative path", () => {
    const uploads = filesFromPicker([picked("notes.txt", "")] as unknown as FileList);

    expect(uploads.map((u) => u.relativePath)).toEqual(["notes.txt"]);
  });

  it("has nothing to enqueue when the picker was dismissed", () => {
    expect(filesFromPicker(null)).toEqual([]);
  });
});
