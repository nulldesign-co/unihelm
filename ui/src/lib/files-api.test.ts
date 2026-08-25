/**
 * Behaviour tests for the file-manager client logic (spec §11.7).
 *
 * The server is the security boundary; these tests pin down the client-side
 * claims that still matter — a hostile URL never renders as a breadcrumb it
 * could not list, dialog inputs cannot smuggle separators, and the encoding
 * helpers round-trip bytes exactly (a corrupting editor is worse than none).
 */

import { describe, expect, it } from "vitest";

import {
  archiveFormatOf,
  base64ToBytes,
  baseName,
  cleanPath,
  CHUNK_BYTES,
  formatMode,
  isValidName,
  joinPath,
  looksBinary,
  MAX_EDIT_BYTES,
  modeToOctal,
  octalToMode,
  parentPath,
} from "./files-api";

describe("cleanPath", () => {
  it("drops dotdot segments from a hostile url instead of rendering them", () => {
    expect(cleanPath("../../etc/passwd")).toBe("etc/passwd");
    expect(cleanPath("a/../../b")).toBe("a/b");
    expect(cleanPath("..")).toBe("");
  });

  it("collapses duplicate and leading slashes", () => {
    expect(cleanPath("//a///b/")).toBe("a/b");
    expect(cleanPath("/")).toBe("");
  });

  it("drops single-dot segments", () => {
    expect(cleanPath("./a/./b")).toBe("a/b");
  });

  it("leaves an honest path alone", () => {
    expect(cleanPath("public_html/wp-content")).toBe("public_html/wp-content");
  });
});

describe("isValidName", () => {
  it("rejects names that would traverse or split a path", () => {
    for (const bad of ["", ".", "..", "a/b", "a\\b", "a\0b"]) {
      expect(isValidName(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  it("accepts ordinary names, including dotfiles and farsi", () => {
    for (const good of [".htaccess", "index.php", "گزارش.txt", "a b c"]) {
      expect(isValidName(good), good).toBe(true);
    }
  });
});

describe("path helpers", () => {
  it("joins against the home root without a leading slash", () => {
    expect(joinPath("", "a.txt")).toBe("a.txt");
    expect(joinPath("dir", "a.txt")).toBe("dir/a.txt");
  });

  it("walks back up the way it joined down", () => {
    expect(parentPath("dir/sub/a.txt")).toBe("dir/sub");
    expect(parentPath("a.txt")).toBe("");
    expect(baseName("dir/sub/a.txt")).toBe("a.txt");
    expect(baseName("a.txt")).toBe("a.txt");
  });
});

describe("mode formatting", () => {
  it("renders permission bits the way ls does", () => {
    expect(formatMode(0o755)).toBe("rwxr-xr-x");
    expect(formatMode(0o644)).toBe("rw-r--r--");
    expect(formatMode(0o000)).toBe("---------");
    expect(formatMode(0o777)).toBe("rwxrwxrwx");
  });

  it("round-trips through the octal field", () => {
    expect(modeToOctal(0o644)).toBe("644");
    expect(octalToMode("644")).toBe(0o644);
    expect(octalToMode(modeToOctal(0o750))).toBe(0o750);
  });

  it("refuses octal input that is not a mode", () => {
    for (const bad of ["", "8", "77", "77777", "abc", "7 5 5", "-644"]) {
      expect(octalToMode(bad), bad).toBeNull();
    }
  });
});

describe("archiveFormatOf", () => {
  it("recognises archives only by their full final extension", () => {
    expect(archiveFormatOf("site.zip")).toBe("zip");
    expect(archiveFormatOf("SITE.ZIP")).toBe("zip");
    expect(archiveFormatOf("b.tar.gz")).toBe("tar_gz");
    expect(archiveFormatOf("b.tgz")).toBe("tar_gz");
    expect(archiveFormatOf("b.tar.zst")).toBe("tar_zst");
    // `evil.zip.php` is a PHP file wearing a costume; offering "extract" on it
    // would teach users to trust the costume.
    expect(archiveFormatOf("evil.zip.php")).toBeNull();
    expect(archiveFormatOf("notes.txt")).toBeNull();
  });
});

describe("looksBinary", () => {
  it("spots common binary types without a server round trip", () => {
    for (const name of ["a.png", "a.sqlite", "a.woff2", "a.tar", "backdoor.phar"]) {
      expect(looksBinary(name), name).toBe(true);
    }
  });

  it("keeps every editable web language editable", () => {
    for (const name of ["index.php", "app.tsx", "style.css", ".env", "nginx.conf", "no-extension"]) {
      expect(looksBinary(name), name).toBe(false);
    }
  });
});

describe("base64ToBytes", () => {
  it("round-trips bytes exactly, including nul and high bytes", () => {
    const bytes = new Uint8Array([0, 1, 127, 128, 255, 10, 13]);
    const b64 = btoa(String.fromCharCode(...bytes));
    expect(Array.from(base64ToBytes(b64))).toEqual(Array.from(bytes));
  });

  it("decodes the empty chunk an empty upload sends", () => {
    expect(base64ToBytes("").length).toBe(0);
  });
});

describe("chunking constants", () => {
  it("uses 4 MB chunks and a 5 MB editor cap, per spec §11.7", () => {
    // These are contract values shared with the server, not tuning knobs; a
    // drive-by "optimisation" should have to change a test to change them.
    expect(CHUNK_BYTES).toBe(4 * 1024 * 1024);
    expect(MAX_EDIT_BYTES).toBe(5 * 1024 * 1024);
  });
});
