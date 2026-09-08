/**
 * Behaviour tests for the repository field's client-side refusals (spec §11.2).
 *
 * `git.attach` refuses the same three things again and its message is the one
 * that ships, so nothing here is a boundary. What is worth pinning down is that
 * the two mistakes people actually make are caught at the keyboard: pasting the
 * SSH address a forge offers first, and pasting a URL with a token in it — the
 * second because the panel's whole answer to private repositories is "we will
 * not put your credential in a file inside the document root", and a field that
 * accepted it would read as though it might.
 */

import { describe, expect, it } from "vitest";

import { repositoryProblem, shortCommit } from "./git-api";

describe("repositoryProblem", () => {
  it("accepts the public HTTPS addresses people paste", () => {
    for (const ok of [
      "https://github.com/owner/project.git",
      "https://gitlab.example.com:8443/group/sub/project",
      "  https://codeberg.org/owner/project  ",
    ]) {
      expect(repositoryProblem(ok)).toBeNull();
    }
  });

  it("refuses an empty field rather than posting a blank repository", () => {
    expect(repositoryProblem("")).toBe("required");
    expect(repositoryProblem("   ")).toBe("required");
  });

  it("refuses every address that is not HTTPS, SSH included", () => {
    for (const bad of [
      "git@github.com:owner/project.git",
      "ssh://git@github.com/owner/project.git",
      "http://github.com/owner/project.git",
      "git://github.com/owner/project.git",
      "github.com/owner/project.git",
    ]) {
      expect(repositoryProblem(bad), bad).toBe("https");
    }
  });

  it("refuses a URL carrying a username or token, which git would write to disk", () => {
    expect(repositoryProblem("https://user:ghp_token@github.com/o/p.git")).toBe("credentials");
    expect(repositoryProblem("https://ghp_token@github.com/o/p.git")).toBe("credentials");
  });

  it("does not mistake an @ in the path for a credential", () => {
    // Only the authority — everything before the first slash — carries
    // userinfo. A scoped npm-style path is an ordinary repository.
    expect(repositoryProblem("https://github.com/owner/@scope/project.git")).toBeNull();
  });
});

describe("shortCommit", () => {
  it("shortens a commit to the length people read, and says nothing when there is none", () => {
    expect(shortCommit("1a2b3c4d5e6f7890abcdef1234567890abcdef12")).toBe("1a2b3c4");
    expect(shortCommit(null)).toBe("");
    expect(shortCommit(undefined)).toBe("");
  });
});
