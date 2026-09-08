/**
 * Deploying a site from a Git repository (spec §11.2).
 *
 * Before this, putting a site live meant dragging files into the file manager
 * one directory at a time. The panel now records which repository a site comes
 * from, clones it into the document root, and fast-forwards it on demand.
 *
 * Kept out of `lib/api.ts` on purpose: that file is the shared client every
 * page imports, and this is one card on one page.
 *
 * `clone` and `pull` answer 202 with a task id — a clone is a network transfer
 * that can take minutes — so the caller watches the task rather than trusting
 * the response. `status`, `attach` and `detach` answer in the round trip.
 */

import { api, type TaskAccepted } from "@/lib/api";

/** What the panel was told to deploy. Its own record, not a reading of disk. */
export interface GitAttachment {
  repository: string;
  branch?: string | null;
  attached_at: string;
  /** Absent until a clone or a deploy has actually moved something. */
  last_commit?: string | null;
  last_deployed_at?: string | null;
}

/**
 * What is in the document root right now.
 *
 * `holding_page` is the page `site.create` writes into an empty root — the one
 * file a clone is allowed to replace. `occupied` is everything else, and it is
 * why cloning is refused rather than silently overwriting a live site.
 */
export type GitRootState = "missing" | "empty" | "holding_page" | "checkout" | "occupied";

/** What the checkout on disk says about itself. */
export interface GitCheckout {
  remote: string | null;
  branch: string | null;
  commit: string | null;
  subject: string | null;
  committed_at: string | null;
  dirty: boolean;
  /** Tracked files with uncommitted changes; the server caps the list at ten. */
  changed_files: string[];
  /** False when the checkout pulls from a different repository than the one attached. */
  remote_matches_attachment: boolean;
}

export interface GitStatus {
  site_id: number;
  domain: string;
  document_root: string;
  linux_user: string;
  git_installed: boolean;
  git_version: string | null;
  attachment: GitAttachment | null;
  root_state: GitRootState;
  /** The first few names in the document root, so a refusal can show them. */
  root_entries: string[];
  checkout: GitCheckout | null;
}

export const gitApi = {
  status: (siteId: number) => api.get<GitStatus>(`/api/sites/${siteId}/git`),
  /**
   * Record the repository and branch. Writes nothing to disk.
   *
   * `branch` is omitted when blank rather than sent as an empty string: an
   * untouched field means "the repository's default branch", and the first
   * clone writes back which branch that turned out to be.
   */
  attach: (siteId: number, repository: string, branch: string) =>
    api.post<{ repository: string; branch: string | null; replaced?: string }>(
      `/api/sites/${siteId}/git`,
      branch.trim() === "" ? { repository } : { repository, branch: branch.trim() },
    ),
  detach: (siteId: number) => api.del<{ detached: boolean }>(`/api/sites/${siteId}/git`),
  clone: (siteId: number) => api.post<TaskAccepted>(`/api/sites/${siteId}/git/clone`),
  pull: (siteId: number) => api.post<TaskAccepted>(`/api/sites/${siteId}/git/pull`),
};

/** Why this cannot be sent yet, or `null`. */
export type RepositoryProblem = "required" | "https" | "credentials";

/**
 * The three refusals worth making without a round trip.
 *
 * A mirror, not a boundary: `git.attach` parses the URL again and its message
 * is the one that matters — it knows about transport helpers, port numbers and
 * host names, and this deliberately does not try to. What this buys is a
 * message under the field for the two mistakes people actually make (pasting
 * the SSH address GitHub offers first, and pasting a URL with a token in it)
 * instead of a red callout a second later.
 */
export function repositoryProblem(raw: string): RepositoryProblem | null {
  const value = raw.trim();
  if (value === "") return "required";
  if (!/^https:\/\//i.test(value)) return "https";
  // A `@` before the first slash of the path is userinfo — a username or a
  // token, which git would write into `.git/config` in plain text.
  const authority = value.slice("https://".length).split(/[/?#]/, 1)[0] ?? "";
  if (authority.includes("@")) return "credentials";
  return null;
}

/** A commit id at the length people actually read. */
export function shortCommit(commit: string | null | undefined): string {
  return commit ? commit.slice(0, 7) : "";
}
