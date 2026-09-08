/**
 * Panel accounts, and your own password (spec §6.1, §12 rule 7).
 *
 * Two endpoints groups behind one client, because the Users page is one page.
 *
 * # The password call is not a plain POST
 *
 * `POST /api/account/password` revokes every session for the account —
 * including the one that asked — and issues a replacement on the response. The
 * cookie rides along on its own; the **CSRF token does not**, and the panel
 * refuses every state-changing request without a matching one. So
 * [`usersApi.changePassword`] hands the new token to `setCsrfToken` before it
 * returns. Miss that and the tab keeps working until the operator's next save,
 * which fails with `csrf_invalid` for no reason they can see.
 *
 * # The refusal mirrors are messages, not boundaries
 *
 * `unihelm_ops::users` refuses to delete, demote or suspend the last
 * administrator, refuses anything aimed at the account you are signed in as,
 * and refuses to delete an account that still owns subscriptions, plans or
 * customers. Every one of those is enforced there, over the agent socket, from
 * the CLI as well as from here. [`refusalFor`] repeats the same rules so the
 * page can grey an item out and say why, instead of letting somebody click and
 * read the answer afterwards — the same bargain `plans-api.ts` makes about
 * suspension reasons.
 */

import { api, setCsrfToken } from "@/lib/api";

// ---------------------------------------------------------------------------
// Wire shapes (mirrors unihelm-ops `users`)
// ---------------------------------------------------------------------------

export type PanelRole = "admin" | "reseller" | "customer";

/** What `user.status.set` may write. */
export type SettableStatus = "active" | "suspended";

/**
 * What a row may hold. `locked` is not settable from the panel — it is a
 * throttle state lifted with `unihelm user unlock` — but it can be read, so
 * the page has to be able to render it.
 */
export type AccountStatus = SettableStatus | "locked";

export interface PanelUser {
  id: number;
  role: PanelRole;
  username: string;
  email: string;
  full_name: string | null;
  status: AccountStatus;
  /** The reseller this account belongs to, when it belongs to one. */
  reseller_id: number | null;
  created_at: string;
  last_login_at: string | null;
  /** Subscriptions it owns. Deletion is refused above zero. */
  subscriptions: number;
  /** Plans it owns. Deletion is refused above zero. */
  owned_plans: number;
  /** Accounts beneath it. Deletion is refused above zero. */
  customers: number;
}

export interface UsersResponse {
  users: PanelUser[];
  /**
   * Administrators who can sign in, panel-wide. `null` for a reseller, whose
   * list contains no administrators for it to be about.
   */
  admin_count: number | null;
}

export interface CreateUserRequest {
  username: string;
  email: string;
  role: PanelRole;
  password: string;
  full_name?: string | null;
}

export interface DeleteResult {
  user_id: number;
  username: string;
  sessions_ended: number;
  api_tokens_removed: number;
  webhooks_removed: number;
  audit_entries_kept: number;
}

export interface ChangePasswordResult {
  /** Other devices signed out. This one was replaced, not counted. */
  sessions_ended: number;
  csrf_token: string;
}

export const usersApi = {
  list: () => api.get<UsersResponse>("/api/users"),
  create: (body: CreateUserRequest) => api.post<{ user: PanelUser }>("/api/users", body),
  setRole: (id: number, role: PanelRole) =>
    api.post<{ user: PanelUser; sessions_ended: number }>(`/api/users/${id}/role`, { role }),
  setStatus: (id: number, status: SettableStatus) =>
    api.post<{ user: PanelUser; sessions_ended: number }>(`/api/users/${id}/status`, { status }),
  // The confirmation rides in the query string because this is a DELETE, the
  // same shape `DELETE /api/databases/{id}` uses for its `confirm_name`.
  remove: (id: number, confirmUsername: string) =>
    api.del<DeleteResult>(
      `/api/users/${id}?confirm_username=${encodeURIComponent(confirmUsername)}`,
    ),
  /**
   * Change the password of the signed-in account.
   *
   * The response replaces this session, so the new CSRF token is stored before
   * the promise resolves — see the module docs.
   */
  changePassword: async (
    currentPassword: string,
    newPassword: string,
  ): Promise<ChangePasswordResult> => {
    const result = await api.post<ChangePasswordResult>("/api/account/password", {
      current_password: currentPassword,
      new_password: newPassword,
    });
    setCsrfToken(result.csrf_token);
    return result;
  },
};

// ---------------------------------------------------------------------------
// Client-side mirrors of the agent's rules
// ---------------------------------------------------------------------------

export type PasswordProblem = "required" | "tooShort" | "tooLong";

/** The floor `unihelm_db::password::check_strength` enforces. */
export const MIN_PASSWORD_CHARS = 12;
/** And its ceiling, which is in bytes rather than characters. */
export const MAX_PASSWORD_BYTES = 1024;

/**
 * A password, checked the way the panel checks it.
 *
 * Characters for the floor and bytes for the ceiling, because that is what
 * `check_strength` counts: `chars().count()` against the minimum and `len()`
 * against the maximum. Spreading the string yields code points, which is what
 * Rust's `chars()` iterates.
 */
export function passwordProblem(raw: string): PasswordProblem | null {
  if (raw === "") return "required";
  if ([...raw].length < MIN_PASSWORD_CHARS) return "tooShort";
  if (new TextEncoder().encode(raw).length > MAX_PASSWORD_BYTES) return "tooLong";
  return null;
}

export type NewPasswordProblem = PasswordProblem | "mismatch" | "same";

/**
 * The three fields of the password form, as one answer.
 *
 * "Same as the current one" is checked here as well as on the server, and it
 * is not pedantry: the server refuses it precisely because going through with
 * it would sign every other device out for no change at all.
 */
export function newPasswordProblem(
  current: string,
  next: string,
  repeat: string,
): NewPasswordProblem | null {
  const problem = passwordProblem(next);
  if (problem) return problem;
  if (next === current) return "same";
  if (next !== repeat) return "mismatch";
  return null;
}

/** Who is looking, and what the panel would still have without this account. */
export interface Viewer {
  id: number;
  /** From `UsersResponse.admin_count`; `null` when the caller is a reseller. */
  adminCount: number | null;
}

export type Refusal = "self" | "lastAdmin" | "owns";
export type ManageAction = "role" | "suspend" | "delete";

/**
 * Why `unihelm_ops::users` would refuse this action, or `null` if it would not.
 *
 * The order matches the operations' own: the account you are signed in as is
 * answered before the last-administrator rule, which is answered before what
 * the account owns. Getting the order wrong here would show a reason the
 * server would not have given.
 *
 * Reinstating a suspended account is never refused, so `suspend` here means
 * suspending — a row that is already suspended offers the other direction.
 */
export function refusalFor(action: ManageAction, user: PanelUser, viewer: Viewer): Refusal | null {
  if (user.id === viewer.id) return "self";
  // Only an administrator who can still sign in is holding the panel up; a
  // suspended one is already not administering anything.
  if (user.role === "admin" && user.status === "active" && (viewer.adminCount ?? 0) <= 1) {
    return "lastAdmin";
  }
  if (action === "delete" && owned(user).length > 0) return "owns";
  return null;
}

export interface Owned {
  kind: "subscriptions" | "plans" | "customers";
  count: number;
}

/** What this account holds, in the order the agent lists it when it refuses. */
export function owned(user: PanelUser): Owned[] {
  const out: Owned[] = [];
  if (user.subscriptions > 0) out.push({ kind: "subscriptions", count: user.subscriptions });
  if (user.owned_plans > 0) out.push({ kind: "plans", count: user.owned_plans });
  if (user.customers > 0) out.push({ kind: "customers", count: user.customers });
  return out;
}

/**
 * Is the typed confirmation the account's own username?
 *
 * Trimmed on both sides, matching `user.delete`, which compares
 * `confirm_username.trim()` against the stored name.
 */
export function confirmationMatches(typed: string, username: string): boolean {
  return typed.trim() === username;
}
