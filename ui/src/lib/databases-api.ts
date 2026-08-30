/**
 * Database-management API client (spec §11.4).
 *
 * Two facts from the server shape everything in this file and in the page
 * above it:
 *
 * 1. **Passwords are shown once and stored never.** `db.user.create` and
 *    `db.user.password` are the only channels a generated password ever
 *    travels on, and both are `Execution::Immediate` precisely so the secret
 *    never lands in the tasks table or a task log. There is no "show me that
 *    password again" endpoint and there never will be — losing one means
 *    resetting it. The UI's job is to make that unmissable *before* the
 *    operator closes the dialog.
 * 2. **Identifiers are a type, not a string.** The agent parses every name
 *    through `unihelm_core::DbName` (`[A-Za-z0-9_]`, not reserved), which is
 *    what makes identifier injection impossible by construction. The mirror of
 *    that rule below is for the error message only — it turns a round trip
 *    into a red line under the field. It is not the security boundary and must
 *    never be treated as one.
 */

import { api, type TaskAccepted } from "@/lib/api";

// ---------------------------------------------------------------------------
// Wire shapes (mirrors unihelm-ops `db` and `adminer`)
// ---------------------------------------------------------------------------

/** The engine strings are stable across the schema, the API and the audit log. */
export type DbEngine = "mysql" | "postgres";

export const DB_ENGINES: readonly DbEngine[] = ["mysql", "postgres"] as const;

export interface DatabaseRow {
  id: number;
  subscription_id: number;
  engine: DbEngine;
  name: string;
  created_at: string;
  updated_at: string;
}

export interface DbUserRow {
  id: number;
  subscription_id: number;
  engine: DbEngine;
  username: string;
  created_at: string;
  updated_at: string;
}

export interface DatabasesResponse {
  databases: DatabaseRow[];
  users: DbUserRow[];
}

export interface CreateDatabaseRequest {
  name: string;
  engine: DbEngine;
  subscription_id?: number;
  /** An existing user of the same engine and subscription, bound as owner. */
  owner?: string;
}

export interface CreateDatabaseResponse {
  database_id: number;
  name: string;
  engine: DbEngine;
  owner?: string;
}

export interface CreateDbUserRequest {
  username: string;
  engine: DbEngine;
  subscription_id?: number;
}

/**
 * The one and only sighting of a generated password.
 *
 * Returned by both `POST /api/databases/users` and
 * `POST /api/databases/users/{username}/password`. Never persisted anywhere by
 * the panel — not in a task row, not in the audit detail, not here.
 */
export interface DbUserSecret {
  user_id: number;
  username: string;
  engine: DbEngine;
  password: string;
}

/**
 * `GET /api/databases/adminer`.
 *
 * `url` is a **loopback** URL (`http://127.0.0.1:8806/`). It is not a link a
 * browser can follow, and rendering it as one would be a lie — see the card in
 * `routes/databases.tsx`.
 */
export interface AdminerStatus {
  enabled: boolean;
  url: string | null;
  php_version: string | null;
  adminer_version: string;
  pin_provenance: string;
}

export const databasesApi = {
  list: () => api.get<DatabasesResponse>("/api/databases"),
  create: (body: CreateDatabaseRequest) =>
    api.post<CreateDatabaseResponse>("/api/databases", body),
  /**
   * `confirm_name` is retyped by a human and re-checked by the agent, which
   * compares it byte-for-byte against the stored name before it drops
   * anything. Passing the typed value (not the row's) keeps that second gate
   * meaningful.
   */
  drop: (id: number, confirmName: string) =>
    api.del<{ name: string; engine: DbEngine; dropped: boolean }>(
      `/api/databases/${id}?confirm_name=${encodeURIComponent(confirmName)}`,
    ),
  createUser: (body: CreateDbUserRequest) => api.post<DbUserSecret>("/api/databases/users", body),
  dropUser: (username: string) =>
    api.del<{ username: string; engine: DbEngine; dropped: boolean }>(
      `/api/databases/users/${encodeURIComponent(username)}`,
    ),
  resetPassword: (username: string) =>
    api.post<DbUserSecret>(`/api/databases/users/${encodeURIComponent(username)}/password`),
  grant: (database: string, username: string) =>
    api.post<unknown>("/api/databases/grants", { database, username }),
  adminer: () => api.get<AdminerStatus>("/api/databases/adminer"),
  setAdminer: (enable: boolean) => api.post<TaskAccepted>("/api/databases/adminer", { enable }),
};

// ---------------------------------------------------------------------------
// Client-side mirrors of the agent's rules (messages, not boundaries)
// ---------------------------------------------------------------------------

/** Names the engines own. Same list as `unihelm_core::RESERVED_DB_NAMES`. */
const RESERVED_DB_NAMES = new Set([
  "information_schema",
  "mysql",
  "performance_schema",
  "sys",
  "postgres",
  "template0",
  "template1",
]);

/** Why a name would be refused, as an i18n key suffix — or null when it is fine. */
export type DbNameProblem = "required" | "tooLong" | "start" | "charset" | "reserved";

/**
 * The same rule `DbName::parse` applies, in the same order, so the message the
 * operator sees here is the message they would have got from the server.
 */
export function dbNameProblem(raw: string): DbNameProblem | null {
  const value = raw.trim();
  if (value === "") return "required";
  // `DbName` measures bytes; every accepted character is single-byte ASCII, so
  // for anything that could pass, length and byte length agree. A multi-byte
  // string is rejected by the charset rule below in either counting.
  if (value.length > 63) return "tooLong";
  if (!/^[A-Za-z_]/.test(value)) return "start";
  if (!/^[A-Za-z0-9_]+$/.test(value)) return "charset";
  const lower = value.toLowerCase();
  if (RESERVED_DB_NAMES.has(lower) || lower.startsWith("pg_")) return "reserved";
  return null;
}

/**
 * Has the operator retyped the exact name?
 *
 * Surrounding whitespace is forgiven because a copy-paste picks it up and the
 * value we send is trimmed to match; nothing else is. A name that differs by a
 * character or by case is a different database, and the whole point of the
 * gate is that dropping the wrong one takes a deliberate second act.
 */
export function confirmsName(typed: string, name: string): boolean {
  return typed.trim() === name;
}

/**
 * The users that may legitimately be granted on `database`.
 *
 * The agent enforces this too — a grant across engines is meaningless and a
 * grant across subscriptions is a tenancy breach (spec §6.1) — but the UI must
 * not *offer* a pairing that would be refused, because a picker that lists
 * another tenant's usernames has already leaked them.
 */
export function grantableUsers(database: DatabaseRow, users: DbUserRow[]): DbUserRow[] {
  return users.filter(
    (u) => u.engine === database.engine && u.subscription_id === database.subscription_id,
  );
}

/**
 * Copy to the clipboard, reporting whether it actually happened.
 *
 * `navigator.clipboard` needs a secure context and a permission the browser can
 * refuse; a panel reached over plain HTTP on a LAN address is exactly the case
 * where it is missing. Returning false lets the dialog say "select it and copy
 * it yourself" instead of pretending — which, for a password shown once, is the
 * difference between an operator who has it and one who does not.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (!navigator.clipboard?.writeText) return false;
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
