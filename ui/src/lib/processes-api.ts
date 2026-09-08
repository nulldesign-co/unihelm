/**
 * The process table's client (spec §11.11; issue 46).
 *
 * Three facts from the agent shape everything here and on the page above it:
 *
 * 1. **The memory column is `RssAnon`, not the resident set.** The service view
 *    learned this the hard way: a cgroup's `MemoryCurrent` carries the page
 *    cache the unit happened to touch, so a database that had just read a table
 *    reported gigabytes beside Docker's 40 MB. `RssAnon` is the per-process form
 *    of the `anon` the Stack page now reports, which is the only way the two
 *    pages can be read against each other. Where a kernel is too old to split
 *    the RSS the agent falls back to `VmRSS` and says so on the row — the page's
 *    job is to keep saying so rather than let a fallback pass for the real
 *    thing.
 * 2. **The poll interval belongs to the server.** `refresh_seconds` comes back
 *    on every listing because the CPU figures are two samples divided, and a
 *    client that polled faster than the counters move would be drawing noise.
 *    {@link pollIntervalMs} is the only place that number becomes a timer, and
 *    it refuses to go below {@link MIN_POLL_MS} whatever the server says.
 * 3. **A kill is confirmed by naming the process, and the name is the
 *    operator's.** The agent compares `confirm_command` and `confirm_user`
 *    against the process actually behind that pid and refuses if either has
 *    moved. Pids are recycled in seconds on a busy machine, so that check is the
 *    difference between a stale row being a refusal and it being a kill of
 *    whatever now holds the number. {@link killRequest} therefore sends what was
 *    typed, never the row's own command.
 */

import { api } from "@/lib/api";

// ---------------------------------------------------------------------------
// Wire shapes (mirrors unihelm-ops `processes`)
// ---------------------------------------------------------------------------

export type ProcessSort = "cpu" | "memory";

export const PROCESS_SORTS: readonly ProcessSort[] = ["cpu", "memory"] as const;

/**
 * Which memory reading a row carries.
 *
 * `anonymous` is what a process is using. `resident` is the whole resident set,
 * shared library pages included, and reads high by however much the process has
 * mapped — never mix the two in one comparison without saying which is which.
 */
export type MemorySource = "anonymous" | "resident";

export type ProcessState =
  | "running"
  | "sleeping"
  | "disk_sleep"
  | "stopped"
  | "zombie"
  | "idle"
  | "unknown";

/** Why the panel will not signal a process. */
export type ProtectionRule = "init" | "panel" | "system_account";

export interface Protection {
  rule: ProtectionRule;
  /**
   * The agent's own sentence, naming the process, the rule and the way to do
   * what the operator wanted instead. Rendered verbatim: it is the same text
   * the kill itself would answer with, and a paraphrase here would be a second
   * source of truth about a machine this page cannot see.
   */
  explanation: string;
}

export interface ProcessTenant {
  subscription_id: number;
  linux_user: string;
}

export interface ProcessRow {
  pid: number;
  ppid: number;
  /** The executable name, capped at 15 characters by the kernel. */
  command: string;
  /** The full argv. Absent for a kernel thread and for a zombie. */
  cmdline?: string;
  uid: number;
  /** Absent for a uid with no `passwd` entry — a number is more honest than a
   *  name invented for it. */
  user?: string;
  state: ProcessState;
  kernel_thread: boolean;
  /** Read `memory_source` before putting this beside another number. */
  memory_bytes: number | null;
  memory_source: MemorySource | null;
  /** Percent of one core, the way `top` reports it. `null` when there was
   *  nothing to measure against — which is not zero. */
  cpu_pct: number | null;
  unit?: string;
  tenant?: ProcessTenant;
  /** Present exactly when a kill would be refused. */
  protected?: Protection;
}

export interface ProcessListResponse {
  processes: ProcessRow[];
  /** Every process on the machine, before the search and the limit. */
  total: number;
  /** How many the search matched; equal to `total` when nothing was searched. */
  matched: number;
  cpu_cores: number;
  /** How far apart the two CPU samples were. Every `cpu_pct` is a rate over
   *  this window and nothing longer. */
  cpu_window_ms: number;
  refresh_seconds: number;
  sort: ProcessSort;
  limit: number;
  /** Why no row carries a tenant, when the panel's database could not be asked. */
  tenant_lookup_error?: string;
}

export type KillSignal = "term" | "kill";

export interface KillRequest {
  pid: number;
  confirm_command: string;
  confirm_user: string;
  signal: KillSignal;
}

export interface KillResponse {
  pid: number;
  command: string;
  user: string | null;
  /** `SIGTERM` or `SIGKILL`, as it was sent. */
  signal: string;
  /** The agent's sentence about what a signal does and does not mean. */
  note: string;
}

export interface ProcessQuery {
  sort: ProcessSort;
  search: string;
}

export const processesApi = {
  list: ({ sort, search }: ProcessQuery) => {
    const params = new URLSearchParams({ sort });
    if (search) params.set("search", search);
    return api.get<ProcessListResponse>(`/api/processes?${params.toString()}`);
  },
  kill: (body: KillRequest) => api.post<KillResponse>("/api/processes/kill", body),
};

// ---------------------------------------------------------------------------
// The three decisions this file owns
// ---------------------------------------------------------------------------

/** Until the first listing says otherwise. The agent's own default is the same. */
export const DEFAULT_REFRESH_SECONDS = 5;

/**
 * The fastest this page will ever ask again, whatever it is told.
 *
 * The kernel accounts CPU in ticks — a hundred a second — and a sweep reads
 * four small files per process, so a sub-second refresh buys noise at a real
 * cost on the machine the operator is already worried about.
 */
export const MIN_POLL_MS = 2_000;

/**
 * How long to wait before asking again.
 *
 * The server's number, floored. A missing or nonsensical `refresh_seconds` —
 * an older agent, a proxy that mangled the body — falls back to the default
 * rather than to "as fast as possible".
 */
export function pollIntervalMs(refreshSeconds: number | undefined | null): number {
  const seconds =
    typeof refreshSeconds === "number" && Number.isFinite(refreshSeconds) && refreshSeconds > 0
      ? refreshSeconds
      : DEFAULT_REFRESH_SECONDS;
  return Math.max(MIN_POLL_MS, Math.round(seconds * 1000));
}

/**
 * Has the operator typed the command they were shown?
 *
 * Surrounding whitespace is forgiven, as the agent forgives it: a pasted value
 * carries it, and refusing that is a puzzle rather than a guard. Nothing else
 * is — a confirmation that matched loosely would confirm a different process.
 */
export function confirmsCommand(typed: string, command: string): boolean {
  return typed.trim() === command.trim();
}

/**
 * The kill request for a row, given what the operator typed.
 *
 * `confirm_command` is the **typed** value, not the row's: sending back the
 * string we were handed would turn the agent's staleness check into a no-op.
 * `confirm_user` is the empty string for a uid with no `passwd` entry, which is
 * both what the row shows and what the agent compares against.
 */
export function killRequest(row: ProcessRow, typed: string, signal: KillSignal): KillRequest {
  return {
    pid: row.pid,
    confirm_command: typed.trim(),
    confirm_user: row.user ?? "",
    signal,
  };
}

/**
 * The owner of a row, as one string.
 *
 * A uid with no account behind it is shown as the number, because that is what
 * is true about it — inventing a name would put a stranger on the row somebody
 * is deciding whether to kill.
 */
export function ownerLabel(row: ProcessRow): string {
  return row.user ?? `uid ${row.uid}`;
}
