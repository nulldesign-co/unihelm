/**
 * The WordPress toolkit's client (spec §11.12).
 *
 * Kept out of `lib/api.ts` for the same reason `sites-api.ts` is: that file is
 * the shared client every page imports, and this is one page's surface.
 *
 * Three facts about the server shape everything here and on the page above it:
 *
 * 1. **Installing, updating core and updating plugins are tasks.** They answer
 *    202 with a task id — the work has not happened yet, and everything that
 *    can go wrong afterwards (a checksum that did not match, a download that
 *    died, a plugin whose author pulled the release) is reported by the task
 *    and nowhere else. `queuedTaskId` exists so a caller cannot mistake the
 *    receipt for the outcome.
 * 2. **`wp.install` returns no password, ever.** The database password is
 *    written into `wp-config.php` and the WordPress administrator password is
 *    generated, used once and discarded (`CREDENTIALS_NOTE` in the operation).
 *    On top of that, a task's *output* is not readable through the API at all —
 *    only its log — so even the fields that are returned never reach a browser.
 *    Everything the operator needs to know about credentials has to be said
 *    before they press the button.
 * 3. **The plugin list is WP-CLI's JSON, passed through unmodelled.** The
 *    operation deliberately does not re-shape it, so the fields are WordPress's
 *    to define and this file must read them defensively: `readPluginList`
 *    counts what it could not read rather than dropping it, because a plugin
 *    that vanished from the table is a plugin nobody updates.
 *
 * The `…Problem` functions mirror the agent's validators. They are for the
 * message under the field, not for safety: `unihelm_ops::wordpress` parses
 * every one of these again and its copy is the one that is trusted.
 */

import { api, type BackupRun, type TaskAccepted } from "@/lib/api";

// ---------------------------------------------------------------------------
// Wire shapes (mirrors unihelm-ops `wordpress`)
// ---------------------------------------------------------------------------

/** A row in `wp_installs`: a WordPress the panel itself put there. */
export interface WpInstallRow {
  id: number;
  site_id: number;
  /** Absolute directory holding `wp-config.php`. Panel-derived, never typed. */
  path: string;
  /** Last observed core version; null until something has looked. */
  version: string | null;
  db_id: number | null;
  auto_update: boolean;
  created_at: string;
  updated_at: string;
}

/**
 * `GET /api/wordpress?site_id=…`.
 *
 * `detected` comes from the filesystem and `install` from the database, and the
 * page has to render all four combinations rather than collapsing them:
 * "detected with no row" is a WordPress somebody uploaded, and none of the
 * operations addressed by install id can touch it.
 *
 * `install` and `version` are omitted rather than sent as null, so both are
 * optional here.
 */
export interface WpDetect {
  site_id: number;
  path: string;
  detected: boolean;
  install?: WpInstallRow;
  version?: string;
  wp_cli_version: string;
  /** See `WP_CLI_SHA256`: the pin has one source, and the panel says so. */
  wp_cli_pin_provenance: string;
  wp_cli_installed: boolean;
}

export interface WpInstallRequest {
  site_id: number;
  /** Install into a subdirectory of the document root, e.g. `blog`. */
  subdirectory?: string;
  /** Omitted entirely when unchosen — the agent's default is `en_US`. */
  locale?: string;
  title: string;
  admin_user: string;
  admin_email: string;
}

/**
 * What `wp.install` produces.
 *
 * Typed for completeness, not because a browser sees it: the operation is a
 * task, and a task's output is not exposed by the API.
 */
export interface WpInstallResult {
  install_id: number;
  site_id: number;
  path: string;
  url: string;
  version: string;
  locale: string;
  admin_user: string;
  db_name: string;
  db_user: string;
  credentials_note: string;
}

export interface WpCoreUpdateRequest {
  /** Omitted for "the latest release". */
  version?: string;
  /** `wp core update-db`; the agent's default is true. */
  update_db?: boolean;
}

export interface WpCoreUpdateResult {
  install_id: number;
  from_version: string | null;
  to_version: string;
  database_updated: boolean;
}

export interface WpPluginsResponse {
  install_id: number;
  /** `wp plugin list --format=json`, verbatim. See `readPluginList`. */
  plugins: unknown;
}

export interface WpPluginUpdateResult {
  install_id: number;
  plugins: string[];
  all: boolean;
  output: string;
}

/** The WP-CLI command groups the agent's enum accepts. Anything else is a 400. */
export const WP_SUBCOMMANDS = [
  "core",
  "plugin",
  "theme",
  "option",
  "user",
  "db",
  "cache",
  "rewrite",
] as const;

export type WpSubcommand = (typeof WP_SUBCOMMANDS)[number];

/**
 * `POST /api/wordpress/{id}/cli`.
 *
 * A non-zero `status` is data, not an error: `wp option get missing_key` exits
 * 1, and the page renders that as an exit code rather than as a failure of the
 * panel.
 */
export interface WpCliResult {
  install_id: number;
  /** The exact argv WP-CLI received, `--path` included. Echoed, not guessed. */
  argv: string[];
  status: number;
  stdout: string;
  stderr: string;
}

/** A task's receipt, or — when the agent ran the work inline — its own output. */
export type Queued<T> = TaskAccepted | T;

/**
 * The task id in a response, or null when the response is the finished work.
 *
 * `ops::invoke` answers 202 with a task id for anything the agent turned into a
 * task and 200 with the operation's data otherwise, and the caller cannot know
 * which in advance. Reading the receipt as the outcome is the specific way this
 * page would lie: "WordPress installed" printed over a download that has not
 * started yet.
 */
export function queuedTaskId(response: unknown): string | null {
  if (typeof response !== "object" || response === null) return null;
  const id = (response as { task_id?: unknown }).task_id;
  return typeof id === "string" && id !== "" ? id : null;
}

export const wordpressApi = {
  /**
   * Is there a WordPress on this site?
   *
   * `subdirectory` is sent only when it has been typed: an empty value means
   * the document root, and spelling that as an explicit empty parameter would
   * make two different requests out of one question.
   */
  detect: (siteId: number, subdirectory?: string) =>
    api.get<WpDetect>(
      `/api/wordpress?site_id=${siteId}` +
        (subdirectory ? `&subdirectory=${encodeURIComponent(subdirectory)}` : ""),
    ),
  install: (body: WpInstallRequest) => api.post<Queued<WpInstallResult>>("/api/wordpress", body),
  updateCore: (installId: number, body: WpCoreUpdateRequest) =>
    api.post<Queued<WpCoreUpdateResult>>(`/api/wordpress/${installId}/update`, body),
  plugins: (installId: number) =>
    api.get<WpPluginsResponse>(`/api/wordpress/${installId}/plugins`),
  /** An empty list means every plugin with an update waiting. */
  updatePlugins: (installId: number, plugins: string[]) =>
    api.post<Queued<WpPluginUpdateResult>>(`/api/wordpress/${installId}/plugins/update`, {
      plugins,
    }),
  cli: (installId: number, subcommand: WpSubcommand, args: string[]) =>
    api.post<WpCliResult>(`/api/wordpress/${installId}/cli`, { subcommand, args }),
};

// ---------------------------------------------------------------------------
// Reading WP-CLI's plugin list
// ---------------------------------------------------------------------------

/** One row of `wp plugin list`, narrowed to the fields the table renders. */
export interface WpPlugin {
  name: string;
  /** `active`, `inactive`, `must-use`, `dropin` — WordPress's word, not ours. */
  status: string | null;
  version: string | null;
  /** `available`, `none`, `unavailable`, or something newer than this build. */
  update: string | null;
  update_version: string | null;
}

/**
 * What the panel managed to make of the plugin list.
 *
 * `unreadable` is the whole point of this shape. The operation passes WP-CLI's
 * JSON through untouched, so an entry this build cannot read is possible, and
 * quietly filtering it out would print a table that says "these are your
 * plugins" while one of them is missing — the plugin nobody then updates. It is
 * counted and reported instead.
 *
 * `kind: "unreadable"` is the stronger failure: WP-CLI answered with something
 * that is not a list at all, and an empty table would claim the site has no
 * plugins.
 */
export type PluginListReading =
  | { kind: "plugins"; plugins: WpPlugin[]; unreadable: number }
  | { kind: "unreadable" };

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

export function readPluginList(value: unknown): PluginListReading {
  if (!Array.isArray(value)) return { kind: "unreadable" };

  const plugins: WpPlugin[] = [];
  let unreadable = 0;
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null) {
      unreadable += 1;
      continue;
    }
    const row = entry as Record<string, unknown>;
    // The name is the only field that must be there: it is the row's identity
    // and the slug `wp.plugin.update` is given. A row without one cannot be
    // named on screen and cannot be updated, so it is counted, not shown.
    const name = optionalString(row.name);
    if (name === null) {
      unreadable += 1;
      continue;
    }
    plugins.push({
      name,
      status: optionalString(row.status),
      version: optionalString(row.version),
      update: optionalString(row.update),
      update_version: optionalString(row.update_version),
    });
  }
  return { kind: "plugins", plugins, unreadable };
}

/**
 * Does this plugin have an update waiting?
 *
 * Exactly `available`, WP-CLI's own word. The other values it reports —
 * `none`, `unavailable`, and `version higher than expected` for a plugin ahead
 * of its directory listing — are all "do not update this", and treating an
 * unrecognised value as an update would put a button on a row that has nothing
 * to install.
 */
export function hasUpdate(plugin: WpPlugin): boolean {
  return plugin.update === "available";
}

export function pluginsWithUpdates(plugins: readonly WpPlugin[]): WpPlugin[] {
  return plugins.filter(hasUpdate);
}

// ---------------------------------------------------------------------------
// The backup question an update should answer
// ---------------------------------------------------------------------------

/**
 * The newest finished backup that actually contains this tenant's files.
 *
 * Scope is the load-bearing part. A `panel`-scope run backs up `panel.db`,
 * `/etc/unihelm` and the panel's state directory — not one byte of a tenant
 * home — so counting one as "you have a backup" before replacing a live site's
 * core files would be the worst lie this page could tell. Only a
 * `subscription`-scope run for *this* subscription that finished `ok` counts.
 *
 * A null answer means "nothing in the runs handed to this function", which is
 * not the same as "no backup exists": the page asks for a bounded, recent page
 * of run history, and says so in its copy.
 */
export function lastFileBackup(
  runs: readonly BackupRun[],
  subscriptionId: number,
): BackupRun | null {
  const matching = runs.filter(
    (run) =>
      run.scope === "subscription" &&
      run.subscription_id === subscriptionId &&
      run.status === "ok" &&
      run.finished_at !== null,
  );
  if (matching.length === 0) return null;
  // The list arrives newest-first, but the ordering is the server's business
  // and this answer is used to decide whether to warn somebody before an
  // irreversible change. Picking the maximum makes it independent of that.
  return matching.reduce((newest, run) =>
    (run.finished_at ?? "") > (newest.finished_at ?? "") ? run : newest,
  );
}

// ---------------------------------------------------------------------------
// The agent's rules, mirrored for the field labels
// ---------------------------------------------------------------------------

/**
 * The bytes `unihelm_ops::wordpress::SHELL_METACHARACTERS` refuses.
 *
 * Every one of them is inert through argv — but WP-CLI builds its own
 * `mysql` and `mysqldump` command lines for parts of `wp db`, and the panel's
 * argv discipline does not reach into another program's spawning. The agent
 * filters them for that reason; this list exists so the form says so before the
 * round trip.
 */
const SHELL_METACHARACTERS = ";&|<>`$(){}[]*?!\\\"'\n\r\t";

/** Rust measures every one of these limits in bytes. */
function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

function hasMetacharacter(value: string): boolean {
  return [...value].some((c) => SHELL_METACHARACTERS.includes(c));
}

export type TitleProblem = "required" | "tooLong" | "control" | "metacharacter";

/**
 * Mirrors `validate_title`.
 *
 * A title may be Unicode — it is prose, and it reaches WP-CLI as one argv
 * element where a space cannot split a word. What it may not carry is anything
 * that ends a line or a shell word.
 */
export function titleProblem(raw: string): TitleProblem | null {
  const title = raw.trim();
  if (title === "") return "required";
  if ([...title].length > 200) return "tooLong";
  if (/\p{Cc}/u.test(title)) return "control";
  if (hasMetacharacter(title)) return "metacharacter";
  return null;
}

export type AdminUserProblem = "required" | "length" | "start" | "charset";

/**
 * Mirrors `unihelm_core::Username::parse`, which the install operation reuses
 * for the WordPress login rather than inventing a second set of rules.
 *
 * It lowercases, so the account WordPress ends up with is not always what was
 * typed — the field's hint says so.
 */
export function adminUserProblem(raw: string): AdminUserProblem | null {
  const user = raw.trim().toLowerCase();
  if (user === "") return "required";
  const length = byteLength(user);
  if (length < 3 || length > 32) return "length";
  if (!/^[a-z0-9]/.test(user)) return "start";
  if (!/^[a-z0-9._-]+$/.test(user)) return "charset";
  return null;
}

export type EmailProblem = "required" | "length" | "charset" | "shape";

/**
 * A deliberately loose mirror of `unihelm_core::Email::parse`.
 *
 * The agent's copy is the one that decides; this catches the typo that would
 * otherwise cost a round trip, and in particular the characters that are
 * refused rather than escaped.
 */
export function emailProblem(raw: string): EmailProblem | null {
  const email = raw.trim().toLowerCase();
  if (email === "") return "required";
  const length = byteLength(email);
  if (length < 3 || length > 254) return "length";
  if (/[\u0000-\u001f\u007f ,;]/.test(email)) return "charset";
  const at = email.indexOf("@");
  if (at < 1) return "shape";
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64) return "length";
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) return "shape";
  return null;
}

export type SubdirectoryProblem =
  | "absolute"
  | "backslash"
  | "control"
  | "emptyComponent"
  | "traversal"
  | "tooLong";

/**
 * Mirrors `unihelm_core::TenantPath::parse`.
 *
 * An empty value is not a problem: it is the document root itself, which is
 * where WordPress goes unless somebody asks for a subdirectory.
 */
export function subdirectoryProblem(raw: string): SubdirectoryProblem | null {
  const path = raw.trim();
  if (path === "") return null;
  if (byteLength(path) > 4096) return "tooLong";
  if (path.startsWith("/")) return "absolute";
  if (/[\u0000-\u001f\u007f]/.test(path)) return "control";
  if (path.includes("\\")) return "backslash";
  for (const part of path.split("/")) {
    if (part === "") return "emptyComponent";
    if (part === "." || part === "..") return "traversal";
    if (byteLength(part) > 255) return "tooLong";
  }
  return null;
}

export type LocaleProblem = "shape";

/**
 * Mirrors `WpLocale::parse`.
 *
 * This is the language **WordPress** is installed in — a site's content, not
 * the panel's interface, which is English. An empty value is not a problem: the
 * key is then omitted and the agent's own default (`en_US`) applies.
 */
export function localeProblem(raw: string): LocaleProblem | null {
  const locale = raw.trim();
  if (locale === "") return null;
  const ok =
    locale.length >= 2 &&
    locale.length <= 8 &&
    locale.split("_").length <= 2 &&
    /^[A-Za-z0-9_]+$/.test(locale);
  return ok ? null : "shape";
}

export type CoreVersionProblem = "shape";

/**
 * Mirrors the version check in `wp.update`.
 *
 * Empty means "the latest release", which is what the operation does when the
 * key is absent.
 */
export function coreVersionProblem(raw: string): CoreVersionProblem | null {
  const version = raw.trim();
  if (version === "") return null;
  if (cliArgProblem(version) !== null) return "shape";
  return /^[0-9.-]+$/.test(version) ? null : "shape";
}

/**
 * The WP-CLI global flags the panel keeps for itself.
 *
 * `--require` loads an arbitrary PHP file and `--exec` runs arbitrary PHP, so
 * either of them turns a restricted subcommand into "run any code as the
 * tenant"; `--path` decides which installation is operated on; `--ssh` reaches
 * another machine over a shell; `--http` retargets the command; `--prompt`
 * waits for a terminal that is not there. Mirrored from `RESERVED_WP_FLAGS`.
 */
export const RESERVED_WP_FLAGS = [
  "path",
  "require",
  "exec",
  "ssh",
  "http",
  "prompt",
  "context",
] as const;

/** `MAX_CLI_ARGS` — a bound on the argv, not a WP-CLI limit. */
export const MAX_CLI_ARGS = 32;

/** `MAX_ARG_LEN`, in bytes. */
const MAX_ARG_LEN = 512;

export type CliArgProblem =
  | "empty"
  | "tooLong"
  | "nonAscii"
  | "control"
  | "metacharacter"
  | "malformedFlag"
  | "reservedFlag"
  | "shortFlag";

/**
 * Mirrors `validate_arg`, in its order, so the message names the reason the
 * agent would actually give.
 */
export function cliArgProblem(arg: string): CliArgProblem | null {
  if (arg === "") return "empty";
  if (byteLength(arg) > MAX_ARG_LEN) return "tooLong";
  // eslint-disable-next-line no-control-regex -- the ASCII range is the check
  if (!/^[\u0000-\u007f]*$/.test(arg)) return "nonAscii";
  if (/[\u0000-\u001f\u007f]/.test(arg)) return "control";
  if (hasMetacharacter(arg)) return "metacharacter";

  if (arg.startsWith("--")) {
    const name = arg.slice(2).split("=")[0] ?? "";
    const bare = name.startsWith("no-") ? name.slice(3) : name;
    // Uppercase is caught here rather than by the reserved list, which is the
    // point: `--PATH` and `--no-path` are both refused, so the list is not
    // decoration an exact match could be walked around.
    if (bare === "" || !/^[a-z0-9_-]+$/.test(bare)) return "malformedFlag";
    if ((RESERVED_WP_FLAGS as readonly string[]).includes(bare)) return "reservedFlag";
    return null;
  }
  // `-` alone means stdin to a good many programs, and WP-CLI has no short
  // flags at all.
  if (arg.startsWith("-")) return "shortFlag";
  return null;
}

/**
 * One argument per line.
 *
 * Never split on spaces: `--title=My Blog` is one argv element, and the agent's
 * own tests pin that a legitimate space stays inside one argument rather than
 * becoming two commands' worth of words. Leading and trailing whitespace on a
 * line is trimmed — a trailing space that changed what WP-CLI received while
 * being invisible in the box is a worse surprise than a rule stated in the
 * hint.
 */
export function splitCliArgs(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

export type CliProblem =
  | { kind: "tooMany" }
  | { kind: "interactive" }
  | { kind: "arg"; index: number; problem: CliArgProblem };

/**
 * The whole `wp.cli` request, checked the way `validate_cli_args` checks it.
 *
 * `wp db cli` is refused for a reason worth repeating on the form: with no
 * terminal it blocks until the 25-second timeout kills it, so the failure looks
 * like the panel hanging rather than like a command that cannot work here.
 */
export function cliProblem(subcommand: WpSubcommand, args: readonly string[]): CliProblem | null {
  if (args.length > MAX_CLI_ARGS) return { kind: "tooMany" };
  if (subcommand === "db" && args[0] === "cli") return { kind: "interactive" };
  for (const [index, arg] of args.entries()) {
    const problem = cliArgProblem(arg);
    if (problem !== null) return { kind: "arg", index, problem };
  }
  return null;
}
