/**
 * Composing a cron command out of the job somebody actually meant (spec §11.8).
 *
 * The dialog used to be one bare input whose placeholder was `/usr/bin/php
 * ~/cron.php`, so every job had to be written as a shell line by an operator
 * who may never have written one — and on a hosting panel that line is almost
 * always one of three things (call a URL, run WordPress's own cron, run
 * Laravel's scheduler) plus an escape hatch for everything else.
 *
 * What this file deliberately does **not** do is change what is stored. A
 * composed draft becomes a single shell line that goes through `checkCommand`
 * and to the agent exactly as a hand-typed one always did: the builder is a
 * keyboard, not a new wire format, and nothing here is a security boundary —
 * `unihelm_ops::cron` validates the command again and `render_crontab` a third
 * time on the way into the crontab.
 */

import type { DerivedSubscription } from "@/lib/plans-api";

/** The four things people schedule; `custom` is the one that wraps nothing. */
export type JobKind = "url" | "wordpress" | "laravel" | "custom";

export const JOB_KINDS = ["url", "wordpress", "laravel", "custom"] as const;

/**
 * Every field the builder can hold, kept side by side rather than in a union.
 *
 * Switching from WordPress to URL and back should not lose the path that was
 * already typed — a union would drop it, and re-typing a path because you
 * looked at another option is the kind of small punishment that teaches people
 * not to explore the thing that was built to help them.
 */
export interface JobDraft {
  kind: JobKind;
  /** `url`: the address to fetch. */
  url: string;
  /** `wordpress` and `laravel`: the folder the site lives in. */
  path: string;
  /** `custom`: the shell line, verbatim. */
  custom: string;
}

/** A draft that stores exactly what it is given — the escape hatch's shape. */
export function customDraft(command = ""): JobDraft {
  return { kind: "custom", url: "", path: "", custom: command };
}

/**
 * The interpreter the two site templates call.
 *
 * A bare `php` would depend on cron's PATH and on which version the distro
 * made default; an absolute path at least fails loudly and identically on
 * every box. An operator who needs `/opt/remi/php83/root/usr/bin/php` switches
 * to Custom, which is exactly what the escape hatch is for — and switching
 * carries the composed line across, so it is an edit rather than a retype.
 */
export const PHP_BINARY = "/usr/bin/php";

/** Why a draft cannot be composed yet. Same shape as `CommandProblem`. */
export interface DraftProblem {
  key: string;
  params?: Record<string, string | number>;
}

/** Every refusal `draftProblem` can emit, for a translation-coverage check. */
export const JOB_PROBLEM_KEYS = [
  "urlRequired",
  "urlScheme",
  "urlSpace",
  "urlQuote",
  "pathRequired",
  "pathAbsolute",
  "pathQuote",
] as const;

/**
 * Wrap a value for the shell in single quotes.
 *
 * The URL is the case that matters: `curl https://x/y?a=1&b=2` unquoted ends
 * the command at the `&` and backgrounds the front half, which is a job that
 * half-runs and reports nothing. Single quotes suspend every metacharacter
 * except the single quote itself, and a value containing one is *refused*
 * before it reaches here rather than escaped — one rule the operator can read
 * beats a second quoting grammar for this file to get subtly wrong.
 */
function quoted(value: string): string {
  return `'${value}'`;
}

/**
 * Check the fields the chosen template will interpolate.
 *
 * `custom` has nothing to check here on purpose: it is stored verbatim, so the
 * only rules it answers to are the agent's own, which `checkCommand` mirrors
 * against the composed line for every kind alike.
 */
export function draftProblem(draft: JobDraft): DraftProblem | null {
  if (draft.kind === "url") {
    const url = draft.url.trim();
    if (url === "") return { key: "urlRequired" };
    if (!/^https?:\/\/\S/i.test(url)) return { key: "urlScheme" };
    // Anything the shell splits on. The quoting below would survive a space,
    // but a URL with one in it is a typo far more often than it is a plan.
    if (/\s/.test(url)) return { key: "urlSpace" };
    if (url.includes("'")) return { key: "urlQuote" };
    return null;
  }
  if (draft.kind === "wordpress" || draft.kind === "laravel") {
    const path = draft.path.trim();
    if (path === "") return { key: "pathRequired" };
    // `cd '~/example.com'` does not go home: quoting is what stops `&` and `?`
    // from being read as syntax, and it stops `~` from being read as anything
    // at all. A relative path is worse still — cron's working directory is the
    // home directory on some daemons and unspecified on others.
    if (!path.startsWith("/")) return { key: "pathAbsolute" };
    if (path.includes("'")) return { key: "pathQuote" };
    return null;
  }
  return null;
}

/**
 * The single shell line a draft becomes, or null while it still has a problem.
 *
 * Null rather than a best-effort line: a composed command shown next to a red
 * field would be a command nobody is going to run, and the whole point of
 * showing it is that it is the thing that will run.
 */
export function composeCommand(draft: JobDraft): string | null {
  if (draftProblem(draft) !== null) return null;
  switch (draft.kind) {
    case "url":
      // `-f` makes an HTTP error status a non-zero exit and `-sS` keeps curl
      // quiet unless something goes wrong, so cron mails the operator on a
      // failure and stays silent on a success. `-o /dev/null` throws away the
      // body, which is a page nobody wants delivered by mail every hour.
      return `curl -fsS -o /dev/null ${quoted(draft.url.trim())}`;
    case "wordpress":
      // `cd` first, because WordPress and its plugins read paths relative to
      // the working directory, and a wp-cron run from `/` finds a different
      // (or no) configuration.
      return `cd ${quoted(draft.path.trim())} && ${PHP_BINARY} wp-cron.php`;
    case "laravel":
      return `cd ${quoted(draft.path.trim())} && ${PHP_BINARY} artisan schedule:run`;
    case "custom":
      return draft.custom.trim();
  }
}

/**
 * Which builder, if any, could have produced a stored command.
 *
 * Deliberately exact: a command is claimed for a template only when
 * re-composing the recovered draft reproduces it character for character. A
 * looser parser would open `curl -s https://…` in the URL mode and then
 * silently rewrite it to this file's own flags the next time the operator
 * pressed Save — the dialog would be showing one command while another ran.
 * Anything not recognised opens in Custom, where what is shown is what is
 * stored.
 */
export function recogniseCommand(command: string): JobDraft {
  const line = command.trim();
  const url = /^curl -fsS -o \/dev\/null '([^']*)'$/.exec(line);
  const site = /^cd '([^']*)' && \S+ (wp-cron\.php|artisan schedule:run)$/.exec(line);

  const candidates: JobDraft[] = [];
  if (url) candidates.push({ kind: "url", url: url[1] ?? "", path: "", custom: line });
  if (site) {
    candidates.push({
      kind: site[2] === "wp-cron.php" ? "wordpress" : "laravel",
      url: "",
      path: site[1] ?? "",
      custom: line,
    });
  }
  for (const draft of candidates) {
    if (composeCommand(draft) === line) return draft;
  }
  return customDraft(line);
}

/**
 * Whether a schedule fires every minute.
 *
 * Only the Laravel template cares: `artisan schedule:run` is a dispatcher that
 * decides for itself which of the app's tasks are due, so a crontab line that
 * runs it hourly does not run the app's hourly tasks — it runs its every-minute
 * tasks once an hour and skips the rest. The dialog says so rather than
 * quietly changing the schedule under the operator.
 */
export function runsEveryMinute(schedule: string): boolean {
  return schedule.trim().split(/\s+/).join(" ") === "* * * * *";
}

/** The two entries in the subscription picker that are not a subscription. */
export const OWN_SUBSCRIPTION = "own";
export const SUBSCRIPTION_BY_ID = "by-id";

/**
 * What the picker's current selection means for the request body.
 *
 * `own` omits `subscription_id` entirely, which is how the agent is told "the
 * caller's own". The case worth naming is `problem`: an operator who chose
 * "another subscription, by number" and typed nothing has asked for a tenant
 * this cannot name, and creating the job under *them* instead would be the
 * panel answering a question nobody asked — so it refuses and says which field
 * is empty.
 */
export type SubscriptionChoice = { kind: "own" } | { kind: "id"; id: number } | { kind: "problem" };

export function chosenSubscription(choice: string, typedId: string): SubscriptionChoice {
  if (choice === OWN_SUBSCRIPTION) return { kind: "own" };
  // Up to 18 digits: the column is a signed 64-bit id, and anything longer
  // loses precision on the way through `Number` before the agent ever sees it.
  const raw = choice === SUBSCRIPTION_BY_ID ? typedId.trim() : choice;
  if (!/^\d{1,18}$/.test(raw)) return { kind: "problem" };
  return { kind: "id", id: Number(raw) };
}

/**
 * The domains that name a subscription in a one-line option, cut short.
 *
 * A picker's option is one line: a tenant with forty domains would otherwise
 * push the id — the only part that is actually being chosen — off the end of
 * it. Live domains lead because they are the ones the operator recognises as
 * "the sites".
 */
export function subscriptionDomains(
  subscription: DerivedSubscription,
  limit = 3,
): { shown: string[]; more: number } {
  const all = [...subscription.liveDomains, ...subscription.otherDomains];
  return { shown: all.slice(0, limit), more: Math.max(0, all.length - limit) };
}
