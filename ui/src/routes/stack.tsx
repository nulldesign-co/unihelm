import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Download, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { SectionHeader } from "@/components/ui/section-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  ApiError,
  endpoints,
  type CatalogueEntry,
  type CatalogueVersion,
  type ComponentState,
  type StackCategory,
  type StackComponentRequest,
  type StackComponentView,
  type StackRuntime,
} from "@/lib/api";
import { staggerStyle } from "@/lib/motion";

/**
 * The Stack Manager (spec §11.1) — the one place anything is installed.
 *
 * This page renders the server's catalogue and nothing else. It used to name
 * nginx, PHP and two database engines in its own source, which is why the panel
 * offered exactly those: the page was a second, quieter copy of the list, and it
 * went stale the moment the agent learned a fifth thing. Every section heading,
 * every row and every version in the menu below comes from the `catalogue` that
 * `stack.status` sends beside the components, so adding an engine is an entry in
 * `unihelm_ops::catalogue` and nothing here at all. They arrive together, in one
 * response, on purpose: joining two independently-polled queries is how a row
 * ends up naming a stale installed version in a Replace warning.
 *
 * Three of the decisions this page makes are worth stating out loud, because
 * each of them is a click an operator cannot take back:
 *
 * 1. **A component the panel did not install offers no button.** `unmanaged` is
 *    nginx serving a dozen vhosts somebody wrote by hand. Install would add a
 *    vendor repository over it and replace a working configuration; Remove is
 *    worse. Neither is ours to press, and the row says so instead.
 * 2. **Only some things can have two versions at once.** PHP can — each site
 *    names its own and gets its own pool. A database cannot: two of them want
 *    one port and one data directory, so choosing a different version *replaces*
 *    what is there. The row says that before the click, in a warning that names
 *    both versions, and the button reads Replace rather than Install.
 * 3. **End-of-life versions are offered.** Somebody migrating a ten-year-old
 *    application needs PHP 7.4 and there is no honest way to refuse them. It is
 *    marked in the menu, and choosing it raises a warning that says what "end of
 *    life" costs — which is the difference between a deliberate choice and an
 *    accident.
 * 4. **Host packages and a container are not the same install.** A container
 *    adds no repository to this server and touches none of its packages, and
 *    two versions that collide on the host — one port, one data directory — are
 *    two containers that do not. So the mode is not decoration: it decides
 *    whether the Replace warning above is true. Every sentence on the row is
 *    chosen against the mode the chooser is on, because a warning that is right
 *    for one mode is a lie in the other, and the operator reads it as a fact
 *    either way.
 */

const TONE: Record<ComponentState, "success" | "accent" | "danger" | "neutral"> = {
  installed: "success",
  installing: "accent",
  removing: "accent",
  failed: "danger",
  absent: "neutral",
  // Neutral, not success: it is there and working, but the panel did not put it
  // there and cannot vouch for how it is configured.
  unmanaged: "neutral",
};

/** A pseudo-version meaning "whatever this release maintains"; not a number. */
const DISTRO_VERSION = "distro";

/** The catalogue entry that installs the container runtime everything else needs. */
const DOCKER_SLUG = "docker";

/** Where the Docker row can be linked to from a row that is waiting on it. */
function entryAnchor(slug: string): string {
  return `stack-entry-${slug}`;
}

/**
 * One category and the entries in it, in the order the server sent them.
 *
 * First appearance decides the order rather than a list of categories held
 * here: a category this build has never heard of still gets a heading and its
 * rows, in the place the catalogue put it, instead of vanishing.
 */
export function groupByCategory(
  entries: readonly CatalogueEntry[],
): { category: StackCategory; entries: CatalogueEntry[] }[] {
  const groups: { category: StackCategory; entries: CatalogueEntry[] }[] = [];
  for (const entry of entries) {
    const group = groups.find((g) => g.category === entry.category);
    if (group) group.entries.push(entry);
    else groups.push({ category: entry.category, entries: [entry] });
  }
  return groups;
}

/**
 * Every row the server has for one entry, whatever state it is in.
 *
 * Matched on `component`, never on `slug`. `slug` is the key of a row in the
 * agent's `stack_components` table and it is versioned where several versions
 * can be installed at once — `php8.3` and `php8.4` are two rows, `mariadb` is
 * one. Grouping on it would find no rows at all for PHP or Node and draw them as
 * "not installed" with an armed Install button, over a live FPM pool.
 */
export function rowsFor(
  entry: CatalogueEntry,
  components: readonly StackComponentView[],
): StackComponentView[] {
  return components.filter((c) => c.component === entry.slug && c.status !== "absent");
}

/**
 * Where one installed row actually lives.
 *
 * An agent older than this panel sends no `runtime` at all, and everything it
 * ever installed is host packages. Reading a missing field as "container" would
 * put "Container" on a chip over an apt package and offer to remove a container
 * that does not exist.
 */
export function runtimeOf(row: StackComponentView): StackRuntime {
  return row.runtime === "container" ? "container" : "host";
}

/** Which modes one entry offers. `either` is the only one that draws a menu. */
export type RuntimeSupport = "host" | "container" | "either";

/**
 * Which modes a row offers, read off the catalogue's list of them.
 *
 * Derived rather than sent as a field of its own, because the catalogue already
 * answers it: an entry that lists both runtimes is a choice, and an entry that
 * lists one is not.
 *
 * An entry that lists nothing runs on the host — which is what every entry did
 * before this existed, and what an agent older than this panel means by sending
 * no `install` block at all. That is why the read is defensive against a field
 * the types say is always there: guessing "either" would draw a chooser the
 * agent cannot honour, and fail every install made from its second option.
 */
export function supportFor(entry: CatalogueEntry): RuntimeSupport {
  const runtimes = entry.install?.runtimes ?? [];
  if (runtimes.includes("host") && runtimes.includes("container")) return "either";
  return runtimes.includes("container") && !runtimes.includes("host") ? "container" : "host";
}

/**
 * Which mode the chooser opens on.
 *
 * On the mode of what is already installed, for the reason `defaultVersionFor`
 * opens on the installed version: a row that loads pointing somewhere else is
 * proposing a migration nobody asked for, and the operator who came to install
 * a second version reads the mode as a description rather than a choice.
 */
export function defaultRuntimeFor(
  entry: CatalogueEntry,
  rows: readonly StackComponentView[],
): StackRuntime {
  const support = supportFor(entry);
  if (support !== "either") return support;
  const held = rows.find((r) => r.status === "installed" || r.status === "removing");
  if (held) return runtimeOf(held);
  return entry.install?.default_runtime === "container" ? "container" : "host";
}

/**
 * Whether several versions can be installed at once *in this mode*.
 *
 * The one place the two modes genuinely disagree, and the reason the mode is on
 * the page at all. MariaDB on the host is one port and one data directory, so a
 * second version replaces the first. As containers it is one container per tool
 * and version — the model `docs/design/containerised-runtimes.md` settles on —
 * each with its own port and its own data, and nothing is replaced by anything.
 *
 * `side_by_side` on the entry is an answer about the host path only; the
 * catalogue says so in as many words. Reading it as the answer for containers
 * is what puts "installing this replaces what is there" under a click that
 * replaces nothing, and that sentence is the one an operator believes.
 *
 * The Replace warning hangs off this, so being wrong here is the page telling
 * somebody their database is about to be taken out when it is not — or not
 * telling them when it is.
 */
export function sideBySideIn(entry: CatalogueEntry, runtime: StackRuntime): boolean {
  return runtime === "container" ? true : entry.side_by_side;
}

/**
 * Whether anything can run as a container on this server at all.
 *
 * `unmanaged` counts. Docker installed by hand is still Docker, and the panel
 * already drives containers it did not create — refusing to use it because a
 * different tool ran the install would be a rule with no reason behind it.
 */
export function dockerReady(components: readonly StackComponentView[]): boolean {
  return components.some(
    (c) => c.component === DOCKER_SLUG && (c.status === "installed" || c.status === "unmanaged"),
  );
}

/**
 * Whether host packages of this engine already hold the machine.
 *
 * The agent refuses a container while they do, and the reason is not tidiness:
 * with a host MariaDB on its socket and a container MariaDB on another port,
 * "create this tenant a database" has two answers, and the wrong one writes a
 * customer's data somewhere nothing will look for it again. So the host install
 * is the incumbent and the container is the one that does not happen.
 *
 * The page has to know this because it draws the button. Left to the agent, the
 * operator picks the mode the design recommends, presses a live Install, and
 * gets a red task explaining a rule the row could have stated before the click.
 *
 * Only `installed` counts, which is the same test the agent applies: an
 * unmanaged host copy is not the panel's, and reinstalling a container the
 * panel already runs has to stay idempotent.
 */
export function hostHoldsEntry(rows: readonly StackComponentView[]): boolean {
  return rows.some((r) => runtimeOf(r) === "host" && r.status === "installed");
}

/**
 * The versions of one entry that are in this machine, in the mode being chosen.
 *
 * Scoped to the mode because presence is what "held" and "replace" are computed
 * from, and a host MariaDB neither occupies a container's port nor gets removed
 * by installing one. Rows themselves stay unfiltered everywhere else: the
 * operator has to see every version that is on the machine, not only the ones
 * matching whichever mode the chooser happens to be on.
 */
function presentVersions(
  rows: readonly StackComponentView[],
  runtime: StackRuntime,
): Set<string> {
  return new Set(
    rows
      .filter((r) => r.status === "installed" || r.status === "removing")
      .filter((r) => runtimeOf(r) === runtime)
      .map((r) => r.version),
  );
}

/**
 * Which version the chooser opens on.
 *
 * A row that can hold one version opens on the one it holds, so nothing reads
 * as a replacement until the operator actually asks for one. Everything else
 * opens on the best version it does *not* have, because a menu already showing
 * an installed version puts a no-op under the Install button.
 *
 * It never opens on an end-of-life version, even when that is all that is left
 * to install. PHP 7.4 is on the menu because somebody migrating needs it, and
 * it stays a version they went and chose rather than the one the page armed the
 * button with while they were reading the summary.
 *
 * Both of those depend on the mode: "the version it holds" and "one at a time"
 * are answers about the host or about containers, never about both.
 */
export function defaultVersionFor(
  entry: CatalogueEntry,
  rows: readonly StackComponentView[],
  runtime: StackRuntime = defaultRuntimeFor(entry, rows),
): string {
  const present = presentVersions(rows, runtime);
  if (!sideBySideIn(entry, runtime)) {
    const held = entry.versions.find((v) => present.has(v.version));
    if (held) return held.version;
  }
  const open = entry.versions.filter((v) => !present.has(v.version));
  const pick =
    open.find((v) => v.recommended) ??
    open.find((v) => !v.eol) ??
    entry.versions.find((v) => v.recommended) ??
    entry.versions.find((v) => !v.eol) ??
    entry.versions[0];
  return pick?.version ?? "";
}

/** What the primary button on a row would do with the selected version. */
export type RowAction =
  | "install"
  // The last attempt at this exact version failed; the click is a second go.
  | "retry"
  // One version at a time: installing this one takes the other one out first.
  | "replace"
  // The selected version is already here. The Remove beside it is the action.
  | "held"
  // Somebody else's install. Neither button belongs to this panel.
  | "none";

export interface RowPlan {
  action: RowAction;
  /** The version a replace would take out. Non-null only for `replace`. */
  replaces: string | null;
  /** Rows the panel has for this entry — installed, failed or mid-operation. */
  rows: StackComponentView[];
  /** On the machine, installed by somebody other than this panel. */
  unmanaged: boolean;
  /** A package manager is running for this entry right now. */
  working: boolean;
  /** Versions still on offer. Empty means there is nothing left to install. */
  offered: CatalogueVersion[];
  /** The version the chooser is on, resolved against the catalogue. */
  selected: CatalogueVersion | null;
  /** The mode this plan was computed for — host packages or a container. */
  runtime: StackRuntime;
  /** Which modes the entry allows. `either` is the only one that gets a menu. */
  support: RuntimeSupport;
  /**
   * A container was chosen and there is no container runtime to put it in.
   *
   * Its own field rather than folding into `action: "none"`: the button still
   * says what the click would do, and the row says why it cannot happen yet.
   */
  dockerMissing: boolean;
  /**
   * A container was chosen and host packages of this engine are already
   * installed, which the agent refuses. Same shape as `dockerMissing`, and for
   * the same reason: a blocked click the row explains rather than a click that
   * reaches the agent and comes back red.
   */
  hostIncumbent: boolean;
}

/**
 * Everything a row needs to decide, in one place and with no rendering in it.
 *
 * Split out because it is the part that must not be wrong: the difference
 * between Install and Replace is a database that is still there and one that is
 * not, and that difference is worth pinning in a test rather than reading off a
 * JSX tree.
 */
export function planFor(
  entry: CatalogueEntry,
  components: readonly StackComponentView[],
  selectedVersion: string,
  runtime: StackRuntime = defaultRuntimeFor(entry, rowsFor(entry, components)),
): RowPlan {
  const rows = rowsFor(entry, components);
  const unmanaged = rows.some((r) => r.status === "unmanaged");
  const working = rows.some((r) => r.status === "installing" || r.status === "removing");
  const present = presentVersions(rows, runtime);
  const selected = entry.versions.find((v) => v.version === selectedVersion) ?? null;
  const offered = entry.versions.filter((v) => !present.has(v.version));
  const support = supportFor(entry);
  const dockerMissing = runtime === "container" && !dockerReady(components);
  const hostIncumbent = runtime === "container" && hostHoldsEntry(rows);
  const shape = {
    rows,
    unmanaged,
    working,
    offered,
    selected,
    runtime,
    support,
    dockerMissing,
    hostIncumbent,
  };

  // Deliberately first: an unmanaged nginx is installed, has no version the
  // panel knows, and every other branch below would offer to act on it.
  if (unmanaged) {
    // No chooser on this row, so nothing here is blocked: a warning about a
    // click the row does not offer is a warning about nothing.
    return { action: "none", replaces: null, ...shape, dockerMissing: false, hostIncumbent: false };
  }

  const held = entry.versions.find((v) => present.has(v.version))?.version ?? null;
  const failed = rows.some(
    (r) => r.status === "failed" && r.version === selectedVersion && runtimeOf(r) === runtime,
  );

  const action: RowAction =
    selected === null || selected.version === ""
      ? "none"
      : present.has(selected.version)
        ? "held"
        : failed
          ? "retry"
          : !sideBySideIn(entry, runtime) && held !== null
            ? "replace"
            : "install";

  return { action, replaces: action === "replace" ? held : null, ...shape };
}

/**
 * `slug@version@mode`, the identity of a row — and of a mutation in flight.
 *
 * The mode is part of it because one version can be on the machine twice, once
 * as packages and once as a container. Without it, removing the container spins
 * the spinner on both chips and the operator cannot tell which one is going.
 */
function keyOf(request: StackComponentRequest | undefined): string | null {
  return request === undefined
    ? null
    : `${request.component}@${request.version ?? ""}@${request.runtime ?? "host"}`;
}

function rowKey(slug: string, version: string, runtime: StackRuntime): string {
  return `${slug}@${version}@${runtime}`;
}

export function StackPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  // Only the rows the operator has actually touched. Anything absent falls back
  // to `defaultVersionFor`, so a refetch that installs a version does not leave
  // the menu pointing at something that is now on the machine.
  const [chosen, setChosen] = useState<Record<string, string>>({});
  // Same rule for the mode: only what the operator touched. Anything absent
  // falls back to `defaultRuntimeFor`, so a row whose container finishes
  // installing stops offering to install it on the host.
  const [chosenRuntime, setChosenRuntime] = useState<Record<string, StackRuntime>>({});

  // True from the moment a button is pressed until the row it changed settles.
  //
  // The status the poll used to key on is written by the agent *after* the task
  // starts, and the invalidate fired before that — so the refetch it triggered
  // saw the old state, found nothing installing, and went back to sleep for
  // twenty seconds. From the operator's side: press install, nothing happens,
  // reload and it is suddenly underway. That reload was doing the work.
  const [justActed, setJustActed] = useState(false);

  const stack = useQuery({
    queryKey: ["stack"],
    queryFn: endpoints.stack,
    // Installs take minutes; keep the page honest while one is running.
    refetchInterval: (query) =>
      justActed ||
      query.state.data?.components.some((c) => c.status === "installing" || c.status === "removing")
        ? 2_000
        : 20_000,
  });

  // Stop the fast poll once the agent's own status agrees something is happening
  // — or has finished. Without this the page polls every two seconds forever
  // after any click.
  useEffect(() => {
    if (!justActed) return;
    const busy = stack.data?.components.some(
      (c) => c.status === "installing" || c.status === "removing",
    );
    if (busy) {
      setJustActed(false);
      return;
    }
    // Nothing is running and nothing has started: give it a few seconds, then
    // fall back to the slow poll rather than hammering forever if the task
    // failed before it ever wrote a status.
    const timer = setTimeout(() => setJustActed(false), 15_000);
    return () => clearTimeout(timer);
  }, [justActed, stack.data]);

  const settle = {
    onSuccess: () => {
      setError(null);
      setJustActed(true);
      void queryClient.invalidateQueries({ queryKey: ["stack"] });
    },
    onError: (e: unknown) => {
      setJustActed(false);
      setError(e instanceof ApiError ? e.message : String(e));
    },
  };

  const install = useMutation({ mutationFn: endpoints.installComponent, ...settle });
  const remove = useMutation({ mutationFn: endpoints.removeComponent, ...settle });

  if (stack.isPending) {
    return (
      <div className="space-y-6">
        <PageHeader title={t("stack.title")} description={t("stack.subtitle")} />
        <CatalogueSkeleton />
      </div>
    );
  }

  if (stack.error) {
    return (
      <div className="space-y-6">
        <PageHeader title={t("stack.title")} description={t("stack.subtitle")} />
        <Callout tone="danger" title={t("stack.loadFailed")}>
          {stack.error instanceof ApiError ? stack.error.message : String(stack.error)}
        </Callout>
      </div>
    );
  }

  const catalogue = stack.data?.catalogue ?? [];
  const components = stack.data?.components ?? [];
  const groups = groupByCategory(catalogue);

  // Only offer to jump to the Docker row if this catalogue actually has one.
  // A link to an anchor that is not on the page is worse than no link: it looks
  // like the panel can fix the problem and then does nothing when clicked.
  const dockerAnchor = catalogue.some((e) => e.slug === DOCKER_SLUG)
    ? `#${entryAnchor(DOCKER_SLUG)}`
    : null;

  // The agent runs one package manager at a time, so every button is disabled
  // while any of them is in flight — but only the row that was clicked spins.
  const busy = install.isPending || remove.isPending;
  const acting = install.isPending
    ? keyOf(install.variables)
    : remove.isPending
      ? keyOf(remove.variables)
      : null;

  return (
    <div className="space-y-6">
      <PageHeader title={t("stack.title")} description={t("stack.subtitle")} />

      {error ? <Callout tone="danger">{error}</Callout> : null}

      {groups.length === 0 ? (
        <EmptyState
          icon={<Boxes aria-hidden />}
          title={t("stack.emptyTitle")}
          hint={t("stack.empty")}
        />
      ) : (
        groups.map((group) => (
          <section
            key={group.category}
            aria-labelledby={`stack-${group.category}`}
            className="space-y-3"
          >
            <SectionHeader
              title={
                <span id={`stack-${group.category}`}>
                  {t(`stack.category.${group.category}`)}
                </span>
              }
              description={t(`stack.categoryHint.${group.category}`)}
            />
            <Card>
              <ul className="divide-y divide-border">
                {group.entries.map((entry, index) => {
                  const rows = rowsFor(entry, components);
                  const runtime = chosenRuntime[entry.slug] ?? defaultRuntimeFor(entry, rows);
                  const selected =
                    chosen[entry.slug] ?? defaultVersionFor(entry, rows, runtime);
                  const plan = planFor(entry, components, selected, runtime);
                  return (
                    <EntryRow
                      key={entry.slug}
                      entry={entry}
                      plan={plan}
                      selected={selected}
                      index={index}
                      busy={busy}
                      acting={acting}
                      dockerAnchor={dockerAnchor}
                      onSelect={(version) =>
                        setChosen((current) => ({ ...current, [entry.slug]: version }))
                      }
                      onSelectRuntime={(next) => {
                        setChosenRuntime((current) => ({ ...current, [entry.slug]: next }));
                        // Drop the version too. What is installed differs by
                        // mode, so the version that was open in the other one is
                        // an answer to a question nobody asked here: switching
                        // to containers on a machine holding MariaDB 11.8 should
                        // land on the recommended version, not on the one the
                        // host copy made the page point at.
                        setChosen((current) => {
                          const { [entry.slug]: _dropped, ...rest } = current;
                          return rest;
                        });
                      }}
                      onInstall={() =>
                        install.mutate({
                          component: entry.slug,
                          version: selected,
                          runtime: plan.runtime,
                        })
                      }
                      onRemove={(version, rowRuntime) =>
                        remove.mutate({ component: entry.slug, version, runtime: rowRuntime })
                      }
                    />
                  );
                })}
              </ul>
            </Card>
          </section>
        ))
      )}

      {(stack.data?.unverified_pins.length ?? 0) > 0 ? (
        <Callout tone="warning" title={t("stack.pinsTitle")}>
          <p>{t("stack.pinsHint")}</p>
          <p className="mt-1.5 font-mono text-xs text-ink-subtle">
            {stack.data!.unverified_pins.join(", ")}
          </p>
        </Callout>
      ) : null}
    </div>
  );
}

/**
 * A version as the menu says it.
 *
 * `distro` is not a number and must not be shown as one — it is the promise
 * "whatever this release maintains", and printing the literal string would have
 * an operator hunting for a version called distro.
 */
function versionLabel(version: string, t: (key: string) => string): string {
  return version === DISTRO_VERSION ? t("stack.distroVersion") : version;
}

function EntryRow({
  entry,
  plan,
  selected,
  index,
  busy,
  acting,
  dockerAnchor,
  onSelect,
  onSelectRuntime,
  onInstall,
  onRemove,
}: {
  entry: CatalogueEntry;
  plan: RowPlan;
  selected: string;
  index: number;
  busy: boolean;
  /** `slug@version@mode` of the mutation in flight, if any. */
  acting: string | null;
  /** Anchor of the row that installs Docker, when this catalogue has one. */
  dockerAnchor: string | null;
  onSelect: (version: string) => void;
  onSelectRuntime: (runtime: StackRuntime) => void;
  onInstall: () => void;
  onRemove: (version: string, runtime: StackRuntime) => void;
}) {
  const { t } = useTranslation();
  const label = (version: string) => versionLabel(version, t);
  const installing = acting === rowKey(entry.slug, selected, plan.runtime);
  const chooserId = `stack-version-${entry.slug}`;
  const runtimeChooserId = `stack-runtime-${entry.slug}`;
  const eol = plan.selected?.eol === true;
  const container = plan.runtime === "container";
  // Worth its own sentence only where the two modes disagree: on the host this
  // engine replaces itself and in a container it does not, which is the whole
  // reason the mode is on the page.
  const gainsSideBySide = container && !entry.side_by_side;

  return (
    <li
      id={entryAnchor(entry.slug)}
      // Reachable as an anchor target from a row that is waiting on this one,
      // and focusable when it is jumped to so a keyboard lands where the eye
      // does — not back at the top of the page.
      tabIndex={-1}
      className="stagger animate-rise-in px-5 py-4 first:pt-5 last:pb-5"
      style={staggerStyle(index)}
    >
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-ink">{entry.display_name}</h3>
          <p className="mt-0.5 max-w-prose text-sm text-ink-muted">{entry.summary}</p>

          {plan.rows.length > 0 ? (
            <ul className="mt-2.5 flex flex-wrap items-center gap-2">
              {plan.rows.map((row) => (
                <InstalledChip
                  key={rowKey(row.slug, row.version, runtimeOf(row))}
                  entry={entry}
                  row={row}
                  support={plan.support}
                  busy={busy}
                  pending={acting === rowKey(entry.slug, row.version, runtimeOf(row))}
                  onRemove={() => onRemove(row.version, runtimeOf(row))}
                />
              ))}
            </ul>
          ) : (
            <p className="mt-2.5 text-sm text-ink-subtle">{t("stack.notInstalled")}</p>
          )}

          {plan.working ? (
            // An install runs for minutes behind a 3s poll. A bar that keeps
            // sweeping says the agent is still working on it; a disabled button
            // on its own is indistinguishable from a page that has stopped.
            <div
              className="shimmer mt-2.5 h-0.5 w-40 max-w-full rounded-full bg-accent-soft"
              aria-hidden
            />
          ) : null}
        </div>

        {plan.unmanaged ? (
          <p className="max-w-56 text-end text-xs text-ink-muted">{t("stack.unmanagedHint")}</p>
        ) : (
          <div className="flex w-full flex-wrap items-end gap-2 sm:w-auto">
            {/* "Nothing left to install" is now an answer about one mode. The
                mode menu stays beside it, because every container version being
                installed is not a reason to strand an operator who came to put
                one on the host — the row would otherwise have no way back. */}
            {plan.offered.length === 0 ? (
              <p className="max-w-56 text-end text-xs text-ink-muted">{t("stack.allInstalled")}</p>
            ) : (
              // Rendered even when there is one version to pick: the label is
              // where "which version am I about to get" is answered, and a row
              // that answers it only sometimes is a row the operator has to
              // read twice.
              <div className="min-w-44 flex-1 space-y-1.5">
                <label htmlFor={chooserId} className="block text-xs font-medium text-ink-muted">
                  {t("stack.chooseVersion")}
                </label>
                <Select
                  id={chooserId}
                  value={selected}
                  disabled={busy}
                  onChange={(event) => onSelect(event.target.value)}
                >
                  {entry.versions.map((version) => (
                    <option key={version.version} value={version.version}>
                      {optionLabel(version, label(version.version), t)}
                    </option>
                  ))}
                </Select>
              </div>
            )}
            {/* Only where both are real. An entry that runs one way is not a
                choice, and a menu with one option in it reads as a decision the
                operator has to make and then cannot. */}
            {plan.support === "either" ? (
              <div className="min-w-40 flex-1 space-y-1.5">
                <label
                  htmlFor={runtimeChooserId}
                  className="block text-xs font-medium text-ink-muted"
                >
                  {t("stack.chooseRuntime")}
                </label>
                <Select
                  id={runtimeChooserId}
                  value={plan.runtime}
                  disabled={busy}
                  onChange={(event) => onSelectRuntime(event.target.value as StackRuntime)}
                >
                  <option value="host">{t("stack.runtime.host")}</option>
                  <option value="container">{t("stack.runtime.container")}</option>
                </Select>
              </div>
            ) : null}
            {plan.offered.length === 0 ? null : (
              <Button
                variant={plan.action === "replace" || eol ? "outline" : "primary"}
                loading={installing}
                // `none` here means the chooser resolved to nothing in the
                // catalogue, so there is no version to send. The other two are
                // clicks that would reach the agent and be refused there; the
                // callouts below say what to do about them instead.
                disabled={
                  busy ||
                  plan.action === "held" ||
                  plan.action === "none" ||
                  plan.dockerMissing ||
                  plan.hostIncumbent
                }
                onClick={onInstall}
                aria-label={t(
                  plan.action === "replace"
                    ? container
                      ? "stack.replaceAriaContainer"
                      : "stack.replaceAria"
                    : container
                      ? "stack.installAriaContainer"
                      : "stack.installAria",
                  {
                    name: entry.display_name,
                    version: label(selected),
                    current: label(plan.replaces ?? ""),
                  },
                )}
              >
                <Download className="h-3.5 w-3.5" aria-hidden />
                {t(
                  plan.action === "replace"
                    ? "stack.replace"
                    : plan.action === "retry"
                      ? "common.retry"
                      : plan.action === "held"
                        ? "stack.state.installed"
                        : "stack.install",
                )}
              </Button>
            )}
          </div>
        )}
      </div>

      {/* Where the operator is choosing, so the promise sits next to the choice:
          the distribution's package and a vendor's are not the same offer, and
          which one this is decides who ships the next security fix. The
          version's own note is not repeated here — it is already in the option
          the operator just read.

          In container mode the source note is not merely less relevant, it is
          false: nothing adds a repository, nothing pins a key, and no package on
          this server moves. So the mode's own sentence replaces it rather than
          sitting beside it. */}
      {!plan.unmanaged && plan.offered.length > 0 && plan.selected ? (
        <p className="mt-2.5 text-xs text-ink-subtle">
          {container
            ? t("stack.runtimeNote.container")
            : t(`stack.source.${plan.selected.source}`)}
          {gainsSideBySide ? ` ${t("stack.runtimeNote.containerSideBySide")}` : null}
        </p>
      ) : null}

      {/* Before the Replace and end-of-life warnings, because it is the one that
          says the click cannot happen at all. */}
      {plan.dockerMissing ? (
        <Callout
          tone="warning"
          className="mt-3"
          title={t("stack.dockerNeededTitle")}
          action={
            dockerAnchor ? (
              <a
                href={dockerAnchor}
                className="font-medium text-accent transition-colors hover:underline"
              >
                {t("stack.dockerNeededLink")}
              </a>
            ) : null
          }
        >
          {t("stack.dockerNeeded")}
        </Callout>
      ) : null}

      {/* Also before Replace: the Remove it points at is on a chip above, so the
          row reads top to bottom as "this is why, and there is the thing to
          press". */}
      {plan.hostIncumbent ? (
        <Callout tone="warning" className="mt-3" title={t("stack.hostIncumbentTitle")}>
          {t("stack.hostIncumbent", { name: entry.display_name })}
        </Callout>
      ) : null}

      {plan.action === "replace" && plan.replaces ? (
        <Callout tone="warning" className="mt-3" title={t("stack.replaceTitle")}>
          {t("stack.replaceWarning", {
            name: entry.display_name,
            current: label(plan.replaces),
            next: label(selected),
          })}
        </Callout>
      ) : null}

      {eol && plan.action !== "held" ? (
        <Callout tone="warning" className="mt-3" title={t("stack.eolTitle")}>
          {t("stack.eolWarning", { name: entry.display_name, version: label(selected) })}
        </Callout>
      ) : null}
    </li>
  );
}

/**
 * One version's option text.
 *
 * The end-of-life mark rides in the option itself rather than only in a warning
 * underneath, because the menu is where the version is picked and a menu that
 * looks uniform is one an operator scrolls through without reading.
 */
function optionLabel(
  version: CatalogueVersion,
  label: string,
  t: (key: string) => string,
): string {
  const marks = [
    version.eol ? t("stack.eol") : version.recommended ? t("stack.recommended") : null,
    version.note || null,
  ].filter(Boolean);
  return marks.length === 0 ? label : `${label} — ${marks.join(", ")}`;
}

/**
 * One version that is on the machine.
 *
 * An unmanaged row carries no Remove: the panel did not install it, does not
 * know what depends on it, and removing it is how a server stops serving.
 */
function InstalledChip({
  entry,
  row,
  support,
  busy,
  pending,
  onRemove,
}: {
  entry: CatalogueEntry;
  row: StackComponentView;
  /** Which modes the entry allows — decides whether "where" is worth saying. */
  support: RuntimeSupport;
  busy: boolean;
  pending: boolean;
  onRemove: () => void;
}) {
  const { t } = useTranslation();
  const removable = row.status === "installed";
  const runtime = runtimeOf(row);
  // Said only where it could have been the other one. Stamping "Host packages"
  // on nginx, which has nowhere else to run, is noise on every row of the page;
  // leaving it off MariaDB is how two chips reading 11.8 and 11.4 look like a
  // contradiction instead of two containers.
  const whereMatters = support === "either";
  // Our bookkeeping and systemd can disagree if somebody removed a package by
  // hand. Say so rather than quietly showing one of the two.
  const disagrees = row.status === "installed" && !row.unit_active;

  return (
    <li className="inline-flex flex-col gap-1">
      <span className="inline-flex items-center gap-2">
        <Badge tone={TONE[row.status]} dot>
          <span className="tnum font-mono">
            {/* An unmanaged row's version is the agent's guess at which of the
                catalogue's versions this is — it has no record of what anybody
                asked for, because it did not install it. Printing the guess as
                a fact is how an operator reads "MariaDB 11.8" off a machine
                running 10.11 and presses Replace on the wrong thing. */}
            {row.status === "unmanaged" ? t("common.unknown") : versionLabel(row.version, t)}
          </span>
          <span className="text-ink-muted">{t(`stack.state.${row.status}`)}</span>
        </Badge>
        {whereMatters ? <Badge tone="neutral">{t(`stack.runtime.${runtime}`)}</Badge> : null}
        {removable ? (
          <Button
            variant="ghost"
            size="sm"
            loading={pending}
            disabled={busy}
            onClick={onRemove}
            aria-label={t(
              runtime === "container" ? "stack.removeAriaContainer" : "stack.removeAria",
              {
                name: entry.display_name,
                version: versionLabel(row.version, t),
              },
            )}
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
            {t("stack.remove")}
          </Button>
        ) : null}
      </span>
      {/* The package manager's own answer, which is the only version on this row
          that nothing inferred. The old table had a column for it; keeping it is
          what lets an operator see that the row above says 11.8 and the machine
          says 10.11. */}
      {row.installed_version ? (
        <span className="tnum font-mono text-xs text-ink-subtle">
          {t("stack.packageVersion", { version: row.installed_version })}
        </span>
      ) : null}
      {disagrees ? <span className="text-xs text-warning">{t("stack.notRunning")}</span> : null}
      {row.last_error ? (
        <span className="max-w-md font-mono text-xs break-words text-danger">{row.last_error}</span>
      ) : null}
    </li>
  );
}

/** Ghost rows in the real shell, so nothing moves when the catalogue lands. */
function CatalogueSkeleton() {
  return (
    <div role="status" aria-live="polite" className="space-y-6">
      {Array.from({ length: 2 }, (_, section) => (
        <section key={section} className="space-y-3">
          <Skeleton className="h-4 w-40" />
          <Card>
            <ul className="divide-y divide-border">
              {Array.from({ length: 3 }, (_, i) => (
                <li
                  key={i}
                  className="stagger animate-rise-in flex items-start justify-between gap-4 px-5 py-4"
                  style={staggerStyle(section * 3 + i)}
                >
                  <div className="min-w-0 flex-1 space-y-2">
                    <Skeleton className="h-4 w-32" />
                    <Skeleton className="h-3 w-72 max-w-full" />
                    <Skeleton className="h-5 w-24 rounded-full" />
                  </div>
                  <Skeleton className="h-9 w-52 rounded-lg" />
                </li>
              ))}
            </ul>
          </Card>
        </section>
      ))}
    </div>
  );
}
