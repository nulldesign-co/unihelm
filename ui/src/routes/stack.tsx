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

/** The versions of one entry that are on this machine right now. */
function presentVersions(rows: readonly StackComponentView[]): Set<string> {
  return new Set(
    rows
      .filter((r) => r.status === "installed" || r.status === "removing")
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
 */
export function defaultVersionFor(
  entry: CatalogueEntry,
  rows: readonly StackComponentView[],
): string {
  const present = presentVersions(rows);
  if (!entry.side_by_side) {
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
): RowPlan {
  const rows = rowsFor(entry, components);
  const unmanaged = rows.some((r) => r.status === "unmanaged");
  const working = rows.some((r) => r.status === "installing" || r.status === "removing");
  const present = presentVersions(rows);
  const selected = entry.versions.find((v) => v.version === selectedVersion) ?? null;
  const offered = entry.versions.filter((v) => !present.has(v.version));

  // Deliberately first: an unmanaged nginx is installed, has no version the
  // panel knows, and every other branch below would offer to act on it.
  if (unmanaged) {
    return { action: "none", replaces: null, rows, unmanaged, working, offered, selected };
  }

  const held = entry.versions.find((v) => present.has(v.version))?.version ?? null;
  const failed = rows.some((r) => r.status === "failed" && r.version === selectedVersion);

  const action: RowAction =
    selected === null || selected.version === ""
      ? "none"
      : present.has(selected.version)
        ? "held"
        : failed
          ? "retry"
          : !entry.side_by_side && held !== null
            ? "replace"
            : "install";

  return {
    action,
    replaces: action === "replace" ? held : null,
    rows,
    unmanaged,
    working,
    offered,
    selected,
  };
}

/** `slug@version`, the identity of a row — and of a mutation in flight. */
function keyOf(request: StackComponentRequest | undefined): string | null {
  return request === undefined ? null : `${request.component}@${request.version ?? ""}`;
}

export function StackPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  // Only the rows the operator has actually touched. Anything absent falls back
  // to `defaultVersionFor`, so a refetch that installs a version does not leave
  // the menu pointing at something that is now on the machine.
  const [chosen, setChosen] = useState<Record<string, string>>({});

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
                  const selected =
                    chosen[entry.slug] ?? defaultVersionFor(entry, rowsFor(entry, components));
                  const plan = planFor(entry, components, selected);
                  return (
                    <EntryRow
                      key={entry.slug}
                      entry={entry}
                      plan={plan}
                      selected={selected}
                      index={index}
                      busy={busy}
                      acting={acting}
                      onSelect={(version) =>
                        setChosen((current) => ({ ...current, [entry.slug]: version }))
                      }
                      onInstall={() => install.mutate({ component: entry.slug, version: selected })}
                      onRemove={(version) =>
                        remove.mutate({ component: entry.slug, version })
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
  onSelect,
  onInstall,
  onRemove,
}: {
  entry: CatalogueEntry;
  plan: RowPlan;
  selected: string;
  index: number;
  busy: boolean;
  /** `slug@version` of the mutation in flight, if any. */
  acting: string | null;
  onSelect: (version: string) => void;
  onInstall: () => void;
  onRemove: (version: string) => void;
}) {
  const { t } = useTranslation();
  const label = (version: string) => versionLabel(version, t);
  const installing = acting === `${entry.slug}@${selected}`;
  const chooserId = `stack-version-${entry.slug}`;
  const eol = plan.selected?.eol === true;

  return (
    <li
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
                  key={row.slug}
                  entry={entry}
                  row={row}
                  busy={busy}
                  pending={acting === `${entry.slug}@${row.version}`}
                  onRemove={() => onRemove(row.version)}
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
        ) : plan.offered.length === 0 ? (
          <p className="max-w-56 text-end text-xs text-ink-muted">{t("stack.allInstalled")}</p>
        ) : (
          <div className="flex w-full flex-wrap items-end gap-2 sm:w-auto">
            {/* Rendered even when there is one version to pick: the label is
                where "which version am I about to get" is answered, and a row
                that answers it only sometimes is a row the operator has to
                read twice. */}
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
            <Button
              variant={plan.action === "replace" || eol ? "outline" : "primary"}
              loading={installing}
              // `none` here means the chooser resolved to nothing in the
              // catalogue, so there is no version to send.
              disabled={busy || plan.action === "held" || plan.action === "none"}
              onClick={onInstall}
              aria-label={t(
                plan.action === "replace" ? "stack.replaceAria" : "stack.installAria",
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
          </div>
        )}
      </div>

      {/* Where the operator is choosing, so the promise sits next to the choice:
          the distribution's package and a vendor's are not the same offer, and
          which one this is decides who ships the next security fix. The
          version's own note is not repeated here — it is already in the option
          the operator just read. */}
      {!plan.unmanaged && plan.offered.length > 0 && plan.selected ? (
        <p className="mt-2.5 text-xs text-ink-subtle">
          {t(`stack.source.${plan.selected.source}`)}
        </p>
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
  busy,
  pending,
  onRemove,
}: {
  entry: CatalogueEntry;
  row: StackComponentView;
  busy: boolean;
  pending: boolean;
  onRemove: () => void;
}) {
  const { t } = useTranslation();
  const removable = row.status === "installed";
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
        {removable ? (
          <Button
            variant="ghost"
            size="sm"
            loading={pending}
            disabled={busy}
            onClick={onRemove}
            aria-label={t("stack.removeAria", {
              name: entry.display_name,
              version: versionLabel(row.version, t),
            })}
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
