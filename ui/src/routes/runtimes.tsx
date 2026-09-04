import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Boxes, Download } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { TaskLogPanel } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { SectionHeader } from "@/components/ui/section-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { ApiError, api, type TaskAccepted } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";

/**
 * Language runtimes (`runtime.list`, `runtime.install`).
 *
 * The survey is the easy half. What this page has to get right is the three
 * things an operator is wrong about when they arrive:
 *
 * 1. **One version of each runtime is privileged and the rest are not.** A bare
 *    `node` in a cron line, or an app created without a version pinned, resolves
 *    to exactly one binary; every other version on the machine is reachable only
 *    by its absolute path. That is a property of a *row*, so it is a badge on
 *    the row that owns it and names the command — not a "default" column of
 *    yes/no, which puts the answer six columns away from the version it is about.
 * 2. **Installing something already there changes nothing.** The agent checks
 *    first and reports the version it found. So the button stays enabled on a
 *    runtime that is present — disabling it would claim the click is dangerous
 *    when it is the safest one on the page — and the card says what the click
 *    will do *before* it happens, rather than making the operator read a task log
 *    to learn that nothing happened.
 * 3. **Four of the seven install from here, and the other three each have their
 *    own reason.** Node comes from NodeSource; Python, Go and Ruby from the
 *    server's own distribution, which already signs them. PHP is the Stack
 *    page's, because it needs an FPM pool as well as a package. Deno and Bun are
 *    single vendor binaries over https with no signed repository, which this
 *    panel will not unpack as root. Somebody looking for an "install Go" button
 *    finds out either way; the choice is whether they find out from this page or
 *    from its silence. So it is said at the top, and said again per runtime in
 *    the survey — everything the panel knows how to look for and did not find is
 *    listed with where it would come from.
 *
 * The version control changes with the runtime because the runtimes do not
 * offer the same thing. Node has major lines and NodeSource builds each one.
 * Python has whatever lines the distribution shipped — usually one, sometimes
 * two — so the menu is a guess the agent answers honestly when this release does
 * not carry the pick. Go and Ruby have exactly one that lands on `$PATH`, so
 * offering a version box for them would be offering a choice that does not
 * exist.
 *
 * Read on demand rather than polled: `runtime.list` shells out to every
 * interpreter it finds for a `--version`, with five seconds of patience for each
 * one, so running it again on every window focus spends a whole survey to learn
 * nothing. An install started here invalidates the list the moment its task
 * settles; anything the panel did not do — a PHP version added on the Stack
 * page, a tarball unpacked over ssh — is picked up the next time the page is
 * opened. The Stack page polls because a package manager is running behind its
 * back and a stale row there is a lie; a row here is at worst a minute old.
 */

// ---------------------------------------------------------------------------
// Wire shapes (mirrors unihelm-ops `runtimes`)
// ---------------------------------------------------------------------------

/** The seven the panel knows how to look for, in the order the agent reports. */
const RUNTIMES = ["node", "python", "php", "ruby", "go", "deno", "bun"] as const;

type RuntimeName = (typeof RUNTIMES)[number];

interface InstalledRuntime {
  runtime: RuntimeName;
  /** As the binary reports it, e.g. `22.11.0`. */
  version: string;
  /** Absolute, because that is what a systemd unit or a pinned app needs. */
  path: string;
  /** Whether a bare command name resolves to this one. */
  is_default: boolean;
}

interface RuntimeListResponse {
  runtimes: InstalledRuntime[];
}

/** What `runtime.install` takes: a runtime, and a version if it has a choice. */
interface InstallRuntimeRequest {
  runtime: RuntimeName;
  version?: string;
}

const runtimesApi = {
  list: () => api.get<RuntimeListResponse>("/api/runtimes"),
  install: (body: InstallRuntimeRequest) => api.post<TaskAccepted>("/api/runtimes/install", body),
};

/** The four this page installs, in the order the menu offers them. */
const INSTALLABLE = ["node", "python", "go", "ruby"] as const;

type InstallableRuntime = (typeof INSTALLABLE)[number];

/**
 * The Node lines this panel offers.
 *
 * The agent accepts 18 through 40 so a version manager's leftovers still
 * validate, but a menu is a recommendation: these are the lines NodeSource
 * currently builds, and offering a line nobody ships turns a click into a 404
 * halfway through an apt update.
 */
const NODE_LINES = [20, 22, 24] as const;

/** The default choice — the current LTS line, which is what most apps want. */
const DEFAULT_LINE = 22;

/**
 * Python lines a supported release might carry as `python3.X`.
 *
 * A guess, unavoidably: only the server knows what its release shipped, and
 * asking it would mean a second round trip for a menu. Picking one this release
 * does not have costs nothing — the agent answers with what it does have and
 * installs nothing — which is why the menu leads with the distribution's own.
 */
const PYTHON_LINES = ["3.11", "3.12", "3.13"] as const;

/** The empty option: whatever `python3` is on this release. */
const DISTRO_PYTHON = "";

/** `/usr/bin/python3` → `python3`: the bare name that resolves to this row. */
function commandOf(path: string): string {
  return path.split("/").pop() || path;
}

/**
 * Whether an installed version is the one being asked for.
 *
 * Component-wise, the same comparison the agent makes: `3.12` matches `3.12.3`
 * and not `3.1`. A string prefix would call `3.1` a match for `3.12.3` and tell
 * an operator they already had a version they do not have.
 */
function versionMatches(installed: string, wanted: string): boolean {
  const have = installed.split(".");
  return wanted.split(".").every((part, index) => have[index] === part);
}

/**
 * Group the flat list by runtime, keeping each runtime's own order.
 *
 * The API returns rows, not groups, because the CLI renders a list of objects as
 * a table. A table wants them adjacent, and a runtime the panel does not know
 * about would otherwise sort to the front of the list on an `indexOf` of -1.
 */
function grouped(rows: InstalledRuntime[]): InstalledRuntime[] {
  const rank = (row: InstalledRuntime) => {
    const index = RUNTIMES.indexOf(row.runtime);
    return index === -1 ? RUNTIMES.length : index;
  };
  return [...rows].sort((a, b) => rank(a) - rank(b));
}

export function RuntimesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const list = useQuery({
    queryKey: ["runtimes"],
    queryFn: runtimesApi.list,
    // The default 2s would re-survey the machine on every glance at the tab,
    // and a survey is seven `--version` calls deep. Nothing on a server grows a
    // new interpreter between two looks at a browser window; an install that
    // does invalidates this key without waiting for the clock.
    staleTime: 60_000,
  });

  const rows = grouped(list.data?.runtimes ?? []);
  const found = new Set(rows.map((row) => row.runtime));
  const missing = RUNTIMES.filter((runtime) => !found.has(runtime));

  return (
    <div className="space-y-6">
      <PageHeader title={t("runtimes.title")} description={t("runtimes.subtitle")} />

      <Callout tone="info">
        {t("runtimes.scope")}{" "}
        <Link to="/stack" className="font-medium text-accent transition-colors hover:underline">
          {t("runtimes.scopeStack")}
        </Link>
      </Callout>

      <InstallCard
        installed={rows}
        // A finished install is the one thing that changes the survey, so the
        // list refetches exactly then.
        onSettled={() => void queryClient.invalidateQueries({ queryKey: ["runtimes"] })}
      />

      <section className="space-y-3">
        <SectionHeader title={t("runtimes.listTitle")} description={t("runtimes.defaultHint")} />

        {list.isPending ? (
          <RuntimeSkeleton />
        ) : list.error ? (
          <Callout tone="danger">
            {list.error instanceof ApiError ? list.error.message : String(list.error)}
          </Callout>
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<Boxes aria-hidden />}
            title={t("runtimes.emptyTitle")}
            hint={t("runtimes.empty")}
          />
        ) : (
          <RuntimeTable rows={rows} />
        )}
      </section>

      {/* Only once the survey is real: a loading page has "found" nothing, and
          listing all seven as missing while the request is in flight is a
          confident wrong answer. */}
      {!list.isPending && !list.error && missing.length > 0 ? (
        <MissingCard missing={missing} />
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Installing a runtime
// ---------------------------------------------------------------------------

function InstallCard({
  installed,
  onSettled,
}: {
  installed: InstalledRuntime[];
  onSettled: () => void;
}) {
  const { t } = useTranslation();
  const [runtime, setRuntime] = useState<InstallableRuntime>("node");
  const [major, setMajor] = useState<number>(DEFAULT_LINE);
  const [pythonVersion, setPythonVersion] = useState<string>(DISTRO_PYTHON);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Node is asked for by line, Python by line or not at all, and Go and Ruby
  // have only the one the distribution ships — so for those two the field is
  // absent rather than empty, which is what the agent reads as "the one you
  // have".
  const wanted =
    runtime === "node"
      ? String(major)
      : runtime === "python" && pythonVersion !== DISTRO_PYTHON
        ? pythonVersion
        : undefined;

  // Answered before the click, not after it. The agent finds this same row and
  // returns it untouched; saying so here is the difference between a button
  // whose outcome is known and one an operator is afraid to press twice.
  const present = installed.filter((row) => row.runtime === runtime);
  const already = wanted
    ? present.find((row) => versionMatches(row.version, wanted))
    : // With no version asked for, the agent takes the default row and falls
      // back to the first one when nothing is default — a Node that lives only
      // under a version manager has no bare `node`. Matching only on
      // `is_default` would leave the card silent on exactly the machine where
      // the click is about to be answered with "already installed".
      (present.find((row) => row.is_default) ?? present[0]);

  const install = useMutation({
    mutationFn: () => runtimesApi.install({ runtime, version: wanted }),
    onSuccess: (accepted) => {
      setError(null);
      setTaskId(accepted.task_id);
    },
    onError: (e) => {
      setTaskId(null);
      setError(e instanceof ApiError ? e.message : String(e));
    },
  });

  return (
    <Card>
      <CardHeader title={t("runtimes.install.title")} description={t("runtimes.install.hint")} />
      <CardBody>
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            install.mutate();
          }}
        >
          {/* A plain label rather than `Field`: nothing validates a menu of
              names, and Field's reserved error line would push the button out
              of line with the control it belongs to. */}
          <div className="min-w-48 flex-1 space-y-1.5">
            <label htmlFor="runtime-name" className="block text-sm font-medium text-ink">
              {t("runtimes.install.runtime")}
            </label>
            <Select
              id="runtime-name"
              value={runtime}
              onChange={(e) => {
                setRuntime(e.target.value as InstallableRuntime);
                // A task log belonging to the previous runtime is worse than
                // none: it is a finished install of something else, sitting
                // under a form that now says Ruby.
                setTaskId(null);
                setError(null);
              }}
            >
              {INSTALLABLE.map((name) => (
                <option key={name} value={name}>
                  {t(`runtimes.name.${name}`)}
                </option>
              ))}
            </Select>
          </div>

          {runtime === "node" ? (
            <div className="min-w-48 flex-1 space-y-1.5">
              <label htmlFor="runtime-major" className="block text-sm font-medium text-ink">
                {t("runtimes.install.major")}
              </label>
              <Select
                id="runtime-major"
                value={String(major)}
                onChange={(e) => setMajor(Number(e.target.value))}
              >
                {NODE_LINES.map((line) => (
                  <option key={line} value={line}>
                    {t("runtimes.install.line", { major: line })}
                  </option>
                ))}
              </Select>
            </div>
          ) : null}

          {runtime === "python" ? (
            <div className="min-w-48 flex-1 space-y-1.5">
              <label htmlFor="runtime-python" className="block text-sm font-medium text-ink">
                {t("runtimes.install.version")}
              </label>
              <Select
                id="runtime-python"
                value={pythonVersion}
                onChange={(e) => setPythonVersion(e.target.value)}
              >
                <option value={DISTRO_PYTHON}>{t("runtimes.install.distroVersion")}</option>
                {PYTHON_LINES.map((line) => (
                  <option key={line} value={line}>
                    {t("runtimes.install.pythonLine", { version: line })}
                  </option>
                ))}
              </Select>
            </div>
          ) : null}

          <Button type="submit" variant="primary" loading={install.isPending}>
            <Download className="h-4 w-4" aria-hidden />
            {t("runtimes.install.submit")}
          </Button>
        </form>

        {already ? (
          <Callout tone="info" className="mt-3">
            {t("runtimes.install.already", {
              runtime: t(`runtimes.name.${runtime}`),
              version: already.version,
            })}
          </Callout>
        ) : null}

        <p className="mt-3 text-xs text-ink-muted">
          {runtime === "node"
            ? t("runtimes.install.noteNode")
            : runtime === "python"
              ? t("runtimes.install.notePython")
              : t("runtimes.install.noteDistro", { runtime: t(`runtimes.name.${runtime}`) })}
        </p>

        {error ? (
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}

        {/* The log, not a chip: the package manager is the only thing that knows
            which point release it resolved to, and it says so as it goes. */}
        {taskId ? <TaskLogPanel taskId={taskId} onSettled={onSettled} /> : null}
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// What is on the machine
// ---------------------------------------------------------------------------

/** The same table shell the data lands in, so the page does not resize. */
function RuntimeSkeleton() {
  return (
    <div role="status" aria-live="polite">
      <Table className="min-w-[560px]">
        <ColumnHeadings />
        <tbody>
          {Array.from({ length: 4 }, (_, i) => (
            <tr key={i} className="stagger animate-rise-in" style={staggerStyle(i)}>
              <Td>
                <Skeleton className="h-4 w-24" />
              </Td>
              <Td>
                <Skeleton className="h-3.5 w-20" />
              </Td>
              <Td>
                <Skeleton className="h-3.5 w-56 max-w-full" />
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function ColumnHeadings() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th className="w-40">{t("runtimes.runtime")}</Th>
        <Th className="w-56">{t("runtimes.version")}</Th>
        <Th>{t("runtimes.path")}</Th>
      </tr>
    </thead>
  );
}

function RuntimeTable({ rows }: { rows: InstalledRuntime[] }) {
  const { t } = useTranslation();
  return (
    <Table className="min-w-[560px]">
      <ColumnHeadings />
      <tbody>
        {rows.map((row, index) => (
          // The absolute path is the identity: two rows can share a runtime and
          // a version string, but not a location.
          <Tr key={row.path} className="stagger animate-rise-in" style={staggerStyle(index)}>
            <Td className="text-sm font-medium whitespace-nowrap">
              {t(`runtimes.name.${row.runtime}`)}
            </Td>
            <Td>
              <div className="flex flex-wrap items-center gap-2">
                <span className="tnum font-mono text-xs text-ink">{row.version}</span>
                {/* The badge names the command rather than saying "default",
                    because the command is the thing that will actually run. */}
                {row.is_default ? (
                  <Badge tone="accent">
                    {t("runtimes.resolvesHere", { command: commandOf(row.path) })}
                  </Badge>
                ) : null}
              </div>
            </Td>
            <Td className="font-mono text-xs break-all text-ink-subtle">{row.path}</Td>
          </Tr>
        ))}
      </tbody>
    </Table>
  );
}

/**
 * The runtimes the panel looked for and did not find.
 *
 * Present in full rather than only when somebody asks: "there is no Ruby here"
 * and "Ruby is not something this page installs" are different sentences, and an
 * operator hunting for the second one will otherwise read the empty survey as
 * the first.
 */
function MissingCard({ missing }: { missing: readonly RuntimeName[] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader title={t("runtimes.missingTitle")} description={t("runtimes.missingHint")} />
      <CardBody>
        <ul className="divide-y divide-border">
          {missing.map((runtime, index) => (
            <li
              key={runtime}
              className="stagger animate-rise-in py-3 first:pt-0 last:pb-0"
              style={staggerStyle(index)}
            >
              <p className="text-sm font-medium text-ink">{t(`runtimes.name.${runtime}`)}</p>
              <p className="mt-0.5 text-sm text-ink-muted">{t(`runtimes.origin.${runtime}`)}</p>
            </li>
          ))}
        </ul>
      </CardBody>
    </Card>
  );
}
