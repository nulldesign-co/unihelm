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
 * 2. **Installing a line that is already there changes nothing.** The agent
 *    checks first and reports the version it found. So the button stays enabled
 *    on a line that is present — disabling it would claim the click is dangerous
 *    when it is the safest one on the page — and the card says what the click
 *    will do *before* it happens, rather than making the operator read a task log
 *    to learn that nothing happened.
 * 3. **Only Node installs from here.** Somebody looking for an "install Python"
 *    button will find out either way; the choice is whether they find out from
 *    this page or from its silence. So it is said at the top, and said again per
 *    runtime in the survey: every runtime the panel knows how to look for and did
 *    not find is listed with where it comes from. Go, Deno and Bun have no signed
 *    repository, and the panel does not fetch a tarball over https and unpack it
 *    as root — but it will happily report one that arrived by other means.
 *
 * Read on demand rather than polled: `runtime.list` shells out to every
 * interpreter it finds for a `--version`, with five seconds of patience for each
 * one, so running it again on every window focus spends a whole survey to learn
 * nothing. An install started here invalidates the list the moment its task
 * settles; anything the panel did not do — a PHP version added on the Stack
 * page, a tarball unpacked over ssh — is picked up the next time the page is
 * opened. The Stack page polls because a package manager is running behind its
 * back and a stale row there is a lie; a row here is at worst a minute old.
 *
 * The two calls below name REST routes the server does not serve yet: both
 * operations are registered with the agent, but nothing exposes them over HTTP.
 * The paths mirror `/api/stack` and `/api/stack/install`, so the missing piece is
 * a `routes/runtimes.rs` handing them to `ops::invoke_now` and `ops::invoke`, and
 * the typed client belongs in `lib/api.ts` next to `installComponent`. Until then
 * the page fails through its error state rather than rendering half a survey.
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

const runtimesApi = {
  list: () => api.get<RuntimeListResponse>("/api/runtimes"),
  install: (major: number) => api.post<TaskAccepted>("/api/runtimes/install", { major }),
};

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

/** `22.11.0` → 22. The same comparison the agent makes before it installs. */
function majorOf(version: string): number {
  return Number.parseInt(version.split(".")[0] ?? "", 10);
}

/** `/usr/bin/python3` → `python3`: the bare name that resolves to this row. */
function commandOf(path: string): string {
  return path.split("/").pop() || path;
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
  const node = rows.filter((row) => row.runtime === "node");

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
        node={node}
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
// Installing a Node line
// ---------------------------------------------------------------------------

function InstallCard({ node, onSettled }: { node: InstalledRuntime[]; onSettled: () => void }) {
  const { t } = useTranslation();
  const [major, setMajor] = useState<number>(DEFAULT_LINE);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Answered before the click, not after it. The agent finds this same row and
  // returns it untouched; saying so here is the difference between a button
  // whose outcome is known and one an operator is afraid to press twice.
  const already = node.find((row) => majorOf(row.version) === major);

  const install = useMutation({
    mutationFn: () => runtimesApi.install(major),
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
              three numbers, and Field's reserved error line would push the
              button out of line with the control it belongs to. */}
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
          <Button type="submit" variant="primary" loading={install.isPending}>
            <Download className="h-4 w-4" aria-hidden />
            {t("runtimes.install.submit")}
          </Button>
        </form>

        {already ? (
          <Callout tone="info" className="mt-3">
            {t("runtimes.install.already", { major, version: already.version })}
          </Callout>
        ) : null}

        <p className="mt-3 text-xs text-ink-muted">{t("runtimes.install.note")}</p>

        {error ? (
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}

        {/* The log, not a chip: apt is the only thing that knows which point
            release it resolved the line to, and it says so as it goes. */}
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
 * Present in full rather than only when somebody asks: "there is no Python here"
 * and "Python is not something this page installs" are different sentences, and
 * an operator hunting for the second one will otherwise read the empty survey as
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
