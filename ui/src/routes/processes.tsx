import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Search, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { ApiError } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import {
  confirmsCommand,
  killRequest,
  ownerLabel,
  pollIntervalMs,
  processesApi,
  type KillResponse,
  type KillSignal,
  type ProcessListResponse,
  type ProcessRow,
  type ProcessSort,
  type ProcessState,
} from "@/lib/processes-api";
import { useSession } from "@/lib/session";
import { formatBytes, formatPercent } from "@/lib/utils";

/**
 * What is running on this server (spec §11.11; issue 46).
 *
 * Before this page, "the server is slow" ended at the dashboard: it could say
 * the machine was at 96% and not what was using it, so the only way to find out
 * was an SSH session and `top`. Five decisions here are the page rather than
 * its layout.
 *
 * 1. **Read first, and the kill is the small part.** The table is the feature.
 *    Ending a process is one button behind a confirmation, and most rows do not
 *    have it at all — see (4).
 * 2. **The memory column is the same number the Stack page reports.** The agent
 *    sends `RssAnon`, the per-process form of the `anon` a service's row shows,
 *    precisely so the two can be read against each other; a cgroup's whole
 *    charge counts page cache and once had a database reporting gigabytes
 *    beside Docker's 40 MB. Where a kernel is too old to split the RSS the
 *    agent falls back to the whole resident set and says so, and the row keeps
 *    saying so — a fallback the reader cannot see is the same defect with a
 *    different number.
 * 3. **Live is a poll on an interval the operator can read.** The interval is
 *    the server's (`refresh_seconds`, floored), and the header states the one
 *    actually in use rather than leaving it implicit; the caption above the
 *    table states the window the CPU percentages are a rate over. A process
 *    with nothing to measure against shows "—", never 0% — "not measured" and
 *    "idle" are different claims, and on a page about what is busy the second
 *    one is the dangerous half.
 * 4. **The refusal travels with the row.** Every process the agent would not
 *    signal arrives carrying the reason it would not, in the words the kill
 *    itself would use. So a protected row shows "Protected" instead of an End
 *    button, and pressing it explains which rule applies and what to do
 *    instead — usually restarting a service from the Stack page. Deciding that
 *    here would be a weaker second opinion: the uid and the cgroup it is
 *    derived from are only legible on the machine.
 * 5. **The confirmation is typed, and what is typed is what is sent.** Pids are
 *    recycled in seconds on a busy machine. The dialog names the process and
 *    its owner and asks for the command back, and the agent compares that
 *    against whatever now holds the pid — so a row that went stale while the
 *    dialog was open is a refusal rather than a kill of something else. That is
 *    also why no row click ends anything.
 */
export function ProcessesPage() {
  const { t } = useTranslation();
  const { user } = useSession();
  const [sort, setSort] = useState<ProcessSort>("cpu");
  const [typedSearch, setTypedSearch] = useState("");
  const [search, setSearch] = useState("");
  const [target, setTarget] = useState<ProcessRow | null>(null);

  // The list is a request to a machine that is already struggling — that is why
  // somebody opened this page — so keystrokes settle before one is sent.
  useEffect(() => {
    const timer = setTimeout(() => setSearch(typedSearch.trim()), 300);
    return () => clearTimeout(timer);
  }, [typedSearch]);

  const list = useQuery({
    queryKey: ["processes", sort, search],
    queryFn: () => processesApi.list({ sort, search }),
    // The server's interval, floored. The page does not get to choose: the CPU
    // figures are two samples divided, and polling faster than the counters
    // move would draw noise on the machine it is meant to be diagnosing.
    refetchInterval: (query) => pollIntervalMs(query.state.data?.refresh_seconds),
    // Changing the sort or the search keeps the rows on screen while the new
    // answer arrives. A table that empties itself every time somebody types a
    // letter is unreadable at a five-second refresh.
    placeholderData: (previous) => previous,
  });

  const data = list.data;
  const canManage = user?.permissions.includes("server_manage") ?? false;

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("processes.title")}
        description={t("processes.subtitle")}
        actions={
          // Nothing to claim about liveness while the last request failed: the
          // error below is the current state of this page, not a 5-second
          // promise about numbers that are no longer arriving.
          data && !list.error ? (
            <LiveCue interval={pollIntervalMs(data.refresh_seconds)} fetching={list.isFetching} />
          ) : null
        }
      />

      <Callout tone="info" title={t("processes.readingTitle")}>
        {t("processes.reading")}
      </Callout>

      {data?.tenant_lookup_error ? (
        // The agent's own sentence: it says which half of the page is affected
        // and that the rest is current. A blank tenant column with no
        // explanation reads as "these belong to nobody".
        <Callout tone="warning">{data.tenant_lookup_error}</Callout>
      ) : null}

      <div className="flex flex-wrap items-end gap-3">
        <div className="relative min-w-56 flex-1">
          <Search
            className="pointer-events-none absolute inset-y-0 start-3 my-auto h-4 w-4 text-ink-subtle"
            aria-hidden
          />
          <Input
            className="ps-9"
            type="search"
            aria-label={t("processes.searchLabel")}
            placeholder={t("processes.searchPlaceholder")}
            value={typedSearch}
            onChange={(event) => setTypedSearch(event.target.value)}
          />
        </div>
        <div className="w-56">
          <Select
            aria-label={t("processes.sortLabel")}
            value={sort}
            onChange={(event) => setSort(event.target.value as ProcessSort)}
          >
            <option value="cpu">{t("processes.sortCpu")}</option>
            <option value="memory">{t("processes.sortMemory")}</option>
          </Select>
        </div>
      </div>

      {list.isPending ? (
        <TableSkeleton />
      ) : list.error ? (
        <Callout tone="danger" title={t("processes.unavailableTitle")}>
          {list.error instanceof ApiError ? list.error.message : String(list.error)}
        </Callout>
      ) : data ? (
        <ProcessTable data={data} canManage={canManage} search={search} onPick={setTarget} />
      ) : null}

      {target ? (
        // Keyed by pid so a second dialog starts empty rather than inheriting
        // the command typed for a different process.
        <KillDialog key={target.pid} row={target} onClose={() => setTarget(null)} />
      ) : null}
    </div>
  );
}

/**
 * "This page is live, and here is how often."
 *
 * The interval is stated rather than implied by numbers that move: an operator
 * watching a runaway needs to know whether a figure is a second old or a minute
 * old before deciding anything on it.
 */
function LiveCue({ interval, fetching }: { interval: number; fetching: boolean }) {
  const { t } = useTranslation();
  // The interval actually being used, not the one the server asked for. They
  // differ when the server names something below the floor, and a cue that
  // announces a rate the page is not keeping is a small lie about how old the
  // numbers are.
  const seconds = Math.round(interval / 1000);
  return (
    <span className="inline-flex items-center gap-2 text-xs font-medium text-ink-muted">
      <span className="relative grid h-2 w-2 place-items-center" aria-hidden>
        {fetching ? (
          <span className="absolute inset-0 animate-ping-slow rounded-full bg-success" />
        ) : null}
        <span className="relative h-2 w-2 rounded-full bg-success" />
      </span>
      {t("processes.refreshEvery", { seconds })}
    </span>
  );
}

function ProcessTable({
  data,
  canManage,
  search,
  onPick,
}: {
  data: ProcessListResponse;
  canManage: boolean;
  search: string;
  onPick: (row: ProcessRow) => void;
}) {
  const { t } = useTranslation();

  if (data.processes.length === 0) {
    return (
      <EmptyState
        icon={<Activity />}
        title={search ? t("processes.noMatchTitle") : t("processes.noneTitle")}
        hint={search ? t("processes.noMatchHint", { search }) : t("processes.noneHint")}
      />
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-xs text-ink-muted">
        {search
          ? t("processes.showingFiltered", {
              shown: data.processes.length,
              matched: data.matched,
              total: data.total,
            })
          : t("processes.showing", { shown: data.processes.length, total: data.total })}
        {" · "}
        {t("processes.cpuWindow", {
          seconds: (data.cpu_window_ms / 1000).toFixed(1),
          cores: data.cpu_cores,
        })}
      </p>

      <Table className="min-w-[1080px]">
        <thead>
          <tr>
            <Th className="w-20">{t("processes.colPid")}</Th>
            <Th className="w-[280px]">{t("processes.colCommand")}</Th>
            <Th className="w-40">{t("processes.colOwner")}</Th>
            <Th className="w-40">{t("processes.colUnit")}</Th>
            <Th className="w-20 text-end">{t("processes.colCpu")}</Th>
            <Th className="w-24 text-end">{t("processes.colMemory")}</Th>
            <Th className="w-24">{t("processes.colState")}</Th>
            <Th className="w-32">{t("processes.colAction")}</Th>
          </tr>
        </thead>
        <tbody>
          {data.processes.map((row, index) => (
            <ProcessTableRow
              key={row.pid}
              row={row}
              index={index}
              canManage={canManage}
              onPick={onPick}
            />
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function ProcessTableRow({
  row,
  index,
  canManage,
  onPick,
}: {
  row: ProcessRow;
  index: number;
  canManage: boolean;
  onPick: (row: ProcessRow) => void;
}) {
  const { t, i18n } = useTranslation();
  const locale = i18n.language;

  return (
    <Tr className="animate-rise-in stagger" style={staggerStyle(index)}>
      <Td className="font-mono text-xs text-ink-muted tnum">{row.pid}</Td>
      <Td>
        <span className="block truncate font-medium text-ink">{row.command}</span>
        {row.cmdline ? (
          <span className="block truncate font-mono text-xs text-ink-subtle" title={row.cmdline}>
            {row.cmdline}
          </span>
        ) : row.kernel_thread ? (
          <span className="block text-xs text-ink-subtle">{t("processes.kernelThread")}</span>
        ) : null}
      </Td>
      <Td>
        <span className="block truncate text-sm text-ink">{ownerLabel(row)}</span>
        {row.tenant ? (
          <Badge tone="accent" className="mt-0.5">
            {t("processes.tenant", { id: row.tenant.subscription_id })}
          </Badge>
        ) : null}
      </Td>
      <Td className="truncate font-mono text-xs text-ink-muted" title={row.unit ?? undefined}>
        {row.unit ?? t("common.none")}
      </Td>
      <Td className="text-end tnum">
        <CpuCell pct={row.cpu_pct} locale={locale} />
      </Td>
      <Td className="text-end tnum">
        <MemoryCell row={row} locale={locale} />
      </Td>
      <Td>
        <StateBadge state={row.state} />
      </Td>
      <Td>
        {row.protected ? (
          <Button variant="ghost" size="sm" onClick={() => onPick(row)}>
            <ShieldAlert className="h-4 w-4" aria-hidden />
            {t("processes.protected")}
          </Button>
        ) : canManage ? (
          <Button variant="ghost" size="sm" onClick={() => onPick(row)}>
            {t("processes.end")}
          </Button>
        ) : null}
      </Td>
    </Tr>
  );
}

/**
 * A percentage, or an honest blank.
 *
 * `null` is "there was nothing to measure this against" — a process that
 * appeared after the previous sample, or a pid that was reused between the two.
 * Drawing that as 0% on a page about what is busy would be a claim of idleness
 * the panel cannot make.
 */
function CpuCell({ pct, locale }: { pct: number | null; locale: string }) {
  const { t } = useTranslation();
  if (pct === null) {
    return (
      <span className="text-ink-subtle" title={t("processes.cpuUnknown")}>
        {t("common.none")}
      </span>
    );
  }
  return <span className="text-ink">{formatPercent(pct, locale)}</span>;
}

/**
 * The memory reading, with its provenance when that is not the usual one.
 *
 * `anonymous` is the quantity the Stack page reports for a service and needs no
 * mark. `resident` is the fallback on a kernel that does not publish the split,
 * and it reads high by every shared library page the process has mapped — so it
 * is marked, rather than sitting in the same column looking like the same
 * measurement.
 */
function MemoryCell({ row, locale }: { row: ProcessRow; locale: string }) {
  const { t } = useTranslation();
  return (
    <span className="text-ink">
      {formatBytes(row.memory_bytes, locale)}
      {row.memory_source === "resident" ? (
        <span className="ms-1 text-xs text-warning" title={t("processes.residentHint")}>
          {t("processes.residentTag")}
        </span>
      ) : null}
    </span>
  );
}

function StateBadge({ state }: { state: ProcessState }) {
  const { t } = useTranslation();
  const label: Record<ProcessState, string> = {
    running: t("processes.state.running"),
    sleeping: t("processes.state.sleeping"),
    disk_sleep: t("processes.state.diskSleep"),
    stopped: t("processes.state.stopped"),
    zombie: t("processes.state.zombie"),
    idle: t("processes.state.idle"),
    unknown: t("processes.state.unknown"),
  };
  const tone: Record<ProcessState, "success" | "warning" | "neutral"> = {
    running: "success",
    // Not a busy process: one stuck waiting on I/O that cannot be interrupted.
    // A pile of these is a disk problem, which killing helps with not at all.
    disk_sleep: "warning",
    stopped: "warning",
    zombie: "warning",
    sleeping: "neutral",
    idle: "neutral",
    unknown: "neutral",
  };
  return <Badge tone={tone[state]}>{label[state]}</Badge>;
}

function TableSkeleton() {
  return (
    <div role="status" aria-live="polite" className="space-y-2">
      <Skeleton className="h-4 w-64" />
      <Table className="min-w-[1080px]">
        <tbody>
          {Array.from({ length: 8 }, (_, i) => (
            <tr key={i}>
              <Td colSpan={8}>
                <div className="flex animate-rise-in items-center gap-3 stagger" style={staggerStyle(i)}>
                  <Skeleton className="h-4 w-12" />
                  <Skeleton className="h-4 flex-1" />
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-4 w-16" />
                </div>
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

/**
 * End one process, having said which one out loud.
 *
 * Three shapes, and which one appears is decided by the server, not here:
 *
 * - **Protected.** The row arrived with the reason a kill would be refused, so
 *   the dialog shows that sentence and offers nothing else. It is the same text
 *   the API would answer with, and it names the way to do what the operator
 *   wanted — restart the unit, use the Stack page — rather than just saying no.
 * - **Sent.** The agent's note, verbatim. A signal is a request: SIGTERM may be
 *   ignored, and SIGKILL cannot end a process stuck in uninterruptible I/O. The
 *   panel never claims the process exited, because it did not watch it exit.
 * - **Otherwise**, the confirmation: what is about to be signalled, whose it is,
 *   what the two signals cost, and the command typed back.
 */
function KillDialog({ row, onClose }: { row: ProcessRow; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [typed, setTyped] = useState("");
  const [signal, setSignal] = useState<KillSignal>("term");
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<KillResponse | null>(null);

  const armed = confirmsCommand(typed, row.command);

  const send = useMutation({
    mutationFn: () => processesApi.kill(killRequest(row, typed, signal)),
    onSuccess: (response) => {
      setSent(response);
      // Not closed: the note is the answer, and it says the process may still
      // be there. The list refreshes underneath so the next poll shows whether
      // it went.
      void queryClient.invalidateQueries({ queryKey: ["processes"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  if (row.protected) {
    return (
      <Dialog
        open
        onClose={onClose}
        title={t("processes.protectedTitle", { command: row.command })}
        footer={
          <Button variant="secondary" onClick={onClose}>
            {t("common.close")}
          </Button>
        }
      >
        <Callout tone="warning" title={t("processes.protectedHeading")}>
          {row.protected.explanation}
        </Callout>
      </Dialog>
    );
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("processes.killTitle", { pid: row.pid, command: row.command })}
      description={sent ? undefined : t("processes.killHint")}
      footer={
        sent ? (
          <Button variant="secondary" onClick={onClose}>
            {t("common.close")}
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="danger"
              disabled={!armed}
              loading={send.isPending}
              onClick={() => {
                setError(null);
                send.mutate();
              }}
            >
              {t("processes.killConfirm")}
            </Button>
          </>
        )
      }
    >
      {sent ? (
        <Callout tone="info" title={t("processes.sentTitle", { signal: sent.signal })}>
          {sent.note}
        </Callout>
      ) : (
        <div className="space-y-3">
          <dl className="space-y-1.5 rounded-card border border-border bg-surface-muted/40 px-4 py-3 text-sm">
            <DetailRow label={t("processes.colPid")} value={String(row.pid)} />
            <DetailRow label={t("processes.colOwner")} value={ownerLabel(row)} />
            {row.tenant ? (
              <DetailRow
                label={t("processes.tenantLabel")}
                value={t("processes.tenant", { id: row.tenant.subscription_id })}
              />
            ) : null}
            {row.cmdline ? (
              <DetailRow label={t("processes.colCommand")} value={row.cmdline} />
            ) : null}
            <DetailRow
              label={t("processes.colMemory")}
              value={formatBytes(row.memory_bytes, i18n.language)}
            />
          </dl>

          <Field label={t("processes.signalLabel")} htmlFor="process-kill-signal">
            <Select
              id="process-kill-signal"
              value={signal}
              onChange={(event) => setSignal(event.target.value as KillSignal)}
            >
              <option value="term">{t("processes.signalTerm")}</option>
              <option value="kill">{t("processes.signalKill")}</option>
            </Select>
          </Field>

          <Callout tone="danger" title={t("processes.costTitle")}>
            {signal === "term" ? t("processes.costTerm") : t("processes.costKill")}
          </Callout>

          <Field
            label={t("processes.typeCommand", { command: row.command })}
            htmlFor="process-kill-confirm"
            error={typed.length > 0 && !armed ? t("processes.commandMismatch") : undefined}
          >
            <Input
              id="process-kill-confirm"
              autoComplete="off"
              autoFocus
              placeholder={row.command}
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
            />
          </Field>

          {error ? (
            <p role="alert" className="text-sm text-danger">
              {error}
            </p>
          ) : null}
        </div>
      )}
    </Dialog>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="shrink-0 text-ink-muted">{label}</dt>
      <dd className="min-w-0 truncate text-end font-mono text-xs text-ink" title={value}>
        {value}
      </dd>
    </div>
  );
}
