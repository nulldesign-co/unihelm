import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListChecks, RotateCcw, X, XCircle } from "lucide-react";
import { Link } from "@tanstack/react-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError, endpoints, type Task, type TaskStatus } from "@/lib/api";
import { useEventStream } from "@/lib/events";
import { useFocusTrap } from "@/lib/focus";

export const TONE: Record<TaskStatus, "neutral" | "accent" | "success" | "danger" | "warning"> = {
  queued: "neutral",
  running: "accent",
  ok: "success",
  failed: "danger",
  cancelled: "warning",
};

/**
 * The task drawer (spec §11.17): a CI-run view for the panel.
 *
 * Every slow action ends up here with its live output, so nothing the panel does
 * is a spinner with no explanation. The drawer is the *recent* view — the last
 * few things, in a panel you can open from anywhere. The full history, with
 * filters, lives on `/tasks` and shares the pieces exported from this file
 * rather than restating them.
 */
export function TaskDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const [selected, setSelected] = useState<string | null>(null);
  const [lagged, setLagged] = useState(false);
  const panelRef = useRef<HTMLElement>(null);
  useFocusTrap(open, panelRef);

  const tasks = useQuery({
    queryKey: ["tasks", {}],
    queryFn: () => endpoints.tasks(),
    enabled: open,
    refetchInterval: open ? 5_000 : false,
  });

  // Escape closes the drawer, like every other overlay on the platform.
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const refetch = tasks.refetch;
  const onState = useCallback(() => void refetch(), [refetch]);
  useEventStream(open, { onState, onLagged: () => setLagged(true) });

  if (!open) return null;

  const list = tasks.data?.tasks ?? [];

  return (
    <div className="fixed inset-0 z-40" role="dialog" aria-modal="true" aria-label={t("tasks.title")}>
      <button
        className="absolute inset-0 animate-fade-in bg-black/40 backdrop-blur-[2px]"
        onClick={onClose}
        aria-label={t("common.close")}
        tabIndex={-1}
      />

      <aside
        ref={panelRef}
        tabIndex={-1}
        className="fixed inset-y-0 end-0 flex w-96 max-w-[90vw] animate-slide-in-end flex-col border-s border-border bg-surface shadow-pop outline-none"
      >
        <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
          <div className="flex items-center gap-2.5">
            <h2 className="text-sm font-semibold text-ink">{t("tasks.title")}</h2>
            {tasks.data && tasks.data.active > 0 ? (
              <Badge tone="accent" dot>
                {t("tasks.active", { count: tasks.data.active })}
              </Badge>
            ) : null}
          </div>
          <div className="flex items-center gap-1">
            <Link
              to="/tasks"
              onClick={onClose}
              className="text-xs font-medium text-accent transition-colors hover:underline"
            >
              {t("tasks.viewAll")}
            </Link>
            <Button variant="ghost" size="icon-sm" onClick={onClose} aria-label={t("common.close")}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </header>

        {/* The same message the history page shows, on the same component: it
            is a standing warning about this session, not an error, and it can
            be put away once read. */}
        {lagged ? (
          <div className="px-5 pt-3">
            <Callout
              tone="warning"
              action={
                <Button variant="ghost" size="sm" onClick={() => setLagged(false)}>
                  {t("common.dismiss")}
                </Button>
              }
            >
              {t("tasks.reconnected")}
            </Callout>
          </div>
        ) : null}

        <div className="flex-1 overflow-y-auto">
          {tasks.isPending ? (
            <div role="status" aria-live="polite" className="divide-y divide-border">
              {Array.from({ length: 6 }, (_, i) => (
                <div key={i} className="flex items-center gap-3 px-5 py-3.5">
                  <Skeleton className="h-6 w-16 rounded-full" />
                  <Skeleton className="h-3.5 flex-1" />
                  <Skeleton className="h-3 w-10" />
                </div>
              ))}
            </div>
          ) : list.length === 0 ? (
            <EmptyState
              className="m-5"
              icon={<ListChecks aria-hidden />}
              title={t("tasks.empty")}
              hint={t("tasks.emptyHint")}
            />
          ) : (
            <ul className="divide-y divide-border">
              {list.map((task) => (
                <TaskRow
                  key={task.id}
                  task={task}
                  expanded={selected === task.id}
                  onToggle={() => setSelected(selected === task.id ? null : task.id)}
                />
              ))}
            </ul>
          )}
        </div>
      </aside>
    </div>
  );
}

/**
 * One row of the list, used by the drawer and by the history page.
 *
 * `showActions` is off in the drawer on purpose: the drawer is a glance at what
 * is happening, and a cancel button one click from a mis-tap is not what a
 * glance should offer.
 */
export function TaskRow({
  task,
  expanded,
  onToggle,
  showActions = false,
}: {
  task: Task;
  expanded: boolean;
  onToggle: () => void;
  showActions?: boolean;
}) {
  const { t, i18n } = useTranslation();

  return (
    <li>
      <button
        onClick={onToggle}
        aria-expanded={expanded}
        className="flex w-full items-center gap-3 px-5 py-3 text-start transition-colors duration-150 hover:bg-surface-muted/60"
      >
        <Badge tone={TONE[task.status]} dot={task.status === "running"}>
          {t(`tasks.status.${task.status}`)}
        </Badge>
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-ink">{task.op}</span>
        <time className="shrink-0 text-xs text-ink-subtle" dateTime={task.created_at}>
          {new Date(task.created_at).toLocaleTimeString(i18n.language)}
        </time>
      </button>

      {task.status === "running" && task.progress > 0 ? (
        // A bare coloured bar says nothing to a screen reader, and "how far
        // along is my restore" is exactly the question this drawer exists to
        // answer. The role and the value carry it; the label names which task.
        <div
          role="progressbar"
          aria-valuenow={Math.round(task.progress)}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={task.op}
          className="mx-5 mb-2 h-1 overflow-hidden rounded-full bg-surface-muted"
        >
          <div
            className="h-full origin-left bg-accent transition-transform duration-500 ease-out-quint"
            style={{ transform: `scaleX(${Math.min(100, Math.max(0, task.progress)) / 100})` }}
          />
        </div>
      ) : null}

      {task.error_detail ? (
        <p className="px-5 pb-3 text-xs text-danger">
          {task.error_code ? <span className="font-mono">{task.error_code} </span> : null}
          {task.error_detail}
        </p>
      ) : null}

      {showActions ? <TaskActions task={task} /> : null}

      {expanded ? <TaskLogs taskId={task.id} live={task.status === "running"} /> : null}
    </li>
  );
}

/**
 * Cancel and retry (spec §11.17).
 *
 * Retry starts a *new* task rather than reviving this one, so the failed row
 * keeps its logs and its reason — that history is the point of the page. Cancel
 * is offered only where the operation declared itself safe to cancel; a button
 * that silently does nothing is worse than no button.
 */
export function TaskActions({ task }: { task: Task }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["tasks"] });
  const onError = (e: unknown) =>
    setError(e instanceof ApiError ? e.message : t("tasks.actionFailed"));

  const cancel = useMutation({
    mutationFn: () => endpoints.cancelTask(task.id),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError,
  });
  const retry = useMutation({
    mutationFn: () => endpoints.retryTask(task.id),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError,
  });

  const finished = task.status === "ok" || task.status === "failed" || task.status === "cancelled";
  const canCancel = task.cancellable && !finished;

  if (!canCancel && !finished) return null;

  return (
    <div className="flex flex-wrap items-center gap-2 px-5 pb-3">
      {canCancel ? (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => cancel.mutate()}
          loading={cancel.isPending}
        >
          <XCircle className="h-3.5 w-3.5" aria-hidden />
          {t("tasks.cancel")}
        </Button>
      ) : null}
      {finished ? (
        <Button variant="ghost" size="sm" onClick={() => retry.mutate()} loading={retry.isPending}>
          <RotateCcw className="h-3.5 w-3.5" aria-hidden />
          {t("tasks.retry")}
        </Button>
      ) : null}
      {error ? (
        <span role="alert" className="text-xs text-danger">
          {error}
        </span>
      ) : null}
    </div>
  );
}

/** A task's log lines, polling while it runs. */
export function TaskLogs({ taskId, live }: { taskId: string; live: boolean }) {
  const { t } = useTranslation();
  const bottom = useRef<HTMLDivElement>(null);

  const logs = useQuery({
    queryKey: ["task-logs", taskId],
    queryFn: () => endpoints.taskLogs(taskId),
    refetchInterval: live ? 1_500 : false,
  });

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: "nearest" });
  }, [logs.data]);

  const lines = logs.data?.lines ?? [];

  return (
    <div className="mx-5 mb-4 rounded-lg border border-border bg-canvas">
      <p className="border-b border-border px-3 py-1.5 text-xs font-medium text-ink-muted">
        {t("tasks.logs")}
      </p>
      <div className="max-h-64 overflow-y-auto p-3 font-mono text-xs leading-relaxed">
        {lines.length === 0 ? (
          <p className="text-ink-subtle">{t("tasks.noLogs")}</p>
        ) : (
          lines.map((line) => (
            <div key={line.seq} className="whitespace-pre-wrap break-all text-ink-muted">
              {line.line}
            </div>
          ))
        )}
        <div ref={bottom} />
      </div>
    </div>
  );
}
