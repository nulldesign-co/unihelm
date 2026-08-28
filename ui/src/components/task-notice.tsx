import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Spinner } from "@/components/ui/spinner";
import { api, endpoints, type Task, type TaskStatus } from "@/lib/api";

/**
 * The receipt for a 202, and the live output behind it (spec §11.17).
 *
 * Every slow action in the panel answers with a task id and nothing else, so a
 * page that fires one and says "queued" has told the user the least useful true
 * thing it could. These two pieces poll until the task settles: the chip for the
 * places where a line is enough, the log panel for the places where the output
 * *is* the answer — a `restic backup` says how many files it read and how many
 * bytes it actually uploaded, and that is the whole point of running it by hand.
 *
 * Polling rather than the SSE stream: the stream is a whole-panel subscription
 * the task drawer already owns, and a page that opened a second one would
 * duplicate every event for one task it cares about.
 */

const TONE: Record<TaskStatus, "neutral" | "accent" | "success" | "danger" | "warning"> = {
  queued: "neutral",
  running: "accent",
  ok: "success",
  failed: "danger",
  cancelled: "warning",
};

const isSettled = (status: TaskStatus | undefined) =>
  status !== undefined && status !== "queued" && status !== "running";

/** Poll one task until it stops moving. */
function useTask(taskId: string, onSettled?: (status: TaskStatus) => void) {
  const task = useQuery({
    queryKey: ["task", taskId],
    queryFn: () => api.get<Task>(`/api/tasks/${taskId}`),
    refetchInterval: (query) => (isSettled(query.state.data?.status) ? false : 1_500),
  });

  // Once, even though polling keeps re-rendering afterwards.
  const status = task.data?.status;
  const fired = useRef(false);
  useEffect(() => {
    if (!isSettled(status) || fired.current) return;
    fired.current = true;
    onSettled?.(status!);
  }, [status, onSettled]);

  return task.data;
}

export function TaskNotice({
  taskId,
  onSettled,
}: {
  taskId: string;
  onSettled?: (status: TaskStatus) => void;
}) {
  const { t } = useTranslation();
  const task = useTask(taskId, onSettled);

  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg bg-surface-muted px-3 py-2 text-sm">
      {isSettled(task?.status) ? null : <Spinner className="h-3.5 w-3.5" />}
      <span className="text-ink-muted">
        {t("tasks.title")}{" "}
        <span dir="ltr" className="font-mono text-xs">
          {taskId.slice(0, 8)}
        </span>
      </span>
      {task ? <Badge tone={TONE[task.status]}>{t(`tasks.status.${task.status}`)}</Badge> : null}
      {task?.status === "failed" && task.error_detail ? (
        <span role="alert" dir="auto" className="basis-full text-danger">
          {task.error_detail}
        </span>
      ) : null}
    </div>
  );
}

/**
 * The task's status *and* its output, streamed line by line while it runs.
 *
 * `after_seq` is why this is a poll and not a refetch of the whole log: the
 * agent returns only what is new, so a backup that emits ten thousand lines is
 * ten thousand lines transferred once rather than once per second.
 */
export function TaskLogPanel({
  taskId,
  onSettled,
}: {
  taskId: string;
  onSettled?: (status: TaskStatus) => void;
}) {
  const { t } = useTranslation();
  const task = useTask(taskId, onSettled);
  const bottom = useRef<HTMLDivElement>(null);
  // Accumulated across polls, keyed by the task so a second run starts empty.
  const seen = useRef<{ task: string; lines: { seq: number; line: string }[] }>({
    task: taskId,
    lines: [],
  });
  if (seen.current.task !== taskId) seen.current = { task: taskId, lines: [] };

  const logs = useQuery({
    queryKey: ["task-log-tail", taskId],
    queryFn: async () => {
      const after = seen.current.lines[seen.current.lines.length - 1]?.seq ?? 0;
      const page = await endpoints.taskLogs(taskId, after);
      seen.current.lines = [...seen.current.lines, ...page.lines];
      return seen.current.lines;
    },
    refetchInterval: isSettled(task?.status) ? false : 1_200,
  });

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: "nearest" });
  }, [logs.data]);

  const lines = logs.data ?? [];

  return (
    <div className="mt-3 rounded-lg border border-border bg-canvas">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        {isSettled(task?.status) ? null : <Spinner className="h-3.5 w-3.5" />}
        <span className="text-xs font-medium text-ink-muted">{t("tasks.logs")}</span>
        <span dir="ltr" className="font-mono text-[11px] text-ink-subtle">
          {taskId.slice(0, 8)}
        </span>
        {task ? (
          <Badge tone={TONE[task.status]} className="ms-auto">
            {t(`tasks.status.${task.status}`)}
          </Badge>
        ) : null}
      </div>

      <div className="max-h-64 overflow-y-auto p-3 font-mono text-xs leading-relaxed">
        {lines.length === 0 ? (
          <p className="text-ink-subtle">{t("tasks.noLogs")}</p>
        ) : (
          lines.map((line) => (
            // restic's output is machine text: LTR even on an RTL page, and
            // `break-all` keeps a long path inside the box.
            <div key={line.seq} dir="ltr" className="whitespace-pre-wrap break-all text-ink-muted">
              {line.line}
            </div>
          ))
        )}
        <div ref={bottom} />
      </div>

      {task?.status === "failed" && task.error_detail ? (
        <p role="alert" dir="auto" className="border-t border-border px-3 py-2 text-sm text-danger">
          {task.error_code ? <span className="font-mono">{task.error_code} </span> : null}
          {task.error_detail}
        </p>
      ) : null}
    </div>
  );
}
