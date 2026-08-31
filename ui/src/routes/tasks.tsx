import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ListChecks, RotateCw } from "lucide-react";
import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";

import { TaskRow } from "@/components/task-drawer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { ListSkeleton } from "@/components/ui/skeleton";
import { endpoints, type TaskQuery, type TaskStatus } from "@/lib/api";
import { useEventStream } from "@/lib/events";

/**
 * The full task history (spec §11.17).
 *
 * "This is how users *see* the panel working — transparency is the antidote to
 * aaPanel's opaque hangs." So this page is a log, not a dashboard: every task
 * the account has ever run, filterable by operation, status and date, with the
 * live output of anything still running.
 *
 * The rows, their logs and the cancel/retry buttons are the drawer's components
 * (`@/components/task-drawer`) rather than a second implementation — a history
 * page whose rows behaved subtly differently from the drawer's would be the
 * exact opposite of transparency.
 */
const PAGE_SIZE = 50;

const STATUSES: TaskStatus[] = ["queued", "running", "ok", "failed", "cancelled"];

export function TasksPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<TaskQuery>({});
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [lagged, setLagged] = useState(false);

  const query: TaskQuery = { ...filters, limit: PAGE_SIZE, offset: page * PAGE_SIZE };

  const tasks = useQuery({
    queryKey: ["tasks", query],
    queryFn: () => endpoints.tasks(query),
    // Keep the previous page on screen while the next one loads, so changing a
    // filter does not blank the list.
    placeholderData: (previous) => previous,
  });

  // A state change anywhere is a reason to re-read this page: it is the screen
  // that claims to show what the panel is doing right now.
  const refresh = useCallback(
    () => void queryClient.invalidateQueries({ queryKey: ["tasks"] }),
    [queryClient],
  );
  useEventStream(true, { onState: refresh, onLagged: () => setLagged(true) });

  const setFilter = (patch: Partial<TaskQuery>) => {
    setFilters((current) => ({ ...current, ...patch }));
    setPage(0);
  };

  const clearFilters = () => {
    setFilters({});
    setPage(0);
  };

  const list = tasks.data?.tasks ?? [];
  const hasFilters = Object.values(filters).some((v) => v !== undefined && v !== "");

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("tasks.pageTitle")}
        description={t("tasks.pageSubtitle")}
        actions={
          <>
            {tasks.data && tasks.data.active > 0 ? (
              <Badge tone="accent" dot>
                {t("tasks.active", { count: tasks.data.active })}
              </Badge>
            ) : null}
            <Button variant="secondary" onClick={refresh}>
              <RotateCw className="h-4 w-4" aria-hidden />
              {t("tasks.refresh")}
            </Button>
          </>
        }
      />

      {lagged ? (
        <p className="rounded-lg bg-warning-soft px-3 py-2 text-xs text-warning">
          {t("tasks.reconnected")}
        </p>
      ) : null}

      <Card>
        <CardBody className="grid gap-3 pt-5 sm:grid-cols-2 lg:grid-cols-4">
          <label className="space-y-1.5">
            <span className="block text-xs font-medium text-ink-muted">{t("tasks.filterOp")}</span>
            <Select
              value={filters.op ?? ""}
              onChange={(event) => setFilter({ op: event.target.value || undefined })}
            >
              <option value="">{t("tasks.filterAny")}</option>
              {(tasks.data?.ops ?? []).map((op) => (
                <option key={op} value={op}>
                  {op}
                </option>
              ))}
            </Select>
          </label>

          <label className="space-y-1.5">
            <span className="block text-xs font-medium text-ink-muted">
              {t("tasks.filterStatus")}
            </span>
            <Select
              value={filters.status ?? ""}
              onChange={(event) =>
                setFilter({ status: (event.target.value as TaskStatus) || undefined })
              }
            >
              <option value="">{t("tasks.filterAny")}</option>
              {STATUSES.map((status) => (
                <option key={status} value={status}>
                  {t(`tasks.status.${status}`)}
                </option>
              ))}
            </Select>
          </label>

          <label className="space-y-1.5">
            <span className="block text-xs font-medium text-ink-muted">{t("tasks.filterFrom")}</span>
            <Input
              type="date"
              value={dateInput(filters.since)}
              onChange={(event) => setFilter({ since: startOfDay(event.target.value) })}
            />
          </label>

          <label className="space-y-1.5">
            <span className="block text-xs font-medium text-ink-muted">{t("tasks.filterTo")}</span>
            <Input
              type="date"
              value={dateInput(filters.until)}
              onChange={(event) => setFilter({ until: endOfDay(event.target.value) })}
            />
          </label>

          {hasFilters ? (
            <div className="sm:col-span-2 lg:col-span-4">
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                {t("tasks.filterClear")}
              </Button>
            </div>
          ) : null}
        </CardBody>
      </Card>

      {tasks.isPending ? (
        <ListSkeleton rows={8} />
      ) : list.length === 0 ? (
        <EmptyState
          icon={<ListChecks aria-hidden />}
          title={hasFilters ? t("tasks.noMatches") : t("tasks.empty")}
          hint={hasFilters ? t("tasks.noMatchesHint") : t("tasks.emptyHint")}
          action={
            hasFilters ? (
              <Button variant="secondary" onClick={clearFilters}>
                {t("tasks.filterClear")}
              </Button>
            ) : undefined
          }
        />
      ) : (
        <Card className="overflow-hidden">
          <ul className="divide-y divide-border">
            {list.map((task) => (
              <TaskRow
                key={task.id}
                task={task}
                expanded={expanded === task.id}
                onToggle={() => setExpanded(expanded === task.id ? null : task.id)}
                showActions
              />
            ))}
          </ul>
        </Card>
      )}

      <nav className="flex items-center justify-between" aria-label={t("tasks.pagination")}>
        <Button variant="secondary" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
          {t("tasks.previous")}
        </Button>
        <span className="text-xs text-ink-subtle">{t("tasks.page", { page: page + 1 })}</span>
        <Button
          variant="secondary"
          // The API answers with a page, not a count, so "there is more" is
          // "this page is full" — one fewer query on every render.
          disabled={list.length < PAGE_SIZE}
          onClick={() => setPage((p) => p + 1)}
        >
          {t("tasks.next")}
        </Button>
      </nav>
    </div>
  );
}

/** `<input type="date">` wants `YYYY-MM-DD`; the API speaks RFC 3339. */
export function dateInput(value: string | undefined): string {
  return value ? value.slice(0, 10) : "";
}

export function startOfDay(day: string): string | undefined {
  return day ? `${day}T00:00:00Z` : undefined;
}

export function endOfDay(day: string): string | undefined {
  // Inclusive: a filter "to the 5th" that dropped everything logged on the 5th
  // would be a date picker that lies.
  return day ? `${day}T23:59:59Z` : undefined;
}
