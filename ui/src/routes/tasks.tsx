import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ListChecks, RotateCw } from "lucide-react";
import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";

import { TaskRow } from "@/components/task-drawer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
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
const STATUSES: TaskStatus[] = ["queued", "running", "ok", "failed", "cancelled"];

/**
 * How many rows a page of history may hold.
 *
 * It was fifty, hard-coded, with no control — so an operator scanning a month of
 * installs paged through it fifty at a time and one reading on a phone got fifty
 * whether or not the device could show them. Fifty stays the default because it
 * is what this page has always done; the rest are here because "fifty, always"
 * is not an answer to "show me more".
 */
export const PAGE_SIZES = [25, 50, 100, 200] as const;

export const DEFAULT_PAGE_SIZE = 50;

/** Which page of the history is on screen, and how big a page is. */
export interface Pagination {
  /** Zero-based; `page + 1` is what the label shows. */
  page: number;
  /** Rows asked for, which is also what "there is more" is measured against. */
  size: number;
}

/**
 * Where a page-size change lands: the first page of the new size.
 *
 * A page index means nothing without the size it was counted in — page 4 of
 * fifty starts at row 151, and of a hundred at row 301. Carrying the index
 * across the change drops the reader past the end of a short history onto an
 * empty page, which on this screen reads as "that is everything" rather than
 * "you moved". Returning the whole pagination is what keeps the two in step:
 * there is no way to change the size here and forget the reset.
 */
export function firstPageOf(size: number): Pagination {
  return { page: 0, size };
}

/**
 * The size behind a `<select>` value, or the default.
 *
 * The value is a string off a DOM event, and `limit=NaN` is a query the server
 * answers with a 400 — a history page that went blank because somebody's
 * extension touched the option list would look exactly like a history page with
 * nothing in it.
 */
export function pageSizeFrom(raw: string): number {
  const size = Number(raw);
  return PAGE_SIZES.some((offered) => offered === size) ? size : DEFAULT_PAGE_SIZE;
}

/**
 * The rows this page covers, 1-based, for the "Tasks X–Y" label.
 *
 * Counted from the size actually in use, not a constant: with the size fixed at
 * fifty, the label was right by accident. `rows` is what came back rather than
 * what was asked for, because the last page is short and a label counting to the
 * full page size would name tasks that are not on screen.
 */
export function pageWindow(pagination: Pagination, rows: number): { from: number; to: number } {
  const first = pagination.page * pagination.size;
  return { from: first + 1, to: first + rows };
}

export function TasksPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<TaskQuery>({});
  const [pagination, setPagination] = useState<Pagination>(firstPageOf(DEFAULT_PAGE_SIZE));
  const [expanded, setExpanded] = useState<string | null>(null);
  const [lagged, setLagged] = useState(false);

  const query: TaskQuery = {
    ...filters,
    limit: pagination.size,
    offset: pagination.page * pagination.size,
  };

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
    setPagination((current) => ({ ...current, page: 0 }));
  };

  const clearFilters = () => {
    setFilters({});
    setPagination((current) => ({ ...current, page: 0 }));
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
              <Badge tone="accent" dot className="tnum">
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

      {/* The stream reconnected and the reader may be missing lines. It is a
          standing warning, not an error, and it can be put away once read. */}
      {lagged ? (
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
      ) : null}

      <Card>
        <CardHeader
          title={t("tasks.filters")}
          action={
            hasFilters ? (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                {t("tasks.filterClear")}
              </Button>
            ) : null
          }
        />
        {/* Field reserves its own error line, which is the row gap here. */}
        <CardBody className="grid gap-x-3 gap-y-1 sm:grid-cols-2 lg:grid-cols-4">
          <Field label={t("tasks.filterOp")} htmlFor="tasks-filter-op">
            <Select
              id="tasks-filter-op"
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
          </Field>

          <Field label={t("tasks.filterStatus")} htmlFor="tasks-filter-status">
            <Select
              id="tasks-filter-status"
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
          </Field>

          <Field label={t("tasks.filterFrom")} htmlFor="tasks-filter-from">
            <Input
              id="tasks-filter-from"
              type="date"
              value={dateInput(filters.since)}
              onChange={(event) => setFilter({ since: startOfDay(event.target.value) })}
            />
          </Field>

          <Field label={t("tasks.filterTo")} htmlFor="tasks-filter-to">
            <Input
              id="tasks-filter-to"
              type="date"
              value={dateInput(filters.until)}
              onChange={(event) => setFilter({ until: endOfDay(event.target.value) })}
            />
          </Field>
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

      <nav
        className="flex flex-wrap items-center justify-between gap-3"
        aria-label={t("tasks.pagination")}
      >
        <Button
          variant="secondary"
          disabled={pagination.page === 0}
          onClick={() => setPagination((p) => ({ ...p, page: p.page - 1 }))}
        >
          {t("tasks.previous")}
        </Button>
        {/* No total comes back with a page, so position is given as the range
            this page covers — "Page 3" on its own says nothing about where
            the reader is in the history. The size sits with the range it
            governs: "Tasks 101–200" and "100 per page" are one fact, and a
            control for it parked among the filters would read as another thing
            that changes which tasks match. */}
        <div className="flex flex-col items-center gap-1.5 text-center text-xs text-ink-subtle">
          <span className="tnum font-medium">
            {t("tasks.page", { page: pagination.page + 1 })}
          </span>
          {list.length > 0 ? (
            <span className="tnum">{t("tasks.showing", pageWindow(pagination, list.length))}</span>
          ) : null}
          <span className="flex items-center gap-2">
            <label htmlFor="tasks-page-size">{t("tasks.perPage")}</label>
            <Select
              id="tasks-page-size"
              className="h-7 w-auto py-0 text-xs"
              value={String(pagination.size)}
              onChange={(event) => setPagination(firstPageOf(pageSizeFrom(event.target.value)))}
            >
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </Select>
          </span>
        </div>
        <Button
          variant="secondary"
          // The API answers with a page, not a count, so "there is more" is
          // "this page is full" — one fewer query on every render. Measured
          // against the chosen size, or asking for 200 and getting 200 would
          // still look like the end of the history.
          disabled={list.length < pagination.size}
          onClick={() => setPagination((p) => ({ ...p, page: p.page + 1 }))}
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
