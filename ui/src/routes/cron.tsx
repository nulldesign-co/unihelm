import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Clock, Pencil, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { ScheduleField, ScheduleText, useScheduleProblem } from "@/components/schedule-field";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { Menu, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { ApiError, endpoints, type CronJob, type CronSetRequest } from "@/lib/api";
import { checkCommand } from "@/lib/cron-schedule";
import { staggerStyle } from "@/lib/motion";
import { cn } from "@/lib/utils";

/**
 * Cron jobs (spec §11.8).
 *
 * A tenant's crontab is a rendering of the panel database, not a file anybody
 * edits, so every row here is a row the agent will re-render into `crontab -u`.
 * Two consequences shape the page:
 *
 * 1. **`last_error` is the headline, not a detail.** It is the only field that
 *    distinguishes "scheduled" from "saved but not running" — the crontab
 *    install failed, the row survived, and `enabled` still reads true. A page
 *    that tucked that into a tooltip would be showing a green badge next to a
 *    job that has not run since Tuesday.
 * 2. **The schedule is checked and read back before it is sent.** The agent is
 *    the authority and refuses anything wrong, but nobody should need a round
 *    trip to learn they typed four fields — and a *valid* expression can still
 *    be the wrong one, which only the plain-language preview catches.
 */

/** The width of the table: the detail row and the footer both span it. */
const COLUMNS = 4;

export function CronPage() {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<CronJob | "new" | null>(null);

  const cron = useQuery({ queryKey: ["cron"], queryFn: endpoints.cron });
  const jobs = cron.data?.jobs ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("cron.title")}
        description={t("cron.subtitle")}
        actions={
          <Button variant="primary" onClick={() => setEditing("new")}>
            <Plus className="h-4 w-4" aria-hidden />
            {t("cron.create")}
          </Button>
        }
      />

      {cron.isPending ? (
        <JobsSkeleton />
      ) : cron.error ? (
        <Callout tone="danger">
          {cron.error instanceof ApiError ? cron.error.message : String(cron.error)}
        </Callout>
      ) : jobs.length === 0 ? (
        <EmptyState
          icon={<Clock aria-hidden />}
          title={t("cron.empty")}
          hint={t("cron.emptyHint")}
          action={
            <Button variant="primary" onClick={() => setEditing("new")}>
              <Plus className="h-4 w-4" aria-hidden />
              {t("cron.create")}
            </Button>
          }
        />
      ) : (
        /* Five things per row — an expression, a sentence, a command, a badge,
           a toggle — need more than a phone's width, so the card scrolls
           sideways rather than compressing them into an unreadable strip. */
        <Table className="min-w-[640px]">
          <JobsHead />
          <tbody>
            {jobs.map((job, index) => (
              <JobRow key={job.id} job={job} index={index} onEdit={() => setEditing(job)} />
            ))}
          </tbody>
          {/* The allowance belongs to the table, not to the page: as a loose
              paragraph underneath it read as a stray sentence. */}
          <tfoot>
            <tr>
              <Td
                colSpan={COLUMNS}
                className="border-t border-border bg-surface-muted/40 py-2.5 text-xs text-ink-subtle"
              >
                {t("cron.limit", {
                  used: jobs.length,
                  max: cron.data?.max_jobs_per_subscription ?? 0,
                })}
              </Td>
            </tr>
          </tfoot>
        </Table>
      )}

      <JobDialog
        key={editing === "new" || editing === null ? "new" : `job-${editing.id}`}
        job={editing === "new" ? null : editing}
        open={editing !== null}
        onClose={() => setEditing(null)}
      />
    </div>
  );
}

/** Shared by the table and its ghost, so the placeholder has the real columns. */
function JobsHead() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th>{t("cron.schedule")}</Th>
        <Th>{t("cron.command")}</Th>
        <Th>{t("backups.status")}</Th>
        <Th className="text-end">{t("files.actions")}</Th>
      </tr>
    </thead>
  );
}

/**
 * The jobs table before it arrives.
 *
 * A list-shaped ghost promises a list and then a four-column table lands. This
 * keeps the real header and the real column rhythm, so the only thing that
 * changes when the data comes in is the text.
 */
function JobsSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite">
      <Table className="min-w-[640px]">
        <JobsHead />
        <tbody>
          {Array.from({ length: rows }, (_, i) => (
            <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
              <Td>
                <div className="min-h-9">
                  <Skeleton className="h-3.5 w-24" />
                  <Skeleton className="mt-1.5 h-3 w-32" />
                </div>
              </Td>
              <Td>
                <Skeleton className={i % 2 === 0 ? "h-3.5 w-56" : "h-3.5 w-40"} />
              </Td>
              <Td>
                <Skeleton className="h-5 w-20 rounded-full" />
              </Td>
              <Td>
                <div className="flex items-center justify-end gap-2">
                  <Skeleton className="h-5 w-9 rounded-full" />
                  <Skeleton className="h-8 w-8 rounded-lg" />
                </div>
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function JobRow({ job, index, onEdit }: { job: CronJob; index: number; onEdit: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["cron"] });
  const fail = (e: unknown) => setError(e instanceof ApiError ? e.message : String(e));

  const toggle = useMutation({
    // The schedule and command are resent unchanged: `cron.set` is a whole-row
    // upsert, so omitting them would be asking for an empty schedule.
    mutationFn: (enabled: boolean) =>
      endpoints.updateCronJob(job.id, { schedule: job.schedule, command: job.command, enabled }),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: fail,
  });

  const remove = useMutation({
    mutationFn: () => endpoints.deleteCronJob(job.id),
    onSuccess: () => {
      setConfirming(false);
      invalidate();
    },
    onError: fail,
  });

  // A job whose crontab could not be installed is not running, whatever its
  // `enabled` flag says — so that, and not the flag, decides the badge.
  const broken = job.last_error !== null;
  // The extra row below carries the install failure and any mutation error;
  // when it is shown, the main row's bottom border moves down to it. The rule
  // is written once against every cell, so adding a column cannot forget one.
  const detail = broken || error !== null;

  return (
    <>
      <Tr
        className={cn("animate-rise-in stagger", detail && "[&>td]:border-b-0")}
        style={staggerStyle(index)}
      >
        <Td>
          {/* Two lines' worth of height whether or not the schedule reads back
              as a sentence, so a mixed list keeps one rhythm. */}
          <div className="min-h-9">
            <div className="tnum font-mono text-xs font-medium whitespace-nowrap text-ink">
              {job.schedule}
            </div>
            <ScheduleText schedule={job.schedule} className="mt-1 block text-xs text-ink-muted" />
          </div>
        </Td>
        <Td>
          <span
            className="block max-w-md truncate font-mono text-xs text-ink-muted"
            title={job.command}
          >
            {job.command}
          </span>
        </Td>
        <Td>
          <Badge dot tone={broken ? "danger" : job.enabled ? "success" : "neutral"}>
            {broken
              ? t("cron.notRunning")
              : job.enabled
                ? t("cron.scheduled")
                : t("cron.disabledBadge")}
          </Badge>
        </Td>
        <Td>
          <div className="flex items-center justify-end gap-2">
            {/* A slot the spinner can appear in without widening the column —
                and the switch's label stays "Enabled" for the same reason: a
                label that swapped to "Disabled" moved the menu beside it on
                every toggle. Which way it is set is the badge's job. */}
            <span className="grid h-4 w-4 shrink-0 place-items-center">
              {toggle.isPending ? <Spinner className="h-3.5 w-3.5 text-ink-subtle" /> : null}
            </span>
            <Switch
              checked={job.enabled}
              disabled={toggle.isPending}
              onChange={(next) => toggle.mutate(next)}
              label={t("cron.enabled")}
            />
            <Menu label={t("files.actions")}>
              <MenuItem icon={<Pencil />} onClick={onEdit}>
                {t("cron.edit")}
              </MenuItem>
              <MenuSeparator />
              <MenuItem danger icon={<Trash2 />} onClick={() => setConfirming(true)}>
                {t("cron.delete")}
              </MenuItem>
            </Menu>
          </div>

          <Dialog
            open={confirming}
            onClose={() => setConfirming(false)}
            title={t("cron.deleteTitle")}
            description={t("cron.deleteHint")}
            footer={
              <>
                <Button variant="ghost" onClick={() => setConfirming(false)}>
                  {t("common.cancel")}
                </Button>
                <Button variant="danger" onClick={() => remove.mutate()} loading={remove.isPending}>
                  {t("cron.deleteConfirm")}
                </Button>
              </>
            }
          >
            <p className="tnum rounded-lg bg-surface-muted px-3 py-2 font-mono text-xs text-ink-muted">
              {job.schedule} {job.command}
            </p>
          </Dialog>
        </Td>
      </Tr>

      {detail ? (
        /* Same delay as the row it belongs to, so the pair arrives together. */
        <tr className="animate-rise-in stagger" style={staggerStyle(index)}>
          <Td colSpan={COLUMNS} className="space-y-2 pt-0">
            {job.last_error ? (
              <Callout tone="danger" title={t("cron.lastError")}>
                <p className="font-mono text-xs break-words">{job.last_error}</p>
                <p className="mt-1.5">{t("cron.lastErrorHint")}</p>
              </Callout>
            ) : null}
            {error ? <Callout tone="danger">{error}</Callout> : null}
          </Td>
        </tr>
      ) : null}
    </>
  );
}

/**
 * Create or edit one job.
 *
 * The same dialog for both because `cron.set` is one upsert: the difference is
 * whether an id goes in the URL, and whether the subscription can still be
 * chosen (it cannot be changed afterwards — a job does not move between
 * tenants, and the agent refuses the attempt rather than ignoring it).
 */
function JobDialog({
  job,
  open,
  onClose,
}: {
  job: CronJob | null;
  open: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const problemOf = useScheduleProblem();

  const [schedule, setSchedule] = useState(job?.schedule ?? "0 3 * * *");
  const [command, setCommand] = useState(job?.command ?? "");
  const [subscription, setSubscription] = useState("");
  const [enabled, setEnabled] = useState(job?.enabled ?? true);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reopening the dialog on a different job must not show the previous one's
  // half-typed command.
  useEffect(() => {
    if (!open) return;
    setSchedule(job?.schedule ?? "0 3 * * *");
    setCommand(job?.command ?? "");
    setSubscription("");
    setEnabled(job?.enabled ?? true);
    setSubmitted(false);
    setError(null);
  }, [open, job]);

  const scheduleProblem = problemOf(schedule);
  const commandProblem = checkCommand(command);
  const commandMessage = commandProblem
    ? t(`cron.problem.${commandProblem.key}`, { ...commandProblem.params })
    : null;
  const subscriptionProblem =
    subscription.trim() !== "" && !/^\d{1,18}$/.test(subscription.trim())
      ? t("cron.subscriptionInvalid")
      : null;

  const save = useMutation({
    mutationFn: (body: CronSetRequest) =>
      job === null ? endpoints.createCronJob(body) : endpoints.updateCronJob(job.id, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["cron"] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const submit = () => {
    setSubmitted(true);
    setError(null);
    if (scheduleProblem || commandMessage || subscriptionProblem) return;

    const body: CronSetRequest = { schedule: schedule.trim(), command: command.trim(), enabled };
    // Only on create, and only when it was actually typed: an absent key means
    // "the caller's own subscription" to the agent, and an update that carried
    // one would be asking to move the job.
    if (job === null && subscription.trim() !== "") {
      body.subscription_id = Number(subscription.trim());
    }
    save.mutate(body);
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={job === null ? t("cron.create") : t("cron.edit")}
      description={t("cron.createHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={submit} loading={save.isPending}>
            {t("cron.save")}
          </Button>
        </>
      }
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
        className="space-y-3"
      >
        <ScheduleField
          id="cron-schedule"
          label={t("cron.schedule")}
          value={schedule}
          onChange={setSchedule}
          // Not red before anything has been typed, but "enter a schedule"
          // does appear once Save has been pressed on an empty field.
          showProblem={submitted || schedule.trim() !== ""}
        />

        <Field
          label={t("cron.command")}
          htmlFor="cron-command"
          error={submitted ? (commandMessage ?? undefined) : undefined}
        >
          <Input
            id="cron-command"
            className="font-mono"
            placeholder="/usr/bin/php ~/cron.php"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={submitted && Boolean(commandMessage)}
            aria-describedby="cron-command-hint"
            value={command}
            onChange={(event) => setCommand(event.target.value)}
          />
        </Field>
        <p id="cron-command-hint" className="-mt-2 text-xs text-ink-muted">
          {t("cron.commandHint")}
        </p>

        {job === null ? (
          <>
            <Field
              label={t("cron.subscription")}
              htmlFor="cron-subscription"
              error={submitted ? (subscriptionProblem ?? undefined) : undefined}
            >
              <Input
                id="cron-subscription"
                inputMode="numeric"
                placeholder={t("cron.subscriptionPlaceholder")}
                aria-describedby="cron-subscription-hint"
                value={subscription}
                onChange={(event) => setSubscription(event.target.value)}
              />
            </Field>
            <p id="cron-subscription-hint" className="-mt-2 text-xs text-ink-muted">
              {t("cron.subscriptionHint")}
            </p>
          </>
        ) : null}

        <Switch
          checked={enabled}
          onChange={setEnabled}
          label={t("cron.enabled")}
          description={t("cron.enabledHint")}
        />

        {error ? <Callout tone="danger">{error}</Callout> : null}
      </form>
    </Dialog>
  );
}
