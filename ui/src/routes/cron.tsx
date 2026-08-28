import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Clock, Pencil, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { ScheduleField, ScheduleText, useScheduleProblem } from "@/components/schedule-field";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { ApiError, endpoints, type CronJob, type CronSetRequest } from "@/lib/api";
import { checkCommand } from "@/lib/cron-schedule";

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
export function CronPage() {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<CronJob | "new" | null>(null);

  const cron = useQuery({ queryKey: ["cron"], queryFn: endpoints.cron });
  const jobs = cron.data?.jobs ?? [];

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("cron.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">{t("cron.subtitle")}</p>
        </div>
        <Button variant="primary" onClick={() => setEditing("new")}>
          <Plus className="h-4 w-4" />
          {t("cron.create")}
        </Button>
      </header>

      {cron.isPending ? (
        <div className="flex justify-center py-24 text-ink-muted">
          <Spinner className="h-6 w-6" />
        </div>
      ) : cron.error ? (
        <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {cron.error instanceof ApiError ? cron.error.message : String(cron.error)}
        </p>
      ) : jobs.length === 0 ? (
        <EmptyState onCreate={() => setEditing("new")} />
      ) : (
        <>
          <ul className="space-y-3">
            {jobs.map((job) => (
              <li key={job.id}>
                <JobRow job={job} onEdit={() => setEditing(job)} />
              </li>
            ))}
          </ul>
          <p className="text-xs text-ink-subtle">
            {t("cron.limit", {
              used: jobs.length,
              max: cron.data?.max_jobs_per_subscription ?? 0,
            })}
          </p>
        </>
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

function EmptyState({ onCreate }: { onCreate: () => void }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardBody className="py-16 text-center">
        <Clock className="mx-auto mb-3 h-8 w-8 text-ink-subtle" aria-hidden />
        <p className="text-sm font-medium text-ink">{t("cron.empty")}</p>
        <p className="mx-auto mt-1 max-w-md text-sm text-ink-muted">{t("cron.emptyHint")}</p>
        <Button variant="primary" className="mt-4" onClick={onCreate}>
          <Plus className="h-4 w-4" />
          {t("cron.create")}
        </Button>
      </CardBody>
    </Card>
  );
}

function JobRow({ job, onEdit }: { job: CronJob; onEdit: () => void }) {
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

  return (
    <Card>
      <CardBody className="pt-5">
        <div className="flex flex-wrap items-start gap-x-4 gap-y-3">
          <Badge tone={broken ? "danger" : job.enabled ? "success" : "neutral"}>
            {broken
              ? t("cron.notRunning")
              : job.enabled
                ? t("cron.scheduled")
                : t("cron.disabledBadge")}
          </Badge>

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
              <span dir="ltr" className="font-mono text-sm font-medium text-ink">
                {job.schedule}
              </span>
              <ScheduleText schedule={job.schedule} className="text-xs text-ink-muted" />
            </div>
            <p dir="ltr" className="mt-1 truncate font-mono text-xs text-ink-subtle" title={job.command}>
              {job.command}
            </p>
          </div>

          <div className="flex items-center gap-1">
            <Switch
              checked={job.enabled}
              disabled={toggle.isPending}
              onChange={(next) => toggle.mutate(next)}
              label={job.enabled ? t("cron.enabled") : t("cron.disabledBadge")}
            />
            <Button variant="ghost" size="sm" onClick={onEdit}>
              <Pencil className="h-3.5 w-3.5" aria-hidden />
              {t("cron.edit")}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
              {t("cron.delete")}
            </Button>
          </div>
        </div>

        {job.last_error ? (
          <div className="mt-3 rounded-lg bg-danger-soft px-3 py-2.5">
            <p className="flex items-center gap-1.5 text-sm font-medium text-danger">
              <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden />
              {t("cron.lastError")}
            </p>
            <p dir="ltr" className="mt-1 font-mono text-xs break-words text-danger">
              {job.last_error}
            </p>
            <p className="mt-1.5 text-xs text-ink-muted">{t("cron.lastErrorHint")}</p>
          </div>
        ) : null}

        {error ? (
          <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}

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
              <Button variant="danger" onClick={() => remove.mutate()} disabled={remove.isPending}>
                {remove.isPending ? <Spinner /> : null}
                {t("cron.deleteConfirm")}
              </Button>
            </>
          }
        >
          <p dir="ltr" className="rounded-lg bg-surface-muted px-3 py-2 font-mono text-xs text-ink-muted">
            {job.schedule} {job.command}
          </p>
        </Dialog>
      </CardBody>
    </Card>
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
          <Button variant="primary" onClick={submit} disabled={save.isPending}>
            {save.isPending ? <Spinner /> : null}
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
            dir="ltr"
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
                dir="ltr"
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

        {error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}
      </form>
    </Dialog>
  );
}
