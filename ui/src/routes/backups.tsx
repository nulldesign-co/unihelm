import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Archive,
  Copy,
  Database,
  HardDrive,
  History,
  KeyRound,
  Play,
  Plus,
  Trash2,
} from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { ScheduleField, ScheduleText } from "@/components/schedule-field";
import { TaskLogPanel, TaskNotice } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import {
  ApiError,
  endpoints,
  type BackupRepo,
  type BackupRun,
  type BackupRunStatus,
  type BackupScopeKind,
  type RepoInitRequest,
  type RepoInitResponse,
} from "@/lib/api";
import { checkSchedule } from "@/lib/cron-schedule";
import { useSession } from "@/lib/session";
import { formatBytes } from "@/lib/utils";

/**
 * Backups (spec §11.10).
 *
 * The page is built around one asymmetry: everything else the panel stores can
 * be read back, and a repository password cannot. `backup.repo.init` returns it
 * exactly once, in the body of one 200, and no operation anywhere can produce it
 * again — an operation that could would turn a stolen session into every backup
 * this panel has ever taken. So the creation flow ends in a dialog that treats
 * that value as the deliverable rather than as a confirmation, and says the
 * consequence out loud: without the password **and** `/etc/unihelm/secret.key`,
 * a panel-scope backup cannot be restored after the panel is lost.
 *
 * The rest follows the API's own scoping. Repositories, schedules and restores
 * are administrator work (`TenantScope::Global`); runs and history are
 * tenant-scoped, so a customer sees their own subscription's backups and never
 * a panel-scope row.
 */
export function BackupsPage() {
  const { t } = useTranslation();
  const { user } = useSession();
  // Repository, schedule and restore endpoints all require the global scope, and
  // both this layer and the agent check it (routes/backups.rs::require_admin).
  const isAdmin = user?.role === "admin";

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("backups.title")}</h1>
        <p className="mt-1 text-sm text-ink-muted">{t("backups.subtitle")}</p>
      </header>

      <RunNowCard isAdmin={isAdmin} />
      {isAdmin ? <RepositoriesCard /> : null}
      <SchedulesCard isAdmin={isAdmin} />
      <RunsCard />
      <SnapshotsCard isAdmin={isAdmin} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Repository choices
// ---------------------------------------------------------------------------

interface RepoOption {
  id: number;
  label: string;
}

/**
 * The repositories this caller can name, by whatever route they can see them.
 *
 * `GET /api/backups/repos` is administrator-only — deciding where backups go is
 * an administrator's job. A customer holding `backup_manage` can still *run* a
 * backup, but only into a repository some administrator already pointed a
 * schedule for their subscription at, so their own (tenant-scoped) schedules are
 * exactly the right list to build from. They see an id where an administrator
 * sees a label, which is a gap in the API rather than in this page.
 */
function useRepoOptions(isAdmin: boolean): { options: RepoOption[]; isPending: boolean } {
  const repos = useQuery({
    queryKey: ["backup-repos"],
    queryFn: endpoints.backupRepos,
    enabled: isAdmin,
  });
  const schedules = useQuery({
    queryKey: ["backup-schedules"],
    queryFn: endpoints.backupSchedules,
    enabled: !isAdmin,
  });

  const options = useMemo<RepoOption[]>(() => {
    if (isAdmin) {
      return (repos.data?.repos ?? []).map((repo) => ({ id: repo.id, label: repo.label }));
    }
    const ids = new Set((schedules.data?.schedules ?? []).map((schedule) => schedule.repo_id));
    return [...ids].sort((a, b) => a - b).map((id) => ({ id, label: `#${id}` }));
  }, [isAdmin, repos.data, schedules.data]);

  return { options, isPending: isAdmin ? repos.isPending : schedules.isPending };
}

/** Repository + scope + subject, the three fields every write to a repo takes. */
function TargetFields({
  options,
  repoId,
  setRepoId,
  scope,
  setScope,
  subscription,
  setSubscription,
  allowPanel,
  idPrefix,
}: {
  options: RepoOption[];
  repoId: string;
  setRepoId: (next: string) => void;
  scope: BackupScopeKind;
  setScope: (next: BackupScopeKind) => void;
  subscription: string;
  setSubscription: (next: string) => void;
  allowPanel: boolean;
  idPrefix: string;
}) {
  const { t } = useTranslation();

  return (
    <>
      <Field label={t("backups.repository")} htmlFor={`${idPrefix}-repo`}>
        <Select id={`${idPrefix}-repo`} value={repoId} onChange={(e) => setRepoId(e.target.value)}>
          <option value="">{t("backups.chooseRepository")}</option>
          {options.map((option) => (
            <option key={option.id} value={String(option.id)}>
              {option.label}
            </option>
          ))}
        </Select>
      </Field>

      <Field label={t("backups.scope")} htmlFor={`${idPrefix}-scope`}>
        <Select
          id={`${idPrefix}-scope`}
          value={scope}
          onChange={(e) => setScope(e.target.value as BackupScopeKind)}
        >
          {/* Panel scope covers every tenant's panel record, so it is offered
              only where the API would accept it. */}
          {allowPanel ? <option value="panel">{t("backups.scopePanel")}</option> : null}
          <option value="subscription">{t("backups.scopeSubscription")}</option>
        </Select>
      </Field>

      {scope === "subscription" ? (
        <>
          <Field label={t("backups.subscription")} htmlFor={`${idPrefix}-subscription`}>
            <Input
              id={`${idPrefix}-subscription`}
              dir="ltr"
              inputMode="numeric"
              placeholder="1"
              aria-describedby={`${idPrefix}-subscription-hint`}
              value={subscription}
              onChange={(e) => setSubscription(e.target.value)}
            />
          </Field>
          <p id={`${idPrefix}-subscription-hint`} className="-mt-2 text-xs text-ink-muted">
            {t("backups.subscriptionHint")}
          </p>
        </>
      ) : (
        <p className="text-xs text-ink-muted">{t("backups.scopePanelHint")}</p>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Run now
// ---------------------------------------------------------------------------

function RunNowCard({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { options, isPending } = useRepoOptions(isAdmin);
  const [repoId, setRepoId] = useState("");
  const [scope, setScope] = useState<BackupScopeKind>(isAdmin ? "panel" : "subscription");
  const [subscription, setSubscription] = useState("");
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () =>
      endpoints.runBackup({
        repo_id: Number(repoId),
        scope,
        ...(scope === "subscription" && subscription.trim() !== ""
          ? { subscription_id: Number(subscription.trim()) }
          : {}),
      }),
    onSuccess: (accepted) => {
      setError(null);
      setTaskId(accepted.task_id);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const ready = repoId !== "" && (scope === "panel" || subscription.trim() !== "");

  return (
    <Card>
      <CardHeader title={t("backups.runNow")} description={t("backups.runNowHint")} />
      <CardBody className="space-y-3">
        {isPending ? (
          <div className="flex justify-center py-6 text-ink-muted">
            <Spinner />
          </div>
        ) : options.length === 0 ? (
          <p className="text-sm text-ink-muted">
            {isAdmin ? t("backups.noRepos") : t("backups.noReposCustomer")}
          </p>
        ) : (
          <>
            <div className="grid gap-3 sm:grid-cols-2">
              <TargetFields
                options={options}
                repoId={repoId}
                setRepoId={setRepoId}
                scope={scope}
                setScope={setScope}
                subscription={subscription}
                setSubscription={setSubscription}
                allowPanel={isAdmin}
                idPrefix="run"
              />
            </div>

            <Button variant="primary" disabled={!ready || run.isPending} onClick={() => run.mutate()}>
              {run.isPending ? <Spinner /> : <Play className="h-4 w-4" aria-hidden />}
              {t("backups.startRun")}
            </Button>
          </>
        )}

        {error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}

        {/* restic's own output, line by line: how many files it read and how
            many bytes it actually uploaded is the answer to "did that work",
            and a status chip alone does not carry it. */}
        {taskId ? (
          <TaskLogPanel
            key={taskId}
            taskId={taskId}
            onSettled={() => {
              void queryClient.invalidateQueries({ queryKey: ["backup-runs"] });
              void queryClient.invalidateQueries({ queryKey: ["backup-snapshots"] });
            }}
          />
        ) : null}
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Repositories
// ---------------------------------------------------------------------------

function RepositoriesCard() {
  const { t } = useTranslation();
  const [creating, setCreating] = useState(false);
  const repos = useQuery({ queryKey: ["backup-repos"], queryFn: endpoints.backupRepos });

  return (
    <Card>
      <CardHeader
        title={t("backups.repositories")}
        description={t("backups.repositoriesHint")}
        action={
          <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
            <Plus className="h-3.5 w-3.5" aria-hidden />
            {t("backups.addRepository")}
          </Button>
        }
      />
      <CardBody>
        {repos.isPending ? (
          <div className="flex justify-center py-6 text-ink-muted">
            <Spinner />
          </div>
        ) : repos.error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {repos.error instanceof ApiError ? repos.error.message : String(repos.error)}
          </p>
        ) : (repos.data?.repos.length ?? 0) === 0 ? (
          <p className="text-sm text-ink-muted">{t("backups.noRepos")}</p>
        ) : (
          <ul className="divide-y divide-border">
            {repos.data!.repos.map((repo) => (
              <li key={repo.id}>
                <RepoRow repo={repo} />
              </li>
            ))}
          </ul>
        )}
      </CardBody>

      <CreateRepoDialog open={creating} onClose={() => setCreating(false)} />
    </Card>
  );
}

function RepoRow({ repo }: { repo: BackupRepo }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: () => endpoints.deleteBackupRepo(repo.id),
    onSuccess: () => {
      setConfirming(false);
      void queryClient.invalidateQueries({ queryKey: ["backup-repos"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 py-3">
      {repo.kind === "s3" ? (
        <Database className="h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
      ) : (
        <HardDrive className="h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
      )}

      <div className="min-w-0 flex-1">
        <span dir="ltr" className="block truncate font-medium text-ink">
          {repo.label}
        </span>
        <span dir="ltr" className="block truncate font-mono text-xs text-ink-subtle">
          {repo.path_or_url}
        </span>
      </div>

      <Badge tone="neutral">{t(`backups.kind.${repo.kind}`)}</Badge>
      {repo.has_credentials ? <Badge tone="accent">{t("backups.hasCredentials")}</Badge> : null}

      <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
        <Trash2 className="h-3.5 w-3.5" aria-hidden />
        {t("backups.forget")}
      </Button>

      {error ? (
        <p role="alert" className="basis-full rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}

      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t("backups.forgetTitle", { label: repo.label })}
        description={t("backups.forgetHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" onClick={() => remove.mutate()} disabled={remove.isPending}>
              {remove.isPending ? <Spinner /> : null}
              {t("backups.forgetConfirm")}
            </Button>
          </>
        }
      >
        <p className="text-sm text-ink-muted">{t("backups.forgetKeepsData")}</p>
      </Dialog>
    </div>
  );
}

function CreateRepoDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<"local" | "s3">("local");
  const [label, setLabel] = useState("");
  const [location, setLocation] = useState("");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [region, setRegion] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<RepoInitResponse | null>(null);

  const reset = () => {
    setKind("local");
    setLabel("");
    setLocation("");
    setAccessKeyId("");
    setSecretAccessKey("");
    setRegion("");
    setError(null);
  };

  const create = useMutation({
    mutationFn: () => {
      const body: RepoInitRequest = {
        kind,
        label: label.trim(),
        path_or_url: location.trim(),
      };
      if (kind === "s3") {
        body.s3 = {
          access_key_id: accessKeyId.trim(),
          secret_access_key: secretAccessKey,
          ...(region.trim() === "" ? {} : { region: region.trim() }),
        };
      }
      return endpoints.createBackupRepo(body);
    },
    onSuccess: (result) => {
      // The form closes and the password dialog opens in its place: the body of
      // this one 200 is the only time this value exists outside the sealed
      // column, so it must not be behind a form the user might dismiss.
      reset();
      onClose();
      setCreated(result);
      void queryClient.invalidateQueries({ queryKey: ["backup-repos"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const ready =
    label.trim() !== "" &&
    location.trim() !== "" &&
    (kind === "local" || (accessKeyId.trim() !== "" && secretAccessKey !== ""));

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={t("backups.addRepository")}
        description={t("backups.addRepositoryHint")}
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              disabled={!ready || create.isPending}
              onClick={() => create.mutate()}
            >
              {create.isPending ? <Spinner /> : null}
              {t("backups.createRepository")}
            </Button>
          </>
        }
      >
        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (ready) create.mutate();
          }}
        >
          <Field label={t("backups.kindLabel")} htmlFor="repo-kind">
            <Select
              id="repo-kind"
              value={kind}
              onChange={(event) => setKind(event.target.value as "local" | "s3")}
            >
              <option value="local">{t("backups.kind.local")}</option>
              <option value="s3">{t("backups.kind.s3")}</option>
            </Select>
          </Field>

          <Field label={t("backups.label")} htmlFor="repo-label">
            <Input
              id="repo-label"
              dir="ltr"
              placeholder="nightly-offsite"
              autoComplete="off"
              value={label}
              onChange={(event) => setLabel(event.target.value)}
            />
          </Field>

          <Field
            label={kind === "local" ? t("backups.localPath") : t("backups.s3Location")}
            htmlFor="repo-location"
          >
            <Input
              id="repo-location"
              dir="ltr"
              className="font-mono"
              placeholder={kind === "local" ? "/var/backups/unihelm" : "s3.example.com/unihelm-backups"}
              autoComplete="off"
              spellCheck={false}
              aria-describedby="repo-location-hint"
              value={location}
              onChange={(event) => setLocation(event.target.value)}
            />
          </Field>
          <p id="repo-location-hint" className="-mt-2 text-xs text-ink-muted">
            {kind === "local" ? t("backups.localPathHint") : t("backups.s3LocationHint")}
          </p>

          {kind === "s3" ? (
            <>
              <Field label={t("backups.accessKeyId")} htmlFor="repo-access-key">
                <Input
                  id="repo-access-key"
                  dir="ltr"
                  className="font-mono"
                  placeholder="AKIAEXAMPLE"
                  autoComplete="off"
                  value={accessKeyId}
                  onChange={(event) => setAccessKeyId(event.target.value)}
                />
              </Field>

              <Field label={t("backups.secretAccessKey")} htmlFor="repo-secret-key">
                <Input
                  id="repo-secret-key"
                  dir="ltr"
                  type="password"
                  className="font-mono"
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby="repo-secret-hint"
                  value={secretAccessKey}
                  onChange={(event) => setSecretAccessKey(event.target.value)}
                />
              </Field>
              <p id="repo-secret-hint" className="-mt-2 text-xs text-ink-muted">
                {t("backups.secretAccessKeyHint")}
              </p>

              <Field label={t("backups.region")} htmlFor="repo-region">
                <Input
                  id="repo-region"
                  dir="ltr"
                  placeholder="us-east-1"
                  autoComplete="off"
                  value={region}
                  onChange={(event) => setRegion(event.target.value)}
                />
              </Field>
            </>
          ) : null}

          {error ? (
            <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
              {error}
            </p>
          ) : null}
        </form>
      </Dialog>

      <PasswordDialog result={created} onClose={() => setCreated(null)} />
    </>
  );
}

/**
 * The show-once repository password.
 *
 * Everything about this dialog is shaped by "there is no second chance": the
 * value is the content rather than a footnote, copying it is one click, and the
 * acknowledgement has to be ticked before the button that dismisses it becomes
 * available — not as security theatre, but because the sentence next to the tick
 * is the one people otherwise close without reading.
 */
function PasswordDialog({
  result,
  onClose,
}: {
  result: RepoInitResponse | null;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);

  if (result === null) return null;

  const copy = async () => {
    try {
      // Only defined in a secure context; the panel is TLS-only, but a
      // dev instance over plain HTTP would land in the catch rather than
      // throwing an unhandled rejection at the user.
      await navigator.clipboard.writeText(result.password);
      setCopied(true);
      setCopyFailed(false);
    } catch {
      setCopyFailed(true);
    }
  };

  return (
    <Dialog
      open
      onClose={() => {
        setAcknowledged(false);
        setCopied(false);
        setCopyFailed(false);
        onClose();
      }}
      title={t("backups.passwordTitle")}
      description={t("backups.passwordSubtitle", { label: result.label })}
      footer={
        <Button
          variant="primary"
          disabled={!acknowledged}
          onClick={() => {
            setAcknowledged(false);
            setCopied(false);
            setCopyFailed(false);
            onClose();
          }}
        >
          {t("backups.passwordDone")}
        </Button>
      }
    >
      <div className="space-y-3">
        <div className="rounded-lg border border-danger bg-danger-soft px-3 py-2.5">
          <p className="flex items-center gap-1.5 text-sm font-medium text-danger">
            <KeyRound className="h-4 w-4 shrink-0" aria-hidden />
            {t("backups.passwordOnce")}
          </p>
          {/* The consequence, in the words the API states it in: without this
              password *and* /etc/unihelm/secret.key, a panel-scope backup cannot
              be restored after the panel is lost. */}
          <p className="mt-1 text-sm text-ink">{t("backups.passwordNotice")}</p>
        </div>

        <div>
          <p className="text-xs text-ink-subtle">{t("backups.password")}</p>
          <div className="mt-1 flex items-center gap-2">
            <code
              dir="ltr"
              className="min-w-0 flex-1 rounded-lg border border-border bg-canvas px-3 py-2 font-mono text-sm break-all text-ink select-all"
            >
              {result.password}
            </code>
            <Button variant="outline" size="sm" onClick={() => void copy()}>
              <Copy className="h-3.5 w-3.5" aria-hidden />
              {copied ? t("backups.copied") : t("backups.copy")}
            </Button>
          </div>
          {copyFailed ? (
            <p className="mt-1 text-xs text-warning">{t("backups.copyFailed")}</p>
          ) : null}
        </div>

        <div>
          <p className="text-xs text-ink-subtle">{t("backups.resticRepository")}</p>
          <code
            dir="ltr"
            className="mt-1 block rounded-lg border border-border bg-canvas px-3 py-2 font-mono text-xs break-all text-ink-muted"
          >
            {result.repository}
          </code>
          <p className="mt-1 text-xs text-ink-muted">{t("backups.resticRepositoryHint")}</p>
        </div>

        <Switch
          checked={acknowledged}
          onChange={setAcknowledged}
          label={t("backups.passwordAcknowledge")}
          description={t("backups.passwordAcknowledgeHint")}
        />
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Schedules
// ---------------------------------------------------------------------------

function SchedulesCard({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useTranslation();
  const [creating, setCreating] = useState(false);
  const schedules = useQuery({ queryKey: ["backup-schedules"], queryFn: endpoints.backupSchedules });

  return (
    <Card>
      <CardHeader
        title={t("backups.schedules")}
        description={t("backups.schedulesHint")}
        action={
          isAdmin ? (
            <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
              <Plus className="h-3.5 w-3.5" aria-hidden />
              {t("backups.addSchedule")}
            </Button>
          ) : null
        }
      />
      <CardBody>
        {schedules.isPending ? (
          <div className="flex justify-center py-6 text-ink-muted">
            <Spinner />
          </div>
        ) : (schedules.data?.schedules.length ?? 0) === 0 ? (
          <p className="text-sm text-ink-muted">{t("backups.noSchedules")}</p>
        ) : (
          <ul className="divide-y divide-border">
            {schedules.data!.schedules.map((schedule) => (
              <li key={schedule.id} className="flex flex-wrap items-center gap-x-3 gap-y-2 py-3">
                <Badge tone={schedule.enabled ? "success" : "neutral"}>
                  {schedule.enabled ? t("backups.enabled") : t("backups.disabled")}
                </Badge>

                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-x-2.5">
                    <span dir="ltr" className="font-mono text-sm text-ink">
                      {schedule.cron}
                    </span>
                    <ScheduleText schedule={schedule.cron} className="text-xs text-ink-muted" />
                  </div>
                  <p className="mt-0.5 text-xs text-ink-subtle">
                    {t(`backups.scope${schedule.scope === "panel" ? "Panel" : "Subscription"}`)}
                    {schedule.subscription_id === null ? "" : ` · #${schedule.subscription_id}`}
                    {" · "}
                    {/* The retention policy is what decides how far back a
                        restore can go, so it belongs on the row and not behind
                        an edit dialog. */}
                    {t("backups.retentionSummary", {
                      daily: schedule.keep_daily,
                      weekly: schedule.keep_weekly,
                      monthly: schedule.keep_monthly,
                    })}
                  </p>
                </div>

                <Badge tone="neutral">
                  <span dir="ltr">#{schedule.repo_id}</span>
                </Badge>

                {isAdmin ? <DeleteScheduleButton id={schedule.id} /> : null}
              </li>
            ))}
          </ul>
        )}
      </CardBody>

      {/* Mounted only for an administrator: the dialog reads the repository
          list to fill its picker, and that endpoint answers a customer 403. */}
      {isAdmin ? (
        <CreateScheduleDialog open={creating} onClose={() => setCreating(false)} />
      ) : null}
    </Card>
  );
}

function DeleteScheduleButton({ id }: { id: number }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: () => endpoints.deleteBackupSchedule(id),
    onSuccess: () => {
      setConfirming(false);
      void queryClient.invalidateQueries({ queryKey: ["backup-schedules"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
        <Trash2 className="h-3.5 w-3.5" aria-hidden />
        {t("backups.deleteSchedule")}
      </Button>
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t("backups.deleteScheduleTitle")}
        description={t("backups.deleteScheduleHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" onClick={() => remove.mutate()} disabled={remove.isPending}>
              {remove.isPending ? <Spinner /> : null}
              {t("backups.deleteSchedule")}
            </Button>
          </>
        }
      >
        {error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}
      </Dialog>
    </>
  );
}

function CreateScheduleDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { options } = useRepoOptions(true);

  const [repoId, setRepoId] = useState("");
  const [scope, setScope] = useState<BackupScopeKind>("panel");
  const [subscription, setSubscription] = useState("");
  const [cron, setCron] = useState("0 3 * * *");
  const [keepDaily, setKeepDaily] = useState("7");
  const [keepWeekly, setKeepWeekly] = useState("4");
  const [keepMonthly, setKeepMonthly] = useState("6");
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const retentionOk = [keepDaily, keepWeekly, keepMonthly].every((value) =>
    /^\d{1,4}$/.test(value.trim()),
  );
  const ready =
    repoId !== "" &&
    checkSchedule(cron).ok &&
    retentionOk &&
    (scope === "panel" || subscription.trim() !== "");

  const create = useMutation({
    mutationFn: () =>
      endpoints.createBackupSchedule({
        repo_id: Number(repoId),
        scope,
        cron: cron.trim(),
        keep_daily: Number(keepDaily.trim()),
        keep_weekly: Number(keepWeekly.trim()),
        keep_monthly: Number(keepMonthly.trim()),
        enabled,
        ...(scope === "subscription" ? { subscription_id: Number(subscription.trim()) } : {}),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["backup-schedules"] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("backups.addSchedule")}
      description={t("backups.addScheduleHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            disabled={!ready || create.isPending}
            onClick={() => create.mutate()}
          >
            {create.isPending ? <Spinner /> : null}
            {t("backups.createSchedule")}
          </Button>
        </>
      }
    >
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) create.mutate();
        }}
      >
        <TargetFields
          options={options}
          repoId={repoId}
          setRepoId={setRepoId}
          scope={scope}
          setScope={setScope}
          subscription={subscription}
          setSubscription={setSubscription}
          allowPanel
          idPrefix="schedule"
        />

        <ScheduleField
          id="schedule-cron"
          label={t("backups.when")}
          value={cron}
          onChange={setCron}
        />

        <fieldset>
          <legend className="block text-sm font-medium text-ink">{t("backups.retention")}</legend>
          {/* Retention is what decides how far back a restore can reach, and
              restic prunes to it: a policy of zeros keeps nothing. */}
          <p className="mt-0.5 mb-2 text-xs text-ink-muted">{t("backups.retentionHint")}</p>
          <div className="grid grid-cols-3 gap-2">
            {(
              [
                ["keep-daily", t("backups.keepDaily"), keepDaily, setKeepDaily],
                ["keep-weekly", t("backups.keepWeekly"), keepWeekly, setKeepWeekly],
                ["keep-monthly", t("backups.keepMonthly"), keepMonthly, setKeepMonthly],
              ] as const
            ).map(([id, label, value, set]) => (
              <div key={id}>
                <label htmlFor={id} className="block text-xs text-ink-muted">
                  {label}
                </label>
                <Input
                  id={id}
                  dir="ltr"
                  inputMode="numeric"
                  className="mt-1"
                  value={value}
                  onChange={(event) => set(event.target.value)}
                />
              </div>
            ))}
          </div>
        </fieldset>

        <Switch
          checked={enabled}
          onChange={setEnabled}
          label={t("backups.enabled")}
          description={t("backups.scheduleEnabledHint")}
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

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

const RUN_TONE: Record<BackupRunStatus, "accent" | "success" | "danger"> = {
  running: "accent",
  ok: "success",
  failed: "danger",
};

function RunsCard() {
  const { t } = useTranslation();
  const runs = useQuery({
    queryKey: ["backup-runs"],
    queryFn: () => endpoints.backupRuns(),
    // Only while something is still going; a settled history costs one request
    // per visit rather than one per second.
    refetchInterval: (query) =>
      query.state.data?.runs.some((run) => run.status === "running") ? 5_000 : false,
  });

  return (
    <Card>
      <CardHeader title={t("backups.history")} description={t("backups.historyHint")} />
      <CardBody>
        {runs.isPending ? (
          <div className="flex justify-center py-6 text-ink-muted">
            <Spinner />
          </div>
        ) : (runs.data?.runs.length ?? 0) === 0 ? (
          <div className="py-6 text-center">
            <History className="mx-auto mb-2 h-7 w-7 text-ink-subtle" aria-hidden />
            <p className="text-sm text-ink-muted">{t("backups.noRuns")}</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-2xl text-start text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-ink-subtle">
                  <th className="py-2 pe-3 text-start font-medium">{t("backups.status")}</th>
                  <th className="py-2 pe-3 text-start font-medium">{t("backups.started")}</th>
                  <th className="py-2 pe-3 text-start font-medium">{t("backups.scope")}</th>
                  <th className="py-2 pe-3 text-start font-medium">{t("backups.size")}</th>
                  <th className="py-2 pe-3 text-start font-medium">{t("backups.snapshot")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {runs.data!.runs.map((run) => (
                  <RunRow key={run.id} run={run} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardBody>
    </Card>
  );
}

function RunRow({ run }: { run: BackupRun }) {
  const { t, i18n } = useTranslation();

  return (
    <>
      <tr className="align-top">
        <td className="py-2 pe-3">
          <Badge tone={RUN_TONE[run.status]} dot={run.status === "running"}>
            {t(`backups.runStatus.${run.status}`)}
          </Badge>
        </td>
        <td className="py-2 pe-3 text-ink-muted">
          <time dateTime={run.started_at}>{formatDateTime(run.started_at, i18n.language)}</time>
        </td>
        <td className="py-2 pe-3 text-ink-muted">
          {t(`backups.scope${run.scope === "panel" ? "Panel" : "Subscription"}`)}
          {run.subscription_id === null ? "" : ` #${run.subscription_id}`}
        </td>
        <td dir="ltr" className="py-2 pe-3 text-ink-muted">
          {run.bytes === null ? t("common.none") : formatBytes(run.bytes, i18n.language)}
        </td>
        <td dir="ltr" className="py-2 pe-3 font-mono text-xs text-ink-muted">
          {run.snapshot_id === null ? t("common.none") : run.snapshot_id.slice(0, 8)}
        </td>
      </tr>
      {run.error ? (
        // A history that recorded only successes could not answer "when did
        // this stop working", which is the question a backup history exists to
        // answer — so the failure text gets a full row rather than a tooltip.
        <tr>
          <td colSpan={5} className="pb-2">
            <p dir="ltr" className="rounded-lg bg-danger-soft px-3 py-2 font-mono text-xs break-words text-danger">
              {run.error}
            </p>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function formatDateTime(iso: string, language: string): string {
  try {
    // Latin digits on the Persian page: an operator correlating this with a log
    // line is comparing timestamps, not reading prose.
    const locale = language === "fa" ? "fa-IR-u-nu-latn" : language;
    return new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "short" }).format(
      new Date(iso),
    );
  } catch {
    return iso;
  }
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

function SnapshotsCard({ isAdmin }: { isAdmin: boolean }) {
  const { t, i18n } = useTranslation();
  const { options } = useRepoOptions(isAdmin);
  const [repoId, setRepoId] = useState("");
  const [subscription, setSubscription] = useState("");

  const snapshots = useQuery({
    queryKey: ["backup-snapshots", repoId, subscription],
    queryFn: () =>
      endpoints.backupSnapshots(
        Number(repoId),
        subscription.trim() === "" ? undefined : Number(subscription.trim()),
      ),
    enabled: repoId !== "",
    retry: false,
  });

  return (
    <Card>
      <CardHeader title={t("backups.snapshots")} description={t("backups.snapshotsHint")} />
      <CardBody className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("backups.repository")} htmlFor="snapshot-repo">
            <Select
              id="snapshot-repo"
              value={repoId}
              onChange={(event) => setRepoId(event.target.value)}
            >
              <option value="">{t("backups.chooseRepository")}</option>
              {options.map((option) => (
                <option key={option.id} value={String(option.id)}>
                  {option.label}
                </option>
              ))}
            </Select>
          </Field>

          <div>
            <Field label={t("backups.subscriptionFilter")} htmlFor="snapshot-subscription">
              <Input
                id="snapshot-subscription"
                dir="ltr"
                inputMode="numeric"
                placeholder={t("backups.subscriptionFilterPlaceholder")}
                aria-describedby="snapshot-subscription-hint"
                value={subscription}
                onChange={(event) => setSubscription(event.target.value)}
              />
            </Field>
            <p id="snapshot-subscription-hint" className="-mt-2 text-xs text-ink-muted">
              {t("backups.subscriptionFilterHint")}
            </p>
          </div>
        </div>

        {repoId === "" ? (
          <p className="text-sm text-ink-muted">{t("backups.chooseRepositoryFirst")}</p>
        ) : snapshots.isPending ? (
          <div className="flex justify-center py-6 text-ink-muted">
            <Spinner />
          </div>
        ) : snapshots.error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {snapshots.error instanceof ApiError
              ? snapshots.error.message
              : String(snapshots.error)}
          </p>
        ) : snapshots.data!.snapshots.length === 0 ? (
          <p className="text-sm text-ink-muted">{t("backups.noSnapshots")}</p>
        ) : (
          <ul className="divide-y divide-border">
            {snapshots.data!.snapshots.map((snapshot) => (
              <li key={snapshot.id} className="flex flex-wrap items-start gap-x-3 gap-y-2 py-3">
                <Archive className="mt-0.5 h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-x-2.5">
                    <span dir="ltr" className="font-mono text-sm text-ink">
                      {snapshot.short_id || snapshot.id.slice(0, 8)}
                    </span>
                    <span className="text-xs text-ink-muted">
                      {formatDateTime(snapshot.time, i18n.language)}
                    </span>
                  </div>
                  <p dir="ltr" className="truncate font-mono text-xs text-ink-subtle">
                    {snapshot.paths.join(" ")}
                  </p>
                  {snapshot.tags.length > 0 ? (
                    <ul className="mt-1 flex flex-wrap gap-1">
                      {snapshot.tags.map((tag) => (
                        <li key={tag}>
                          <Badge tone="neutral">
                            <span dir="ltr" className="font-mono">
                              {tag}
                            </span>
                          </Badge>
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
                {isAdmin ? (
                  <RestoreButton repoId={Number(repoId)} snapshotId={snapshot.id} />
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}

function RestoreButton({ repoId, snapshotId }: { repoId: number; snapshotId: string }) {
  const { t } = useTranslation();
  const [confirming, setConfirming] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const restore = useMutation({
    mutationFn: () => endpoints.restoreBackup({ repo_id: repoId, snapshot_id: snapshotId }),
    onSuccess: (accepted) => {
      setConfirming(false);
      setError(null);
      setTaskId(accepted.task_id);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <div className="basis-full sm:basis-auto">
      <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
        {t("backups.restore")}
      </Button>

      {error ? (
        <p role="alert" className="mt-2 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
      {taskId ? <TaskNotice key={taskId} taskId={taskId} /> : null}

      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t("backups.restoreTitle")}
        description={t("backups.restoreHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="primary" onClick={() => restore.mutate()} disabled={restore.isPending}>
              {restore.isPending ? <Spinner /> : null}
              {t("backups.restoreConfirm")}
            </Button>
          </>
        }
      >
        {/* Restoring in place is deliberately not implemented: the files land in
            a fresh 0700 staging directory and the finished task says where. */}
        <p className="text-sm text-ink-muted">{t("backups.restoreStaging")}</p>
        <code dir="ltr" className="mt-2 block font-mono text-xs text-ink-subtle">
          {snapshotId}
        </code>
      </Dialog>
    </div>
  );
}
