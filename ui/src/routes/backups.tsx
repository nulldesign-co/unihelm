import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Archive,
  Check,
  Copy,
  Database,
  HardDrive,
  KeyRound,
  Play,
  Plus,
  Trash2,
} from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { ScheduleField, ScheduleText } from "@/components/schedule-field";
import { TaskLogPanel, TaskNotice } from "@/components/task-notice";
import { SectionHeader } from "@/components/ui/section-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { Menu, MenuItem } from "@/components/ui/menu";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import {
  ApiError,
  endpoints,
  type BackupRepo,
  type BackupRun,
  type BackupRunStatus,
  type BackupScopeKind,
  type BackupSnapshot,
  type RepoInitRequest,
  type RepoInitResponse,
} from "@/lib/api";
import { checkSchedule } from "@/lib/cron-schedule";
import { staggerStyle } from "@/lib/motion";
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
      <PageHeader title={t("backups.title")} description={t("backups.subtitle")} />

      <RunNowCard isAdmin={isAdmin} />
      {isAdmin ? <RepositoriesCard /> : null}
      <SchedulesCard isAdmin={isAdmin} />
      <RunsCard />
      <SnapshotsCard isAdmin={isAdmin} />
    </div>
  );
}


/**
 * A ghost of a table, not of a list.
 *
 * Every section on this page loads into a table, and the shared `ListSkeleton`
 * draws an avatar and a trailing pill — a shape none of them has. A placeholder
 * that lies about the layout is worse than none, because the content then lands
 * somewhere other than where the reader was already looking.
 */
function TableSkeleton({ rows = 3, columns = 3 }: { rows?: number; columns?: number }) {
  return (
    // The shared `Table`, not a copy of its classes — the five sections here
    // and every other table ghost in the panel then follow --radius-card and
    // --shadow-card together.
    <div role="status" aria-live="polite">
      <Table>
        <thead>
          <tr>
            {Array.from({ length: columns }, (_, column) => (
              <Th key={column} className={column === 0 ? undefined : "w-32"}>
                <Skeleton className="h-3 w-16" />
              </Th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }, (_, row) => (
            <tr key={row} className="animate-rise-in stagger" style={staggerStyle(row)}>
              {Array.from({ length: columns }, (_, column) => (
                <Td key={column}>
                  {/* Uneven first cells: a perfectly regular ghost reads as a
                      loading graphic rather than as the shape of a row. */}
                  <Skeleton
                    className={
                      column === 0 ? (row % 2 === 0 ? "h-4 w-2/5" : "h-4 w-3/5") : "h-4 w-full"
                    }
                  />
                </Td>
              ))}
            </tr>
          ))}
        </tbody>
      </Table>
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
          <div role="status" aria-live="polite" className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-9 w-full" />
              </div>
              <div className="space-y-1.5">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-9 w-full" />
              </div>
            </div>
            <Skeleton className="h-9 w-36" />
          </div>
        ) : options.length === 0 ? (
          <EmptyState
            className="py-10"
            icon={<Archive aria-hidden />}
            title={isAdmin ? t("backups.noRepos") : t("backups.noReposCustomerTitle")}
            hint={isAdmin ? t("backups.noReposHint") : t("backups.noReposCustomer")}
          />
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

            <Button
              variant="primary"
              disabled={!ready}
              loading={run.isPending}
              onClick={() => run.mutate()}
            >
              <Play className="h-4 w-4" aria-hidden />
              {t("backups.startRun")}
            </Button>
          </>
        )}

        {error ? <Callout tone="danger">{error}</Callout> : null}

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

  const addButton = (size: "sm" | "md") => (
    <Button variant="primary" size={size} onClick={() => setCreating(true)}>
      <Plus className={size === "sm" ? "h-3.5 w-3.5" : "h-4 w-4"} aria-hidden />
      {t("backups.addRepository")}
    </Button>
  );

  return (
    <section className="space-y-3">
      <SectionHeader
        title={t("backups.repositories")}
        description={t("backups.repositoriesHint")}
        actions={addButton("sm")}
      />

      {repos.isPending ? (
        <TableSkeleton rows={3} columns={4} />
      ) : repos.error ? (
        <Callout tone="danger">
          {repos.error instanceof ApiError ? repos.error.message : String(repos.error)}
        </Callout>
      ) : (repos.data?.repos.length ?? 0) === 0 ? (
        <EmptyState
          icon={<Archive aria-hidden />}
          title={t("backups.noRepos")}
          hint={t("backups.noReposHint")}
          action={addButton("md")}
        />
      ) : (
        // Every table on this page states its own scroll threshold in pixels,
        // sized to its column count, so the five of them agree about when a
        // narrow viewport starts scrolling sideways instead of squeezing.
        <Table className="min-w-[560px]">
          <thead>
            <tr>
              <Th>{t("backups.label")}</Th>
              <Th>{t("backups.kindLabel")}</Th>
              <Th>{t("backups.credentials")}</Th>
              <Th>
                <span className="sr-only">{t("backups.actions")}</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {repos.data!.repos.map((repo, index) => (
              <RepoRow key={repo.id} repo={repo} index={index} />
            ))}
          </tbody>
        </Table>
      )}

      <CreateRepoDialog open={creating} onClose={() => setCreating(false)} />
    </section>
  );
}

function RepoRow({ repo, index }: { repo: BackupRepo; index: number }) {
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
    <>
      <Tr className="animate-rise-in stagger" style={staggerStyle(index)}>
        <Td>
          <div className="flex min-w-0 items-center gap-3">
            {repo.kind === "s3" ? (
              <Database className="h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
            ) : (
              <HardDrive className="h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
            )}
            <div className="min-w-0">
              <span className="block max-w-xs truncate font-medium text-ink">{repo.label}</span>
              <span className="block max-w-xs truncate font-mono text-xs text-ink-subtle">
                {repo.path_or_url}
              </span>
            </div>
          </div>
        </Td>
        <Td>
          <Badge tone="neutral">{t(`backups.kind.${repo.kind}`)}</Badge>
        </Td>
        <Td>
          {repo.has_credentials ? (
            <Badge tone="accent" dot>
              {t("backups.hasCredentials")}
            </Badge>
          ) : (
            <span className="text-ink-subtle">{t("common.none")}</span>
          )}
        </Td>
        <Td className="w-px text-end">
          <Menu label={t("backups.actions")}>
            <MenuItem danger icon={<Trash2 />} onClick={() => setConfirming(true)}>
              {t("backups.forget")}
            </MenuItem>
          </Menu>

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
                <Button
                  variant="danger"
                  loading={remove.isPending}
                  onClick={() => remove.mutate()}
                >
                  {t("backups.forgetConfirm")}
                </Button>
              </>
            }
          >
            <p className="text-sm text-ink-muted">{t("backups.forgetKeepsData")}</p>
          </Dialog>
        </Td>
      </Tr>
      {/* A continuation of the row above rather than a row of its own, so it
          gets no hover tint and no accent bar — a second highlighted row would
          read as a second repository. `RunRow` reports failure the same way. */}
      {error ? (
        <tr>
          <Td colSpan={4}>
            <Callout tone="danger">{error}</Callout>
          </Td>
        </tr>
      ) : null}
    </>
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
              disabled={!ready}
              loading={create.isPending}
              onClick={() => create.mutate()}
            >
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
                  placeholder="us-east-1"
                  autoComplete="off"
                  value={region}
                  onChange={(event) => setRegion(event.target.value)}
                />
              </Field>
            </>
          ) : null}

          {error ? <Callout tone="danger">{error}</Callout> : null}
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
 *
 * Deliberately *not* built on `Dialog`, for the same reason databases.tsx forks
 * it: `Dialog` closes on Escape and on a backdrop click, which is right for
 * every other modal in the panel and exactly wrong here. A stray Escape would
 * defeat the acknowledgement gate and cost the operator a password no endpoint
 * can produce again. The gated button is the only way out.
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

  const dismiss = () => {
    setAcknowledged(false);
    setCopied(false);
    setCopyFailed(false);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex animate-fade-in items-start justify-center overflow-y-auto bg-black/60 p-4 pt-[8vh] backdrop-blur-[2px]"
      role="alertdialog"
      aria-modal="true"
      aria-label={t("backups.passwordTitle")}
    >
      <div className="w-full max-w-lg animate-pop-in rounded-card border border-danger/40 bg-surface shadow-pop">
        <header className="flex items-start gap-3 border-b border-border px-5 py-4">
          <KeyRound className="mt-0.5 h-5 w-5 shrink-0 text-danger" aria-hidden />
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-ink">{t("backups.passwordTitle")}</h2>
            <p className="mt-0.5 text-sm text-ink-muted">
              {t("backups.passwordSubtitle", { label: result.label })}
            </p>
          </div>
        </header>

        <div className="space-y-3 px-5 py-4">
          {/* The consequence, in the words the API states it in: without this
              password *and* /etc/unihelm/secret.key, a panel-scope backup cannot
              be restored after the panel is lost. */}
          <Callout tone="danger" title={t("backups.passwordOnce")}>
            {t("backups.passwordNotice")}
          </Callout>

          <div>
            <p className="text-xs text-ink-subtle">{t("backups.password")}</p>
            <div className="mt-1 flex items-center gap-2">
              <code className="min-w-0 flex-1 rounded-lg border border-border bg-canvas px-3 py-2 font-mono text-sm break-all text-ink select-all">
                {result.password}
              </code>
              <Button variant="outline" size="sm" onClick={() => void copy()}>
                {copied ? (
                  <Check className="h-3.5 w-3.5" aria-hidden />
                ) : (
                  <Copy className="h-3.5 w-3.5" aria-hidden />
                )}
                {copied ? t("backups.copied") : t("backups.copy")}
              </Button>
            </div>
            {copyFailed ? (
              <p role="alert" className="mt-1 text-xs text-danger">
                {t("backups.copyFailed")}
              </p>
            ) : null}
          </div>

          <div>
            <p className="text-xs text-ink-subtle">{t("backups.resticRepository")}</p>
            <code className="mt-1 block rounded-lg border border-border bg-canvas px-3 py-2 font-mono text-xs break-all text-ink-muted">
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

        <footer className="flex justify-end rounded-b-card border-t border-border bg-surface-muted/50 px-5 py-3.5">
          <Button variant="primary" disabled={!acknowledged} onClick={dismiss}>
            {t("backups.passwordDone")}
          </Button>
        </footer>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Schedules
// ---------------------------------------------------------------------------

function SchedulesCard({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useTranslation();
  const [creating, setCreating] = useState(false);
  const schedules = useQuery({ queryKey: ["backup-schedules"], queryFn: endpoints.backupSchedules });

  const addButton = (size: "sm" | "md") =>
    isAdmin ? (
      <Button variant="primary" size={size} onClick={() => setCreating(true)}>
        <Plus className={size === "sm" ? "h-3.5 w-3.5" : "h-4 w-4"} aria-hidden />
        {t("backups.addSchedule")}
      </Button>
    ) : null;

  return (
    <section className="space-y-3">
      <SectionHeader
        title={t("backups.schedules")}
        description={t("backups.schedulesHint")}
        actions={addButton("sm")}
      />

      {schedules.isPending ? (
        <TableSkeleton rows={3} columns={isAdmin ? 6 : 5} />
      ) : (schedules.data?.schedules.length ?? 0) === 0 ? (
        <EmptyState
          icon={<Archive aria-hidden />}
          title={t("backups.noSchedules")}
          hint={t("backups.noSchedulesHint")}
          action={addButton("md")}
        />
      ) : (
        <Table className="min-w-[720px]">
          <thead>
            <tr>
              <Th>{t("backups.status")}</Th>
              <Th>{t("backups.when")}</Th>
              <Th>{t("backups.scope")}</Th>
              {/* The retention policy is what decides how far back a restore
                  can go, so it belongs on the row and not behind an edit
                  dialog. */}
              <Th>{t("backups.retention")}</Th>
              <Th>{t("backups.repository")}</Th>
              {isAdmin ? (
                <Th>
                  <span className="sr-only">{t("backups.actions")}</span>
                </Th>
              ) : null}
            </tr>
          </thead>
          <tbody>
            {schedules.data!.schedules.map((schedule, index) => (
              <Tr
                key={schedule.id}
                className="animate-rise-in stagger"
                style={staggerStyle(index)}
              >
                <Td>
                  <Badge tone={schedule.enabled ? "success" : "neutral"} dot>
                    {schedule.enabled ? t("backups.enabled") : t("backups.disabled")}
                  </Badge>
                </Td>
                <Td>
                  <span className="block font-mono text-xs text-ink tnum">{schedule.cron}</span>
                  <ScheduleText
                    schedule={schedule.cron}
                    className="mt-0.5 block text-xs text-ink-muted"
                  />
                </Td>
                <Td className="text-ink-muted">
                  {t(`backups.scope${schedule.scope === "panel" ? "Panel" : "Subscription"}`)}
                  {schedule.subscription_id === null ? "" : ` #${schedule.subscription_id}`}
                </Td>
                <Td className="text-xs text-ink-muted tnum">
                  {t("backups.retentionSummary", {
                    daily: schedule.keep_daily,
                    weekly: schedule.keep_weekly,
                    monthly: schedule.keep_monthly,
                  })}
                </Td>
                <Td>
                  <Badge tone="neutral">
                    <span className="font-mono tnum">#{schedule.repo_id}</span>
                  </Badge>
                </Td>
                {isAdmin ? (
                  <Td className="w-px text-end">
                    <DeleteScheduleButton id={schedule.id} />
                  </Td>
                ) : null}
              </Tr>
            ))}
          </tbody>
        </Table>
      )}

      {/* Mounted only for an administrator: the dialog reads the repository
          list to fill its picker, and that endpoint answers a customer 403. */}
      {isAdmin ? (
        <CreateScheduleDialog open={creating} onClose={() => setCreating(false)} />
      ) : null}
    </section>
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
      <Menu label={t("backups.actions")}>
        <MenuItem danger icon={<Trash2 />} onClick={() => setConfirming(true)}>
          {t("backups.deleteSchedule")}
        </MenuItem>
      </Menu>
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
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
              {t("backups.deleteSchedule")}
            </Button>
          </>
        }
      >
        {error ? <Callout tone="danger">{error}</Callout> : null}
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
            disabled={!ready}
            loading={create.isPending}
            onClick={() => create.mutate()}
          >
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
                  inputMode="numeric"
                  className="mt-1 tnum"
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

        {error ? <Callout tone="danger">{error}</Callout> : null}
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
    <section className="space-y-3">
      <SectionHeader title={t("backups.history")} description={t("backups.historyHint")} />

      {runs.isPending ? (
        <TableSkeleton rows={4} columns={5} />
      ) : (runs.data?.runs.length ?? 0) === 0 ? (
        <EmptyState
          icon={<Archive aria-hidden />}
          title={t("backups.noRuns")}
          hint={t("backups.noRunsHint")}
        />
      ) : (
        <Table className="min-w-[640px]">
          <thead>
            <tr>
              <Th>{t("backups.status")}</Th>
              <Th>{t("backups.started")}</Th>
              <Th>{t("backups.scope")}</Th>
              <Th>{t("backups.size")}</Th>
              <Th>{t("backups.snapshot")}</Th>
            </tr>
          </thead>
          <tbody>
            {runs.data!.runs.map((run, index) => (
              <RunRow key={run.id} run={run} index={index} />
            ))}
          </tbody>
        </Table>
      )}
    </section>
  );
}

function RunRow({ run, index }: { run: BackupRun; index: number }) {
  const { t, i18n } = useTranslation();

  return (
    <>
      <Tr className="animate-rise-in stagger" style={staggerStyle(index)}>
        <Td>
          <Badge tone={RUN_TONE[run.status]} dot>
            {t(`backups.runStatus.${run.status}`)}
          </Badge>
        </Td>
        <Td className="text-ink-muted">
          <time dateTime={run.started_at}>{formatDateTime(run.started_at, i18n.language)}</time>
        </Td>
        <Td className="text-ink-muted">
          {t(`backups.scope${run.scope === "panel" ? "Panel" : "Subscription"}`)}
          {run.subscription_id === null ? "" : ` #${run.subscription_id}`}
        </Td>
        <Td className="text-ink-muted tnum">
          {run.bytes === null ? t("common.none") : formatBytes(run.bytes, i18n.language)}
        </Td>
        <Td className="font-mono text-xs text-ink-muted tnum">
          {run.snapshot_id === null ? t("common.none") : run.snapshot_id.slice(0, 8)}
        </Td>
      </Tr>
      {run.error ? (
        // A history that recorded only successes could not answer "when did
        // this stop working", which is the question a backup history exists to
        // answer — so the failure text gets a full row rather than a tooltip.
        // A plain `tr`, like RepoRow's: it continues the row above rather than
        // standing beside it, so it takes neither the tint nor the accent bar.
        <tr>
          <Td colSpan={5}>
            <Callout tone="danger">
              <span className="block font-mono text-xs break-words">{run.error}</span>
            </Callout>
          </Td>
        </tr>
      ) : null}
    </>
  );
}

function formatDateTime(iso: string, language: string): string {
  try {
    return new Intl.DateTimeFormat(language, { dateStyle: "short", timeStyle: "short" }).format(
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
  const { t } = useTranslation();
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
    <section className="space-y-3">
      <SectionHeader title={t("backups.snapshots")} description={t("backups.snapshotsHint")} />

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
              inputMode="numeric"
              className="tnum"
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
        // The idle state is still a state: the reader is told what the picker
        // above would fill this space with, rather than left with a bare line.
        <EmptyState
          icon={<Archive aria-hidden />}
          title={t("backups.chooseRepositoryFirst")}
          hint={t("backups.snapshotsHint")}
        />
      ) : snapshots.isPending ? (
        <TableSkeleton rows={3} columns={isAdmin ? 3 : 2} />
      ) : snapshots.error ? (
        <Callout tone="danger">
          {snapshots.error instanceof ApiError
            ? snapshots.error.message
            : String(snapshots.error)}
        </Callout>
      ) : snapshots.data!.snapshots.length === 0 ? (
        <EmptyState
          icon={<Archive aria-hidden />}
          title={t("backups.noSnapshots")}
          hint={t("backups.noSnapshotsHint")}
        />
      ) : (
        <Table className="min-w-[520px]">
          <thead>
            <tr>
              <Th>{t("backups.snapshot")}</Th>
              <Th>{t("backups.started")}</Th>
              {isAdmin ? (
                <Th>
                  <span className="sr-only">{t("backups.actions")}</span>
                </Th>
              ) : null}
            </tr>
          </thead>
          <tbody>
            {snapshots.data!.snapshots.map((snapshot, index) => (
              <SnapshotRow
                key={snapshot.id}
                snapshot={snapshot}
                repoId={Number(repoId)}
                isAdmin={isAdmin}
                index={index}
              />
            ))}
          </tbody>
        </Table>
      )}
    </section>
  );
}

function SnapshotRow({
  snapshot,
  repoId,
  isAdmin,
  index,
}: {
  snapshot: BackupSnapshot;
  repoId: number;
  isAdmin: boolean;
  index: number;
}) {
  const { t, i18n } = useTranslation();
  const [confirming, setConfirming] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const restore = useMutation({
    mutationFn: () => endpoints.restoreBackup({ repo_id: repoId, snapshot_id: snapshot.id }),
    onSuccess: (accepted) => {
      setConfirming(false);
      setError(null);
      setTaskId(accepted.task_id);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const columns = isAdmin ? 3 : 2;

  return (
    <>
      <Tr className="animate-rise-in stagger" style={staggerStyle(index)}>
        <Td>
          <div className="flex min-w-0 items-start gap-3">
            <Archive className="mt-0.5 h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
            <div className="min-w-0">
              <span className="block font-mono text-sm text-ink tnum">
                {snapshot.short_id || snapshot.id.slice(0, 8)}
              </span>
              <span className="block max-w-md truncate font-mono text-xs text-ink-subtle">
                {snapshot.paths.join(" ")}
              </span>
              {snapshot.tags.length > 0 ? (
                <ul className="mt-1 flex flex-wrap gap-1">
                  {snapshot.tags.map((tag) => (
                    <li key={tag}>
                      <Badge tone="neutral">
                        <span className="font-mono">{tag}</span>
                      </Badge>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          </div>
        </Td>
        <Td className="text-ink-muted">
          <time dateTime={snapshot.time}>{formatDateTime(snapshot.time, i18n.language)}</time>
        </Td>
        {isAdmin ? (
          <Td className="w-px text-end align-top">
            <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
              {t("backups.restore")}
            </Button>

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
                  <Button
                    variant="primary"
                    loading={restore.isPending}
                    onClick={() => restore.mutate()}
                  >
                    {t("backups.restoreConfirm")}
                  </Button>
                </>
              }
            >
              {/* Restoring in place is deliberately not implemented: the files
                  land in a fresh 0700 staging directory and the finished task
                  says where. */}
              <p className="text-sm text-ink-muted">{t("backups.restoreStaging")}</p>
              <code className="mt-2 block text-start font-mono text-xs text-ink-subtle">
                {snapshot.id}
              </code>
            </Dialog>
          </Td>
        ) : null}
      </Tr>
      {/* The receipt gets a full-width continuation row rather than the action
          cell it was fired from: that cell is `w-px` and end-aligned, and a
          bordered task card inside it pulled the whole row out of shape. */}
      {error !== null || taskId !== null ? (
        <tr>
          <Td colSpan={columns} className="space-y-2 text-start">
            {error ? <Callout tone="danger">{error}</Callout> : null}
            {taskId ? <TaskNotice key={taskId} taskId={taskId} /> : null}
          </Td>
        </tr>
      ) : null}
    </>
  );
}
