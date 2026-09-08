import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  Archive,
  Download,
  Globe,
  Newspaper,
  Plug,
  RefreshCw,
  TerminalSquare,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { TaskLogPanel } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input, Textarea } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { SectionHeader } from "@/components/ui/section-header";
import { Select } from "@/components/ui/select";
import { ListSkeleton, Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { ApiError, endpoints, type BackupRun, type SiteView } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import { useSession } from "@/lib/session";
import {
  MAX_CLI_ARGS,
  WP_SUBCOMMANDS,
  adminUserProblem,
  cliProblem,
  coreVersionProblem,
  emailProblem,
  hasUpdate,
  lastFileBackup,
  localeProblem,
  queuedTaskId,
  readPluginList,
  splitCliArgs,
  subdirectoryProblem,
  titleProblem,
  wordpressApi,
  type WpDetect,
  type WpInstallRow,
  type WpPlugin,
  type WpSubcommand,
} from "@/lib/wordpress-api";

/**
 * The WordPress toolkit (spec §11.12).
 *
 * The whole backend for this shipped with no page at all, so the most common
 * thing anybody does with a hosting panel was reachable only from the command
 * line. Every control here maps to one of the six `wp.*` operations and to its
 * real input; there is no control on this page the agent cannot honour.
 *
 * Three decisions worth stating, because each is a place a page like this
 * usually lies:
 *
 * 1. **An install is a task, not a click.** `wp.install`, `wp.update` and
 *    `wp.plugin.update` answer 202 with a task id, so nothing here reports an
 *    outcome on the strength of the response. The task's own log is shown until
 *    it settles and the site is re-read afterwards — what the panel says about
 *    a site is what the next `wp.detect` said, never what a button did.
 * 2. **A WordPress with no install row cannot be managed, and says so.**
 *    `detected` comes from the filesystem and `install` from the database, and
 *    the combinations are genuinely different. Everything except detection is
 *    addressed by install id, which only `wp.install` creates, so a WordPress
 *    somebody uploaded gets a card admitting the panel can see it and cannot
 *    touch it — rather than buttons that would 404.
 * 3. **The reads here run PHP.** `wp.detect` shells out to `wp core version`
 *    and `wp.plugin.list` to `wp plugin list`, each a real process on the
 *    server running as the tenant. So these queries do not refetch on window
 *    focus the way the rest of the panel's do; they refresh on a button, which
 *    is the honest cost of an answer that is live rather than a cached table.
 */

/** How long a `wp.*` read stays fresh. See the note above: each one is a process. */
const WP_READ_STALE_MS = 60_000;

/** Recent backup history: enough to answer "has this tenant's home been backed up". */
const BACKUP_RUN_WINDOW = 50;

/** What the page is waiting on for one site, so the log lands in the right card. */
interface Pending {
  taskId: string;
  /** Which button queued it. Only the line above the log differs. */
  kind: "install" | "core" | "plugins";
}

/**
 * A queued task, or `null` when the agent ran the work inside the request.
 *
 * Both are success; only one of them has anything to watch. Passing the
 * distinction up rather than substituting an empty task id keeps a log panel
 * from being rendered for a task that does not exist.
 */
type QueueHandler = (taskId: string | null) => void;

export function WordPressPage() {
  const { t } = useTranslation();
  const { user } = useSession();
  const queryClient = useQueryClient();
  const [installing, setInstalling] = useState(false);
  const [pending, setPending] = useState<Record<number, Pending>>({});

  const sites = useQuery({ queryKey: ["sites"], queryFn: endpoints.sites });
  const siteList = sites.data?.sites ?? [];

  // One detect per site: no operation lists installations, so "which sites run
  // WordPress" is that question asked of each of them.
  const detects = useQueries({
    queries: siteList.map((site) => ({
      queryKey: ["wordpress", "detect", site.id],
      queryFn: () => wordpressApi.detect(site.id),
      staleTime: WP_READ_STALE_MS,
      refetchOnWindowFocus: false,
      retry: false,
    })),
  });

  // `backup_manage` is a different permission from `site_manage`, so an
  // operator who may install WordPress may not be allowed to read run history.
  // That is a reason to say nothing about backups, never a reason to imply
  // there are none.
  const canReadBackups = user?.permissions.includes("backup_manage") ?? false;
  const backupRuns = useQuery({
    queryKey: ["backup-runs", BACKUP_RUN_WINDOW],
    queryFn: () => endpoints.backupRuns(BACKUP_RUN_WINDOW),
    enabled: canReadBackups,
    retry: false,
  });

  const rows = siteList.map((site, index) => ({ site, detect: detects[index] }));
  const withWordPress = rows.flatMap(({ site, detect }) =>
    detect?.data?.detected === true ? [{ site, data: detect.data }] : [],
  );
  const withoutWordPress = rows.flatMap(({ site, detect }) =>
    detect?.data?.detected === false ? [site] : [],
  );
  // Never folded into "no WordPress here": a site whose check failed is a site
  // the panel knows nothing about, and listing it as installable would invite
  // installing over a live one.
  const unchecked = rows.flatMap(({ site, detect }) =>
    detect?.isError === true ? [{ site, error: detect.error }] : [],
  );
  // An install queued for a site with no card yet — it is in the list below,
  // not above — still has to be watched somewhere.
  const installedIds = new Set(withWordPress.map(({ site }) => site.id));
  const installingOn = siteList.flatMap((site) => {
    const task = pending[site.id];
    return task?.kind === "install" && !installedIds.has(site.id) ? [{ site, task }] : [];
  });

  // What the panel says about a site after a task is whatever the next read
  // says, not what the button did. The plugin lists go too, and deliberately
  // all of them: a core update changes which plugins report an update waiting,
  // and a stale table there is the one that gets acted on.
  const settle = (siteId: number) => () => {
    void queryClient.invalidateQueries({ queryKey: ["wordpress", "detect", siteId] });
    void queryClient.invalidateQueries({ queryKey: ["wordpress", "plugins"] });
  };

  const queue =
    (siteId: number, kind: Pending["kind"]): QueueHandler =>
    (taskId) => {
      if (taskId === null) {
        // Finished inside the request: there is no log to watch, and the
        // refetch is the whole of the answer.
        settle(siteId)();
        return;
      }
      setPending((current) => ({ ...current, [siteId]: { taskId, kind } }));
    };

  const dismiss = (siteId: number) =>
    setPending((current) => {
      const next = { ...current };
      delete next[siteId];
      return next;
    });

  // Any answered detect carries the toolkit's state: it is a property of the
  // server, not of whichever site happened to be asked.
  const toolkit = detects.find((query) => query.data !== undefined)?.data;
  const refreshing = sites.isFetching || detects.some((query) => query.isFetching);

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("wordpress.title")}
        description={t("wordpress.subtitle")}
        actions={
          <>
            <Button
              variant="secondary"
              loading={refreshing}
              onClick={() => {
                void queryClient.invalidateQueries({ queryKey: ["sites"] });
                void queryClient.invalidateQueries({ queryKey: ["wordpress"] });
              }}
            >
              <RefreshCw className="h-4 w-4" aria-hidden />
              {t("wordpress.refresh")}
            </Button>
            <Button
              variant="primary"
              disabled={withoutWordPress.length === 0}
              onClick={() => setInstalling(true)}
            >
              <Download className="h-4 w-4" aria-hidden />
              {t("wordpress.install")}
            </Button>
          </>
        }
      />

      {sites.isPending ? (
        <ListSkeleton rows={3} />
      ) : sites.error ? (
        <Callout tone="danger" title={t("wordpress.sitesFailed")}>
          {sites.error instanceof ApiError ? sites.error.message : String(sites.error)}
        </Callout>
      ) : siteList.length === 0 ? (
        <EmptyState
          icon={<Globe aria-hidden />}
          title={t("wordpress.noSites")}
          hint={t("wordpress.noSitesHint")}
          action={
            <Link to="/sites">
              <Button variant="primary">{t("wordpress.noSitesAction")}</Button>
            </Link>
          }
        />
      ) : (
        <>
          <ToolkitCard toolkit={toolkit} />

          {installingOn.map(({ site, task }) => (
            <Card key={site.id}>
              <CardHeader
                title={t("wordpress.installQueued", { domain: site.domain })}
                description={t("wordpress.installQueuedHint")}
                action={
                  <Button variant="ghost" size="sm" onClick={() => dismiss(site.id)}>
                    {t("common.dismiss")}
                  </Button>
                }
              />
              <CardBody className="pt-0">
                <TaskLogPanel key={task.taskId} taskId={task.taskId} onSettled={settle(site.id)} />
              </CardBody>
            </Card>
          ))}

          <section className="space-y-4">
            <SectionHeader
              title={t("wordpress.installedTitle")}
              description={t("wordpress.installedSubtitle")}
            />
            {withWordPress.length === 0 && detects.some((query) => query.isPending) ? (
              <ListSkeleton rows={2} />
            ) : withWordPress.length === 0 ? (
              <EmptyState
                icon={<Newspaper aria-hidden />}
                title={t("wordpress.noneInstalled")}
                hint={t("wordpress.noneInstalledHint")}
              />
            ) : (
              withWordPress.map(({ site, data }, index) => (
                <SiteCard
                  key={site.id}
                  site={site}
                  detect={data}
                  index={index}
                  pending={pending[site.id]}
                  backup={
                    canReadBackups && backupRuns.data
                      ? lastFileBackup(backupRuns.data.runs, site.subscription_id)
                      : null
                  }
                  backupKnown={canReadBackups && backupRuns.data !== undefined}
                  onQueued={queue}
                  onDismiss={dismiss}
                  onSettled={settle(site.id)}
                />
              ))
            )}
          </section>

          {withoutWordPress.length > 0 ? (
            <section className="space-y-4">
              <SectionHeader
                title={t("wordpress.installableTitle")}
                description={t("wordpress.installableSubtitle")}
              />
              <InstallableTable sites={withoutWordPress} />
            </section>
          ) : null}

          {unchecked.length > 0 ? (
            <section className="space-y-4">
              <SectionHeader title={t("wordpress.uncheckedTitle")} />
              <Callout tone="warning" title={t("wordpress.uncheckedHint")}>
                <ul className="space-y-1">
                  {unchecked.map(({ site, error }) => (
                    <li key={site.id}>
                      <span className="font-medium text-ink">{site.domain}</span>
                      {" — "}
                      {error instanceof ApiError ? error.message : String(error)}
                    </li>
                  ))}
                </ul>
              </Callout>
            </section>
          ) : null}
        </>
      )}

      <InstallDialog
        open={installing}
        sites={withoutWordPress}
        onClose={() => setInstalling(false)}
        onQueued={(siteId, taskId) => {
          setInstalling(false);
          queue(siteId, "install")(taskId);
        }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// WP-CLI itself
// ---------------------------------------------------------------------------

/**
 * What the panel will run WordPress with.
 *
 * The pin's provenance is repeated from the operation rather than summarised.
 * The release's OpenPGP signature is **not** verified by this build, and an
 * operator who reads "checksum verified" without that sentence has been told
 * the download is trustworthier than it is.
 */
function ToolkitCard({ toolkit }: { toolkit: WpDetect | undefined }) {
  const { t } = useTranslation();

  return (
    <Card>
      <CardHeader title={t("wordpress.toolkitTitle")} description={t("wordpress.toolkitSubtitle")} />
      <CardBody className="space-y-3 pt-0">
        {toolkit === undefined ? (
          <Skeleton className="h-6 w-48" />
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={toolkit.wp_cli_installed ? "success" : "neutral"} dot>
                {toolkit.wp_cli_installed
                  ? t("wordpress.toolkitInstalled")
                  : t("wordpress.toolkitMissing")}
              </Badge>
              <Badge tone="neutral">
                <span>WP-CLI</span>
                <span className="font-mono tnum">{toolkit.wp_cli_version}</span>
              </Badge>
            </div>
            {!toolkit.wp_cli_installed ? (
              <p className="text-sm text-ink-muted">
                {t("wordpress.toolkitMissingHint", { version: toolkit.wp_cli_version })}
              </p>
            ) : null}
            <p className="text-xs text-ink-subtle">
              {t("wordpress.toolkitPin", { provenance: toolkit.wp_cli_pin_provenance })}
            </p>
          </>
        )}
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// One site that has WordPress on it
// ---------------------------------------------------------------------------

function SiteCard({
  site,
  detect,
  index,
  pending,
  backup,
  backupKnown,
  onQueued,
  onDismiss,
  onSettled,
}: {
  site: SiteView;
  detect: WpDetect;
  index: number;
  pending: Pending | undefined;
  backup: BackupRun | null;
  backupKnown: boolean;
  onQueued: (siteId: number, kind: Pending["kind"]) => QueueHandler;
  onDismiss: (siteId: number) => void;
  onSettled: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [updating, setUpdating] = useState(false);
  const [cli, setCli] = useState(false);

  const install = detect.install;
  // What WP-CLI said this visit, falling back to what the row remembers. The
  // difference matters: a row's version is the last time anything looked.
  const version = detect.version ?? install?.version ?? null;

  return (
    <Card className="animate-rise-in stagger" style={staggerStyle(index)}>
      <CardHeader
        title={site.domain}
        description={detect.path}
        action={
          install ? (
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="ghost" size="sm" onClick={() => setCli(true)}>
                <TerminalSquare className="h-4 w-4" aria-hidden />
                {t("wordpress.cliOpen")}
              </Button>
              <Button variant="primary" size="sm" onClick={() => setUpdating(true)}>
                {t("wordpress.updateCore")}
              </Button>
            </div>
          ) : null
        }
      />
      <CardBody className="space-y-4 pt-0">
        <div className="flex flex-wrap items-center gap-2">
          {version ? (
            <Badge tone="accent">
              <span>WordPress</span>
              <span className="font-mono tnum">{version}</span>
            </Badge>
          ) : (
            <Badge tone="warning">{t("wordpress.versionUnknown")}</Badge>
          )}
          {install ? (
            <>
              <Badge tone="neutral">{t("wordpress.installIdBadge", { id: install.id })}</Badge>
              <Badge tone="neutral">
                {install.db_id === null
                  ? t("wordpress.databaseNone")
                  : t("wordpress.databaseRecorded")}
              </Badge>
            </>
          ) : null}
        </div>

        {version === null && install ? (
          <p className="text-sm text-ink-muted">{t("wordpress.versionUnknownHint")}</p>
        ) : null}

        {install ? (
          <>
            <BackupLine backup={backup} known={backupKnown} language={i18n.language} />
            <PluginsSection installId={install.id} onQueued={onQueued(site.id, "plugins")} />
          </>
        ) : (
          <Callout tone="warning" title={t("wordpress.unmanagedTitle")}>
            {t("wordpress.unmanagedBody", { path: detect.path })}
          </Callout>
        )}

        {pending ? (
          <div>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm text-ink-muted">{t(`wordpress.queued.${pending.kind}`)}</p>
              <Button variant="ghost" size="sm" onClick={() => onDismiss(site.id)}>
                {t("common.dismiss")}
              </Button>
            </div>
            <TaskLogPanel key={pending.taskId} taskId={pending.taskId} onSettled={onSettled} />
          </div>
        ) : null}
      </CardBody>

      {install ? (
        <>
          <CoreUpdateDialog
            open={updating}
            site={site}
            install={install}
            version={version}
            backup={backup}
            backupKnown={backupKnown}
            language={i18n.language}
            onClose={() => setUpdating(false)}
            onQueued={(taskId) => {
              setUpdating(false);
              onQueued(site.id, "core")(taskId);
            }}
          />
          <CliDialog open={cli} installId={install.id} onClose={() => setCli(false)} />
        </>
      ) : null}
    </Card>
  );
}

/**
 * Whether anything has actually been backed up, before an update replaces files.
 *
 * The scope matters more than the date. A panel-scope run holds `panel.db`,
 * `/etc/unihelm` and the panel's state directory — not one byte of a tenant
 * home — so it is not an answer to this question at all; `lastFileBackup`
 * refuses to count one. And what a subscription-scope run *does* hold is the
 * home directory and not the site's database, which is said rather than left
 * for somebody to discover during a restore.
 */
function BackupLine({
  backup,
  known,
  language,
}: {
  backup: BackupRun | null;
  known: boolean;
  language: string;
}) {
  const { t } = useTranslation();

  return (
    <p className="flex items-start gap-2 text-sm text-ink-muted">
      <Archive className="mt-0.5 h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
      {!known ? (
        <span>{t("wordpress.backupUnknown")}</span>
      ) : (
        <span>
          {backup?.finished_at
            ? t("wordpress.backupKnown", { when: formatDateTime(backup.finished_at, language) })
            : t("wordpress.backupNone")}{" "}
          {t("wordpress.backupScopeNote")}
        </span>
      )}
    </p>
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
// Plugins
// ---------------------------------------------------------------------------

function PluginsSection({
  installId,
  onQueued,
}: {
  installId: number;
  onQueued: QueueHandler;
}) {
  const { t } = useTranslation();
  const [confirming, setConfirming] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const plugins = useQuery({
    queryKey: ["wordpress", "plugins", installId],
    queryFn: () => wordpressApi.plugins(installId),
    staleTime: WP_READ_STALE_MS,
    refetchOnWindowFocus: false,
    retry: false,
  });

  const update = useMutation({
    mutationFn: (slugs: string[]) => wordpressApi.updatePlugins(installId, slugs),
    onSuccess: (response) => onQueued(queuedTaskId(response)),
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const reading = plugins.data ? readPluginList(plugins.data.plugins) : null;
  const outdated =
    reading?.kind === "plugins" ? reading.plugins.filter(hasUpdate).map((p) => p.name) : [];

  return (
    <div className="space-y-3">
      <SectionHeader
        title={t("wordpress.pluginsTitle")}
        description={t("wordpress.pluginsSubtitle")}
        actions={
          <>
            <Button
              variant="ghost"
              size="sm"
              loading={plugins.isFetching}
              onClick={() => void plugins.refetch()}
            >
              <RefreshCw className="h-4 w-4" aria-hidden />
              {t("wordpress.refresh")}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              disabled={outdated.length === 0}
              loading={update.isPending}
              onClick={() => setConfirming(outdated)}
            >
              <Plug className="h-4 w-4" aria-hidden />
              {t("wordpress.updateAll", { total: outdated.length })}
            </Button>
          </>
        }
      />

      {plugins.isPending ? (
        <Skeleton className="h-24 w-full" />
      ) : plugins.error ? (
        <Callout tone="danger">
          {plugins.error instanceof ApiError ? plugins.error.message : String(plugins.error)}
        </Callout>
      ) : reading === null || reading.kind === "unreadable" ? (
        // Not an empty table: an empty table would say this site has no
        // plugins, and what actually happened is that WP-CLI answered with
        // something this build cannot read.
        <Callout tone="warning">{t("wordpress.pluginsUnreadable")}</Callout>
      ) : (
        <>
          {reading.unreadable > 0 ? (
            <Callout tone="warning">
              {t("wordpress.pluginsPartial", { total: reading.unreadable })}
            </Callout>
          ) : null}
          {reading.plugins.length === 0 ? (
            <p className="text-sm text-ink-muted">{t("wordpress.pluginsEmpty")}</p>
          ) : (
            <Table containerClassName="shadow-none">
              <thead>
                <tr>
                  <Th>{t("wordpress.pluginName")}</Th>
                  <Th>{t("wordpress.pluginStatus")}</Th>
                  <Th>{t("wordpress.pluginVersion")}</Th>
                  <Th>{t("wordpress.pluginUpdate")}</Th>
                  <Th className="w-24">
                    <span className="sr-only">{t("wordpress.pluginActions")}</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {reading.plugins.map((plugin) => (
                  <PluginRow
                    key={plugin.name}
                    plugin={plugin}
                    onUpdate={() => setConfirming([plugin.name])}
                  />
                ))}
              </tbody>
            </Table>
          )}
        </>
      )}

      {error ? <Callout tone="danger">{error}</Callout> : null}

      <PluginUpdateDialog
        slugs={confirming}
        onClose={() => setConfirming(null)}
        onConfirm={(slugs) => {
          setConfirming(null);
          setError(null);
          update.mutate(slugs);
        }}
      />
    </div>
  );
}

function PluginRow({ plugin, onUpdate }: { plugin: WpPlugin; onUpdate: () => void }) {
  const { t } = useTranslation();
  const outdated = hasUpdate(plugin);

  return (
    <Tr>
      <Td className="font-medium">{plugin.name}</Td>
      <Td className="text-ink-muted">{plugin.status ?? t("common.unknown")}</Td>
      <Td className="font-mono text-xs tnum text-ink-muted">
        {plugin.version ?? t("common.none")}
      </Td>
      <Td>
        {outdated ? (
          <Badge tone="warning" dot>
            {plugin.update_version
              ? t("wordpress.pluginUpdateTo", { version: plugin.update_version })
              : t("wordpress.pluginUpdateAvailable")}
          </Badge>
        ) : (
          // WP-CLI's own word, not a verdict of ours. `none`, `unavailable` and
          // `version higher than expected` all mean "nothing to install", and
          // flattening them to one word would hide the third — a plugin ahead
          // of its own directory listing, which is worth seeing.
          <span className="text-sm text-ink-muted">{plugin.update ?? t("common.unknown")}</span>
        )}
      </Td>
      <Td>
        {outdated ? (
          <Button variant="secondary" size="sm" onClick={onUpdate}>
            {t("wordpress.updatePlugin")}
          </Button>
        ) : null}
      </Td>
    </Tr>
  );
}

/**
 * The pause before a plugin update.
 *
 * A plugin update replaces files under a site that is serving, and WordPress
 * runs the new code on the very next request — there is no staging step here
 * and no undo. The dialog names what will change rather than asking whether
 * somebody is sure.
 */
function PluginUpdateDialog({
  slugs,
  onClose,
  onConfirm,
}: {
  slugs: string[] | null;
  onClose: () => void;
  onConfirm: (slugs: string[]) => void;
}) {
  const { t } = useTranslation();
  const list = slugs ?? [];

  return (
    <Dialog
      open={slugs !== null}
      onClose={onClose}
      title={
        list.length === 1
          ? t("wordpress.pluginUpdateTitle", { name: list[0] })
          : t("wordpress.pluginUpdateAllTitle", { total: list.length })
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={() => onConfirm(list)}>
            {t("wordpress.pluginUpdateConfirm")}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-ink-muted">
        <p>{t("wordpress.pluginUpdateBody")}</p>
        {list.length > 1 ? (
          <p className="font-mono text-xs break-words text-ink">{list.join(", ")}</p>
        ) : null}
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Core updates
// ---------------------------------------------------------------------------

function CoreUpdateDialog({
  open,
  site,
  install,
  version,
  backup,
  backupKnown,
  language,
  onClose,
  onQueued,
}: {
  open: boolean;
  site: SiteView;
  install: WpInstallRow;
  version: string | null;
  backup: BackupRun | null;
  backupKnown: boolean;
  language: string;
  onClose: () => void;
  onQueued: QueueHandler;
}) {
  const { t } = useTranslation();
  const [target, setTarget] = useState("");
  const [updateDb, setUpdateDb] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const versionProblem = coreVersionProblem(target);
  const pinned = target.trim();

  const update = useMutation({
    mutationFn: () =>
      wordpressApi.updateCore(install.id, {
        // Absent, not empty: a missing key means "the latest release", where an
        // empty string is a version the agent has to refuse.
        ...(pinned === "" ? {} : { version: pinned }),
        update_db: updateDb,
      }),
    onSuccess: (response) => onQueued(queuedTaskId(response)),
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("wordpress.updateTitle", { domain: site.domain })}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            loading={update.isPending}
            disabled={versionProblem !== null}
            onClick={() => {
              setError(null);
              update.mutate();
            }}
          >
            {t("wordpress.updateConfirm")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {/* What will change, in the two halves an operator needs: where this
            install is now, and where this button would put it. */}
        <p className="text-sm text-ink-muted">
          {version ? t("wordpress.updateFrom", { version }) : t("wordpress.updateFromUnknown")}{" "}
          {pinned === ""
            ? t("wordpress.updateTargetLatest")
            : t("wordpress.updateTargetPinned", { version: pinned })}
        </p>

        <Field
          label={t("wordpress.updateVersionLabel")}
          htmlFor="wp-core-version"
          error={versionProblem ? t("wordpress.updateVersionInvalid") : undefined}
        >
          <Input
            id="wp-core-version"
            value={target}
            placeholder="6.8.2"
            aria-invalid={versionProblem !== null}
            onChange={(event) => setTarget(event.target.value)}
          />
        </Field>
        <p className="-mt-2 text-xs text-ink-muted">{t("wordpress.updateVersionHint")}</p>

        <Switch
          checked={updateDb}
          onChange={setUpdateDb}
          label={t("wordpress.updateDbLabel")}
          description={t("wordpress.updateDbHint")}
        />

        <Callout tone="warning" title={t("wordpress.updateCostTitle")}>
          {t("wordpress.updateCost")}
        </Callout>

        <BackupLine backup={backup} known={backupKnown} language={language} />

        <p className="text-xs text-ink-subtle">{t("wordpress.updateNoAuto")}</p>

        {error ? <Callout tone="danger">{error}</Callout> : null}
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// The escape hatch
// ---------------------------------------------------------------------------

/**
 * `wp.cli`, treated as what it is: an advanced control, not the primary path.
 *
 * One argument per line rather than a command box, because there is no shell
 * here and a box that looked like one would be the lie. `--title=My Blog` is a
 * single argument; splitting a typed line on spaces would quietly make it two,
 * and the operator would be debugging the panel's parser instead of their
 * command.
 */
function CliDialog({
  open,
  installId,
  onClose,
}: {
  open: boolean;
  installId: number;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [subcommand, setSubcommand] = useState<WpSubcommand>("core");
  const [text, setText] = useState("version");
  const [error, setError] = useState<string | null>(null);

  const args = splitCliArgs(text);
  const problem = cliProblem(subcommand, args);
  const problemText =
    problem === null
      ? undefined
      : problem.kind === "tooMany"
        ? t("wordpress.cliTooMany", { max: MAX_CLI_ARGS })
        : problem.kind === "interactive"
          ? t("wordpress.cliInteractive")
          : t("wordpress.cliLine", {
              line: problem.index + 1,
              reason: t(`wordpress.cliArgProblem.${problem.problem}`),
            });

  const run = useMutation({
    mutationFn: () => wordpressApi.cli(installId, subcommand, args),
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title={t("wordpress.cliTitle")}
      description={t("wordpress.cliSubtitle")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.close")}
          </Button>
          <Button
            variant="primary"
            loading={run.isPending}
            disabled={problem !== null}
            onClick={() => {
              setError(null);
              run.mutate();
            }}
          >
            {t("wordpress.cliRun")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Callout tone="info">{t("wordpress.cliIntro")}</Callout>

        <Field label={t("wordpress.cliGroup")} htmlFor="wp-cli-group">
          <Select
            id="wp-cli-group"
            value={subcommand}
            onChange={(event) => setSubcommand(event.target.value as WpSubcommand)}
          >
            {WP_SUBCOMMANDS.map((group) => (
              <option key={group} value={group}>
                {group}
              </option>
            ))}
          </Select>
        </Field>

        <Field label={t("wordpress.cliArgs")} htmlFor="wp-cli-args" error={problemText}>
          <Textarea
            id="wp-cli-args"
            rows={5}
            className="font-mono text-xs"
            value={text}
            aria-invalid={problem !== null}
            onChange={(event) => setText(event.target.value)}
          />
        </Field>
        <p className="-mt-2 text-xs text-ink-muted">
          {t("wordpress.cliArgsHint", { max: MAX_CLI_ARGS })}
        </p>

        {error ? <Callout tone="danger">{error}</Callout> : null}

        {run.data ? <CliOutput result={run.data} /> : null}
      </div>
    </Dialog>
  );
}

function CliOutput({
  result,
}: {
  result: { argv: string[]; status: number; stdout: string; stderr: string };
}) {
  const { t } = useTranslation();
  const quiet = result.stdout.trim() === "" && result.stderr.trim() === "";

  return (
    <div className="space-y-2 rounded-lg border border-border bg-canvas p-3">
      <div className="flex flex-wrap items-center gap-2">
        {/* A non-zero exit is data, not a panel failure: `wp option get
            missing_key` exits 1, and calling that an error would make half of
            WP-CLI unusable. The number is shown; no verdict is added. */}
        <Badge tone={result.status === 0 ? "success" : "warning"}>
          {t("wordpress.cliExit", { status: result.status })}
        </Badge>
        <span className="text-xs text-ink-subtle">{t("wordpress.cliArgv")}</span>
      </div>
      {/* Echoed by the operation, so the `--path` the panel chose on the
          caller's behalf is visible rather than implied. */}
      <p className="font-mono text-xs break-all text-ink-subtle">{result.argv.join(" ")}</p>
      {result.stdout.trim() !== "" ? (
        <pre className="max-h-56 overflow-auto font-mono text-xs whitespace-pre-wrap text-ink">
          {result.stdout}
        </pre>
      ) : null}
      {result.stderr.trim() !== "" ? (
        <pre className="max-h-56 overflow-auto font-mono text-xs whitespace-pre-wrap text-danger">
          {result.stderr}
        </pre>
      ) : null}
      {quiet ? <p className="text-sm text-ink-muted">{t("wordpress.cliNoOutput")}</p> : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sites that could take a WordPress
// ---------------------------------------------------------------------------

/**
 * Whether WordPress could actually be *served* from this site.
 *
 * `wp.install` does not look at the site type, and would happily lay WordPress
 * down in a static site's root — where nginx hands `index.php` to the browser
 * as a download instead of running it, and a redirect site never serves its
 * document root at all. A site's type cannot be changed from the panel, so the
 * honest control is no control: the row says why, and the install dialog does
 * not offer it.
 */
export function servesPhp(site: SiteView): boolean {
  return site.site_type === "php";
}

function InstallableTable({ sites }: { sites: SiteView[] }) {
  const { t } = useTranslation();

  return (
    <Table>
      <thead>
        <tr>
          <Th>{t("sites.domain")}</Th>
          <Th>{t("sites.type")}</Th>
          <Th>{t("wordpress.rootDir")}</Th>
          <Th>{t("wordpress.eligibility")}</Th>
        </tr>
      </thead>
      <tbody>
        {sites.map((site) => (
          <Tr key={site.id}>
            <Td className="font-medium">{site.domain}</Td>
            <Td className="text-ink-muted">{t(`sites.kind.${site.site_type}`)}</Td>
            <Td className="font-mono text-xs break-all text-ink-muted">{site.root_dir}</Td>
            <Td>
              {servesPhp(site) ? (
                <Badge tone="success">{t("wordpress.eligible")}</Badge>
              ) : (
                <span className="text-sm text-ink-muted">{t("wordpress.notPhp")}</span>
              )}
            </Td>
          </Tr>
        ))}
      </tbody>
    </Table>
  );
}

// ---------------------------------------------------------------------------
// Installing
// ---------------------------------------------------------------------------

function InstallDialog({
  open,
  sites,
  onClose,
  onQueued,
}: {
  open: boolean;
  sites: SiteView[];
  onClose: () => void;
  onQueued: (siteId: number, taskId: string | null) => void;
}) {
  const { t } = useTranslation();
  const [siteId, setSiteId] = useState("");
  const [title, setTitle] = useState("");
  const [adminUser, setAdminUser] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [locale, setLocale] = useState("en_US");
  const [subdirectory, setSubdirectory] = useState("");
  const [error, setError] = useState<string | null>(null);

  const eligible = sites.filter(servesPhp);
  const chosen = eligible.find((site) => String(site.id) === siteId) ?? eligible[0];
  const problems = {
    title: titleProblem(title),
    adminUser: adminUserProblem(adminUser),
    adminEmail: emailProblem(adminEmail),
    locale: localeProblem(locale),
    subdirectory: subdirectoryProblem(subdirectory),
  };
  const ready = chosen !== undefined && Object.values(problems).every((p) => p === null);

  const install = useMutation({
    mutationFn: (site: SiteView) => {
      const trimmedLocale = locale.trim();
      const trimmedSubdirectory = subdirectory.trim();
      return wordpressApi.install({
        site_id: site.id,
        title: title.trim(),
        // Sent as the agent will store it, so the audit row and the WordPress
        // account cannot disagree about which login was created.
        admin_user: adminUser.trim().toLowerCase(),
        admin_email: adminEmail.trim().toLowerCase(),
        // Both keys omitted rather than sent empty: the agent reads an absent
        // `locale` as `en_US` and an absent `subdirectory` as the document
        // root, and an explicit null fails deserialization there.
        ...(trimmedLocale === "" ? {} : { locale: trimmedLocale }),
        ...(trimmedSubdirectory === "" ? {} : { subdirectory: trimmedSubdirectory }),
      });
    },
    onSuccess: (response, site) => onQueued(site.id, queuedTaskId(response)),
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title={t("wordpress.installTitle")}
      description={t("wordpress.installSubtitle")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            disabled={!ready}
            loading={install.isPending}
            onClick={() => {
              if (chosen === undefined) return;
              setError(null);
              install.mutate(chosen);
            }}
          >
            <Download className="h-4 w-4" aria-hidden />
            {t("wordpress.installSubmit")}
          </Button>
        </>
      }
    >
      {eligible.length === 0 ? (
        <EmptyState
          className="py-10"
          icon={<Globe aria-hidden />}
          title={t("wordpress.noEligibleSites")}
          hint={t("wordpress.noEligibleSitesHint")}
        />
      ) : (
        <div className="space-y-4">
          <Field label={t("wordpress.installSite")} htmlFor="wp-site">
            <Select
              id="wp-site"
              value={chosen ? String(chosen.id) : ""}
              onChange={(event) => setSiteId(event.target.value)}
            >
              {eligible.map((site) => (
                <option key={site.id} value={String(site.id)}>
                  {site.domain}
                </option>
              ))}
            </Select>
          </Field>

          <Field
            label={t("wordpress.installTitleField")}
            htmlFor="wp-title"
            error={problems.title ? t(`wordpress.titleProblem.${problems.title}`) : undefined}
          >
            <Input
              id="wp-title"
              value={title}
              aria-invalid={problems.title !== null}
              onChange={(event) => setTitle(event.target.value)}
            />
          </Field>

          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              label={t("wordpress.installAdminUser")}
              htmlFor="wp-admin-user"
              error={
                problems.adminUser
                  ? t(`wordpress.adminUserProblem.${problems.adminUser}`)
                  : undefined
              }
            >
              <Input
                id="wp-admin-user"
                value={adminUser}
                autoComplete="off"
                aria-invalid={problems.adminUser !== null}
                onChange={(event) => setAdminUser(event.target.value)}
              />
            </Field>
            <Field
              label={t("wordpress.installAdminEmail")}
              htmlFor="wp-admin-email"
              error={
                problems.adminEmail ? t(`wordpress.emailProblem.${problems.adminEmail}`) : undefined
              }
            >
              <Input
                id="wp-admin-email"
                type="email"
                value={adminEmail}
                autoComplete="off"
                aria-invalid={problems.adminEmail !== null}
                onChange={(event) => setAdminEmail(event.target.value)}
              />
            </Field>
          </div>
          <p className="-mt-2 text-xs text-ink-muted">{t("wordpress.installAdminUserHint")}</p>

          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              label={t("wordpress.installLocale")}
              htmlFor="wp-locale"
              error={problems.locale ? t("wordpress.localeProblem.shape") : undefined}
            >
              <Input
                id="wp-locale"
                value={locale}
                placeholder="en_US"
                aria-invalid={problems.locale !== null}
                onChange={(event) => setLocale(event.target.value)}
              />
            </Field>
            <Field
              label={t("wordpress.installSubdirectory")}
              htmlFor="wp-subdirectory"
              error={
                problems.subdirectory
                  ? t(`wordpress.subdirectoryProblem.${problems.subdirectory}`)
                  : undefined
              }
            >
              <Input
                id="wp-subdirectory"
                value={subdirectory}
                placeholder="blog"
                aria-invalid={problems.subdirectory !== null}
                onChange={(event) => setSubdirectory(event.target.value)}
              />
            </Field>
          </div>
          <p className="-mt-2 text-xs text-ink-muted">{t("wordpress.installLocaleHint")}</p>

          {chosen ? (
            <p className="text-xs text-ink-subtle">
              {t("wordpress.installTarget", {
                path: subdirectory.trim()
                  ? `${chosen.root_dir}/${subdirectory.trim()}`
                  : chosen.root_dir,
              })}
            </p>
          ) : null}

          <Callout tone="info" title={t("wordpress.installCreatesTitle")}>
            {t("wordpress.installCreates")}
          </Callout>

          {/* Said before the click because it cannot be said after it: the
              install is a task, and a task's output never reaches a browser —
              so the sentence the operation returns about credentials would be
              read by nobody. */}
          <Callout tone="warning" title={t("wordpress.installCredentialsTitle")}>
            {t("wordpress.installCredentials")}
          </Callout>

          {error ? <Callout tone="danger">{error}</Callout> : null}
        </div>
      )}
    </Dialog>
  );
}
