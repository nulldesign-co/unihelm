import { useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  BellRing,
  CheckCircle2,
  ChevronRight,
  Cpu,
  HardDrive,
  MemoryStick,
  Power,
  Server,
  ShieldCheck,
  Slash,
  Timer,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { Meter } from "@/components/ui/meter";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton, StatSkeleton } from "@/components/ui/skeleton";
import {
  api,
  ApiError,
  endpoints,
  type Overview,
  type ServiceStatus,
  type ServicesResponse,
  type SystemInfo,
  type UnitState,
} from "@/lib/api";
import { staggerStyle, useCountUp } from "@/lib/motion";
import { useSession } from "@/lib/session";
import { cn, formatBytes, formatPercent, formatUptime } from "@/lib/utils";

/** A disk this full is a problem the operator should be told about, not shown. */
const DISK_ALARM_PCT = 90;

/**
 * `server.reboot.status`, as the agent answers it.
 *
 * Three states, not two, and the third is the point: a machine whose
 * restart-pending flag could not be read reports `unknown` with the reason,
 * never `not_required`. "This server does not need restarting" and "the panel
 * could not tell" are different sentences, and rendering them the same turns an
 * unknown into a reassurance.
 */
export type RebootRequirement =
  | { state: "not_required" }
  | { state: "required"; packages: string[]; evidence: string }
  | { state: "unknown"; reason: string };

export interface RebootStatus {
  requirement: RebootRequirement;
  /** What the confirmation asks to be retyped; `null` when it could not be read. */
  hostname: string | null;
  hostname_error?: string;
  /** Every site that stops for the duration of the restart. */
  sites: string[];
  site_count: number;
}

interface RebootScheduled {
  hostname: string;
  in_seconds: number;
  sites_stopping: string[];
  note: string;
}

const rebootApi = {
  status: () => api.get<RebootStatus>("/api/server/reboot"),
  /** The typed hostname goes over the wire; the agent compares it to the machine's own. */
  reboot: (confirmHostname: string) =>
    api.post<RebootScheduled>("/api/server/reboot", { confirm_hostname: confirmHostname }),
};

const SERVICE_TONE: Record<UnitState, "success" | "danger" | "warning" | "neutral"> = {
  active: "success",
  failed: "danger",
  activating: "warning",
  deactivating: "warning",
  inactive: "neutral",
  not_found: "neutral",
  unknown: "neutral",
};

export function DashboardPage() {
  const { t, i18n } = useTranslation();
  const { user } = useSession();

  const overview = useQuery({
    queryKey: ["overview"],
    queryFn: endpoints.overview,
    refetchInterval: 5_000,
  });
  const services = useQuery({
    queryKey: ["services"],
    queryFn: endpoints.services,
    refetchInterval: 15_000,
  });
  // Same key and options as the security card below, so react-query serves both
  // from one request rather than asking twice on every dashboard load.
  const openAlerts = useQuery({
    queryKey: ["alerts-open"],
    queryFn: endpoints.openAlerts,
    enabled: user?.permissions.includes("server_read") ?? false,
    retry: false,
  });
  // Not on an interval. A pending restart does not resolve itself while
  // somebody watches the page — it resolves when they restart the machine, and
  // that reloads everything anyway.
  const reboot = useQuery({
    queryKey: ["reboot-status"],
    queryFn: rebootApi.status,
    enabled: user?.permissions.includes("server_read") ?? false,
    retry: false,
  });

  const data = overview.data;
  const metrics = data?.metrics;
  const locale = i18n.language;

  const problems = collectProblems({
    t,
    locale,
    overview: data,
    services: services.data,
    openAlertCount: openAlerts.data?.events.length ?? null,
    reboot: reboot.data,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("dashboard.title")}
        description={t("dashboard.subtitle")}
        actions={overview.isFetching || overview.isSuccess ? <LiveDot label={t("dashboard.live")} /> : null}
      />

      {overview.isPending ? (
        <>
          <Skeleton className="h-24 w-full rounded-card" />
          <StatSkeleton />
        </>
      ) : (
        <>
          <HealthBanner problems={problems} />

          {/* The banner counts it; this explains it. An offline agent is the
              one failure where what still works matters as much as what does
              not, and the daemon's own error is the thing an operator will
              paste into a search box. */}
          {data && !data.agent_online ? (
            <Callout tone="warning" title={t("dashboard.agentOffline")}>
              {t("dashboard.agentOfflineHint")}
              {data.agent_error ? (
                <p dir="ltr" className="mt-1 font-mono text-xs text-ink-subtle">
                  {data.agent_error}
                </p>
              ) : null}
            </Callout>
          ) : null}

          {/* The banner counts it; this is where it can be acted on. Below the
              agent notice deliberately: an agent that is not answering cannot
              restart anything, and the panel should not offer a button that
              would fail. */}
          {reboot.data ? <RebootNotice status={reboot.data} /> : null}

          {metrics ? (
            <>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <Stat
                  index={0}
                  icon={<Cpu className="h-4 w-4" aria-hidden />}
                  label={t("dashboard.cpu")}
                  amount={metrics.cpu.usage_pct}
                  format={(value) => formatPercent(value, locale)}
                  detail={t("dashboard.cores", { count: metrics.cpu.cores })}
                  meter={metrics.cpu.usage_pct}
                />
                <Stat
                  index={1}
                  icon={<MemoryStick className="h-4 w-4" aria-hidden />}
                  label={t("dashboard.memory")}
                  amount={metrics.memory.used_bytes}
                  format={(value) => formatBytes(value, locale)}
                  detail={t("dashboard.ofTotal", {
                    total: formatBytes(metrics.memory.total_bytes, locale),
                  })}
                  meter={(metrics.memory.used_bytes / Math.max(1, metrics.memory.total_bytes)) * 100}
                />
                <Stat
                  index={2}
                  icon={<Timer className="h-4 w-4" aria-hidden />}
                  label={t("dashboard.uptime")}
                  value={formatUptime(metrics.uptime_seconds)}
                  detail={`${t("dashboard.load")} ${metrics.load.one.toFixed(2)} / ${metrics.load.five.toFixed(2)} / ${metrics.load.fifteen.toFixed(2)}`}
                />
                <PanelFootprint
                  index={3}
                  total={metrics.panel.total_rss_bytes}
                  machineTotal={metrics.memory.total_bytes}
                />
              </div>

              {metrics.disks.length > 0 ? (
                <Card>
                  <CardHeader title={t("dashboard.disk")} />
                  <CardBody className="space-y-4">
                    {metrics.disks.map((disk) => {
                      const pct = (disk.used_bytes / Math.max(1, disk.total_bytes)) * 100;
                      return (
                        <div key={disk.mount}>
                          <div className="mb-1.5 flex items-baseline justify-between gap-3 text-sm">
                            <span className="truncate font-mono text-xs text-ink">{disk.mount}</span>
                            <span className="shrink-0 text-ink-muted tnum">
                              {formatBytes(disk.used_bytes, locale)} /{" "}
                              {formatBytes(disk.total_bytes, locale)}
                            </span>
                          </div>
                          <Meter value={pct} label={disk.mount} />
                        </div>
                      );
                    })}
                  </CardBody>
                </Card>
              ) : null}
            </>
          ) : null}
        </>
      )}

      <SecurityCard system={data?.system} />

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title={t("dashboard.services")} />
          <CardBody>
            {services.isPending ? (
              <div role="status" aria-live="polite" className="space-y-4 py-1">
                {Array.from({ length: 4 }, (_, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <Skeleton className="h-6 w-20 rounded-full" />
                    <Skeleton className="h-3.5 w-1/3" />
                    <Skeleton className="ms-auto h-3 w-14" />
                  </div>
                ))}
              </div>
            ) : (services.data?.services.length ?? 0) === 0 ? (
              <EmptyState
                icon={<Server aria-hidden />}
                title={t("dashboard.noServices")}
                hint={t("dashboard.installHint")}
              />
            ) : (
              <ul className="divide-y divide-border">
                {services.data!.services.map((service, index) => (
                  <ServiceRow key={service.unit} service={service} index={index} />
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        {data?.system ? (
          <Card>
            <CardHeader title={t("dashboard.system")} />
            <CardBody>
              <dl className="space-y-2.5 text-sm">
                <Row label="OS" value={data.system.distro} />
                <Row label="Arch" value={data.system.arch} />
                <Row label="Packages" value={data.system.package_backend} />
                <Row label="Firewall" value={data.system.firewall_backend} />
                <Row label="Security" value={data.system.security_module} />
                <Row label="Agent" value={data.system.agent_version} />
                <Row label="Panel" value={data.panel_version} />
              </dl>
            </CardBody>
          </Card>
        ) : null}
      </div>
    </div>
  );
}

/**
 * How a pending restart is said out loud.
 *
 * "Reboot required" moves nobody. "The kernel was updated and this server is
 * still running the old one" does, which is why the package list is carried all
 * the way from the marker file to here. Shared by the banner entry and the
 * notice below it so the two cannot end up describing one machine differently.
 *
 * Three keys rather than one plural: with a single package there is no
 * remainder to count, and `{{count}}` of 0 takes English's *plural* branch —
 * which is how "and 0 more packages" reaches an operator.
 */
function rebootLabel(
  t: (key: string, options?: Record<string, unknown>) => string,
  packages: string[],
  keys: { none: string; one: string; many: string },
): string {
  if (packages.length === 0) return t(keys.none);
  if (packages.length === 1) return t(keys.one, { package: packages[0] });
  return t(keys.many, { package: packages[0], count: packages.length - 1 });
}

interface Problem {
  id: string;
  label: string;
  /**
   * The page that can fix this, or `null` when no page can.
   *
   * `null` rather than `"/"`. The banner above this list says outright that
   * "each one links to the page that can fix it", and every entry was drawn as
   * a link with a chevron — so a problem pointing at `"/"` was a promise of
   * navigation to somebody already standing on `/`, and clicking it did
   * nothing at all. Two of the three did that: a full disk and the panel's own
   * memory, neither of which has a page.
   */
  to: "/alerts" | "/firewall" | "/stack" | null;
}

/**
 * Everything wrong with this server, in one list.
 *
 * The dashboard's job is not to display metrics — it is to answer "is anything
 * broken?" before the operator has to work that out by reading four cards. This
 * gathers the answer from the data already on screen, so it costs no extra
 * request, and every entry names the page that can act on it.
 */
export function collectProblems({
  t,
  locale,
  overview,
  services,
  openAlertCount,
  reboot,
}: {
  t: (key: string, options?: Record<string, unknown>) => string;
  locale: string;
  overview?: Overview;
  services?: ServicesResponse;
  openAlertCount: number | null;
  /** Absent while `server.reboot.status` is in flight, or when it 404s. */
  reboot?: RebootStatus;
}): Problem[] {
  const problems: Problem[] = [];
  if (!overview) return problems;

  if (!overview.agent_online) {
    // `null`, like the other two that have nowhere to send anybody. This one
    // was left pointing at `"/"` when they were fixed — a chevron and a hover
    // lift on a link to the page the reader is already standing on, and a type
    // error besides, since `Problem.to` never allowed `"/"`. The callout
    // directly under the banner is where this problem is actually explained.
    problems.push({ id: "agent", label: t("dashboard.health.agentOffline"), to: null });
  }

  const failed = services?.services.filter((service) => service.state === "failed").length ?? 0;
  if (failed > 0) {
    problems.push({
      id: "services",
      label: t("dashboard.health.servicesFailed", { count: failed }),
      to: "/stack",
    });
  }

  if (openAlertCount !== null && openAlertCount > 0) {
    problems.push({
      id: "alerts",
      label: t("dashboard.health.alertsOpen", { count: openAlertCount }),
      to: "/alerts",
    });
  }

  for (const disk of overview.metrics?.disks ?? []) {
    const pct = (disk.used_bytes / Math.max(1, disk.total_bytes)) * 100;
    if (pct >= DISK_ALARM_PCT) {
      problems.push({
        id: `disk-${disk.mount}`,
        label: t("dashboard.health.diskFull", {
          mount: disk.mount,
          pct: formatPercent(pct, locale),
        }),
        // Nowhere to send them: the panel has no disk page, and the fix is on
        // the server rather than in here.
        to: null,
      });
    }
  }

  if (overview.system?.firewall_backend === "none") {
    problems.push({ id: "firewall", label: t("dashboard.health.firewallOff"), to: "/firewall" });
  }

  // A restart the machine is waiting for, and — separately — a restart state
  // the panel could not establish.
  //
  // The unknown is here rather than swallowed because this banner's green face
  // says "nothing on this server needs your attention right now", and that is a
  // claim. On a Debian install without `update-notifier-common` nothing ever
  // writes the restart flag, so staying silent about it would let the banner
  // make that claim on evidence nobody gathered. Neither entry links anywhere:
  // the notice directly under the banner is where a restart is explained and
  // offered, and it is already on this page.
  if (reboot?.requirement.state === "required") {
    problems.push({
      id: "reboot",
      label: rebootLabel(t, reboot.requirement.packages, {
        none: "dashboard.health.rebootRequired",
        one: "dashboard.health.rebootRequiredFor",
        many: "dashboard.health.rebootRequiredForMany",
      }),
      to: null,
    });
  } else if (reboot?.requirement.state === "unknown") {
    problems.push({ id: "reboot-unknown", label: t("dashboard.health.rebootUnknown"), to: null });
  }

  // The panel's own memory is deliberately *not* here. It used to be: an 80 MB
  // CI regression gate, pushed into the amber "needs attention" banner the
  // moment the panel went over it. The operator who reads that banner has no
  // idea it is a build gate — they read "the panel is over budget" on a machine
  // with gigabytes free as their server running out of memory, and there was
  // nothing on any page they could do about it, because there is nothing to do.
  // Everything else in this list is a condition on their server that they can
  // act on. A number the people who write this panel have to keep down is a
  // fact about the build, and it belongs on the footprint card and nowhere
  // else — see [`PanelFootprint`].

  return problems;
}

/**
 * The one thing worth reading first.
 *
 * Green with a soft halo when there is nothing to do, amber with a list when
 * there is. The halo is a slow ping rather than a static ring: an operator
 * glancing at a wall-mounted dashboard should be able to tell from across the
 * room that the page is live and the server is fine.
 */
function HealthBanner({ problems }: { problems: Problem[] }) {
  const { t } = useTranslation();
  const healthy = problems.length === 0;

  return (
    <div
      className={cn(
        "animate-rise-in overflow-hidden rounded-card border shadow-card",
        healthy ? "border-success/25 bg-success-soft/50" : "border-warning/30 bg-warning-soft/60",
      )}
    >
      <div className="flex flex-wrap items-start gap-4 px-5 py-4">
        <span className="relative mt-0.5 grid h-10 w-10 shrink-0 place-items-center" aria-hidden>
          <span
            className={cn(
              "absolute inset-1 rounded-full",
              healthy ? "animate-ping-slow bg-success/30" : "bg-warning/20",
            )}
          />
          <span
            className={cn(
              "relative grid h-10 w-10 place-items-center rounded-full",
              healthy ? "bg-success/15 text-success" : "bg-warning/20 text-warning",
            )}
          >
            {healthy ? <CheckCircle2 className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
          </span>
        </span>

        <div className="min-w-0 flex-1">
          <p className="text-base font-semibold tracking-tight text-ink">
            {healthy
              ? t("dashboard.health.allGood")
              : t("dashboard.health.attention", { count: problems.length })}
          </p>
          <p className="mt-0.5 text-sm text-ink-muted">
            {healthy ? t("dashboard.health.allGoodHint") : t("dashboard.health.attentionHint")}
          </p>

          {problems.length > 0 ? (
            <ul className="mt-3 flex flex-wrap gap-2">
              {problems.map((problem, index) => (
                <li key={problem.id} className="animate-rise-in stagger" style={staggerStyle(index)}>
                  {problem.to === null ? (
                    // A statement, not a control. No chevron and no hover lift:
                    // both of those say "this goes somewhere", and this does
                    // not — which is the whole defect being fixed.
                    <span className="inline-flex items-center rounded-full border border-warning/30 bg-surface/80 px-3 py-1 text-sm text-ink">
                      {problem.label}
                    </span>
                  ) : (
                    <Link
                      to={problem.to}
                      className="group inline-flex items-center gap-1.5 rounded-full border border-warning/30 bg-surface/80 px-3 py-1 text-sm text-ink transition-[transform,box-shadow,border-color] duration-150 hover:-translate-y-px hover:border-warning hover:shadow-card-hover motion-reduce:hover:translate-y-0"
                    >
                      {problem.label}
                      <ChevronRight
                        className="h-3.5 w-3.5 text-ink-subtle transition-transform duration-150 group-hover:translate-x-0.5 motion-reduce:group-hover:translate-x-0"
                        aria-hidden
                      />
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </div>
    </div>
  );
}

/**
 * The restart this machine is waiting for, and the only place to act on it.
 *
 * Nothing is drawn when the answer is "not required" — a notice that appears on
 * a healthy server is one an operator learns to scroll past. An *unknown* is
 * drawn, because the banner above it claims "nothing needs your attention" when
 * it is empty, and that claim must not rest on a check that could not run.
 *
 * The restart itself is behind a dialog rather than this button, and the dialog
 * is behind retyping the hostname. Every site on the machine stops and the
 * panel stops with them; that is not a single-click action.
 */
function RebootNotice({ status }: { status: RebootStatus }) {
  const { t } = useTranslation();
  const { user } = useSession();
  const [open, setOpen] = useState(false);

  const requirement = status.requirement;
  if (requirement.state === "not_required") return null;

  const required = requirement.state === "required";
  // A restart nobody can perform is a notice with a dead button on it. The
  // agent refuses this operation without `server_manage` anyway; not drawing
  // the control is how the page stops promising what it cannot do.
  const canRestart =
    (user?.permissions.includes("server_manage") ?? false) && status.hostname !== null;

  return (
    <>
      <Callout
        tone="warning"
        title={
          required
            ? rebootLabel(t, requirement.packages, {
                none: "dashboard.reboot.required",
                one: "dashboard.reboot.requiredFor",
                many: "dashboard.reboot.requiredForMany",
              })
            : t("dashboard.reboot.unknownTitle")
        }
        action={
          canRestart ? (
            <Button variant="danger" onClick={() => setOpen(true)}>
              <Power className="h-4 w-4" aria-hidden />
              {t("dashboard.reboot.action")}
            </Button>
          ) : null
        }
      >
        <p>
          {required ? t("dashboard.reboot.requiredHint") : requirement.reason}
        </p>
        <p className="mt-1">
          {status.site_count > 0
            ? t("dashboard.reboot.cost", { count: status.site_count })
            : t("dashboard.reboot.costNoSites")}
        </p>
        {/* Said here as well as in the dialog: an operator who cannot restart
            from the panel needs to know that before they go looking for the
            button, not after. */}
        {!canRestart && status.hostname === null ? (
          <p className="mt-1">{t("dashboard.reboot.noHostname")}</p>
        ) : null}
      </Callout>

      {status.hostname !== null ? (
        <RebootDialog
          open={open}
          onClose={() => setOpen(false)}
          hostname={status.hostname}
          sites={status.sites}
        />
      ) : null}
    </>
  );
}

/**
 * Retype the hostname, then restart.
 *
 * The typed value is what goes over the wire — the agent compares it against
 * the machine's own name, so sending back the one we were handed would turn its
 * check into a no-op.
 */
function RebootDialog({
  open,
  onClose,
  hostname,
  sites,
}: {
  open: boolean;
  onClose: () => void;
  hostname: string;
  sites: string[];
}) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [scheduled, setScheduled] = useState<RebootScheduled | null>(null);

  const armed = typed.trim() === hostname;

  const restart = useMutation({
    mutationFn: () => rebootApi.reboot(typed.trim()),
    // Deliberately not closed on success, and nothing is invalidated: the
    // machine is going down in a minute and every refetch from here would fail.
    // What the agent answered is the last true thing this page will say.
    onSuccess: setScheduled,
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("dashboard.reboot.dialogTitle", { hostname })}
      description={scheduled ? undefined : t("dashboard.reboot.dialogHint")}
      footer={
        scheduled ? (
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
              loading={restart.isPending}
              onClick={() => {
                setError(null);
                restart.mutate();
              }}
            >
              {t("dashboard.reboot.confirm")}
            </Button>
          </>
        )
      }
    >
      {scheduled ? (
        // The agent's own sentence, not a translated paraphrase of it. It is
        // the only statement anywhere that says the panel cannot tell the
        // operator when the machine is back, and one copy of that cannot drift
        // from another.
        <Callout tone="info" title={t("dashboard.reboot.scheduledTitle")}>
          {scheduled.note}
        </Callout>
      ) : (
        <div className="space-y-3">
          <Callout tone="danger" title={t("dashboard.reboot.warning")}>
            {sites.length > 0 ? (
              <>
                <p>{t("dashboard.reboot.stopping", { count: sites.length })}</p>
                <ul className="mt-1 list-disc space-y-0.5 ps-5 font-mono text-xs">
                  {/* Capped, with the remainder counted rather than hidden:
                      a hundred domains would push the confirmation off the
                      screen, and a truncated list that does not say it is
                      truncated understates what is about to stop. */}
                  {sites.slice(0, 8).map((site) => (
                    <li key={site}>{site}</li>
                  ))}
                </ul>
                {sites.length > 8 ? (
                  <p className="mt-1">
                    {t("dashboard.reboot.andMore", { count: sites.length - 8 })}
                  </p>
                ) : null}
              </>
            ) : (
              <p>{t("dashboard.reboot.stoppingNoSites")}</p>
            )}
          </Callout>
          <Field
            label={t("dashboard.reboot.typeHostname", { hostname })}
            htmlFor="reboot-confirm-hostname"
            error={typed.length > 0 && !armed ? t("dashboard.reboot.hostnameMismatch") : undefined}
          >
            <Input
              id="reboot-confirm-hostname"
              autoComplete="off"
              autoFocus
              placeholder={hostname}
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

/** A quiet "this page is live" cue for a dashboard that polls. */
function LiveDot({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-xs font-medium text-ink-muted">
      <span className="relative grid h-2 w-2 place-items-center" aria-hidden>
        <span className="absolute inset-0 animate-ping-slow rounded-full bg-success" />
        <span className="relative h-2 w-2 rounded-full bg-success" />
      </span>
      {label}
    </span>
  );
}

/**
 * The security summary (spec §11.9, §11.11).
 *
 * Three numbers that an operator should never have to go looking for, each a
 * link to the page that can act on it. It is deliberately honest about what it
 * cannot see: a firewall read needs `firewall_manage`, so a customer session
 * gets the tiles it is allowed to have and no misleading zeroes for the rest —
 * "0 bans" from a session that cannot read the ban list would be a lie.
 */
function SecurityCard({ system }: { system?: SystemInfo }) {
  const { t } = useTranslation();
  const { user } = useSession();

  const canFirewall = user?.permissions.includes("firewall_manage") ?? false;
  const canRead = user?.permissions.includes("server_read") ?? false;

  // `retry: false`: on a build without `/api/firewall` these 404 immediately,
  // and three silent retries per tile would be a wasted round of requests on
  // every dashboard load.
  const firewall = useQuery({
    queryKey: ["firewall"],
    queryFn: endpoints.firewall,
    enabled: canFirewall,
    retry: false,
  });
  const bans = useQuery({
    queryKey: ["firewall-bans"],
    queryFn: endpoints.bans,
    enabled: canFirewall,
    retry: false,
  });
  const open = useQuery({
    queryKey: ["alerts-open"],
    queryFn: endpoints.openAlerts,
    enabled: canRead,
    retry: false,
  });

  if (!canFirewall && !canRead) return null;

  // The overview already carries the detected backend under `server_read`, so a
  // session that cannot read the firewall still learns whether one is installed.
  const backend = firewall.data?.backend ?? system?.firewall_backend ?? null;
  const backendName = backend
    ? t(`firewall.backendName.${backend}`, { defaultValue: backend })
    : t("common.unknown");
  const unmanaged = backend === "none";
  const activeBans = bans.data?.bans.filter((ban) => ban.lifted_at === null).length ?? null;
  const openAlerts = open.data?.events.length ?? null;

  return (
    <Card>
      <CardHeader title={t("dashboard.security")} description={t("dashboard.securityHint")} />
      <CardBody>
        <div className="grid gap-3 sm:grid-cols-3">
          <SecurityTile
            index={0}
            to="/firewall"
            icon={
              unmanaged ? (
                <Slash className="h-4 w-4" aria-hidden />
              ) : (
                <ShieldCheck className="h-4 w-4" aria-hidden />
              )
            }
            label={t("dashboard.firewall")}
            value={unmanaged ? t("firewall.backendName.none") : backendName}
            badge={
              firewall.data ? (
                <Badge
                  tone={unmanaged ? "danger" : firewall.data.active ? "success" : "warning"}
                  dot
                >
                  {unmanaged
                    ? t("dashboard.firewallUnprotected")
                    : firewall.data.active
                      ? t("dashboard.firewallActive")
                      : t("dashboard.firewallInactive")}
                </Badge>
              ) : null
            }
          />

          <SecurityTile
            index={1}
            to="/alerts"
            icon={<BellRing className="h-4 w-4" aria-hidden />}
            label={t("dashboard.openAlerts")}
            value={openAlerts === null ? "—" : String(openAlerts)}
            badge={
              openAlerts === null ? null : (
                <Badge tone={openAlerts > 0 ? "danger" : "success"} dot={openAlerts > 0}>
                  {openAlerts > 0 ? t("dashboard.alertsFiring") : t("dashboard.alertsClear")}
                </Badge>
              )
            }
          />

          <SecurityTile
            index={2}
            to="/firewall"
            icon={<AlertTriangle className="h-4 w-4" aria-hidden />}
            label={t("dashboard.activeBans")}
            value={activeBans === null ? "—" : String(activeBans)}
            badge={
              activeBans === null ? null : (
                <Badge tone="neutral">{t("dashboard.bansHint")}</Badge>
              )
            }
          />
        </div>
      </CardBody>
    </Card>
  );
}

function SecurityTile({
  to,
  icon,
  label,
  value,
  badge,
  index,
}: {
  to: "/firewall" | "/alerts";
  icon: ReactNode;
  label: string;
  value: string;
  badge: ReactNode;
  index: number;
}) {
  return (
    <Link
      to={to}
      style={staggerStyle(index)}
      className="group flex animate-rise-in flex-col gap-2 rounded-lg border border-border p-4 stagger transition-[transform,box-shadow,border-color,background-color] duration-200 ease-standard hover:-translate-y-0.5 hover:border-border-strong hover:bg-surface-muted hover:shadow-card-hover motion-reduce:hover:translate-y-0"
    >
      <span className="flex items-center gap-2 text-ink-muted">
        {icon}
        <span className="text-xs font-medium tracking-wide uppercase">{label}</span>
        <ChevronRight
          className="ms-auto h-4 w-4 -translate-x-1 opacity-0 transition-[transform,opacity] duration-200 group-hover:translate-x-0 group-hover:opacity-100 motion-reduce:transition-none"
          aria-hidden
        />
      </span>
      <span className="text-xl font-semibold tracking-tight text-ink tnum">{value}</span>
      {/* `self-start`: a flex column stretches children, and a stretched pill
          reads as a bar. */}
      {badge ? <span className="self-start">{badge}</span> : null}
    </Link>
  );
}

function Stat({
  icon,
  label,
  value,
  amount,
  format,
  detail,
  meter,
  index,
}: {
  icon: ReactNode;
  label: string;
  /** A value that is already a string — uptime, which does not interpolate well. */
  value?: string;
  /** A live number, which travels to its new reading instead of snapping to it. */
  amount?: number;
  format?: (value: number) => string;
  detail: string;
  meter?: number;
  index: number;
}) {
  const animated = useCountUp(amount ?? 0);
  const shown = value ?? (format ? format(animated) : String(Math.round(animated)));

  return (
    <Card className="animate-rise-in p-5 stagger" style={staggerStyle(index)}>
      <div className="mb-3 flex items-center gap-2 text-ink-muted">
        {icon}
        <span className="text-xs font-medium tracking-wide uppercase">{label}</span>
      </div>
      <p className="text-2xl font-semibold tracking-tight text-ink tnum">{shown}</p>
      <p className="mt-0.5 text-xs text-ink-muted">{detail}</p>
      {meter !== undefined ? (
        <div className="mt-3">
          <Meter value={meter} label={label} />
        </div>
      ) : null}
    </Card>
  );
}

/**
 * The panel's own memory use, against the memory the machine actually has.
 *
 * Putting this on the dashboard stays a deliberate promise: the number this
 * project exists to keep small is visible to every operator rather than buried
 * in CI. What it is measured against is what changed, and that was the defect.
 * The 80 MB figure is a regression gate for the people who write this panel,
 * and stating an operator's server against it produced a full meter, a red
 * "Over budget" badge and an entry in the attention banner — three ways of
 * saying "something is wrong here" about a machine with gigabytes free, and
 * nothing anywhere the operator could press about it.
 *
 * Against the machine's own total it says the one thing an operator can use:
 * how much of their server this panel is costing them. The meter reads near
 * empty on any real machine, which is the honest answer and the point.
 */
function PanelFootprint({
  total,
  machineTotal,
  index,
}: {
  total: number | null;
  /** The server's own memory, the denominator this is stated against. */
  machineTotal: number;
  index: number;
}) {
  const { t, i18n } = useTranslation();
  const pct = total === null || machineTotal <= 0 ? 0 : (total / machineTotal) * 100;
  const animated = useCountUp(total ?? 0);

  return (
    <Card className="animate-rise-in p-5 stagger" style={staggerStyle(index)}>
      <div className="mb-3 flex items-center gap-2 text-ink-muted">
        <HardDrive className="h-4 w-4" aria-hidden />
        <span className="text-xs font-medium tracking-wide uppercase">
          {t("dashboard.panelFootprint")}
        </span>
      </div>
      <p className="text-2xl font-semibold tracking-tight text-ink tnum">
        {formatBytes(total === null ? null : animated, i18n.language)}
      </p>
      <p className="mt-0.5 text-xs text-ink-muted">
        {t("dashboard.panelFootprintShare", {
          total: formatBytes(machineTotal, i18n.language),
        })}
      </p>
      <div className="mt-3">
        <Meter value={pct} label={t("dashboard.panelFootprint")} />
      </div>
    </Card>
  );
}

function ServiceRow({ service, index }: { service: ServiceStatus; index: number }) {
  const { t, i18n } = useTranslation();
  return (
    <li
      style={staggerStyle(index)}
      className="-mx-2 flex animate-rise-in items-center gap-3 rounded-lg px-2 py-2.5 stagger transition-colors duration-150 hover:bg-surface-muted/60"
    >
      <Badge tone={SERVICE_TONE[service.state]} dot>
        {t(`service.${service.state}`)}
      </Badge>
      <span className="min-w-0 flex-1 truncate text-sm text-ink">{service.display_name}</span>
      {service.memory_bytes ? (
        <span className="shrink-0 text-xs text-ink-subtle tnum">
          {formatBytes(service.memory_bytes, i18n.language)}
        </span>
      ) : null}
    </li>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="text-ink-muted">{label}</dt>
      <dd className="truncate text-end font-mono text-xs text-ink">{value}</dd>
    </div>
  );
}
