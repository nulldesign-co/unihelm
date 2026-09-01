import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  BellRing,
  CheckCircle2,
  ChevronRight,
  Cpu,
  HardDrive,
  MemoryStick,
  Server,
  ShieldCheck,
  Slash,
  Timer,
} from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Meter } from "@/components/ui/meter";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton, StatSkeleton } from "@/components/ui/skeleton";
import {
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

/** The CI-enforced panel memory budget (spec §3). */
const RSS_BUDGET_BYTES = 80 * 1024 * 1024;

/** A disk this full is a problem the operator should be told about, not shown. */
const DISK_ALARM_PCT = 90;

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

  const data = overview.data;
  const metrics = data?.metrics;
  const locale = i18n.language;

  const problems = collectProblems({
    t,
    locale,
    overview: data,
    services: services.data,
    openAlertCount: openAlerts.data?.events.length ?? null,
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
                <PanelFootprint index={3} total={metrics.panel.total_rss_bytes} />
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

interface Problem {
  id: string;
  label: string;
  to: "/" | "/alerts" | "/firewall" | "/stack";
}

/**
 * Everything wrong with this server, in one list.
 *
 * The dashboard's job is not to display metrics — it is to answer "is anything
 * broken?" before the operator has to work that out by reading four cards. This
 * gathers the answer from the data already on screen, so it costs no extra
 * request, and every entry names the page that can act on it.
 */
function collectProblems({
  t,
  locale,
  overview,
  services,
  openAlertCount,
}: {
  t: (key: string, options?: Record<string, unknown>) => string;
  locale: string;
  overview?: Overview;
  services?: ServicesResponse;
  openAlertCount: number | null;
}): Problem[] {
  const problems: Problem[] = [];
  if (!overview) return problems;

  if (!overview.agent_online) {
    problems.push({ id: "agent", label: t("dashboard.health.agentOffline"), to: "/" });
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
        to: "/",
      });
    }
  }

  if (overview.system?.firewall_backend === "none") {
    problems.push({ id: "firewall", label: t("dashboard.health.firewallOff"), to: "/firewall" });
  }

  const rss = overview.metrics?.panel.total_rss_bytes ?? null;
  if (rss !== null && rss > RSS_BUDGET_BYTES) {
    problems.push({ id: "budget", label: t("dashboard.health.panelOverBudget"), to: "/" });
  }

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
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </div>
    </div>
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
 * The panel's own memory use, shown next to the budget it is held to.
 *
 * Putting this on the dashboard is a deliberate promise: the number that this
 * project exists to beat is visible to every operator, not buried in CI.
 */
function PanelFootprint({ total, index }: { total: number | null; index: number }) {
  const { t, i18n } = useTranslation();
  const within = total === null ? null : total <= RSS_BUDGET_BYTES;
  const pct = total === null ? 0 : (total / RSS_BUDGET_BYTES) * 100;
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
        {t("dashboard.panelFootprintHint", { budget: formatBytes(RSS_BUDGET_BYTES, i18n.language) })}
      </p>
      <div className="mt-3">
        <Meter value={pct} label={t("dashboard.panelFootprint")} />
      </div>
      {within !== null ? (
        <div className="mt-3">
          <Badge tone={within ? "success" : "danger"} dot>
            {within ? t("dashboard.withinBudget") : t("dashboard.overBudget")}
          </Badge>
        </div>
      ) : null}
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
