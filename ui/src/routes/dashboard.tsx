import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  BellRing,
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
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Meter } from "@/components/ui/meter";
import { PageHeader } from "@/components/ui/page-header";
import { ListSkeleton, Skeleton, StatSkeleton } from "@/components/ui/skeleton";
import { endpoints, type ServiceStatus, type SystemInfo, type UnitState } from "@/lib/api";
import { useSession } from "@/lib/session";
import { formatBytes, formatPercent, formatUptime } from "@/lib/utils";

/** The CI-enforced panel memory budget (spec §3). */
const RSS_BUDGET_BYTES = 80 * 1024 * 1024;

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

  if (overview.isPending) {
    return (
      <div className="space-y-6">
        <PageHeader title={t("dashboard.title")} description={t("dashboard.subtitle")} />
        <StatSkeleton />
        <ListSkeleton />
      </div>
    );
  }

  const data = overview.data;
  const metrics = data?.metrics;
  const locale = i18n.language;

  return (
    <div className="space-y-6">
      <PageHeader title={t("dashboard.title")} description={t("dashboard.subtitle")} />

      {data && !data.agent_online ? (
        <div
          role="alert"
          className="flex gap-3 rounded-lg border border-warning/30 bg-warning-soft px-4 py-3"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
          <div>
            <p className="text-sm font-medium text-ink">{t("dashboard.agentOffline")}</p>
            <p className="mt-0.5 text-sm text-ink-muted">{t("dashboard.agentOfflineHint")}</p>
            {data.agent_error ? (
              <p className="mt-1 font-mono text-xs text-ink-subtle">{data.agent_error}</p>
            ) : null}
          </div>
        </div>
      ) : null}

      {metrics ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              icon={<Cpu className="h-4 w-4" aria-hidden />}
              label={t("dashboard.cpu")}
              value={formatPercent(metrics.cpu.usage_pct, locale)}
              detail={t("dashboard.cores", { count: metrics.cpu.cores })}
              meter={metrics.cpu.usage_pct}
              meterLabel={t("dashboard.cpu")}
            />
            <Stat
              icon={<MemoryStick className="h-4 w-4" aria-hidden />}
              label={t("dashboard.memory")}
              value={formatBytes(metrics.memory.used_bytes, locale)}
              detail={t("dashboard.ofTotal", { total: formatBytes(metrics.memory.total_bytes, locale) })}
              meter={(metrics.memory.used_bytes / Math.max(1, metrics.memory.total_bytes)) * 100}
              meterLabel={t("dashboard.memory")}
            />
            <Stat
              icon={<Timer className="h-4 w-4" aria-hidden />}
              label={t("dashboard.uptime")}
              value={formatUptime(metrics.uptime_seconds)}
              detail={`${t("dashboard.load")} ${metrics.load.one.toFixed(2)} / ${metrics.load.five.toFixed(2)} / ${metrics.load.fifteen.toFixed(2)}`}
            />
            <PanelFootprint total={metrics.panel.total_rss_bytes} />
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
                        <span className="shrink-0 text-ink-muted">
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
                {services.data!.services.map((service) => (
                  <ServiceRow key={service.unit} service={service} />
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
}: {
  to: "/firewall" | "/alerts";
  icon: ReactNode;
  label: string;
  value: string;
  badge: ReactNode;
}) {
  return (
    <Link
      to={to}
      className="group flex flex-col gap-2 rounded-lg border border-border p-4 transition-colors hover:bg-surface-muted"
    >
      <span className="flex items-center gap-2 text-ink-muted">
        {icon}
        <span className="text-xs font-medium tracking-wide uppercase">{label}</span>
        <ChevronRight
          className="ms-auto h-4 w-4 opacity-0 transition-opacity group-hover:opacity-100"
          aria-hidden
        />
      </span>
      <span className="text-xl font-semibold tracking-tight text-ink tabular-nums">{value}</span>
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
  detail,
  meter,
  meterLabel,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  detail: string;
  meter?: number;
  meterLabel?: string;
}) {
  return (
    <Card className="p-5">
      <div className="mb-3 flex items-center gap-2 text-ink-muted">
        {icon}
        <span className="text-xs font-medium tracking-wide uppercase">{label}</span>
      </div>
      <p className="text-2xl font-semibold tracking-tight text-ink tabular-nums">{value}</p>
      <p className="mt-0.5 text-xs text-ink-muted">{detail}</p>
      {meter !== undefined ? (
        <div className="mt-3">
          <Meter value={meter} label={meterLabel ?? label} />
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
function PanelFootprint({ total }: { total: number | null }) {
  const { t, i18n } = useTranslation();
  const within = total === null ? null : total <= RSS_BUDGET_BYTES;
  const pct = total === null ? 0 : (total / RSS_BUDGET_BYTES) * 100;

  return (
    <Card className="p-5">
      <div className="mb-3 flex items-center gap-2 text-ink-muted">
        <HardDrive className="h-4 w-4" aria-hidden />
        <span className="text-xs font-medium tracking-wide uppercase">
          {t("dashboard.panelFootprint")}
        </span>
      </div>
      <p className="text-2xl font-semibold tracking-tight text-ink tabular-nums">
        {formatBytes(total, i18n.language)}
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

function ServiceRow({ service }: { service: ServiceStatus }) {
  const { t, i18n } = useTranslation();
  return (
    <li className="-mx-2 flex items-center gap-3 rounded-lg px-2 py-2.5 transition-colors hover:bg-surface-muted/60">
      <Badge tone={SERVICE_TONE[service.state]} dot>
        {t(`service.${service.state}`)}
      </Badge>
      <span className="min-w-0 flex-1 truncate text-sm text-ink">{service.display_name}</span>
      {service.memory_bytes ? (
        <span className="shrink-0 text-xs text-ink-subtle tabular-nums">
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
