import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Cpu, HardDrive, MemoryStick, Timer } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Meter } from "@/components/ui/meter";
import { Spinner } from "@/components/ui/spinner";
import { endpoints, type ServiceStatus, type UnitState } from "@/lib/api";
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
      <div className="flex items-center justify-center py-24 text-ink-muted">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  const data = overview.data;
  const metrics = data?.metrics;
  const locale = i18n.language;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("dashboard.title")}</h1>
        <p className="mt-1 text-sm text-ink-muted">{t("dashboard.subtitle")}</p>
      </header>

      {data && !data.agent_online ? (
        <div
          role="alert"
          className="flex gap-3 rounded-card border border-warning/30 bg-warning-soft px-4 py-3"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
          <div>
            <p className="text-sm font-medium text-ink">{t("dashboard.agentOffline")}</p>
            <p className="mt-0.5 text-sm text-ink-muted">{t("dashboard.agentOfflineHint")}</p>
            {data.agent_error ? (
              <p dir="ltr" className="mt-1 font-mono text-xs text-ink-subtle">
                {data.agent_error}
              </p>
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
                        <span dir="ltr" className="truncate font-mono text-xs text-ink">
                          {disk.mount}
                        </span>
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

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title={t("dashboard.services")} />
          <CardBody>
            {services.isPending ? (
              <div className="flex justify-center py-8 text-ink-muted">
                <Spinner />
              </div>
            ) : (services.data?.services.length ?? 0) === 0 ? (
              <Empty title={t("dashboard.noServices")} hint={t("dashboard.installHint")} />
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
    <li className="flex items-center gap-3 py-2.5 first:pt-0 last:pb-0">
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
      <dd dir="ltr" className="truncate text-end font-mono text-xs text-ink">
        {value}
      </dd>
    </div>
  );
}

function Empty({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="py-10 text-center">
      <p className="text-sm font-medium text-ink">{title}</p>
      <p className="mt-1 text-sm text-ink-muted">{hint}</p>
    </div>
  );
}
