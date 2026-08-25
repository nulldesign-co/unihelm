import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, getRouteApi, useNavigate } from "@tanstack/react-router";
import {
  ArrowLeft,
  ExternalLink,
  FileDiff,
  Lock,
  LockOpen,
  RefreshCw,
  Wrench,
} from "lucide-react";
import { forwardRef, useEffect, useRef, useState, type TextareaHTMLAttributes } from "react";
import { useTranslation } from "react-i18next";

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
  EOL_PHP_VERSIONS,
  api,
  endpoints,
  type DriftResponse,
  type SiteState,
  type SiteView,
  type Task,
  type TaskAccepted,
  type TaskStatus,
  type UpdateSiteRequest,
} from "@/lib/api";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Wire shapes beyond what the list page needs.
//
// The server's site view flattens the whole `Site` row (site.rs::SiteView), so
// these fields are already on the wire — the list page's `SiteView` type just
// does not name them. Declared here rather than in lib/api.ts so parallel tasks
// do not all edit the one shared client file.
// ---------------------------------------------------------------------------

type WwwPolicy = "none" | "add" | "strip";

interface SiteDetail extends SiteView {
  www_policy: WwwPolicy;
  proxy_port: number | null;
  redirect_target: string | null;
  redirect_code: number;
  rate_limit_rps: number;
  rate_limit_burst: number;
  created_at: string;
  updated_at: string;
}

/** One row of `GET /api/certificates` (cert.rs::CertView, spec §11.5). */
interface CertificateView {
  id: number;
  site_id: number | null;
  kind: "le" | "custom" | "self_signed";
  domains: string[];
  issuer: string | null;
  not_before: string | null;
  not_after: string | null;
  auto_renew: boolean;
  status: "pending" | "active" | "superseded" | "expired" | "failed" | "revoked";
  last_error: string | null;
  failure_count: number;
  cert_dir: string;
  days_remaining: number | null;
  due_for_renewal: boolean;
}

/**
 * The PATCH body. `www_policy` is accepted by the `site.update` operation but
 * the web route does not forward it yet — sent anyway so the UI is complete the
 * moment that one-line passthrough lands (noted for the integrator).
 */
type UpdateBody = UpdateSiteRequest & { www_policy?: WwwPolicy };

const STATE_TONE: Record<SiteState, "success" | "accent" | "warning" | "danger"> = {
  active: "success",
  provisioning: "accent",
  suspended: "warning",
  failed: "danger",
};

const CERT_TONE: Record<CertificateView["status"], "neutral" | "success" | "warning" | "danger"> = {
  pending: "neutral",
  active: "success",
  superseded: "neutral",
  expired: "danger",
  failed: "danger",
  revoked: "warning",
};

const routeApi = getRouteApi("/sites/$siteId");

export function SiteDetailPage() {
  const { t } = useTranslation();
  const { siteId } = routeApi.useParams();
  const id = Number(siteId);

  // There is no GET /api/sites/{id}; the list is the source of truth and the
  // cache is shared with the sites page, so navigating here is usually free.
  const sites = useQuery({
    queryKey: ["sites"],
    queryFn: endpoints.sites,
    refetchInterval: (query) =>
      query.state.data?.sites.some((s) => s.status === "provisioning") ? 3_000 : false,
  });

  if (sites.isPending) {
    return (
      <div className="flex justify-center py-24 text-ink-muted">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  const site = sites.data?.sites.find((s) => s.id === id) as SiteDetail | undefined;

  if (!site) {
    return (
      <div className="space-y-6">
        <BackLink />
        <Card>
          <CardBody className="py-16 text-center">
            <p className="text-sm font-medium text-ink">{t("siteDetail.notFound")}</p>
            <p className="mt-1 text-sm text-ink-muted">{t("siteDetail.notFoundHint")}</p>
          </CardBody>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <BackLink />
      <OverviewHeader site={site} />
      <div className="grid gap-6 lg:grid-cols-2">
        <CertificateCard site={site} />
        <AliasesCard site={site} />
      </div>
      <SettingsCard site={site} />
      <DriftCard siteId={site.id} />
      <DangerZone site={site} />
    </div>
  );
}

function BackLink() {
  const { t } = useTranslation();
  return (
    <Link
      to="/sites"
      className="inline-flex items-center gap-1.5 text-sm text-ink-muted hover:text-ink"
    >
      <ArrowLeft className="h-4 w-4 rtl:rotate-180" aria-hidden />
      {t("siteDetail.back")}
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

function OverviewHeader({ site }: { site: SiteDetail }) {
  const { t, i18n } = useTranslation();

  return (
    <header className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 dir="ltr" className="text-2xl font-semibold tracking-tight text-ink">
          {site.domain}
        </h1>
        <Badge tone={STATE_TONE[site.status]} dot={site.status === "provisioning"}>
          {t(`sites.state.${site.status}`)}
        </Badge>
        {site.maintenance_mode ? (
          <Badge tone="warning">
            <Wrench className="h-3 w-3" aria-hidden />
            {t("sites.maintenance")}
          </Badge>
        ) : null}
        <Badge tone="neutral">{t(`sites.kind.${site.site_type}`)}</Badge>
        <a
          href={`http${site.has_certificate ? "s" : ""}://${site.domain}`}
          target="_blank"
          rel="noreferrer noopener"
          className="inline-flex items-center gap-1 text-sm text-ink-muted hover:text-accent"
        >
          <ExternalLink className="h-3.5 w-3.5" aria-hidden />
          {t("siteDetail.openSite")}
        </a>
      </div>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3 lg:grid-cols-5">
        {site.php_version ? (
          <MetaItem label={t("siteDetail.phpVersion")} value={`PHP ${site.php_version}`} mono />
        ) : null}
        <MetaItem label={t("siteDetail.linuxUser")} value={site.linux_user} mono />
        <MetaItem label={t("siteDetail.rootDir")} value={site.root_dir} mono />
        <MetaItem
          label={t("siteDetail.created")}
          value={formatDate(site.created_at, i18n.language)}
        />
        <MetaItem label={t("siteDetail.wwwPolicy")} value={t(`siteDetail.www.${site.www_policy}`)} />
        {site.site_type === "proxy" && site.proxy_port !== null ? (
          <MetaItem label={t("siteDetail.proxyPort")} value={String(site.proxy_port)} mono />
        ) : null}
        {site.site_type === "redirect" && site.redirect_target ? (
          <MetaItem
            label={`${t("siteDetail.redirectTarget")} (${t("siteDetail.redirectCode", { code: site.redirect_code })})`}
            value={site.redirect_target}
            mono
          />
        ) : null}
      </dl>
    </header>
  );
}

function MetaItem({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-ink-subtle">{label}</dt>
      <dd
        dir={mono ? "ltr" : undefined}
        className={cn("mt-0.5 truncate text-ink", mono && "font-mono text-xs leading-5")}
        title={value}
      >
        {value}
      </dd>
    </div>
  );
}

/** Dates in the reader's calendar, digits kept Latin like every other number here. */
function formatDate(iso: string, language: string): string {
  try {
    const locale = language === "fa" ? "fa-IR-u-nu-latn" : language;
    return new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(new Date(iso));
  } catch {
    return iso;
  }
}

// ---------------------------------------------------------------------------
// Task receipt
// ---------------------------------------------------------------------------

/**
 * The receipt for a 202: polls the task until it settles so the user watches
 * the change apply instead of wondering whether the button worked.
 */
function TaskNotice({
  taskId,
  onSettled,
}: {
  taskId: string;
  onSettled?: (status: TaskStatus) => void;
}) {
  const { t } = useTranslation();
  const task = useQuery({
    queryKey: ["task", taskId],
    queryFn: () => api.get<Task>(`/api/tasks/${taskId}`),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === undefined || status === "queued" || status === "running" ? 1_500 : false;
    },
  });

  const status = task.data?.status;
  // Fire the settle callback exactly once, even though polling keeps the query
  // re-rendering afterwards.
  const settled = useRef(false);
  useEffect(() => {
    if (!status || status === "queued" || status === "running" || settled.current) return;
    settled.current = true;
    onSettled?.(status);
  }, [status, onSettled]);

  const tone: Record<TaskStatus, "neutral" | "accent" | "success" | "danger" | "warning"> = {
    queued: "neutral",
    running: "accent",
    ok: "success",
    failed: "danger",
    cancelled: "warning",
  };

  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg bg-surface-muted px-3 py-2 text-sm">
      {status === undefined || status === "queued" || status === "running" ? (
        <Spinner className="h-3.5 w-3.5" />
      ) : null}
      <span className="text-ink-muted">
        {t("siteDetail.task")}{" "}
        <span dir="ltr" className="font-mono text-xs">
          {taskId.slice(0, 8)}
        </span>
      </span>
      {task.data ? <Badge tone={tone[task.data.status]}>{t(`tasks.status.${task.data.status}`)}</Badge> : null}
      {task.data?.status === "failed" && task.data.error_detail ? (
        <span role="alert" dir="auto" className="basis-full text-danger">
          {task.data.error_detail}
        </span>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

function CertificateCard({ site }: { site: SiteDetail }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [staging, setStaging] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const certs = useQuery({
    queryKey: ["certificates"],
    queryFn: () => api.get<{ certificates: CertificateView[] }>("/api/certificates"),
  });

  // The active certificate is the one nginx serves; failing that, the newest
  // row still tells the story (a failed issuance and its error).
  const mine = (certs.data?.certificates ?? []).filter((c) => c.site_id === site.id);
  const cert = mine.find((c) => c.status === "active") ?? mine.sort((a, b) => b.id - a.id)[0];

  const issue = useMutation({
    mutationFn: () => endpoints.issueCertificate(site.id, staging),
    onSuccess: (accepted: TaskAccepted) => {
      setError(null);
      setTaskId(accepted.task_id);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const days = cert?.days_remaining ?? null;
  const daysTone = days === null ? "neutral" : days <= 7 ? "danger" : days <= 21 ? "warning" : "success";

  return (
    <Card>
      <CardHeader
        title={
          <span className="inline-flex items-center gap-1.5">
            {cert?.status === "active" ? (
              <Lock className="h-4 w-4" aria-hidden />
            ) : (
              <LockOpen className="h-4 w-4" aria-hidden />
            )}
            {t("siteDetail.certificate")}
          </span>
        }
        description={t("siteDetail.certificateHint")}
        action={cert ? <Badge tone={CERT_TONE[cert.status]}>{t(`siteDetail.certStatus.${cert.status}`)}</Badge> : null}
      />
      <CardBody>
        {certs.isPending ? (
          <div className="flex justify-center py-6 text-ink-muted">
            <Spinner />
          </div>
        ) : cert ? (
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <MetaItem
              label={t("siteDetail.issuer")}
              value={cert.issuer ?? t(`siteDetail.certKind.${cert.kind}`)}
              mono
            />
            <div className="min-w-0">
              <dt className="text-xs text-ink-subtle">{t("siteDetail.expires")}</dt>
              <dd className="mt-0.5 flex items-center gap-2">
                {cert.not_after ? (
                  <>
                    <span className="text-ink">{formatDate(cert.not_after, i18n.language)}</span>
                    <Badge tone={daysTone}>{t("sites.certDays", { count: days ?? 0 })}</Badge>
                  </>
                ) : (
                  <span className="text-ink-muted">{t("common.none")}</span>
                )}
              </dd>
            </div>
            <MetaItem label={t("siteDetail.domains")} value={cert.domains.join(", ")} mono />
            <MetaItem
              label={t(`siteDetail.certKind.${cert.kind}`)}
              value={cert.auto_renew ? t("siteDetail.autoRenewOn") : t("siteDetail.autoRenewOff")}
            />
            {cert.last_error ? (
              <div className="col-span-2 min-w-0">
                <dt className="text-xs text-ink-subtle">{t("siteDetail.lastError")}</dt>
                <dd dir="ltr" className="mt-0.5 rounded-lg bg-danger-soft px-3 py-2 font-mono text-xs text-danger">
                  {cert.last_error}
                </dd>
              </div>
            ) : null}
          </dl>
        ) : (
          <div className="py-2">
            <p className="text-sm font-medium text-ink">{t("siteDetail.noCert")}</p>
            <p className="mt-1 text-sm text-ink-muted">{t("siteDetail.noCertHint")}</p>
          </div>
        )}

        <div className="mt-4 border-t border-border pt-4">
          <Switch
            checked={staging}
            onChange={setStaging}
            label={t("siteDetail.staging")}
            description={t("siteDetail.stagingHint")}
          />
          <Button
            variant={cert?.status === "active" ? "outline" : "primary"}
            className="mt-2"
            onClick={() => issue.mutate()}
            disabled={issue.isPending || site.status !== "active"}
          >
            {issue.isPending ? <Spinner /> : <RefreshCw className="h-4 w-4" aria-hidden />}
            {cert?.status === "active" ? t("siteDetail.renew") : t("siteDetail.issue")}
          </Button>
          {error ? (
            <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
              {error}
            </p>
          ) : null}
          {taskId ? (
            <TaskNotice
              key={taskId}
              taskId={taskId}
              onSettled={() => {
                void queryClient.invalidateQueries({ queryKey: ["certificates"] });
                void queryClient.invalidateQueries({ queryKey: ["sites"] });
              }}
            />
          ) : null}
        </div>
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Aliases (read-only: there is no alias endpoint in routes/sites.rs yet)
// ---------------------------------------------------------------------------

function AliasesCard({ site }: { site: SiteDetail }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader title={t("siteDetail.aliases")} description={t("siteDetail.aliasesHint")} />
      <CardBody>
        {site.aliases.length === 0 ? (
          <p className="text-sm text-ink-muted">{t("siteDetail.noAliases")}</p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {site.aliases.map((alias) => (
              <li key={alias}>
                <Badge tone="neutral">
                  <span dir="ltr" className="font-mono text-xs">
                    {alias}
                  </span>
                </Badge>
              </li>
            ))}
          </ul>
        )}
        <p className="mt-3 text-xs text-ink-subtle">{t("siteDetail.aliasesReadOnly")}</p>
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/** Every editable field, normalised so dirty comparison is plain `!==`. */
interface Editable {
  php_version: string;
  www_policy: WwwPolicy;
  force_https: boolean;
  http3: boolean;
  maintenance_mode: boolean;
  rate_limit_enabled: boolean;
  client_max_body_size: string;
  custom_nginx_snippet: string;
  php_ini_overrides: string;
}

function baselineOf(site: SiteDetail): Editable {
  return {
    php_version: site.php_version ?? "",
    www_policy: site.www_policy,
    force_https: site.force_https,
    http3: site.http3,
    maintenance_mode: site.maintenance_mode,
    rate_limit_enabled: site.rate_limit_enabled,
    client_max_body_size: site.client_max_body_size,
    custom_nginx_snippet: site.custom_nginx_snippet ?? "",
    php_ini_overrides: site.php_ini_overrides ?? "",
  };
}

function SettingsCard({ site }: { site: SiteDetail }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  // The form is an overlay of edits on top of the server's values, not a copy:
  // a background refetch updates the clean fields underneath while an edit in
  // progress stays put, and "dirty" is simply "the overlay differs".
  const [edits, setEdits] = useState<Partial<Editable>>({});
  const [saveTask, setSaveTask] = useState<{ id: string; keys: (keyof Editable)[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const baseline = baselineOf(site);
  const value = <K extends keyof Editable>(key: K): Editable[K] =>
    (edits[key] ?? baseline[key]) as Editable[K];
  const isDirty = (key: keyof Editable) => key in edits && edits[key] !== baseline[key];
  const set = <K extends keyof Editable>(key: K, next: Editable[K]) =>
    setEdits((prev) => {
      const merged = { ...prev };
      if (next === baseline[key]) delete merged[key];
      else merged[key] = next;
      return merged;
    });

  const dirtyKeys = (Object.keys(edits) as (keyof Editable)[]).filter(isDirty);

  const bodySize = value("client_max_body_size").trim();
  const bodySizeInvalid = isDirty("client_max_body_size") && !/^\d+[kmg]?$/i.test(bodySize);

  // Only the PHP versions actually installed are offered; a version nginx has
  // no pool socket for turns every request into a 502.
  const stack = useQuery({ queryKey: ["stack"], queryFn: endpoints.stack });
  const installedPhp =
    stack.data?.components
      .filter((c) => c.slug.startsWith("php") && c.status === "installed")
      .map((c) => c.slug.replace("php", "")) ?? [];
  // Keep the site's current version selectable even if its package vanished,
  // so opening the page never silently marks the field dirty.
  const phpChoices =
    site.php_version && !installedPhp.includes(site.php_version)
      ? [site.php_version, ...installedPhp]
      : installedPhp;

  const save = useMutation({
    mutationFn: (vars: { body: UpdateBody; keys: (keyof Editable)[] }) =>
      api.patch<TaskAccepted>(`/api/sites/${site.id}`, vars.body),
    onSuccess: (accepted, vars) => {
      setError(null);
      setSaveTask({ id: accepted.task_id, keys: vars.keys });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const submit = () => {
    if (dirtyKeys.length === 0 || bodySizeInvalid) return;
    const body: UpdateBody = {};
    for (const key of dirtyKeys) {
      switch (key) {
        case "php_version":
          body.php_version = value("php_version");
          break;
        case "www_policy":
          body.www_policy = value("www_policy");
          break;
        case "force_https":
          body.force_https = value("force_https");
          break;
        case "http3":
          body.http3 = value("http3");
          break;
        case "maintenance_mode":
          body.maintenance_mode = value("maintenance_mode");
          break;
        case "rate_limit_enabled":
          body.rate_limit_enabled = value("rate_limit_enabled");
          break;
        case "client_max_body_size":
          body.client_max_body_size = bodySize;
          break;
        // Empty means "remove the override": the API distinguishes null
        // (clear) from absent (leave alone), so an emptied textarea must
        // become an explicit null.
        case "custom_nginx_snippet":
          body.custom_nginx_snippet = value("custom_nginx_snippet").trim() || null;
          break;
        case "php_ini_overrides":
          body.php_ini_overrides = value("php_ini_overrides").trim() || null;
          break;
      }
    }
    save.mutate({ body, keys: dirtyKeys });
  };

  const settle = (status: TaskStatus) => {
    if (status === "ok" && saveTask) {
      // Drop only the edits that were saved; anything typed while the task ran
      // survives as a fresh dirty state on top of the new baseline.
      setEdits((prev) => {
        const next = { ...prev };
        for (const key of saveTask.keys) delete next[key];
        return next;
      });
    }
    void queryClient.invalidateQueries({ queryKey: ["sites"] });
    void queryClient.invalidateQueries({ queryKey: ["site-drift", site.id] });
  };

  const saving = save.isPending;

  return (
    <Card>
      <CardHeader
        title={t("siteDetail.settings")}
        description={t("siteDetail.settingsHint")}
        action={
          dirtyKeys.length > 0 ? (
            <Badge tone="accent">{t("siteDetail.changedCount", { count: dirtyKeys.length })}</Badge>
          ) : null
        }
      />
      <CardBody className="space-y-1">
        <div className="grid gap-x-8 sm:grid-cols-2">
          {site.site_type === "php" ? (
            <DirtyMark dirty={isDirty("php_version")}>
              <Field label={t("siteDetail.phpVersion")} htmlFor="php_version">
                <Select
                  id="php_version"
                  value={value("php_version")}
                  onChange={(event) => set("php_version", event.target.value)}
                >
                  {phpChoices.map((version) => (
                    <option key={version} value={version}>
                      PHP {version}
                      {EOL_PHP_VERSIONS.has(version) ? ` — ${t("stack.eol")}` : ""}
                    </option>
                  ))}
                </Select>
              </Field>
            </DirtyMark>
          ) : null}

          <DirtyMark dirty={isDirty("www_policy")}>
            <Field label={t("siteDetail.wwwPolicy")} htmlFor="www_policy">
              <Select
                id="www_policy"
                value={value("www_policy")}
                onChange={(event) => set("www_policy", event.target.value as WwwPolicy)}
              >
                <option value="none">{t("siteDetail.www.none")}</option>
                <option value="add">{t("siteDetail.www.add")}</option>
                <option value="strip">{t("siteDetail.www.strip")}</option>
              </Select>
            </Field>
          </DirtyMark>

          <DirtyMark dirty={isDirty("client_max_body_size")}>
            <Field
              label={t("siteDetail.bodySize")}
              htmlFor="client_max_body_size"
              error={bodySizeInvalid ? t("siteDetail.bodySizeInvalid") : undefined}
            >
              <Input
                id="client_max_body_size"
                dir="ltr"
                placeholder="64m"
                aria-invalid={bodySizeInvalid}
                value={value("client_max_body_size")}
                onChange={(event) => set("client_max_body_size", event.target.value)}
              />
              <p className="text-xs text-ink-subtle">{t("siteDetail.bodySizeHint")}</p>
            </Field>
          </DirtyMark>
        </div>

        <div className="grid gap-x-8 sm:grid-cols-2">
          <DirtyMark dirty={isDirty("force_https")}>
            <Switch
              checked={value("force_https")}
              onChange={(next) => set("force_https", next)}
              label={t("siteDetail.forceHttps")}
              description={t("siteDetail.forceHttpsHint")}
            />
          </DirtyMark>
          <DirtyMark dirty={isDirty("http3")}>
            <Switch
              checked={value("http3")}
              onChange={(next) => set("http3", next)}
              label={t("siteDetail.http3")}
              description={t("siteDetail.http3Hint")}
            />
          </DirtyMark>
          <DirtyMark dirty={isDirty("maintenance_mode")}>
            <Switch
              checked={value("maintenance_mode")}
              onChange={(next) => set("maintenance_mode", next)}
              label={t("siteDetail.maintenanceMode")}
              description={t("siteDetail.maintenanceModeHint")}
            />
          </DirtyMark>
          <DirtyMark dirty={isDirty("rate_limit_enabled")}>
            <Switch
              checked={value("rate_limit_enabled")}
              onChange={(next) => set("rate_limit_enabled", next)}
              label={t("siteDetail.rateLimit")}
              description={t("siteDetail.rateLimitHint", {
                rps: site.rate_limit_rps,
                burst: site.rate_limit_burst,
              })}
            />
          </DirtyMark>
        </div>

        <DirtyMark dirty={isDirty("custom_nginx_snippet")}>
          <Field label={t("siteDetail.nginxSnippet")} htmlFor="custom_nginx_snippet">
            <Textarea
              id="custom_nginx_snippet"
              dir="ltr"
              rows={5}
              spellCheck={false}
              placeholder="location /downloads/ { autoindex on; }"
              value={value("custom_nginx_snippet")}
              onChange={(event) => set("custom_nginx_snippet", event.target.value)}
            />
            <p className="text-xs text-ink-subtle">{t("siteDetail.nginxSnippetHint")}</p>
          </Field>
        </DirtyMark>

        {site.site_type === "php" ? (
          <DirtyMark dirty={isDirty("php_ini_overrides")}>
            <Field label={t("siteDetail.phpIni")} htmlFor="php_ini_overrides">
              <Textarea
                id="php_ini_overrides"
                dir="ltr"
                rows={4}
                spellCheck={false}
                placeholder={"memory_limit = 256M\nmax_execution_time = 120"}
                value={value("php_ini_overrides")}
                onChange={(event) => set("php_ini_overrides", event.target.value)}
              />
              <p className="text-xs text-ink-subtle">{t("siteDetail.phpIniHint")}</p>
            </Field>
          </DirtyMark>
        ) : null}

        {site.site_type === "proxy" ? (
          <p className="text-xs text-ink-subtle">{t("siteDetail.proxyFixed")}</p>
        ) : null}
        {site.site_type === "redirect" ? (
          <p className="text-xs text-ink-subtle">{t("siteDetail.redirectFixed")}</p>
        ) : null}

        <div className="flex items-center gap-2 border-t border-border pt-4">
          <Button
            variant="primary"
            onClick={submit}
            disabled={dirtyKeys.length === 0 || bodySizeInvalid || saving}
          >
            {saving ? <Spinner /> : null}
            {t("siteDetail.save")}
          </Button>
          {dirtyKeys.length > 0 ? (
            <Button variant="ghost" onClick={() => setEdits({})} disabled={saving}>
              {t("siteDetail.discard")}
            </Button>
          ) : null}
        </div>

        {error ? (
          <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}
        {saveTask ? <TaskNotice key={saveTask.id} taskId={saveTask.id} onSettled={settle} /> : null}
      </CardBody>
    </Card>
  );
}

/**
 * A start-side accent bar on fields that differ from what the server has.
 * Logical properties (`border-s`, `ps`) keep it on the correct side in RTL.
 */
function DirtyMark({ dirty, children }: { dirty: boolean; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        "border-s-2 ps-3 transition-colors",
        dirty ? "border-accent" : "border-transparent",
      )}
    >
      {children}
    </div>
  );
}

const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        "w-full rounded-lg border border-border-strong bg-surface px-3 py-2 font-mono text-xs text-ink",
        "placeholder:text-ink-subtle",
        "focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-accent",
        className,
      )}
      {...props}
    />
  ),
);
Textarea.displayName = "Textarea";

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

function DriftCard({ siteId }: { siteId: number }) {
  const { t } = useTranslation();

  const drift = useQuery({
    queryKey: ["site-drift", siteId],
    queryFn: () => endpoints.siteDrift(siteId),
  });

  // `state` is the Debug form of FileState lowercased, so variants with data
  // arrive as `drifted { expected: ... }` — match on the prefix.
  const stateKey = (state: string) =>
    (["managed", "absent", "drifted", "foreign", "unreadable"] as const).find((k) =>
      state.startsWith(k),
    ) ?? "unreadable";

  const tone: Record<ReturnType<typeof stateKey>, "success" | "warning" | "danger"> = {
    managed: "success",
    absent: "warning",
    drifted: "danger",
    foreign: "danger",
    unreadable: "warning",
  };

  const key = drift.data ? stateKey(drift.data.state) : null;

  return (
    <Card>
      <CardHeader
        title={
          <span className="inline-flex items-center gap-1.5">
            <FileDiff className="h-4 w-4" aria-hidden />
            {t("siteDetail.drift")}
          </span>
        }
        description={t("siteDetail.driftHint")}
        action={
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void drift.refetch()}
            disabled={drift.isFetching}
          >
            {drift.isFetching ? <Spinner /> : <RefreshCw className="h-3.5 w-3.5" aria-hidden />}
            {t("siteDetail.recheck")}
          </Button>
        }
      />
      <CardBody>
        {drift.isPending ? (
          <div className="flex justify-center py-6 text-ink-muted">
            <Spinner />
          </div>
        ) : drift.isError ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {drift.error instanceof ApiError ? drift.error.message : String(drift.error)}
          </p>
        ) : drift.data && key ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={tone[key]}>{t(`siteDetail.driftState.${key}`)}</Badge>
              <span dir="ltr" className="truncate font-mono text-xs text-ink-subtle">
                {drift.data.path}
              </span>
            </div>
            <p className="text-sm text-ink-muted">{t(`siteDetail.drift${capitalize(key)}`)}</p>
            {key === "drifted" && drift.data.diff.length > 0 ? (
              <DiffView diff={drift.data.diff} />
            ) : null}
          </div>
        ) : null}
      </CardBody>
    </Card>
  );
}

function capitalize<T extends string>(s: T): Capitalize<T> {
  return (s.charAt(0).toUpperCase() + s.slice(1)) as Capitalize<T>;
}

function DiffView({ diff }: { diff: DriftResponse["diff"] }) {
  const { t } = useTranslation();
  return (
    <div>
      <p className="mb-1 text-xs text-ink-subtle" dir="auto">
        {t("siteDetail.diffLegend")}
      </p>
      {/* Config text is LTR whatever the UI language; the container scrolls so
          long nginx lines never force the page sideways. */}
      <div dir="ltr" className="max-h-96 overflow-auto rounded-lg border border-border bg-surface-muted">
        <table className="w-full border-collapse font-mono text-xs leading-5">
          <tbody>
            {diff.map((line, index) => (
              <tr
                key={`${line.line}-${line.kind}-${index}`}
                className={cn(
                  line.kind === "added" && "bg-success-soft text-success",
                  line.kind === "removed" && "bg-danger-soft text-danger",
                  line.kind === "same" && "text-ink-muted",
                )}
              >
                <td className="w-10 select-none border-e border-border px-2 text-end text-ink-subtle">
                  {line.line}
                </td>
                <td className="w-4 select-none px-1 text-center">
                  {line.kind === "added" ? "+" : line.kind === "removed" ? "−" : ""}
                </td>
                <td className="whitespace-pre px-2">{line.text || " "}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Danger zone
// ---------------------------------------------------------------------------

function DangerZone({ site }: { site: SiteDetail }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [purge, setPurge] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Typing the domain is the confirmation (spec §11.2 delete is irreversible):
  // a checkbox is a reflex, a domain is a decision.
  const confirmed = typed.trim() === site.domain;

  const remove = useMutation({
    mutationFn: () => endpoints.deleteSite(site.id, purge),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["sites"] });
      void navigate({ to: "/sites" });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Card className="border-danger/40">
      <CardHeader title={t("siteDetail.danger")} description={t("siteDetail.dangerHint")} />
      <CardBody className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-medium text-ink">{t("siteDetail.deleteTitle")}</p>
          <p className="mt-0.5 text-sm text-ink-muted">{t("siteDetail.deleteBody")}</p>
        </div>
        <Button variant="danger" onClick={() => setOpen(true)}>
          {t("sites.delete")}
        </Button>
      </CardBody>

      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={t("sites.deleteTitle", { domain: site.domain })}
        description={t("sites.deleteHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="danger"
              onClick={() => remove.mutate()}
              disabled={!confirmed || remove.isPending}
            >
              {remove.isPending ? <Spinner /> : null}
              {t("sites.deleteConfirm")}
            </Button>
          </>
        }
      >
        <Field
          label={t("siteDetail.typeDomain")}
          htmlFor="confirm_domain"
          error={
            typed.length > 0 && !confirmed
              ? t("siteDetail.typeDomainMismatch", { domain: site.domain })
              : undefined
          }
        >
          <Input
            id="confirm_domain"
            dir="ltr"
            autoFocus
            placeholder={site.domain}
            autoComplete="off"
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
          />
        </Field>
        <Switch
          checked={purge}
          onChange={setPurge}
          label={t("sites.purgeFiles")}
          description={t("sites.purgeFilesHint")}
        />
        {error ? (
          <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}
      </Dialog>
    </Card>
  );
}
