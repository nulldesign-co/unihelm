import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getRouteApi, useNavigate } from "@tanstack/react-router";
import {
  Download,
  ExternalLink,
  FileDiff,
  GitBranch,
  Link2,
  Lock,
  LockOpen,
  Plus,
  RefreshCw,
  Wrench,
  X,
} from "lucide-react";
import {
  forwardRef,
  useState,
  type FormEvent,
  type ReactNode,
  type TextareaHTMLAttributes,
} from "react";
import { useTranslation } from "react-i18next";

import { TaskNotice } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  ApiError,
  EOL_PHP_VERSIONS,
  api,
  endpoints,
  type DriftResponse,
  type SiteState,
  type SiteView,
  type TaskAccepted,
  type TaskStatus,
  type UpdateSiteRequest,
} from "@/lib/api";
import { gitApi, repositoryProblem, shortCommit } from "@/lib/git-api";
import { staggerStyle } from "@/lib/motion";
import { aliasProblem, normalizeDomain, sitesApi } from "@/lib/sites-api";
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
    return <PageSkeleton />;
  }

  const site = sites.data?.sites.find((s) => s.id === id) as SiteDetail | undefined;

  if (!site) {
    return (
      <div className="space-y-6">
        <PageHeader
          back={{ to: "/sites", label: t("nav.sites") }}
          title={t("siteDetail.notFound")}
          description={t("siteDetail.notFoundHint")}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        back={{ to: "/sites", label: t("nav.sites") }}
        title={site.domain}
        actions={
          <>
            {/* One cluster, so the badges wrap together instead of scattering
                across three lines of their own at 375px. */}
            <div className="flex flex-wrap items-center gap-2">
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
            </div>
            <a
              href={`http${site.has_certificate ? "s" : ""}://${site.domain}`}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1.5 text-sm text-ink-muted transition-colors hover:text-accent"
            >
              <ExternalLink className="h-3.5 w-3.5" aria-hidden />
              {t("siteDetail.openSite")}
            </a>
          </>
        }
      />
      {site.status === "failed" ? <UnfinishedBanner site={site} /> : null}
      <OverviewCard site={site} />
      <div className="grid gap-6 lg:grid-cols-2">
        <CertificateCard site={site} />
        <AliasesCard site={site} />
      </div>
      <RepositoryCard site={site} />
      <SettingsCard site={site} />
      <DriftCard siteId={site.id} />
      <DangerZone site={site} />
    </div>
  );
}

/**
 * Ghost layout matching the loaded page, so nothing jumps when data lands.
 *
 * Built from Card, not from a copy of its classes: the loading state has to
 * follow --radius-card and --shadow-card wherever they go next.
 */
function PageSkeleton() {
  return (
    <div role="status" aria-live="polite" className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-4 w-20" />
        <Skeleton className="h-7 w-64" />
      </div>
      <Card>
        <CardBody className="pt-5">
          <div className={META_GRID}>
            {Array.from({ length: 5 }, (_, i) => (
              <div key={i} className="animate-rise-in space-y-1.5 stagger" style={staggerStyle(i)}>
                <Skeleton className="h-3 w-16" />
                <Skeleton className="h-4 w-24" />
              </div>
            ))}
          </div>
        </CardBody>
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        {Array.from({ length: 2 }, (_, i) => (
          <Card key={i}>
            <CardBody className="pt-5">
              <Skeleton className="mb-4 h-4 w-32" />
              <div className="space-y-3">
                <Skeleton className="h-4 w-2/3" />
                <Skeleton className="h-4 w-1/2" />
                <Skeleton className="h-4 w-3/5" />
              </div>
            </CardBody>
          </Card>
        ))}
      </div>
      <Card>
        <CardBody className="pt-5">
          <Skeleton className="mb-4 h-4 w-24" />
          <div className="grid gap-x-8 gap-y-4 sm:grid-cols-2">
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

/**
 * One column on a phone, not two: these are mostly filesystem paths, and two
 * 160px columns of truncated `/home/…` tell the operator nothing at all.
 */
const META_GRID = "grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-3 lg:grid-cols-5";

function OverviewCard({ site }: { site: SiteDetail }) {
  const { t, i18n } = useTranslation();

  return (
    <Card>
      <CardBody className="pt-5">
        <dl className={cn(META_GRID, "text-sm")}>
          {site.php_version ? (
            <MetaItem label={t("siteDetail.phpVersion")} value={`PHP ${site.php_version}`} mono />
          ) : null}
          <MetaItem label={t("siteDetail.linuxUser")} value={site.linux_user} mono />
          <MetaItem label={t("siteDetail.rootDir")} value={site.root_dir} mono />
          <MetaItem
            label={t("siteDetail.created")}
            value={formatDate(site.created_at, i18n.language)}
          />
          <MetaItem
            label={t("siteDetail.wwwPolicy")}
            value={t(`siteDetail.www.${site.www_policy}`)}
          />
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
      </CardBody>
    </Card>
  );
}

/**
 * One `dt`/`dd` shape for every fact on the page.
 *
 * `value` takes a node as well as a string so the rows that carry a badge or a
 * callout keep the same label size and the same 2px gap as the plain ones —
 * there used to be two hand-written shapes inside one `<dl>`.
 */
function MetaItem({
  label,
  value,
  mono,
  className,
}: {
  label: ReactNode;
  value: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  const plain = typeof value === "string";
  return (
    <div className={cn("min-w-0", className)}>
      <dt className="text-xs text-ink-subtle">{label}</dt>
      <dd
        className={cn(
          "tnum mt-0.5 text-ink",
          plain ? "truncate" : "flex flex-wrap items-center gap-2",
          mono && "font-mono text-xs leading-5",
        )}
        title={plain ? (value as string) : undefined}
      >
        {value}
      </dd>
    </div>
  );
}

function formatDate(iso: string, language: string): string {
  try {
    return new Intl.DateTimeFormat(language, { dateStyle: "medium" }).format(new Date(iso));
  } catch {
    return iso;
  }
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
          <div
            role="status"
            aria-live="polite"
            className="grid grid-cols-1 gap-x-6 gap-y-3 py-0.5 sm:grid-cols-2"
          >
            {Array.from({ length: 4 }, (_, i) => (
              <div key={i} className="animate-rise-in space-y-1.5 stagger" style={staggerStyle(i)}>
                <Skeleton className="h-3 w-16" />
                <Skeleton className="h-4 w-28" />
              </div>
            ))}
          </div>
        ) : cert ? (
          <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
            <MetaItem
              label={t("siteDetail.issuer")}
              value={cert.issuer ?? t(`siteDetail.certKind.${cert.kind}`)}
              mono
            />
            <MetaItem
              label={t("siteDetail.expires")}
              value={
                cert.not_after ? (
                  <>
                    <span>{formatDate(cert.not_after, i18n.language)}</span>
                    <Badge tone={daysTone} className="tnum">
                      {t("sites.certDays", { count: days ?? 0 })}
                    </Badge>
                  </>
                ) : (
                  <span className="text-ink-muted">{t("common.none")}</span>
                )
              }
            />
            <MetaItem label={t("siteDetail.domains")} value={cert.domains.join(", ")} mono />
            <MetaItem
              label={t(`siteDetail.certKind.${cert.kind}`)}
              value={cert.auto_renew ? t("siteDetail.autoRenewOn") : t("siteDetail.autoRenewOff")}
            />
            {cert.last_error ? (
              <MetaItem
                className="sm:col-span-2"
                label={t("siteDetail.lastError")}
                value={
                  <Callout tone="danger" className="w-full">
                    <span className="font-mono text-xs break-words">{cert.last_error}</span>
                  </Callout>
                }
              />
            ) : null}
          </dl>
        ) : (
          /* The issue button lives directly beneath this, always visible, so
             the empty state teaches rather than repeating the action. */
          <EmptyState
            className="py-8"
            icon={<LockOpen />}
            title={t("siteDetail.noCert")}
            hint={t("siteDetail.noCertHint")}
          />
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
            loading={issue.isPending}
            disabled={site.status !== "active"}
          >
            <RefreshCw className="h-4 w-4" aria-hidden />
            {cert?.status === "active" ? t("siteDetail.renew") : t("siteDetail.issue")}
          </Button>
          {error ? (
            <Callout tone="danger" className="mt-3">
              {error}
            </Callout>
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
// Re-provision
// ---------------------------------------------------------------------------

/**
 * The way out of a `failed` row.
 *
 * A site whose provisioning stopped partway used to be a dead end: the state
 * badge went red, the drift card said "No vhost exists on disk. Saving any
 * setting writes it again" — and saving needs a setting to change — and the
 * only real option left was Delete. The banner sits above the fold because a
 * failed site is the one thing on this page worth reading first.
 */
function UnfinishedBanner({ site }: { site: SiteDetail }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const retry = useMutation({
    mutationFn: () => sitesApi.reprovision(site.id),
    onSuccess: (accepted: TaskAccepted) => {
      setError(null);
      setTaskId(accepted.task_id);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Callout
      tone="danger"
      title={t("siteDetail.unfinishedTitle")}
      action={
        <Button variant="primary" onClick={() => retry.mutate()} loading={retry.isPending}>
          <RefreshCw className="h-4 w-4" aria-hidden />
          {t("siteDetail.reprovision")}
        </Button>
      }
    >
      <p>{t("siteDetail.unfinishedBody")}</p>
      {error ? <p className="mt-2 font-mono text-xs break-words">{error}</p> : null}
      {taskId ? (
        <TaskNotice
          key={taskId}
          taskId={taskId}
          onSettled={() => {
            void queryClient.invalidateQueries({ queryKey: ["sites"] });
            void queryClient.invalidateQueries({ queryKey: ["site-drift", site.id] });
          }}
        />
      ) : null}
    </Callout>
  );
}

// ---------------------------------------------------------------------------
// Aliases
// ---------------------------------------------------------------------------

/**
 * The other domains this site answers to, and the controls that change them.
 *
 * This card used to render a row of badges under the sentence "Aliases are set
 * when the site is created; there is no API to change them yet" — which was
 * true, and meant that attaching `www.` to a live site was a delete and a
 * rebuild. There is an API now.
 *
 * Adding is refused while the site is not serving, because the operation
 * refuses it too: a `failed` site has no vhost to add a name to, and a
 * `provisioning` one is being rewritten by another task. The button says which,
 * rather than posting and letting the task explain.
 */
function AliasesCard({ site }: { site: SiteDetail }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState("");
  const [touched, setTouched] = useState(false);
  const [running, setRunning] = useState(false);
  const [task, setTask] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // The site is only re-rendered as a whole, so an alias change needs a vhost
  // to change. `site.alias.add` refuses the other two states by name.
  const ready = site.status === "active" || site.status === "suspended";
  const problem = aliasProblem(draft, site);
  // Only once the operator has moved on from the field: complaining that a
  // half-typed `www.` needs a dot is complaining about typing.
  const showProblem = touched && draft.trim() !== "" && problem !== null;

  const started = (accepted: TaskAccepted) => {
    setError(null);
    setRunning(true);
    setTask(accepted.task_id);
  };
  const failed = (e: unknown) => {
    setRunning(false);
    setError(e instanceof ApiError ? e.message : String(e));
  };

  const add = useMutation({
    mutationFn: (domain: string) => sitesApi.addAlias(site.id, domain),
    onSuccess: (accepted: TaskAccepted) => {
      setDraft("");
      setTouched(false);
      started(accepted);
    },
    onError: failed,
  });

  const remove = useMutation({
    mutationFn: (alias: string) => sitesApi.removeAlias(site.id, alias),
    onSuccess: started,
    onError: failed,
  });

  const busy = running || add.isPending || remove.isPending;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    // Send the normalised name, because that is the spelling the agent stores
    // and the one the remove button will have to match later.
    if (problem !== null || busy || !ready) return;
    add.mutate(normalizeDomain(draft));
  };

  return (
    <Card>
      <CardHeader title={t("siteDetail.aliases")} description={t("siteDetail.aliasesHint")} />
      <CardBody>
        {site.aliases.length === 0 ? (
          <EmptyState
            className="py-8"
            icon={<Link2 />}
            title={t("siteDetail.noAliases")}
            hint={t("siteDetail.noAliasesHint")}
          />
        ) : (
          <ul className="flex flex-wrap gap-2">
            {site.aliases.map((alias, index) => (
              <li key={alias} className="animate-rise-in stagger" style={staggerStyle(index)}>
                {/* The badge and its remove control are one chip: a separate
                    button beside it would read as an action on the card. */}
                <span className="inline-flex items-center gap-1 rounded-full border border-border bg-surface-muted ps-2.5 pe-1 py-0.5">
                  <span className="font-mono text-xs text-ink">{alias}</span>
                  <button
                    type="button"
                    aria-label={t("siteDetail.aliasRemoveLabel", { domain: alias })}
                    disabled={busy || !ready}
                    onClick={() => remove.mutate(alias)}
                    className={cn(
                      "rounded-full p-0.5 text-ink-subtle transition-colors",
                      "hover:bg-danger-soft hover:text-danger",
                      "focus-visible:outline-2 focus-visible:outline-accent",
                      "disabled:pointer-events-none disabled:opacity-40",
                    )}
                  >
                    <X className="h-3 w-3" aria-hidden />
                  </button>
                </span>
              </li>
            ))}
          </ul>
        )}

        <form onSubmit={submit} className="mt-4 border-t border-border pt-4">
          <Field
            label={t("siteDetail.aliasAddLabel")}
            htmlFor="alias_domain"
            error={showProblem ? t(`siteDetail.aliasProblem.${problem}`) : undefined}
          >
            <div className="flex flex-wrap items-start gap-2">
              <Input
                id="alias_domain"
                className="min-w-48 flex-1 font-mono text-xs"
                placeholder="www.example.com"
                autoComplete="off"
                spellCheck={false}
                aria-invalid={showProblem}
                disabled={busy || !ready}
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                onBlur={() => setTouched(true)}
              />
              <Button
                type="submit"
                variant="outline"
                loading={add.isPending}
                disabled={busy || !ready || draft.trim() === "" || problem !== null}
              >
                <Plus className="h-4 w-4" aria-hidden />
                {t("siteDetail.aliasAdd")}
              </Button>
            </div>
            <p className="text-xs text-ink-subtle">
              {ready ? t("siteDetail.aliasAddHint") : t("siteDetail.aliasNotReady")}
            </p>
          </Field>
        </form>

        {error ? (
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}
        {task ? (
          <TaskNotice
            key={task}
            taskId={task}
            onSettled={() => {
              setRunning(false);
              // The alias list lives on the site row, and the vhost the drift
              // card compares against has just been rewritten.
              void queryClient.invalidateQueries({ queryKey: ["sites"] });
              void queryClient.invalidateQueries({ queryKey: ["site-drift", site.id] });
            }}
          />
        ) : null}
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/**
 * Where this site's code comes from.
 *
 * Deploying used to mean dragging files into the file manager one directory at
 * a time. This attaches a public repository, clones it into the document root
 * once, and fast-forwards it on every deploy after that.
 *
 * The card never claims more than the server told it. `root_state` is a reading
 * of the document root, `checkout` is a reading of what git says about itself,
 * and the attachment is the panel's own note — so when the checkout points at a
 * different repository than the one attached, that is shown as the
 * disagreement it is rather than resolved silently. Every button that would be
 * refused by the agent is disabled here with the reason next to it, because a
 * button that always fails is worse than no button.
 */
function RepositoryCard({ site }: { site: SiteDetail }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [repository, setRepository] = useState("");
  const [branch, setBranch] = useState("");
  const [touched, setTouched] = useState(false);
  const [task, setTask] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const status = useQuery({
    queryKey: ["site-git", site.id],
    queryFn: () => gitApi.status(site.id),
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["site-git", site.id] });
  };
  const failed = (e: unknown) => setError(e instanceof ApiError ? e.message : String(e));
  const started = (accepted: TaskAccepted) => {
    setError(null);
    setTask(accepted.task_id);
  };

  const attach = useMutation({
    mutationFn: () => gitApi.attach(site.id, repository, branch),
    onSuccess: () => {
      setError(null);
      setRepository("");
      setBranch("");
      setTouched(false);
      refresh();
    },
    onError: failed,
  });
  const detach = useMutation({
    mutationFn: () => gitApi.detach(site.id),
    onSuccess: () => {
      setError(null);
      refresh();
    },
    onError: failed,
  });
  const clone = useMutation({ mutationFn: () => gitApi.clone(site.id), onSuccess: started, onError: failed });
  const deploy = useMutation({ mutationFn: () => gitApi.pull(site.id), onSuccess: started, onError: failed });

  const data = status.data;
  const attachment = data?.attachment ?? null;
  const checkout = data?.checkout ?? null;
  const problem = repositoryProblem(repository);
  // Only once the operator has moved on from the field: complaining about a
  // half-typed URL is complaining about typing.
  const showProblem = touched && repository.trim() !== "" && problem !== null;
  const busy = attach.isPending || detach.isPending || clone.isPending || deploy.isPending;
  const canClone =
    !!data?.git_installed && (data.root_state === "empty" || data.root_state === "holding_page");
  const canDeploy =
    !!data?.git_installed &&
    data.root_state === "checkout" &&
    !!checkout &&
    !checkout.dirty &&
    checkout.remote_matches_attachment;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (problem !== null || busy) return;
    attach.mutate();
  };

  return (
    <Card>
      <CardHeader
        title={
          <span className="inline-flex items-center gap-1.5">
            <GitBranch className="h-4 w-4" aria-hidden />
            {t("siteDetail.gitTitle")}
          </span>
        }
        description={t("siteDetail.gitHint")}
        action={
          attachment ? (
            <Button variant="ghost" size="sm" onClick={() => detach.mutate()} loading={detach.isPending}>
              {t("siteDetail.gitDetach")}
            </Button>
          ) : null
        }
      />
      <CardBody>
        {status.isPending ? (
          <div role="status" aria-live="polite" className="space-y-3 py-0.5">
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-4 w-1/2" />
            <Skeleton className="h-9 w-40" />
          </div>
        ) : status.isError ? (
          <Callout tone="danger">
            {status.error instanceof ApiError ? status.error.message : String(status.error)}
          </Callout>
        ) : data ? (
          <div className="space-y-4">
            {!data.git_installed ? (
              <Callout tone="warning" title={t("siteDetail.gitMissingTitle")}>
                {t("siteDetail.gitMissing")}
              </Callout>
            ) : null}

            {attachment ? (
              <>
                <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
                  <MetaItem
                    className="sm:col-span-2"
                    label={t("siteDetail.gitRepository")}
                    value={attachment.repository}
                    mono
                  />
                  <MetaItem
                    label={t("siteDetail.gitBranch")}
                    value={attachment.branch ?? t("siteDetail.gitBranchDefault")}
                    mono={!!attachment.branch}
                  />
                  <MetaItem
                    label={t("siteDetail.gitLastDeployed")}
                    value={
                      attachment.last_deployed_at ? (
                        <>
                          <span>{formatDate(attachment.last_deployed_at, i18n.language)}</span>
                          {attachment.last_commit ? (
                            <Badge tone="neutral" className="font-mono">
                              {shortCommit(attachment.last_commit)}
                            </Badge>
                          ) : null}
                        </>
                      ) : (
                        <span className="text-ink-muted">{t("siteDetail.gitNever")}</span>
                      )
                    }
                  />
                  {checkout?.subject ? (
                    <MetaItem
                      className="sm:col-span-2"
                      label={t("siteDetail.gitCommit")}
                      value={checkout.subject}
                    />
                  ) : null}
                </dl>

                {data.root_state === "missing" ? (
                  <Callout tone="warning" title={t("siteDetail.gitRootMissingTitle")}>
                    {t("siteDetail.gitRootMissing", { root: data.document_root })}
                  </Callout>
                ) : null}

                {data.root_state === "occupied" ? (
                  <Callout tone="danger" title={t("siteDetail.gitOccupiedTitle")}>
                    <p>{t("siteDetail.gitOccupied", { root: data.document_root })}</p>
                    <p className="mt-1 font-mono text-xs break-words">
                      {data.root_entries.join(" · ")}
                    </p>
                  </Callout>
                ) : null}

                {checkout && !checkout.remote_matches_attachment ? (
                  <Callout tone="danger" title={t("siteDetail.gitMismatchTitle")}>
                    {t("siteDetail.gitMismatch", { remote: checkout.remote ?? "" })}
                  </Callout>
                ) : null}

                {checkout?.dirty ? (
                  <Callout tone="warning" title={t("siteDetail.gitDirtyTitle")}>
                    <p>{t("siteDetail.gitDirty", { count: checkout.changed_files.length })}</p>
                    <p className="mt-1 font-mono text-xs break-words">
                      {checkout.changed_files.join(" · ")}
                    </p>
                  </Callout>
                ) : null}

                <div className="flex flex-wrap items-center gap-2 border-t border-border pt-4">
                  {data.root_state === "checkout" ? (
                    <Button
                      variant="primary"
                      onClick={() => deploy.mutate()}
                      loading={deploy.isPending}
                      disabled={busy || !canDeploy}
                    >
                      <RefreshCw className="h-4 w-4" aria-hidden />
                      {t("siteDetail.gitDeploy")}
                    </Button>
                  ) : (
                    <Button
                      variant="primary"
                      onClick={() => clone.mutate()}
                      loading={clone.isPending}
                      disabled={busy || !canClone}
                    >
                      <Download className="h-4 w-4" aria-hidden />
                      {t("siteDetail.gitClone")}
                    </Button>
                  )}
                  <p className="text-xs text-ink-subtle">
                    {data.root_state === "checkout"
                      ? t("siteDetail.gitDeployHint")
                      : data.root_state === "holding_page"
                        ? t("siteDetail.gitCloneReplacesHint", { root: data.document_root })
                        : t("siteDetail.gitCloneHint", { root: data.document_root })}
                  </p>
                </div>
              </>
            ) : (
              <>
                <EmptyState
                  className="py-8"
                  icon={<GitBranch />}
                  title={t("siteDetail.gitNone")}
                  hint={t("siteDetail.gitNoneHint")}
                />
                <form onSubmit={submit} className="space-y-3 border-t border-border pt-4">
                  <Field
                    label={t("siteDetail.gitRepository")}
                    htmlFor="git_repository"
                    error={showProblem ? t(`siteDetail.gitProblem.${problem}`) : undefined}
                  >
                    <Input
                      id="git_repository"
                      className="font-mono text-xs"
                      placeholder="https://github.com/owner/project.git"
                      autoComplete="off"
                      spellCheck={false}
                      aria-invalid={showProblem}
                      disabled={busy}
                      value={repository}
                      onChange={(event) => setRepository(event.target.value)}
                      onBlur={() => setTouched(true)}
                    />
                    <p className="text-xs text-ink-subtle">{t("siteDetail.gitRepositoryHint")}</p>
                  </Field>
                  <Field label={t("siteDetail.gitBranch")} htmlFor="git_branch">
                    <div className="flex flex-wrap items-start gap-2">
                      <Input
                        id="git_branch"
                        className="min-w-40 flex-1 font-mono text-xs"
                        placeholder="main"
                        autoComplete="off"
                        spellCheck={false}
                        disabled={busy}
                        value={branch}
                        onChange={(event) => setBranch(event.target.value)}
                      />
                      <Button
                        type="submit"
                        variant="primary"
                        loading={attach.isPending}
                        disabled={busy || repository.trim() === "" || problem !== null}
                      >
                        <Plus className="h-4 w-4" aria-hidden />
                        {t("siteDetail.gitAttach")}
                      </Button>
                    </div>
                    <p className="text-xs text-ink-subtle">{t("siteDetail.gitBranchHint")}</p>
                  </Field>
                </form>
              </>
            )}
          </div>
        ) : null}

        {error ? (
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}
        {task ? (
          <TaskNotice
            key={task}
            taskId={task}
            onSettled={() => {
              // The document root, the checkout and the recorded commit have
              // all just moved; the sites list has not.
              refresh();
            }}
          />
        ) : null}
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

  // Which of this site's controls the web server currently serving does not
  // apply. Asked of the *active* server with no target, so it is computed from
  // what is running rather than remembered from a switch — a stored list would
  // go on naming a rate limit somebody has since turned off.
  //
  // Without this the page went on presenting HTTP/3, request rate limiting and
  // the nginx snippet as live controls on an Apache machine, where none of them
  // does anything. Those fields are exactly the ones an operator sets and then
  // trusts.
  const notApplied = useQuery({
    queryKey: ["webserver-gaps"],
    queryFn: () => endpoints.webServerGaps(),
    staleTime: 60_000,
  });
  const inert = new Set(
    (notApplied.data?.gaps ?? [])
      .filter((g) => g.domain === site.domain)
      .map((g) => g.field),
  );

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
                className="font-mono text-xs"
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
              description={
                inert.has("http3") ? t("siteDetail.notApplied") : t("siteDetail.http3Hint")
              }
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
              description={
                inert.has("rate_limit_enabled")
                  ? t("siteDetail.notApplied")
                  : t("siteDetail.rateLimitHint", {
                      rps: site.rate_limit_rps,
                      burst: site.rate_limit_burst,
                    })
              }
            />
          </DirtyMark>
        </div>

        <DirtyMark dirty={isDirty("custom_nginx_snippet")}>
          {inert.has("custom_nginx_snippet") ? (
            <Callout tone="warning">{t("siteDetail.notApplied")}</Callout>
          ) : null}
          <Field label={t("siteDetail.nginxSnippet")} htmlFor="custom_nginx_snippet">
            <Textarea
              id="custom_nginx_snippet"
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

        <div className="flex flex-wrap items-center gap-2 border-t border-border pt-4">
          <Button
            variant="primary"
            onClick={submit}
            loading={saving}
            disabled={dirtyKeys.length === 0 || bodySizeInvalid}
          >
            {t("siteDetail.save")}
          </Button>
          {dirtyKeys.length > 0 ? (
            <>
              <Button
                variant="ghost"
                className="animate-pop-in"
                onClick={() => setEdits({})}
                disabled={saving}
              >
                {t("siteDetail.discard")}
              </Button>
              {/* The same count as the header badge, but beside the button that
                  acts on it — the header is a long way from the field the user
                  just edited. */}
              <span className="tnum animate-fade-in text-xs text-ink-muted">
                {t("siteDetail.changedCount", { count: dirtyKeys.length })}
              </span>
            </>
          ) : null}
        </div>

        {error ? (
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}
        {saveTask ? <TaskNotice key={saveTask.id} taskId={saveTask.id} onSettled={settle} /> : null}
      </CardBody>
    </Card>
  );
}

/**
 * A start-side accent bar on fields that differ from what the server has.
 *
 * The bar grows instead of fading its colour in: a field going dirty is the
 * one moment on this page where something needs to be noticed in peripheral
 * vision, and a 2px colour change is exactly what peripheral vision misses.
 * The bar is decoration to a screen reader, so the state is also stated.
 */
function DirtyMark({ dirty, children }: { dirty: boolean; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <div className="relative ps-3">
      <span
        aria-hidden
        className={cn(
          "absolute inset-y-0 start-0 w-0.5 origin-top rounded-full bg-accent",
          "transition-transform duration-200 ease-out-quint",
          dirty ? "scale-y-100" : "scale-y-0",
        )}
      />
      {dirty ? <span className="sr-only">{t("siteDetail.fieldChanged")}</span> : null}
      {children}
    </div>
  );
}

/**
 * The multi-line twin of `Input`, wearing its border, shadow and hover so a
 * snippet box and a text field do not read as controls from two different
 * design systems. There is no textarea in ui/ to reach for yet.
 */
const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        "w-full rounded-lg border border-border bg-surface px-3 py-2 font-mono text-xs text-ink shadow-card",
        "transition-[border-color,box-shadow] duration-150 placeholder:text-ink-subtle hover:border-border-strong",
        "focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-accent",
        "aria-[invalid=true]:border-danger",
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
            loading={drift.isFetching}
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden />
            {t("siteDetail.recheck")}
          </Button>
        }
      />
      <CardBody>
        {drift.isPending ? (
          <div role="status" aria-live="polite" className="space-y-3 py-0.5">
            <div className="flex items-center gap-2">
              <Skeleton className="h-6 w-24 rounded-full" />
              <Skeleton className="h-3.5 w-48" />
            </div>
            <Skeleton className="h-4 w-2/3" />
          </div>
        ) : drift.isError ? (
          <Callout tone="danger">
            {drift.error instanceof ApiError ? drift.error.message : String(drift.error)}
          </Callout>
        ) : drift.data && key ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={tone[key]}>{t(`siteDetail.driftState.${key}`)}</Badge>
              <span className="truncate font-mono text-xs text-ink-subtle">{drift.data.path}</span>
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

/**
 * Not the shared `<Table>`: that one is a card with 12px cell padding, and a
 * diff is a dense block of monospace inside another card. Rows deliberately do
 * not respond to hover either — nothing here is clickable, and hover feedback
 * on a target that cannot be hit is a promise the panel does not keep.
 */
function DiffView({ diff }: { diff: DriftResponse["diff"] }) {
  const { t } = useTranslation();
  return (
    <div>
      <p className="mb-1 text-xs text-ink-subtle">{t("siteDetail.diffLegend")}</p>
      {/* The container scrolls so long nginx lines never force the page sideways. */}
      <div className="max-h-96 overflow-auto rounded-lg border border-border bg-surface-muted">
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
                {/* The glyph is what keeps added/removed from being colour
                    alone, so it gets room to render rather than a 4-unit
                    column that clips the sign off it. */}
                <td className="w-6 select-none px-1 text-center font-semibold">
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
    <Card>
      <CardHeader title={t("siteDetail.danger")} description={t("siteDetail.dangerHint")} />
      <CardBody>
        {/* The tint and the icon come from Callout rather than from a one-off
            danger border on the card — one component owns what a warning looks
            like, wherever the operator meets one. */}
        <Callout
          tone="danger"
          title={t("siteDetail.deleteTitle")}
          action={
            <Button variant="danger" onClick={() => setOpen(true)}>
              {t("sites.delete")}
            </Button>
          }
        >
          {t("siteDetail.deleteBody")}
        </Callout>
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
              loading={remove.isPending}
              disabled={!confirmed}
            >
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
            className="font-mono text-xs"
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
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}
      </Dialog>
    </Card>
  );
}
