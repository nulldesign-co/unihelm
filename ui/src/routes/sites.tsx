import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ExternalLink, Globe, Lock, LockOpen, Play, Plus, Trash2, Wrench } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { Menu, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { ListSkeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import {
  ApiError,
  EOL_PHP_VERSIONS,
  endpoints,
  type CreateSiteRequest,
  type SiteKind,
  type SiteState,
  type SiteView,
  type StackComponentView,
} from "@/lib/api";

const TONE: Record<SiteState, "success" | "accent" | "warning" | "danger"> = {
  active: "success",
  provisioning: "accent",
  suspended: "warning",
  failed: "danger",
};

export function SitesPage() {
  const { t } = useTranslation();
  const [creating, setCreating] = useState(false);

  const sites = useQuery({
    queryKey: ["sites"],
    queryFn: endpoints.sites,
    refetchInterval: (query) =>
      query.state.data?.sites.some((s) => s.status === "provisioning") ? 3_000 : false,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("sites.title")}
        description={t("sites.subtitle")}
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" aria-hidden />
            {t("sites.create")}
          </Button>
        }
      />

      {sites.isPending ? (
        <ListSkeleton />
      ) : (sites.data?.sites.length ?? 0) === 0 ? (
        <EmptyState
          icon={<Globe aria-hidden />}
          title={t("sites.empty")}
          hint={t("sites.emptyHint")}
          action={
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" aria-hidden />
              {t("sites.create")}
            </Button>
          }
        />
      ) : (
        <Card>
          <ul className="divide-y divide-border">
            {sites.data!.sites.map((site) => (
              <SiteRow key={site.id} site={site} />
            ))}
          </ul>
        </Card>
      )}

      <CreateSiteDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}

function SiteRow({ site }: { site: SiteView }) {
  const { t } = useTranslation();

  // A certificate about to expire is the thing an operator most needs to see
  // from a list, so it is a badge rather than a detail-page field.
  const days = site.certificate_expires_in_days;
  const certTone = days === undefined ? "neutral" : days <= 7 ? "danger" : days <= 21 ? "warning" : "success";

  return (
    <li className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-4 transition-colors first:rounded-t-card last:rounded-b-card hover:bg-surface-muted/40">
      <Badge tone={TONE[site.status]} dot={site.status === "provisioning"}>
        {t(`sites.state.${site.status}`)}
      </Badge>

      <div className="min-w-0 flex-1">
        {/* The domain goes to the detail page; the little arrow opens the
            live site. Managing a site is what this list is for — visiting it
            is the secondary act. */}
        <span className="flex items-center gap-1.5">
          <Link
            to="/sites/$siteId"
            params={{ siteId: String(site.id) }}
            className="truncate font-mono text-sm font-medium text-ink transition-colors hover:text-accent"
          >
            {site.domain}
          </Link>
          <a
            href={`http${site.has_certificate ? "s" : ""}://${site.domain}`}
            target="_blank"
            rel="noreferrer noopener"
            className="shrink-0 text-ink-subtle transition-colors hover:text-accent"
            aria-label={site.domain}
          >
            <ExternalLink className="h-3.5 w-3.5" aria-hidden />
          </a>
        </span>
        <p className="truncate font-mono text-xs text-ink-subtle">{site.root_dir}</p>
        {site.aliases.length > 0 ? (
          <p className="mt-0.5 truncate font-mono text-xs text-ink-muted">{site.aliases.join(", ")}</p>
        ) : null}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {site.maintenance_mode ? (
          <Badge tone="warning">
            <Wrench className="h-3 w-3" aria-hidden />
            {t("sites.maintenance")}
          </Badge>
        ) : null}

        {site.php_version ? (
          <Badge tone={EOL_PHP_VERSIONS.has(site.php_version) ? "warning" : "neutral"}>
            PHP {site.php_version}
          </Badge>
        ) : (
          <Badge tone="neutral">{t(`sites.kind.${site.site_type}`)}</Badge>
        )}

        <Badge tone={certTone}>
          {site.has_certificate ? (
            <Lock className="h-3 w-3" aria-hidden />
          ) : (
            <LockOpen className="h-3 w-3" aria-hidden />
          )}
          {site.has_certificate
            ? t("sites.certDays", { count: days ?? 0 })
            : t("sites.noCert")}
        </Badge>

        <SiteActions site={site} />
      </div>
    </li>
  );
}

function SiteActions({ site }: { site: SiteView }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [purge, setPurge] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["sites"] });

  const issueCert = useMutation({
    mutationFn: () => endpoints.issueCertificate(site.id, false),
    onSuccess: invalidate,
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const toggleMaintenance = useMutation({
    mutationFn: () => endpoints.updateSite(site.id, { maintenance_mode: !site.maintenance_mode }),
    onSuccess: invalidate,
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const remove = useMutation({
    mutationFn: () => endpoints.deleteSite(site.id, purge),
    onSuccess: () => {
      setConfirming(false);
      invalidate();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <>
      {!site.has_certificate && site.status === "active" ? (
        <Button
          variant="outline"
          size="sm"
          onClick={() => issueCert.mutate()}
          disabled={issueCert.isPending}
          title={t("sites.issueCertHint")}
        >
          {issueCert.isPending ? <Spinner /> : <Lock className="h-3.5 w-3.5" aria-hidden />}
          {t("sites.issueCert")}
        </Button>
      ) : null}

      <Menu label={t("files.actions")}>
        <MenuItem
          icon={site.maintenance_mode ? <Play aria-hidden /> : <Wrench aria-hidden />}
          onClick={() => toggleMaintenance.mutate()}
          disabled={toggleMaintenance.isPending}
        >
          {site.maintenance_mode ? t("sites.resume") : t("sites.pause")}
        </MenuItem>
        <MenuSeparator />
        <MenuItem danger icon={<Trash2 aria-hidden />} onClick={() => setConfirming(true)}>
          {t("sites.delete")}
        </MenuItem>
      </Menu>

      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t("sites.deleteTitle", { domain: site.domain })}
        description={t("sites.deleteHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" onClick={() => remove.mutate()} disabled={remove.isPending}>
              {remove.isPending ? <Spinner /> : null}
              {t("sites.deleteConfirm")}
            </Button>
          </>
        }
      >
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
    </>
  );
}

interface CreateForm {
  domain: string;
  site_type: SiteKind;
  php_version: string;
  with_www: boolean;
  proxy_port: string;
  redirect_target: string;
}

function CreateSiteDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  // Only versions that are actually installed. Offering one that is not
  // produces a site whose every request 502s.
  const stack = useQuery({ queryKey: ["stack"], queryFn: endpoints.stack, enabled: open });
  const installed: StackComponentView[] =
    stack.data?.components.filter((c) => c.slug.startsWith("php") && c.status === "installed") ?? [];

  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateForm>({
    defaultValues: {
      domain: "",
      site_type: "php",
      php_version: "",
      with_www: true,
      proxy_port: "",
      redirect_target: "",
    },
  });

  const kind = watch("site_type");

  const submit = handleSubmit(async (values) => {
    setError(null);
    const body: CreateSiteRequest = {
      domain: values.domain.trim(),
      site_type: values.site_type,
      with_www: values.with_www,
    };
    if (values.site_type === "php") body.php_version = values.php_version;
    if (values.site_type === "proxy") body.proxy_port = Number(values.proxy_port);
    if (values.site_type === "redirect") body.redirect_target = values.redirect_target.trim();

    try {
      await endpoints.createSite(body);
      reset();
      onClose();
      void queryClient.invalidateQueries({ queryKey: ["sites"] });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("sites.create")}
      description={t("sites.createHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={() => void submit()} disabled={isSubmitting}>
            {isSubmitting ? <Spinner /> : null}
            {t("sites.create")}
          </Button>
        </>
      }
    >
      <form
        className="space-y-1"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Field label={t("sites.domain")} htmlFor="domain" error={errors.domain?.message}>
          <Input
            id="domain"
            placeholder="example.com"
            autoFocus
            aria-invalid={Boolean(errors.domain)}
            {...register("domain", {
              required: t("sites.domainRequired"),
              pattern: {
                // The server validates properly; this only catches the obvious
                // before a round trip.
                value: /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i,
                message: t("sites.domainInvalid"),
              },
            })}
          />
        </Field>

        <Field label={t("sites.type")} htmlFor="site_type">
          <Select id="site_type" {...register("site_type")}>
            <option value="php">{t("sites.kind.php")}</option>
            <option value="static">{t("sites.kind.static")}</option>
            <option value="proxy">{t("sites.kind.proxy")}</option>
            <option value="redirect">{t("sites.kind.redirect")}</option>
          </Select>
        </Field>

        {kind === "php" ? (
          installed.length === 0 ? (
            <p className="mb-4 rounded-lg bg-warning-soft px-3 py-2 text-sm text-warning">
              {t("sites.noPhpInstalled")}
            </p>
          ) : (
            <Field label={t("sites.phpVersion")} htmlFor="php_version" error={errors.php_version?.message}>
              <Select
                id="php_version"
                {...register("php_version", { required: t("sites.phpRequired") })}
              >
                {installed.map((c) => {
                  const version = c.slug.replace("php", "");
                  return (
                    <option key={c.slug} value={version}>
                      {c.display_name}
                      {EOL_PHP_VERSIONS.has(version) ? ` — ${t("stack.eol")}` : ""}
                    </option>
                  );
                })}
              </Select>
            </Field>
          )
        ) : null}

        {kind === "proxy" ? (
          <Field label={t("sites.proxyPort")} htmlFor="proxy_port" error={errors.proxy_port?.message}>
            <Input
              id="proxy_port"
              inputMode="numeric"
              placeholder="3000"
              {...register("proxy_port", {
                required: t("sites.proxyPortRequired"),
                min: { value: 1024, message: t("sites.proxyPortRange") },
                max: { value: 61000, message: t("sites.proxyPortRange") },
              })}
            />
          </Field>
        ) : null}

        {kind === "redirect" ? (
          <Field
            label={t("sites.redirectTarget")}
            htmlFor="redirect_target"
            error={errors.redirect_target?.message}
          >
            <Input
              id="redirect_target"
              placeholder="new.example.com"
              {...register("redirect_target", { required: t("sites.redirectRequired") })}
            />
          </Field>
        ) : null}

        <Switch
          checked={watch("with_www")}
          onChange={(next) =>
            reset({ ...watch(), with_www: next }, { keepErrors: true, keepDirty: true })
          }
          label={t("sites.withWww")}
          description={t("sites.withWwwHint")}
        />

        {error ? (
          <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}
      </form>
    </Dialog>
  );
}
