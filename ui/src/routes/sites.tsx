import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Lock, LockOpen, Plus, Wrench } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
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
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("sites.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">{t("sites.subtitle")}</p>
        </div>
        <Button variant="primary" onClick={() => setCreating(true)}>
          <Plus className="h-4 w-4" />
          {t("sites.create")}
        </Button>
      </header>

      {sites.isPending ? (
        <div className="flex justify-center py-24 text-ink-muted">
          <Spinner className="h-6 w-6" />
        </div>
      ) : (sites.data?.sites.length ?? 0) === 0 ? (
        <EmptyState onCreate={() => setCreating(true)} />
      ) : (
        <ul className="space-y-3">
          {sites.data!.sites.map((site) => (
            <li key={site.id}>
              <SiteRow site={site} />
            </li>
          ))}
        </ul>
      )}

      <CreateSiteDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}

function EmptyState({ onCreate }: { onCreate: () => void }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardBody className="py-16 text-center">
        <Globe className="mx-auto mb-3 h-8 w-8 text-ink-subtle" aria-hidden />
        <p className="text-sm font-medium text-ink">{t("sites.empty")}</p>
        <p className="mx-auto mt-1 max-w-sm text-sm text-ink-muted">{t("sites.emptyHint")}</p>
        <Button variant="primary" className="mt-4" onClick={onCreate}>
          <Plus className="h-4 w-4" />
          {t("sites.create")}
        </Button>
      </CardBody>
    </Card>
  );
}

function SiteRow({ site }: { site: SiteView }) {
  const { t } = useTranslation();

  // A certificate about to expire is the thing an operator most needs to see
  // from a list, so it is a badge rather than a detail-page field.
  const days = site.certificate_expires_in_days;
  const certTone = days === undefined ? "neutral" : days <= 7 ? "danger" : days <= 21 ? "warning" : "success";

  return (
    <Card>
      <CardBody className="flex flex-wrap items-center gap-x-4 gap-y-2 pt-5">
        <Badge tone={TONE[site.status]} dot={site.status === "provisioning"}>
          {t(`sites.state.${site.status}`)}
        </Badge>

        <div className="min-w-0 flex-1">
          <a
            href={`http${site.has_certificate ? "s" : ""}://${site.domain}`}
            target="_blank"
            rel="noreferrer noopener"
            dir="ltr"
            className="truncate font-medium text-ink hover:text-accent"
          >
            {site.domain}
          </a>
          <p dir="ltr" className="truncate font-mono text-xs text-ink-subtle">
            {site.root_dir}
          </p>
          {site.aliases.length > 0 ? (
            <p dir="ltr" className="mt-0.5 truncate text-xs text-ink-muted">
              {site.aliases.join(", ")}
            </p>
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
      </CardBody>
    </Card>
  );
}

function SiteActions({ site }: { site: SiteView }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [purge, setPurge] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["sites"] });

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
      <Button
        variant="ghost"
        size="sm"
        onClick={() => toggleMaintenance.mutate()}
        disabled={toggleMaintenance.isPending}
      >
        {site.maintenance_mode ? t("sites.resume") : t("sites.pause")}
      </Button>
      <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
        {t("sites.delete")}
      </Button>

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
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Field label={t("sites.domain")} htmlFor="domain" error={errors.domain?.message}>
          <Input
            id="domain"
            dir="ltr"
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
              dir="ltr"
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
              dir="ltr"
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
