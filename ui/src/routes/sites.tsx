import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ExternalLink, Globe, Lock, LockOpen, Play, Plus, Trash2, Wrench } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { Menu, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { ListSkeleton, Skeleton } from "@/components/ui/skeleton";
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
import { staggerStyle } from "@/lib/motion";
import { cn } from "@/lib/utils";

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
            {sites.data!.sites.map((site, index) => (
              <SiteRow key={site.id} site={site} index={index} />
            ))}
          </ul>
        </Card>
      )}

      <CreateSiteDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}

/**
 * The site's state, with a dot as well as a colour.
 *
 * A site that is still being set up is the one row that changes on its own —
 * the list re-polls every three seconds while one exists — so its dot pings.
 * Everything else is settled and stays still.
 */
function StatusBadge({ status }: { status: SiteState }) {
  const { t } = useTranslation();

  return (
    <Badge tone={TONE[status]}>
      <span className="relative flex h-1.5 w-1.5 shrink-0" aria-hidden>
        {status === "provisioning" ? (
          <span className="absolute inset-0 animate-ping-slow rounded-full bg-current" />
        ) : null}
        <span className="relative h-1.5 w-1.5 rounded-full bg-current" />
      </span>
      {t(`sites.state.${status}`)}
    </Badge>
  );
}

function SiteRow({ site, index }: { site: SiteView; index: number }) {
  const { t } = useTranslation();

  // A certificate about to expire is the thing an operator most needs to see
  // from a list, so it is a badge rather than a detail-page field.
  const days = site.certificate_expires_in_days;
  const certTone =
    days === undefined ? "neutral" : days <= 7 ? "danger" : days <= 21 ? "warning" : "success";

  return (
    <li
      style={staggerStyle(index)}
      className={cn(
        "group stagger relative flex animate-rise-in flex-wrap items-start gap-x-4 gap-y-3 px-5 py-4",
        "transition-colors duration-150 first:rounded-t-card last:rounded-b-card",
        "hover:bg-surface-muted/60 focus-within:bg-surface-muted/60 active:bg-surface-muted",
        // The same accent bar the shared <Tr> draws for table rows: on a block
        // this tall the tint alone does not say which row the pointer is on.
        // Inset far enough not to poke out of the card's rounded corners.
        "before:absolute before:inset-y-3 before:start-0 before:w-0.5 before:origin-top before:scale-y-0",
        "before:rounded-full before:bg-accent before:transition-transform before:duration-200",
        "hover:before:scale-y-100 focus-within:before:scale-y-100",
      )}
    >
      {/* basis-56 so the actions drop to their own line before the domain gets
          squeezed to nothing on a phone. */}
      <div className="min-w-0 flex-1 basis-56">
        {/* The domain goes to the detail page; the little arrow opens the
            live site. Managing a site is what this list is for — visiting it
            is the secondary act. The domain link stretches over the whole row
            (the ::after), because a row that lights up under the pointer has
            to be clickable everywhere it lights up; the controls sit above
            that overlay on z-10. */}
        <span className="flex items-center gap-1.5">
          <Link
            to="/sites/$siteId"
            params={{ siteId: String(site.id) }}
            className="truncate font-mono text-sm font-medium text-ink transition-colors group-hover:text-accent after:absolute after:inset-0 after:content-['']"
          >
            {site.domain}
          </Link>
          <a
            href={`http${site.has_certificate ? "s" : ""}://${site.domain}`}
            target="_blank"
            rel="noreferrer noopener"
            className="relative z-10 shrink-0 text-ink-subtle transition-colors hover:text-accent"
            aria-label={t("sites.openSite", { domain: site.domain })}
          >
            <ExternalLink className="h-3.5 w-3.5" aria-hidden />
          </a>
        </span>
        <p className="truncate font-mono text-xs text-ink-subtle">{site.root_dir}</p>
        {site.aliases.length > 0 ? (
          <p className="mt-0.5 truncate font-mono text-xs text-ink-muted">
            {site.aliases.join(", ")}
          </p>
        ) : null}

        {/* One shelf under the domain rather than a cluster floating beside the
            actions: five pills sharing a wrap container with a button read as
            unrelated at 375px, and as facts about this site here. */}
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <StatusBadge status={site.status} />

          {site.maintenance_mode ? (
            <Badge tone="warning">
              <Wrench className="h-3 w-3" aria-hidden />
              {t("sites.maintenance")}
            </Badge>
          ) : null}

          {site.php_version ? (
            <Badge
              tone={EOL_PHP_VERSIONS.has(site.php_version) ? "warning" : "neutral"}
              className="tnum"
            >
              PHP {site.php_version}
            </Badge>
          ) : (
            <Badge tone="neutral">{t(`sites.kind.${site.site_type}`)}</Badge>
          )}

          <Badge tone={certTone} className="tnum">
            {site.has_certificate ? (
              <Lock className="h-3 w-3" aria-hidden />
            ) : (
              <LockOpen className="h-3 w-3" aria-hidden />
            )}
            {site.has_certificate ? t("sites.certDays", { count: days ?? 0 }) : t("sites.noCert")}
          </Badge>
        </div>
      </div>

      <SiteActions site={site} />
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
      <div className="relative z-10 ms-auto flex shrink-0 items-center gap-2">
        {!site.has_certificate && site.status === "active" ? (
          <Button
            variant="outline"
            size="sm"
            onClick={() => issueCert.mutate()}
            loading={issueCert.isPending}
            title={t("sites.issueCertHint")}
          >
            <Lock className="h-3.5 w-3.5" aria-hidden />
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
      </div>

      {/* A failed certificate or maintenance toggle used to write into state
          that only the delete dialog rendered, so it never reached the screen.
          It belongs on the row that failed. */}
      {error && !confirming ? (
        <Callout
          tone="danger"
          className="relative z-10 basis-full"
          action={
            <Button variant="ghost" size="sm" onClick={() => setError(null)}>
              {t("common.dismiss")}
            </Button>
          }
        >
          {error}
        </Callout>
      ) : null}

      {/* Mounted only while it is open: a fifty-site list should not carry
          fifty dialog subtrees. */}
      {confirming ? (
        <Dialog
          open
          onClose={() => setConfirming(false)}
          title={t("sites.deleteTitle", { domain: site.domain })}
          description={t("sites.deleteHint")}
          footer={
            <>
              <Button variant="ghost" onClick={() => setConfirming(false)}>
                {t("common.cancel")}
              </Button>
              <Button variant="danger" onClick={() => remove.mutate()} loading={remove.isPending}>
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
            <Callout tone="danger" className="mt-3">
              {error}
            </Callout>
          ) : null}
        </Dialog>
      ) : null}
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
          <Button variant="primary" onClick={() => void submit()} loading={isSubmitting}>
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
          stack.isPending ? (
            // Shaped like the field that is coming, so the dialog does not
            // jump — and so "no PHP is installed" is not claimed before the
            // stack has answered.
            <div className="space-y-1.5">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-9 w-full rounded-lg" />
              <div className="min-h-4" />
            </div>
          ) : installed.length === 0 ? (
            <Callout tone="warning" className="mb-4">
              {t("sites.noPhpInstalled")}
            </Callout>
          ) : (
            <Field
              label={t("sites.phpVersion")}
              htmlFor="php_version"
              error={errors.php_version?.message}
            >
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
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}
      </form>
    </Dialog>
  );
}
