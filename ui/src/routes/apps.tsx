import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Plus, RotateCw, ScrollText, Trash2, X } from "lucide-react";
import { useState } from "react";
import { useFieldArray, useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import {
  ApiError,
  DEFAULT_LOG_LINES,
  endpoints,
  type AppView,
  type CreateAppRequest,
  type NodeEnv,
  type UnitState,
} from "@/lib/api";
import { formatBytes } from "@/lib/utils";

/**
 * Node applications (spec §11.10).
 *
 * The list is systemd's view, not the panel's: `state` comes from the unit, so
 * an app that crash-looped overnight reads `failed` here even though its row
 * still says the panel meant it to run. That difference is the whole reason
 * this page exists rather than a row of names.
 */
const TONE: Record<UnitState, "success" | "accent" | "warning" | "danger" | "neutral"> = {
  active: "success",
  activating: "accent",
  deactivating: "accent",
  inactive: "warning",
  failed: "danger",
  // A unit systemd has never loaded is not "stopped" — it is a unit file that
  // went missing, which needs a different fix from a restart.
  not_found: "danger",
  unknown: "neutral",
};

export function AppsPage() {
  const { t } = useTranslation();
  const [creating, setCreating] = useState(false);

  const apps = useQuery({
    queryKey: ["apps"],
    queryFn: endpoints.apps,
    // Only while something is mid-transition. A page of settled apps costs the
    // agent one systemctl sweep per visit, not one per second.
    refetchInterval: (query) =>
      query.state.data?.apps.some((a) => a.state === "activating" || a.state === "deactivating")
        ? 3_000
        : false,
  });

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("apps.title")}</h1>
          <p className="mt-1 text-sm text-ink-muted">{t("apps.subtitle")}</p>
        </div>
        <Button variant="primary" onClick={() => setCreating(true)}>
          <Plus className="h-4 w-4" />
          {t("apps.create")}
        </Button>
      </header>

      {apps.isPending ? (
        <div className="flex justify-center py-24 text-ink-muted">
          <Spinner className="h-6 w-6" />
        </div>
      ) : (apps.data?.apps.length ?? 0) === 0 ? (
        <EmptyState onCreate={() => setCreating(true)} />
      ) : (
        <ul className="space-y-3">
          {apps.data!.apps.map((app) => (
            <li key={app.id}>
              <AppRow app={app} />
            </li>
          ))}
        </ul>
      )}

      <CreateAppDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}

function EmptyState({ onCreate }: { onCreate: () => void }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardBody className="py-16 text-center">
        <Boxes className="mx-auto mb-3 h-8 w-8 text-ink-subtle" aria-hidden />
        <p className="text-sm font-medium text-ink">{t("apps.empty")}</p>
        <p className="mx-auto mt-1 max-w-sm text-sm text-ink-muted">{t("apps.emptyHint")}</p>
        <Button variant="primary" className="mt-4" onClick={onCreate}>
          <Plus className="h-4 w-4" />
          {t("apps.create")}
        </Button>
      </CardBody>
    </Card>
  );
}

function AppRow({ app }: { app: AppView }) {
  const { t, i18n } = useTranslation();

  return (
    <Card>
      <CardBody className="flex flex-wrap items-center gap-x-4 gap-y-2 pt-5">
        <Badge tone={TONE[app.state]} dot={app.state === "activating" || app.state === "deactivating"}>
          {/* systemd's states are already named on the dashboard; one vocabulary
              for "running" across the panel beats two that nearly agree. */}
          {t(`service.${app.state}`)}
        </Badge>

        <div className="min-w-0 flex-1">
          <span dir="ltr" className="block truncate font-medium text-ink">
            {app.name}
          </span>
          <p dir="ltr" className="truncate font-mono text-xs text-ink-subtle">
            {app.entry}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* The label and the number are separate children so the badge's own
              gap spaces them — and so the number stays LTR on an RTL page. */}
          <Badge tone="neutral">
            <span>{t("apps.port")}</span>
            <span dir="ltr">{app.port}</span>
          </Badge>

          {/* Production is the default and the boring case; the other two are
              worth flagging, because a hosted app in `development` leaks stack
              traces to the internet. */}
          {app.node_env === "production" ? null : (
            <Badge tone="warning">{t(`apps.envName.${app.node_env}`)}</Badge>
          )}

          {app.memory_bytes === undefined ? null : (
            <Badge tone="neutral">{formatBytes(app.memory_bytes, i18n.language)}</Badge>
          )}

          <Badge tone={app.site_id === null ? "neutral" : "accent"}>
            {app.site_id === null ? t("apps.notPublished") : t("apps.published")}
          </Badge>

          <AppActions app={app} />
        </div>
      </CardBody>
    </Card>
  );
}

function AppActions({ app }: { app: AppView }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [showLogs, setShowLogs] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["apps"] });

  const restart = useMutation({
    mutationFn: () => endpoints.restartApp(app.id),
    onSuccess: invalidate,
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const remove = useMutation({
    mutationFn: () => endpoints.deleteApp(app.id),
    onSuccess: () => {
      setConfirming(false);
      invalidate();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setShowLogs(true)}>
        <ScrollText className="h-3.5 w-3.5" aria-hidden />
        {t("apps.logs")}
      </Button>

      <Button
        variant="ghost"
        size="sm"
        onClick={() => restart.mutate()}
        disabled={restart.isPending}
      >
        {restart.isPending ? <Spinner /> : <RotateCw className="h-3.5 w-3.5" aria-hidden />}
        {t("apps.restart")}
      </Button>

      <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
        <Trash2 className="h-3.5 w-3.5" aria-hidden />
        {t("apps.delete")}
      </Button>

      <LogsDialog app={app} open={showLogs} onClose={() => setShowLogs(false)} />

      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t("apps.deleteTitle", { name: app.name })}
        description={t("apps.deleteHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" onClick={() => remove.mutate()} disabled={remove.isPending}>
              {remove.isPending ? <Spinner /> : null}
              {t("apps.deleteConfirm")}
            </Button>
          </>
        }
      >
        {/* Deleting an app deliberately leaves its vhost standing, so say so
            here rather than letting a domain start answering 502 unexplained. */}
        {app.site_id === null ? null : (
          <p className="text-sm text-ink-muted">{t("apps.deleteKeepsSite")}</p>
        )}
        {error ? (
          <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}
      </Dialog>
    </>
  );
}

function LogsDialog({
  app,
  open,
  onClose,
}: {
  app: AppView;
  open: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();

  const logs = useQuery({
    queryKey: ["app-logs", app.id],
    queryFn: () => endpoints.appLogs(app.id),
    enabled: open,
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("apps.logsTitle", { name: app.name })}
      description={t("apps.logsHint", { count: DEFAULT_LOG_LINES })}
      footer={
        <>
          <Button variant="ghost" onClick={() => void logs.refetch()} disabled={logs.isFetching}>
            {logs.isFetching ? <Spinner /> : <RotateCw className="h-3.5 w-3.5" aria-hidden />}
            {t("apps.refresh")}
          </Button>
          <Button variant="secondary" onClick={onClose}>
            {t("common.close")}
          </Button>
        </>
      }
    >
      <p dir="ltr" className="mb-2 truncate font-mono text-xs text-ink-subtle">
        {logs.data?.unit ?? app.unit}
      </p>

      {logs.isPending ? (
        <div className="flex justify-center py-10 text-ink-muted">
          <Spinner className="h-5 w-5" />
        </div>
      ) : logs.error ? (
        <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {logs.error instanceof ApiError ? logs.error.message : String(logs.error)}
        </p>
      ) : (
        <div className="max-h-[50vh] overflow-y-auto rounded-lg border border-border bg-canvas p-3 font-mono text-xs leading-relaxed">
          {(logs.data?.lines.length ?? 0) === 0 ? (
            <p className="text-ink-subtle">{t("apps.logsEmpty")}</p>
          ) : (
            logs.data!.lines.map((line, index) => (
              // Journal output is machine text: it stays LTR even on an RTL
              // page, and `break-all` keeps a long stack trace inside the box.
              <div
                key={`${index}-${line}`}
                dir="ltr"
                className="whitespace-pre-wrap break-all text-ink-muted"
              >
                {line}
              </div>
            ))
          )}
        </div>
      )}
    </Dialog>
  );
}

interface CreateForm {
  name: string;
  entry: string;
  node_env: NodeEnv;
  memory_mb: string;
  proxy_domain: string;
  env: { key: string; value: string }[];
}

/**
 * The entry path, checked the way the server checks it.
 *
 * A duplicate of the agent's rule on purpose, and only for the message: the
 * agent refuses traversal, absolute paths and anything systemd would read as
 * syntax in `ExecStart` (a space, a quote, `%`, `$`). Catching it here turns a
 * failed task into a red line under the field.
 */
export function entryProblem(raw: string): boolean {
  const value = raw.trim();
  if (value === "" || value.startsWith("/")) return true;
  if (value.split("/").includes("..")) return true;
  return /[\s"'`$%\\]/.test(value);
}

function CreateAppDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    control,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateForm>({
    defaultValues: {
      name: "",
      entry: "",
      node_env: "production",
      memory_mb: "",
      proxy_domain: "",
      env: [],
    },
  });

  const env = useFieldArray({ control, name: "env" });

  const submit = handleSubmit(async (values) => {
    setError(null);
    const body: CreateAppRequest = {
      name: values.name.trim(),
      entry: values.entry.trim(),
      node_env: values.node_env,
    };

    // A blank row is somebody who clicked "add" and changed their mind, not an
    // empty variable name — which the agent would refuse for the whole request.
    const declared = values.env
      .filter((pair) => pair.key.trim() !== "")
      .map((pair) => ({ key: pair.key.trim(), value: pair.value }));
    if (declared.length > 0) body.env = declared;

    if (values.memory_mb.trim() !== "") body.memory_mb = Number(values.memory_mb);
    if (values.proxy_domain.trim() !== "") body.proxy_domain = values.proxy_domain.trim();

    try {
      await endpoints.createApp(body);
      reset();
      onClose();
      void queryClient.invalidateQueries({ queryKey: ["apps"] });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("apps.create")}
      description={t("apps.createHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={() => void submit()} disabled={isSubmitting}>
            {isSubmitting ? <Spinner /> : null}
            {t("apps.create")}
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
        <Field label={t("apps.name")} htmlFor="app-name" error={errors.name?.message}>
          <Input
            id="app-name"
            dir="ltr"
            placeholder="blog"
            autoFocus
            aria-invalid={Boolean(errors.name)}
            {...register("name", {
              required: t("apps.nameRequired"),
              pattern: {
                // The server validates properly; this only catches the obvious
                // before a round trip.
                value: /^[a-z0-9][a-z0-9_-]{0,31}$/,
                message: t("apps.nameInvalid"),
              },
            })}
          />
        </Field>

        <Field label={t("apps.entry")} htmlFor="app-entry" error={errors.entry?.message}>
          <Input
            id="app-entry"
            dir="ltr"
            placeholder="apps/blog/server.js"
            aria-describedby="app-entry-hint"
            aria-invalid={Boolean(errors.entry)}
            {...register("entry", {
              required: t("apps.entryRequired"),
              validate: (value) => !entryProblem(value) || t("apps.entryInvalid"),
            })}
          />
        </Field>
        <p id="app-entry-hint" className="-mt-1 mb-3 text-xs text-ink-muted">
          {t("apps.entryHint")}
        </p>

        <Field label={t("apps.nodeEnv")} htmlFor="app-node-env">
          <Select id="app-node-env" {...register("node_env")}>
            <option value="production">{t("apps.envName.production")}</option>
            <option value="development">{t("apps.envName.development")}</option>
            <option value="test">{t("apps.envName.test")}</option>
          </Select>
        </Field>

        <Field label={t("apps.memory")} htmlFor="app-memory" error={errors.memory_mb?.message}>
          <Input
            id="app-memory"
            dir="ltr"
            inputMode="numeric"
            placeholder="512"
            aria-describedby="app-memory-hint"
            {...register("memory_mb", {
              validate: (value) =>
                value.trim() === "" || /^\d{1,7}$/.test(value.trim()) || t("apps.memoryInvalid"),
            })}
          />
        </Field>
        <p id="app-memory-hint" className="-mt-1 mb-3 text-xs text-ink-muted">
          {t("apps.memoryHint")}
        </p>

        <Field
          label={t("apps.proxyDomain")}
          htmlFor="app-proxy-domain"
          error={errors.proxy_domain?.message}
        >
          <Input
            id="app-proxy-domain"
            dir="ltr"
            placeholder="blog.example.com"
            aria-describedby="app-proxy-hint"
            {...register("proxy_domain", {
              validate: (value) =>
                value.trim() === "" ||
                /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(
                  value.trim(),
                ) ||
                t("apps.proxyDomainInvalid"),
            })}
          />
        </Field>
        <p id="app-proxy-hint" className="-mt-1 mb-4 text-xs text-ink-muted">
          {t("apps.proxyDomainHint")}
        </p>

        <fieldset className="mb-3">
          <legend className="block text-sm font-medium text-ink">{t("apps.env")}</legend>
          <p className="mt-0.5 mb-2 text-xs text-ink-muted">{t("apps.envHint")}</p>

          <ul className="space-y-2">
            {env.fields.map((field, index) => (
              <li key={field.id} className="flex items-center gap-2">
                <Input
                  dir="ltr"
                  className="flex-1"
                  aria-label={t("apps.envKey")}
                  placeholder="DATABASE_URL"
                  {...register(`env.${index}.key` as const)}
                />
                <Input
                  dir="ltr"
                  className="flex-1"
                  aria-label={t("apps.envValue")}
                  {...register(`env.${index}.value` as const)}
                />
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={t("apps.envRemove")}
                  onClick={() => env.remove(index)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </li>
            ))}
          </ul>

          <Button
            variant="outline"
            size="sm"
            className="mt-2"
            onClick={() => env.append({ key: "", value: "" })}
          >
            <Plus className="h-3.5 w-3.5" aria-hidden />
            {t("apps.envAdd")}
          </Button>
        </fieldset>

        {error ? (
          <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}
      </form>
    </Dialog>
  );
}
