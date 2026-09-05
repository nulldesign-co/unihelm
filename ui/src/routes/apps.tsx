import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Boxes, Plus, RotateCw, ScrollText, SlidersHorizontal, Trash2, X } from "lucide-react";
import { useState } from "react";
import { useFieldArray, useForm } from "react-hook-form";
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
import {
  ApiError,
  DEFAULT_LOG_LINES,
  endpoints,
  type AppMode,
  type AppRuntime,
  type AppView,
  type CreateAppRequest,
  type NodeEnv,
  type StackComponentView,
  type UnitState,
} from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import { cn, formatBytes } from "@/lib/utils";
// Imported rather than re-derived. "Is there a container runtime on this
// machine" has one answer and one set of edge cases — an unmanaged Docker
// counts — and a second copy of that rule here is a second copy to get wrong.
import { dockerReady } from "@/routes/stack";

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

/**
 * Where one application's process actually lives.
 *
 * Absent means the host, and that read is load-bearing rather than tidy: every
 * app made before containers existed is a systemd unit on this server, and an
 * agent older than this field sends no `mode` at all. Reading the gap as
 * "container" would tell an operator to look in `docker logs` for a journal,
 * and put "In a container" on a row that is nothing of the kind.
 */
export function modeOf(app: AppView): AppMode {
  return app.mode === "container" ? "container" : "host";
}

/**
 * Whether the chosen mode cannot start on this server as it is.
 *
 * A container needs a container runtime, and there is no point letting somebody
 * fill in a form whose only possible ending is a red task saying Docker is not
 * installed. The Stack page is where that is fixed, so the callout points there.
 *
 * `undefined` components mean the catalogue has not answered — a dialog opened
 * before the query landed, or an agent that is offline. That is not the same
 * answer as "no Docker", and treating it as one would disable Create on a
 * machine that has been running containers all along. Unknown lets the click
 * through and the agent gives the real answer.
 */
export function modeUnavailable(
  mode: AppMode,
  components: readonly StackComponentView[] | undefined,
): boolean {
  return mode === "container" && components !== undefined && !dockerReady(components);
}

/**
 * The state, narrowed to one this build knows how to name.
 *
 * `state` is a bare string on the wire and a container has more ways to be
 * not-running than systemd does — `exited`, `created`, `restarting`. An
 * unrecognised one reached both the tone table and `t()` unguarded, which is a
 * badge with no colour reading `service.exited` at a customer.
 *
 * `unknown` is the one honest answer for a state this build cannot read, and it
 * is deliberately not `active`: a container that died on its first second must
 * never come back up this page reading "Running".
 *
 * `Object.hasOwn` rather than `in`, because `in` walks the prototype and would
 * wave `constructor` and `toString` through as states.
 */
export function unitState(state: string): UnitState {
  return Object.hasOwn(TONE, state) ? (state as UnitState) : "unknown";
}

/**
 * Whether this page can offer a version to pin, for an app running this way.
 *
 * Two separate reasons it cannot, and they are not the same reason:
 *
 * - **Go is compiled.** The entry file is the program; there is no interpreter.
 * - **A container's version is its image tag**, and the only list this page has
 *   is `runtime.list` — the interpreters installed on *this server*, which is
 *   the wrong list twice over. Offering it would pin a host Node 22 onto an app
 *   that runs from an image, and on a Docker-only machine it is empty, so the
 *   dialog would answer "no version is installed — install one from the
 *   Runtimes page" to somebody whose app needs nothing installed here at all.
 *   Installing something on a live host because this panel advised it is the
 *   shape of the outage this project has already had. Until the agent can
 *   report the tags an image actually has, the honest control is no control.
 */
export function offersVersion(mode: AppMode, runtime: AppRuntime): boolean {
  return mode === "host" && runtime !== "go";
}

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
      <PageHeader
        title={t("apps.title")}
        description={t("apps.subtitle")}
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" aria-hidden />
            {t("apps.create")}
          </Button>
        }
      />

      {apps.isPending ? (
        <ListSkeleton />
      ) : (apps.data?.apps.length ?? 0) === 0 ? (
        <EmptyState
          icon={<Boxes aria-hidden />}
          title={t("apps.empty")}
          hint={t("apps.emptyHint")}
          action={
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" aria-hidden />
              {t("apps.create")}
            </Button>
          }
        />
      ) : (
        <Card>
          <ul className="divide-y divide-border">
            {apps.data!.apps.map((app, index) => (
              // The hover tint lives on the <li> rather than inside AppRow so
              // the first and last rows can round with the card they sit in;
              // the card cannot clip them itself without also clipping the
              // row's ⋯ popover, which is rendered inline.
              <li
                key={app.id}
                className={
                  "animate-rise-in stagger transition-colors duration-150 " +
                  "first:rounded-t-card last:rounded-b-card hover:bg-surface-muted/60"
                }
                style={staggerStyle(index)}
              >
                <AppRow app={app} />
              </li>
            ))}
          </ul>
        </Card>
      )}

      <CreateAppDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}

function AppRow({ app }: { app: AppView }) {
  const { t, i18n } = useTranslation();
  const state = unitState(app.state);

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-3 px-5 py-4">
      <Badge tone={TONE[state]} dot={state === "activating" || state === "deactivating"}>
        {/* systemd's states are already named on the dashboard; one vocabulary
            for "running" across the panel beats two that nearly agree. */}
        {t(`service.${state}`)}
      </Badge>

      <div className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium text-ink">{app.name}</span>
        {/* How it runs sits on the entry line rather than among the badges. It
            is a standing fact about the app, not news: given a badge of its own
            it would carry the same weight as the state, which is the one thing
            on this row worth looking at twice. The path keeps the title as well
            as the truncation — it is still the longest thing here — and the
            mode keeps its full width, because a truncated mode says nothing. */}
        <p className="flex items-baseline gap-1.5 text-xs text-ink-subtle">
          <span className="min-w-0 truncate font-mono" title={app.entry}>
            {app.entry}
          </span>
          <span aria-hidden>·</span>
          <span className="shrink-0">{t(`apps.modeName.${modeOf(app)}`)}</span>
        </p>
      </div>

      {/* Facts and actions travel together: below `sm` they take a line of
          their own under the name instead of ragging four pills and a button
          across three. */}
      <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
        {/* The label and the number are separate children so the badge's own
            gap spaces them. */}
        <Badge tone="neutral">
          <span>{t("apps.port")}</span>
          <span className="tnum">{app.port}</span>
        </Badge>

        {/* Production is the default and the boring case; the other two are
            worth flagging, because a hosted app in `development` leaks stack
            traces to the internet. */}
        {app.runtime && app.runtime !== "node" ? (
          <Badge tone="neutral">{runtimeLabel(app.runtime)}</Badge>
        ) : null}
        {app.node_env === "production" ? null : (
          <Badge tone="warning">{t(`apps.envName.${app.node_env}`)}</Badge>
        )}

        {app.memory_bytes === undefined ? null : (
          // Memory re-polls every 3s while an app is activating; tabular
          // figures keep the badge from breathing as the number lands.
          <Badge tone="neutral" className="tnum">
            {formatBytes(app.memory_bytes, i18n.language)}
          </Badge>
        )}

        <Badge tone={app.site_id === null ? "neutral" : "accent"}>
          {app.site_id === null ? t("apps.notPublished") : t("apps.published")}
        </Badge>

        <div className="ms-auto flex shrink-0 items-center gap-1 sm:ms-1">
          <AppActions app={app} />
        </div>
      </div>
    </div>
  );
}

function AppActions({ app }: { app: AppView }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [showLogs, setShowLogs] = useState(false);
  const [changingRuntime, setChangingRuntime] = useState(false);
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
      {/* Restart is the only one of the three worth keeping in the open: it is
          the action with a result to watch, and a spinner inside a menu that
          closes on click is no feedback at all. */}
      <Button variant="ghost" size="sm" loading={restart.isPending} onClick={() => restart.mutate()}>
        <RotateCw className="h-3.5 w-3.5" aria-hidden />
        {t("apps.restart")}
      </Button>

      <Menu label={t("files.actions")}>
        <MenuItem icon={<ScrollText aria-hidden />} onClick={() => setShowLogs(true)}>
          {t("apps.logs")}
        </MenuItem>
        <MenuItem
          icon={<SlidersHorizontal aria-hidden />}
          onClick={() => setChangingRuntime(true)}
        >
          {t("apps.changeRuntime")}
        </MenuItem>
        <MenuSeparator />
        <MenuItem danger icon={<Trash2 aria-hidden />} onClick={() => setConfirming(true)}>
          {t("apps.delete")}
        </MenuItem>
      </Menu>

      <LogsDialog app={app} open={showLogs} onClose={() => setShowLogs(false)} />

      <RuntimeDialog
        app={app}
        open={changingRuntime}
        onClose={() => setChangingRuntime(false)}
      />

      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t("apps.deleteTitle", { name: app.name })}
        // "its unit is removed" is not what happens to a container, and the
        // half of this sentence that matters — the files stay — is the half an
        // operator most needs to believe before pressing a red button.
        description={t(`apps.deleteHint.${modeOf(app)}`)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
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
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}
      </Dialog>
    </>
  );
}

/**
 * Change which runtime and version an application runs on.
 *
 * Three decisions worth stating, because each is a place this could mislead:
 *
 * 1. **The restart is announced before the button, not after it.** Re-rendering
 *    the unit and restarting means seconds of connection refused, and an
 *    operator who learns that from their monitoring rather than from this dialog
 *    has been ambushed.
 * 2. **The version list is what the server actually has.** Read from
 *    `runtime.list` rather than typed, because the operation refuses a version
 *    that is not installed — offering a free-text box would be inviting a
 *    failure the page could have prevented.
 * 3. **Go takes no version, and neither does a container.** For Go the entry
 *    file is the program and there is no interpreter to point at. For a
 *    container the version is the image's tag, and the only list this page has
 *    is what is installed on *this server* — see `offersVersion`. Either way
 *    the control disappears rather than showing a list that is wrong.
 * 4. **There is no control for where it runs.** `app.update` changes the
 *    language and the version of the app it is given; it does not move one
 *    between a container and the host, and a select offering both would be a
 *    migration this panel cannot perform — discovered after the restart warning
 *    above, by a refusal. The dialog states which it is instead, so the
 *    question is answered where it is asked. If moving ever lands in the agent,
 *    this is the sentence that becomes a chooser.
 */
function RuntimeDialog({
  app,
  open,
  onClose,
}: {
  app: AppView;
  open: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [runtime, setRuntime] = useState<AppRuntime>(app.runtime ?? "node");
  const [version, setVersion] = useState<string>(app.runtime_version ?? "");
  const [error, setError] = useState<string | null>(null);

  const mode = modeOf(app);
  const versioned = offersVersion(mode, runtime);

  // Only asked for while the dialog is open and only when there is a version
  // control to fill: it shells out to every interpreter on the machine, which
  // is cheap but not free, and a container app has no use for the answer.
  const runtimes = useQuery({
    queryKey: ["runtimes"],
    queryFn: () => endpoints.runtimes(),
    enabled: open && versioned,
  });

  const available = (runtimes.data?.runtimes ?? []).filter((r) => r.runtime === runtime);

  const save = useMutation({
    mutationFn: () =>
      endpoints.updateAppRuntime(app.id, {
        runtime,
        // An empty selection is "unpin", which the API spells as an explicit
        // null — undefined would mean "leave the pin alone" and the two must
        // not collapse. Where no version was offered we send neither: an
        // explicit null here would silently unpin a container's image tag
        // because this dialog had no control for it.
        ...(versioned ? { runtime_version: version === "" ? null : version } : {}),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["apps"] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("apps.changeRuntime")}
      description={t("apps.changeRuntimeHint", { name: app.name })}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button loading={save.isPending} onClick={() => save.mutate()}>
            {t("apps.changeRuntimeConfirm")}
          </Button>
        </>
      }
    >
      {error ? (
        <Callout tone="danger" className="mb-3">
          {error}
        </Callout>
      ) : null}

      {/* Mode-keyed, because the reassurance in the second half is not the same
          fact: a host app falls back on a version that is not installed, and a
          container app on an image that cannot be pulled. */}
      <Callout tone="info" className="mb-4">
        {t(`apps.changeRuntimeRestart.${mode}`)}
      </Callout>

      <Field label={t("apps.runtime")} htmlFor="change-runtime">
        <Select
          id="change-runtime"
          value={runtime}
          onChange={(e) => {
            setRuntime(e.target.value as AppRuntime);
            // The version belonged to the old runtime, and carrying it over
            // would send Node's 22.14.0 to Python.
            setVersion("");
          }}
        >
          <option value="node">Node.js</option>
          <option value="python">Python</option>
          <option value="ruby">Ruby</option>
          <option value="bun">Bun</option>
          <option value="deno">Deno</option>
          <option value="go">Go</option>
        </Select>
      </Field>

      {!versioned ? (
        // Two different reasons for the same missing control, and an operator
        // deserves the one that applies: a container's version rides on its
        // image, a Go program has no interpreter at all. The container sentence
        // is checked first because it is true whatever the language.
        <p className="mt-3 text-xs text-ink-muted">
          {mode === "container" ? t("apps.imageVersion") : t("apps.compiledNoVersion")}
        </p>
      ) : (
        <>
          <div className="mt-3">
          <Field label={t("apps.version")} htmlFor="change-version">
            <Select
              id="change-version"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
            >
              <option value="">{t("apps.versionDefault")}</option>
              {available.map((r) => (
                <option key={r.path} value={r.version}>
                  {r.version}
                  {r.is_default ? ` — ${t("apps.versionIsDefault")}` : ""}
                </option>
              ))}
            </Select>
          </Field>
          </div>
          <p className="mt-1 text-xs text-ink-muted">
            {available.length === 0 && !runtimes.isLoading
              ? t("apps.versionNoneInstalled")
              : t("apps.versionHint")}
          </p>
        </>
      )}

      {/* Last, under the choice it qualifies: whatever is picked above, this app
          keeps running where it already runs. */}
      <p className="mt-3 text-xs text-ink-muted">{t(`apps.modeStays.${modeOf(app)}`)}</p>
    </Dialog>
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
  // Naming the wrong source is the specific mistake this whole change exists to
  // stop: an operator told these are journal lines goes to `journalctl -u` for
  // a container that has no unit, finds nothing, and concludes the app is fine.
  const mode = modeOf(app);

  const logs = useQuery({
    queryKey: ["app-logs", app.id],
    queryFn: () => endpoints.appLogs(app.id),
    enabled: open,
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title={t("apps.logsTitle", { name: app.name })}
      description={t(`apps.logsHint.${mode}`, { count: DEFAULT_LOG_LINES })}
      footer={
        <>
          <Button variant="ghost" loading={logs.isFetching} onClick={() => void logs.refetch()}>
            <RotateCw className="h-3.5 w-3.5" aria-hidden />
            {t("apps.refresh")}
          </Button>
          <Button variant="secondary" onClick={onClose}>
            {t("common.close")}
          </Button>
        </>
      }
    >
      <p className="mb-2 truncate font-mono text-xs text-ink-subtle">
        {logs.data?.unit ?? app.unit}
      </p>

      {logs.isPending ? (
        <div className="space-y-2 rounded-lg border border-border bg-canvas p-3">
          <Skeleton className="h-3 w-full" />
          <Skeleton className="h-3 w-5/6" />
          <Skeleton className="h-3 w-2/3" />
          <Skeleton className="h-3 w-3/4" />
        </div>
      ) : logs.error ? (
        <Callout tone="danger">
          {logs.error instanceof ApiError ? logs.error.message : String(logs.error)}
        </Callout>
      ) : (
        <div
          aria-busy={logs.isFetching || undefined}
          className={cn(
            "max-h-[50vh] overflow-y-auto rounded-lg border border-border bg-canvas p-3 font-mono text-xs leading-relaxed",
            // A refetch replaces every line in one frame. Fading the panel out
            // and back is what tells the reader the text they were part-way
            // through is no longer the same text.
            "transition-opacity duration-150",
            logs.isFetching && "opacity-50",
          )}
        >
          {(logs.data?.lines.length ?? 0) === 0 ? (
            // No second dashed border inside the log panel's own box, and back
            // to the UI face — the mono is for machine lines, not for prose.
            <EmptyState
              className="border-0 px-2 py-8 font-sans"
              icon={<ScrollText aria-hidden />}
              title={t(`apps.logsEmpty.${mode}`)}
            />
          ) : (
            logs.data!.lines.map((line, index) => (
              // Log output is machine text; `break-all` keeps a long stack
              // trace inside the box.
              <div key={`${index}-${line}`} className="whitespace-pre-wrap break-all text-ink-muted">
                {line}
              </div>
            ))
          )}
        </div>
      )}
    </Dialog>
  );
}

/** `Node.js`, not `node`. Mirrors AppRuntime::label on the agent. */
function runtimeLabel(runtime: AppRuntime): string {
  const names: Record<AppRuntime, string> = {
    node: "Node.js",
    python: "Python",
    ruby: "Ruby",
    bun: "Bun",
    deno: "Deno",
    go: "Go",
  };
  return names[runtime];
}

interface CreateForm {
  name: string;
  entry: string;
  runtime: AppRuntime;
  mode: AppMode;
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
    watch,
    formState: { errors, isSubmitting },
  } = useForm<CreateForm>({
    defaultValues: {
      name: "",
      entry: "",
      runtime: "node",
      // A container is the default for a new app, which is the point of the
      // move: what it runs on comes from an image rather than from whatever
      // this server happens to have installed this week.
      mode: "container",
      node_env: "production",
      memory_mb: "",
      proxy_domain: "",
      env: [],
    },
  });

  const env = useFieldArray({ control, name: "env" });
  const mode = watch("mode");

  // Only while the dialog is open, and shared with the Stack page's own cache —
  // the question is small and the answer is the same one that page renders.
  const stack = useQuery({
    queryKey: ["stack"],
    queryFn: endpoints.stack,
    enabled: open,
    staleTime: 60_000,
  });

  const unavailable = modeUnavailable(mode, stack.data?.components);

  const submit = handleSubmit(async (values) => {
    setError(null);
    // The footer button is disabled for this, but Enter in any field submits
    // the form and never touches it. The callout explaining it is already on
    // screen, so there is nothing to say here that is not already said.
    if (modeUnavailable(values.mode, stack.data?.components)) return;
    const body: CreateAppRequest = {
      name: values.name.trim(),
      entry: values.entry.trim(),
      node_env: values.node_env,
      runtime: values.runtime,
      // Sent whichever way it is set, including the one that matches the
      // agent's own default. The form showed a choice and somebody may have
      // left it where it was on purpose; letting the request fall back to a
      // default is how "In a container" on screen becomes a unit on the host
      // the first time the two defaults drift apart.
      mode: values.mode,
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
          <Button
            variant="primary"
            loading={isSubmitting}
            // A container on a server with no Docker is a click whose only
            // ending is a red task. The callout at the mode field says so and
            // says what to do about it; this stops the round trip.
            disabled={unavailable}
            onClick={() => void submit()}
          >
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

        {/* After the entry field, not before it: the entry is what people came
            to type, and asking for the language first makes the common case —
            Node, the default — answer a question nobody had. */}
        <Field label={t("apps.runtime")} htmlFor="app-runtime">
          <Select id="app-runtime" {...register("runtime")}>
            <option value="node">Node.js</option>
            <option value="python">Python</option>
            <option value="ruby">Ruby</option>
            <option value="bun">Bun</option>
            <option value="deno">Deno</option>
            <option value="go">Go</option>
          </Select>
        </Field>
        <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("apps.runtimeHint")}</p>

        {/* Directly under the language, because the two answer one question
            between them: what it runs on, and where that comes from. */}
        <Field label={t("apps.mode")} htmlFor="app-mode">
          <Select id="app-mode" aria-describedby="app-mode-hint" {...register("mode")}>
            <option value="container">{t("apps.modeName.container")}</option>
            <option value="host">{t("apps.modeName.host")}</option>
          </Select>
        </Field>
        {/* One sentence, and it changes with the choice: a hint describing both
            modes at once is one nobody reads far enough into to learn which of
            them they are about to get. */}
        <p id="app-mode-hint" className="-mt-1 mb-3 text-xs text-ink-muted">
          {t(`apps.modeHint.${mode}`)}
        </p>

        {/* Before the rest of the form rather than beside the disabled button:
            this is the answer to "why can I not create this", and it belongs at
            the control that caused it. */}
        {unavailable ? (
          <Callout
            tone="warning"
            className="mb-3"
            title={t("apps.dockerNeededTitle")}
            action={
              <Link
                to="/stack"
                className="font-medium text-accent transition-colors hover:underline"
              >
                {t("apps.dockerNeededLink")}
              </Link>
            }
          >
            {t("apps.dockerNeeded")}
          </Callout>
        ) : null}

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

          {env.fields.length === 0 ? (
            // Without this the fieldset is a legend, a hint and a lone "Add"
            // button with nothing between them to say what would go there.
            <EmptyState className="px-4 py-6" title={t("apps.envEmpty")} />
          ) : (
            <ul className="space-y-2">
              {/* No stagger on these: rows appear one at a time because the
                  operator clicked Add, and a delay on the row they just asked
                  for reads as lag. */}
              {env.fields.map((field, index) => (
                <li key={field.id} className="flex animate-pop-in items-center gap-2">
                  <Input
                    className="flex-1 font-mono text-xs"
                    aria-label={t("apps.envKey")}
                    placeholder="DATABASE_URL"
                    {...register(`env.${index}.key` as const)}
                  />
                  <Input
                    className="flex-1 font-mono text-xs"
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
          )}

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
          <Callout tone="danger" className="mt-3">
            {error}
          </Callout>
        ) : null}
      </form>
    </Dialog>
  );
}
