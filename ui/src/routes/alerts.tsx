import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BellRing,
  CheckCircle2,
  Plus,
  Send,
  ShieldCheck,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import {
  ApiError,
  endpoints,
  type AlertEvent,
  type AlertKind,
  type AlertRule,
  type ChannelKind,
  type ChannelRequest,
  type ChannelTestResult,
  type NotifyChannel,
} from "@/lib/api";

/**
 * Alerting (spec §11.11).
 *
 * Three things this page refuses to fudge:
 *
 * 1. **An event is a span, not a notification.** The server records
 *    `raised_at`/`resolved_at` precisely so a disk sitting at 90% produces one
 *    row and not one row a minute; rendering that history as a flat feed would
 *    throw away the only fact an operator actually wants — how long it lasted.
 * 2. **A channel's secret is write-only.** The API never returns it, so the
 *    edit form shows "configured" rather than an empty box. An empty box reads
 *    as data the panel lost, and the operator re-pastes a token they never
 *    needed to touch.
 * 3. **A failed test is an answer.** `delivered: false` with a reason is a 200,
 *    and it is rendered as a result, not as an error.
 */
export function AlertsPage() {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <PageHeader title={t("alerts.title")} description={t("alerts.subtitle")} />

      <RulesCard />
      <HistoryCard />
      <ChannelsCard />
    </div>
  );
}

function errorText(error: unknown): string {
  return error instanceof ApiError ? error.message : String(error);
}

/** Ghost rows shaped like the list they stand in for, inside a card body. */
function RowsSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite" className="space-y-4">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-3">
          <Skeleton className="h-6 w-16 rounded-full" />
          <div className="min-w-0 flex-1 space-y-1.5">
            <Skeleton className="h-3.5 w-1/3" />
            <Skeleton className="h-3 w-1/2" />
          </div>
          <Skeleton className="h-8 w-16 rounded-lg" />
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

/** Every kind's threshold bounds, matching `validate_rule` in the agent. */
const BOUNDS: Record<Exclude<AlertKind, "service_down">, [number, number]> = {
  disk_pct: [1, 100],
  mem_pct: [1, 100],
  // Beyond 89 days a cert rule fires the instant a 90-day certificate is
  // issued, which is not a warning, it is a stuck horn.
  cert_expiry_days: [1, 89],
  load: [0.1, 1000],
};

/** Units the agent's `service_target` accepts, minus the `php_fpm:<version>` form. */
export const SERVICE_TARGETS = [
  "nginx",
  "mariadb",
  "postgresql",
  "kv_store",
  "docker",
  "sshd",
  "unihelm_web",
  "unihelm_agentd",
] as const;

export type RuleProblem =
  | "target_required"
  | "target_not_a_mount"
  | "target_not_allowed"
  | "threshold_required"
  | "threshold_range";

/**
 * The rule form's checks, in step with `validate_rule` in the agent.
 *
 * A `disk_pct` rule saved at 0 fires on every filesystem on the machine the
 * moment it is stored and never stops — the alert-fatigue failure the whole
 * module is written to avoid. The agent refuses it; this only says so sooner.
 */
export function ruleProblem(kind: AlertKind, target: string, threshold: string): RuleProblem | null {
  const subject = target.trim();

  if (kind === "service_down") {
    if (subject === "") return "target_required";
    // A boolean rule: the server stores a sentinel threshold, so the form does
    // not ask for one.
    return null;
  }
  if (kind === "disk_pct" && subject !== "" && !subject.startsWith("/")) {
    return "target_not_a_mount";
  }
  if ((kind === "mem_pct" || kind === "load") && subject !== "") return "target_not_allowed";

  if (threshold.trim() === "") return "threshold_required";
  const value = Number(threshold.trim());
  if (!Number.isFinite(value)) return "threshold_range";
  const [low, high] = BOUNDS[kind];
  return value < low || value > high ? "threshold_range" : null;
}

function RulesCard() {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<AlertRule | "new" | null>(null);

  const rules = useQuery({ queryKey: ["alert-rules"], queryFn: endpoints.alertRules });

  const openByRule = new Map<number, AlertEvent[]>();
  for (const event of rules.data?.open ?? []) {
    const list = openByRule.get(event.rule_id) ?? [];
    list.push(event);
    openByRule.set(event.rule_id, list);
  }

  return (
    <Card>
      <CardHeader
        title={t("alerts.rules.title")}
        description={t("alerts.rules.hint")}
        action={
          <Button variant="primary" size="sm" onClick={() => setEditing("new")}>
            <Plus className="h-3.5 w-3.5" aria-hidden />
            {t("alerts.rules.add")}
          </Button>
        }
      />
      <CardBody>
        {rules.isPending ? (
          <RowsSkeleton />
        ) : rules.error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {errorText(rules.error)}
          </p>
        ) : rules.data!.rules.length === 0 ? (
          <EmptyState
            icon={<BellRing aria-hidden />}
            title={t("alerts.rules.empty")}
            hint={t("alerts.rules.emptyHint")}
            action={
              <Button variant="primary" size="sm" onClick={() => setEditing("new")}>
                <Plus className="h-3.5 w-3.5" aria-hidden />
                {t("alerts.rules.add")}
              </Button>
            }
          />
        ) : (
          <ul className="divide-y divide-border">
            {rules.data!.rules.map((rule) => (
              <RuleRow
                key={rule.id}
                rule={rule}
                open={openByRule.get(rule.id) ?? []}
                onEdit={() => setEditing(rule)}
              />
            ))}
          </ul>
        )}
      </CardBody>

      {editing ? (
        <RuleDialog
          rule={editing === "new" ? null : editing}
          kinds={rules.data?.kinds ?? []}
          onClose={() => setEditing(null)}
        />
      ) : null}
    </Card>
  );
}

function RuleRow({
  rule,
  open,
  onEdit,
}: {
  rule: AlertRule;
  open: AlertEvent[];
  onEdit: () => void;
}) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const toggle = useMutation({
    mutationFn: (enabled: boolean) =>
      endpoints.setAlertRule({
        kind: rule.kind,
        target: rule.target,
        // `service_down` carries a sentinel threshold the server settles on its
        // own; sending the stored value back is harmless and keeps this a
        // single code path.
        threshold: rule.threshold,
        enabled,
      }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["alert-rules"] }),
    onError: (e) => setError(errorText(e)),
  });

  const number = new Intl.NumberFormat(i18n.language, { maximumFractionDigits: 2 });

  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-2 py-3 first:pt-0 last:pb-0">
      {open.length > 0 ? (
        <Badge tone="danger" dot>
          {t("alerts.rules.firing")}
        </Badge>
      ) : rule.enabled ? (
        <Badge tone="success" dot>
          {t("alerts.rules.armed")}
        </Badge>
      ) : (
        <Badge tone="neutral">{t("alerts.rules.off")}</Badge>
      )}

      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium text-ink">{t(`alerts.kind.${rule.kind}`)}</p>
        <p className="truncate font-mono text-xs text-ink-subtle">
          {rule.target ?? t("alerts.rules.everySubject")}
        </p>
      </div>

      {rule.kind === "service_down" ? null : (
        <Badge tone="neutral">
          <span>{t("alerts.rules.threshold")}</span>
          <span className="tabular-nums">
            {number.format(rule.threshold)}
            {t(`alerts.unit.${rule.kind}`)}
          </span>
        </Badge>
      )}

      {open.length > 0 ? (
        <p className="w-full text-xs text-danger">
          {open.map((event) => event.message).join(" · ")}
        </p>
      ) : null}

      <Switch
        checked={rule.enabled}
        onChange={(enabled) => toggle.mutate(enabled)}
        disabled={toggle.isPending}
        label={t("alerts.rules.enabled")}
      />

      <Button variant="ghost" size="sm" onClick={onEdit}>
        {t("alerts.rules.edit")}
      </Button>

      {error ? (
        <p role="alert" className="w-full text-xs text-danger">
          {error}
        </p>
      ) : null}
    </li>
  );
}

function RuleDialog({
  rule,
  kinds,
  onClose,
}: {
  rule: AlertRule | null;
  kinds: AlertKind[];
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const [kind, setKind] = useState<AlertKind>(rule?.kind ?? kinds[0] ?? "disk_pct");
  const [target, setTarget] = useState(rule?.target ?? "");
  const [threshold, setThreshold] = useState(rule ? String(rule.threshold) : "");
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);

  const problem = ruleProblem(kind, target, threshold);

  const save = useMutation({
    mutationFn: () =>
      endpoints.setAlertRule({
        kind,
        target: target.trim() === "" ? null : target.trim(),
        ...(kind === "service_down" ? {} : { threshold: Number(threshold.trim()) }),
        enabled,
      }),
    onSuccess: () => {
      onClose();
      void queryClient.invalidateQueries({ queryKey: ["alert-rules"] });
    },
    onError: (e) => setError(errorText(e)),
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title={rule ? t("alerts.rules.editTitle") : t("alerts.rules.add")}
      // `(kind, target)` is the rule's identity on the server, so saving the
      // same pair edits the existing rule rather than adding a second one that
      // would notify twice for one full disk.
      description={t("alerts.rules.addHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={() => save.mutate()}
            disabled={save.isPending || problem !== null}
          >
            {save.isPending ? <Spinner /> : null}
            {t("alerts.rules.save")}
          </Button>
        </>
      }
    >
      <Field label={t("alerts.rules.kind")} htmlFor="alert-kind">
        <Select
          id="alert-kind"
          value={kind}
          // Editing the kind of an existing rule would create a second rule
          // rather than change this one, so it is fixed once saved.
          disabled={rule !== null}
          onChange={(event) => {
            setKind(event.target.value as AlertKind);
            setTarget("");
          }}
        >
          {(kinds.length > 0 ? kinds : (["disk_pct"] as AlertKind[])).map((option) => (
            <option key={option} value={option}>
              {t(`alerts.kind.${option}`)}
            </option>
          ))}
        </Select>
      </Field>

      <Field
        label={t("alerts.rules.target")}
        htmlFor="alert-target"
        error={
          problem === "target_required"
            ? t("alerts.rules.targetRequired")
            : problem === "target_not_a_mount"
              ? t("alerts.rules.targetNotAMount")
              : problem === "target_not_allowed"
                ? t("alerts.rules.targetNotAllowed", { kind: t(`alerts.kind.${kind}`) })
                : undefined
        }
      >
        {kind === "service_down" ? (
          <Select
            id="alert-target"
            value={target}
            disabled={rule !== null}
            onChange={(event) => setTarget(event.target.value)}
          >
            <option value="">{t("alerts.rules.pickService")}</option>
            {SERVICE_TARGETS.map((unit) => (
              <option key={unit} value={unit}>
                {unit}
              </option>
            ))}
          </Select>
        ) : (
          <Input
            id="alert-target"
            className="font-mono"
            disabled={rule !== null}
            placeholder={kind === "disk_pct" ? "/" : kind === "cert_expiry_days" ? "example.com" : ""}
            value={target}
            aria-describedby="alert-target-hint"
            aria-invalid={problem?.startsWith("target") ?? false}
            onChange={(event) => setTarget(event.target.value)}
          />
        )}
      </Field>
      <p id="alert-target-hint" className="-mt-1 mb-3 text-xs text-ink-muted">
        {t(`alerts.targetHint.${kind}`)}
      </p>

      {kind === "service_down" ? null : (
        <Field
          label={t("alerts.rules.threshold")}
          htmlFor="alert-threshold"
          error={
            problem === "threshold_required"
              ? t("alerts.rules.thresholdRequired")
              : problem === "threshold_range"
                ? t("alerts.rules.thresholdRange", {
                    low: BOUNDS[kind][0],
                    high: BOUNDS[kind][1],
                  })
                : undefined
          }
        >
          <Input
            id="alert-threshold"
            inputMode="decimal"
            value={threshold}
            aria-invalid={problem?.startsWith("threshold") ?? false}
            onChange={(event) => setThreshold(event.target.value)}
          />
        </Field>
      )}

      <Switch
        checked={enabled}
        onChange={setEnabled}
        label={t("alerts.rules.enabled")}
        description={t("alerts.rules.enabledHint")}
      />

      {error ? (
        <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

export interface EventSpan {
  event: AlertEvent;
  open: boolean;
  startedAt: Date;
  endedAt: Date | null;
  /** How long the condition held, in seconds; for an open span, so far. */
  seconds: number;
}

/**
 * Turn the event rows into spans, ongoing ones first.
 *
 * The server already models an event as a span — `raise_alert` is idempotent
 * while one is open — so the work here is only to compute how long each lasted
 * and to float the ones that have not ended yet. A flat, purely chronological
 * list would bury a firing alert under last week's resolved ones.
 */
export function toSpans(events: AlertEvent[], now: number): EventSpan[] {
  const spans = events.map((event) => {
    const startedAt = new Date(event.raised_at);
    const endedAt = event.resolved_at === null ? null : new Date(event.resolved_at);
    const end = endedAt?.getTime() ?? now;
    return {
      event,
      open: endedAt === null,
      startedAt,
      endedAt,
      // Clamped at zero: a clock that stepped backwards between the two
      // timestamps must not render a negative duration.
      seconds: Math.max(0, Math.round((end - startedAt.getTime()) / 1000)),
    };
  });

  return spans.sort((a, b) => {
    if (a.open !== b.open) return a.open ? -1 : 1;
    return b.startedAt.getTime() - a.startedAt.getTime();
  });
}

/** `3d 4h`, `4h 12m`, `12m`, `45s` — sub-minute matters when it resolved fast. */
export function formatSpan(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${seconds}s`;
}

function HistoryCard() {
  const { t, i18n } = useTranslation();

  const events = useQuery({
    queryKey: ["alert-events"],
    queryFn: () => endpoints.alertEvents(),
    refetchInterval: 30_000,
  });

  const dateFormat = new Intl.DateTimeFormat(i18n.language, {
    dateStyle: "medium",
    timeStyle: "short",
  });

  const spans = toSpans(events.data?.events ?? [], Date.now());
  const ongoing = spans.filter((span) => span.open).length;

  return (
    <Card>
      <CardHeader
        title={t("alerts.history.title")}
        description={t("alerts.history.hint")}
        action={
          ongoing > 0 ? (
            <Badge tone="danger" dot>
              {t("alerts.history.ongoing", { count: ongoing })}
            </Badge>
          ) : (
            <Badge tone="success" dot>
              {t("alerts.history.allClear")}
            </Badge>
          )
        }
      />
      <CardBody>
        {events.isPending ? (
          <RowsSkeleton />
        ) : events.error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {errorText(events.error)}
          </p>
        ) : spans.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck aria-hidden />}
            title={t("alerts.history.empty")}
            hint={t("alerts.history.emptyHint")}
          />
        ) : (
          <ul className="divide-y divide-border">
            {spans.map((span) => (
              <SpanRow key={span.event.id} span={span} dateFormat={dateFormat} />
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}

function SpanRow({ span, dateFormat }: { span: EventSpan; dateFormat: Intl.DateTimeFormat }) {
  const { t } = useTranslation();

  return (
    <li className="flex items-start gap-3 py-3 first:pt-0 last:pb-0">
      <span className="mt-0.5 shrink-0">
        {span.open ? (
          <TriangleAlert className="h-4 w-4 text-danger" aria-hidden />
        ) : (
          <CheckCircle2 className="h-4 w-4 text-success" aria-hidden />
        )}
      </span>

      <div className="min-w-0 flex-1">
        <p className="text-sm text-ink">{span.event.message}</p>
        {/* The span itself: when it started, when it ended (or that it has
            not), and how long that was. This line is the whole reason the
            history is not a list of notifications. */}
        <p className="mt-0.5 text-xs text-ink-muted">
          {span.open
            ? t("alerts.history.since", {
                at: dateFormat.format(span.startedAt),
                duration: formatSpan(span.seconds),
              })
            : t("alerts.history.span", {
                from: dateFormat.format(span.startedAt),
                to: dateFormat.format(span.endedAt!),
                duration: formatSpan(span.seconds),
              })}
        </p>
      </div>

      <div className="flex shrink-0 flex-col items-end gap-1">
        <Badge tone={span.open ? "danger" : "success"} dot={span.open}>
          {span.open ? t("alerts.history.open") : t("alerts.history.resolved")}
        </Badge>
        <span className="truncate font-mono text-xs text-ink-subtle">{span.event.subject}</span>
      </div>
    </li>
  );
}

// ---------------------------------------------------------------------------
// notifier channels
// ---------------------------------------------------------------------------

export interface ChannelForm {
  kind: ChannelKind;
  label: string;
  enabled: boolean;
  /** Webhook. */
  url: string;
  /** Telegram. */
  botToken: string;
  chatId: string;
}

export type ChannelProblem = "label" | "config";

/**
 * Build the write for a channel, honouring the one-way street the secret takes.
 *
 * The API never returns a channel's configuration, so on an edit an untouched
 * secret field means "keep what is stored" and the `config` key must be absent
 * from the body entirely. An explicit `null` there would read as "seal this"
 * and fail validation; an empty object would overwrite a working bot token with
 * nothing. This mirrors the agent's own contract (`ChannelsSetInput.config` is
 * `Option`, absent = keep).
 */
export function buildChannelRequest(
  form: ChannelForm,
  existing: NotifyChannel | null,
): { ok: true; request: ChannelRequest } | { ok: false; problem: ChannelProblem } {
  const label = form.label.trim();
  if (label === "") return { ok: false, problem: "label" };

  const url = form.url.trim();
  const botToken = form.botToken.trim();
  const chatId = form.chatId.trim();
  const touched = form.kind === "webhook" ? url !== "" : botToken !== "" || chatId !== "";

  let config: Record<string, string> | undefined;
  if (touched) {
    if (form.kind === "webhook") {
      config = { url };
    } else {
      // Both halves or neither: a bot token with no chat id is a channel that
      // cannot deliver, and the agent would refuse it a round trip later.
      if (botToken === "" || chatId === "") return { ok: false, problem: "config" };
      config = { bot_token: botToken, chat_id: chatId };
    }
  } else if (existing === null) {
    // A new channel has nothing stored to fall back on.
    return { ok: false, problem: "config" };
  }

  return {
    ok: true,
    request: {
      ...(existing ? { id: existing.id } : { kind: form.kind }),
      label,
      ...(config ? { config } : {}),
      enabled: form.enabled,
    },
  };
}

function ChannelsCard() {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<NotifyChannel | "new" | null>(null);

  const channels = useQuery({ queryKey: ["alert-channels"], queryFn: endpoints.channels });

  return (
    <Card>
      <CardHeader
        title={t("alerts.channels.title")}
        description={t("alerts.channels.hint")}
        action={
          <Button variant="primary" size="sm" onClick={() => setEditing("new")}>
            <Plus className="h-3.5 w-3.5" aria-hidden />
            {t("alerts.channels.add")}
          </Button>
        }
      />
      <CardBody>
        {channels.isPending ? (
          <RowsSkeleton />
        ) : channels.error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {errorText(channels.error)}
          </p>
        ) : channels.data!.channels.length === 0 ? (
          <EmptyState
            icon={<Send aria-hidden />}
            title={t("alerts.channels.empty")}
            hint={t("alerts.channels.emptyHint")}
            action={
              <Button variant="primary" size="sm" onClick={() => setEditing("new")}>
                <Plus className="h-3.5 w-3.5" aria-hidden />
                {t("alerts.channels.add")}
              </Button>
            }
          />
        ) : (
          <ul className="divide-y divide-border">
            {channels.data!.channels.map((channel) => (
              <ChannelRow key={channel.id} channel={channel} onEdit={() => setEditing(channel)} />
            ))}
          </ul>
        )}
      </CardBody>

      {editing ? (
        <ChannelDialog
          channel={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
        />
      ) : null}
    </Card>
  );
}

function ChannelRow({ channel, onEdit }: { channel: NotifyChannel; onEdit: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [result, setResult] = useState<ChannelTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  const test = useMutation({
    mutationFn: () => endpoints.testChannel(channel.id),
    // A refusal from the far end is a result, not a failure: the operator asked
    // "does this work?" and "no, it answered 403" answers that question.
    onSuccess: (data) => {
      setError(null);
      setResult(data);
    },
    onError: (e) => setError(errorText(e)),
  });

  const remove = useMutation({
    mutationFn: () => endpoints.deleteChannel(channel.id),
    onSuccess: () => {
      setConfirming(false);
      void queryClient.invalidateQueries({ queryKey: ["alert-channels"] });
    },
    onError: (e) => setError(errorText(e)),
  });

  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-2 py-3 first:pt-0 last:pb-0">
      <Badge tone={channel.enabled ? "success" : "neutral"} dot={channel.enabled}>
        {channel.enabled ? t("alerts.channels.on") : t("alerts.channels.off")}
      </Badge>

      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium text-ink">{channel.label}</p>
        <p className="truncate text-xs text-ink-subtle">{t(`alerts.channelKind.${channel.kind}`)}</p>
      </div>

      {/* "Configured", never the value. The API does not return the credential
          at all, so this badge is the only honest thing to show for it. */}
      <Badge tone="accent">{t("alerts.channels.configured")}</Badge>

      <Button variant="ghost" size="sm" onClick={() => test.mutate()} disabled={test.isPending}>
        {test.isPending ? <Spinner /> : <Send className="h-3.5 w-3.5" aria-hidden />}
        {t("alerts.channels.test")}
      </Button>

      <Button variant="ghost" size="sm" onClick={onEdit}>
        {t("alerts.channels.edit")}
      </Button>

      <Button
        variant="ghost"
        size="sm"
        className="text-danger hover:bg-danger-soft hover:text-danger"
        onClick={() => setConfirming(true)}
      >
        <Trash2 className="h-3.5 w-3.5" aria-hidden />
        {t("alerts.channels.delete")}
      </Button>

      {result ? (
        <p
          role="status"
          className={`w-full text-xs ${result.delivered ? "text-success" : "text-danger"}`}
        >
          {result.delivered
            ? t("alerts.channels.testOk")
            : t("alerts.channels.testFailed", { detail: result.detail ?? "" })}
        </p>
      ) : null}

      {error ? (
        <p role="alert" className="w-full text-xs text-danger">
          {error}
        </p>
      ) : null}

      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t("alerts.channels.deleteTitle", { label: channel.label })}
        description={t("alerts.channels.deleteHint")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" onClick={() => remove.mutate()} disabled={remove.isPending}>
              {remove.isPending ? <Spinner /> : null}
              {t("alerts.channels.delete")}
            </Button>
          </>
        }
      >
        <p className="text-sm text-ink-muted">{t("alerts.channels.deleteBody")}</p>
      </Dialog>
    </li>
  );
}

function ChannelDialog({
  channel,
  onClose,
}: {
  channel: NotifyChannel | null;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const [form, setForm] = useState<ChannelForm>({
    kind: channel?.kind ?? "webhook",
    label: channel?.label ?? "",
    enabled: channel?.enabled ?? true,
    url: "",
    botToken: "",
    chatId: "",
  });
  const [error, setError] = useState<string | null>(null);

  const built = buildChannelRequest(form, channel);

  const save = useMutation({
    mutationFn: () => {
      if (!built.ok) throw new Error("blocked by validation");
      return endpoints.setChannel(built.request);
    },
    onSuccess: () => {
      onClose();
      void queryClient.invalidateQueries({ queryKey: ["alert-channels"] });
    },
    onError: (e) => setError(errorText(e)),
  });

  const patch = (change: Partial<ChannelForm>) => setForm((current) => ({ ...current, ...change }));

  return (
    <Dialog
      open
      onClose={onClose}
      title={channel ? t("alerts.channels.editTitle") : t("alerts.channels.add")}
      description={t("alerts.channels.addHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={() => save.mutate()}
            disabled={save.isPending || !built.ok}
          >
            {save.isPending ? <Spinner /> : null}
            {t("alerts.channels.save")}
          </Button>
        </>
      }
    >
      <Field label={t("alerts.channels.kind")} htmlFor="channel-kind">
        <Select
          id="channel-kind"
          value={form.kind}
          // The server refuses a kind change outright: reinterpreting a stored
          // Telegram config as a webhook would POST a bot token at somebody's
          // URL. So the field is fixed once the channel exists.
          disabled={channel !== null}
          onChange={(event) => patch({ kind: event.target.value as ChannelKind })}
        >
          <option value="webhook">{t("alerts.channelKind.webhook")}</option>
          <option value="telegram">{t("alerts.channelKind.telegram")}</option>
        </Select>
      </Field>
      {channel ? (
        <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("alerts.channels.kindFixed")}</p>
      ) : null}

      <Field
        label={t("alerts.channels.label")}
        htmlFor="channel-label"
        error={!built.ok && built.problem === "label" ? t("alerts.channels.labelRequired") : undefined}
      >
        <Input
          id="channel-label"
          placeholder={t("alerts.channels.labelPlaceholder")}
          value={form.label}
          autoFocus
          onChange={(event) => patch({ label: event.target.value })}
        />
      </Field>

      {form.kind === "webhook" ? (
        <Field
          label={t("alerts.channels.url")}
          htmlFor="channel-url"
          error={!built.ok && built.problem === "config" ? t("alerts.channels.urlRequired") : undefined}
        >
          <Input
            id="channel-url"
            className="font-mono"
            type="url"
            // The stored value is unreachable by design, so the placeholder
            // states that rather than sitting empty and looking like loss.
            placeholder={channel ? t("alerts.channels.keepStored") : "https://hooks.example.com/…"}
            value={form.url}
            aria-describedby="channel-secret-hint"
            onChange={(event) => patch({ url: event.target.value })}
          />
        </Field>
      ) : (
        <>
          <Field label={t("alerts.channels.botToken")} htmlFor="channel-token">
            <Input
              id="channel-token"
              className="font-mono"
              // Not `type="password"`: nothing is ever pre-filled here, so the
              // dots would only stop the operator checking their own paste.
              placeholder={channel ? t("alerts.channels.keepStored") : "123456:ABC-DEF…"}
              value={form.botToken}
              aria-describedby="channel-secret-hint"
              onChange={(event) => patch({ botToken: event.target.value })}
            />
          </Field>
          <Field
            label={t("alerts.channels.chatId")}
            htmlFor="channel-chat"
            error={
              !built.ok && built.problem === "config"
                ? t("alerts.channels.telegramIncomplete")
                : undefined
            }
          >
            <Input
              id="channel-chat"
              className="font-mono"
              placeholder={channel ? t("alerts.channels.keepStored") : "-1001234567890"}
              value={form.chatId}
              onChange={(event) => patch({ chatId: event.target.value })}
            />
          </Field>
        </>
      )}

      <p id="channel-secret-hint" className="-mt-1 mb-3 text-xs text-ink-muted">
        {channel ? t("alerts.channels.secretKept") : t("alerts.channels.secretWriteOnly")}
      </p>

      <Switch
        checked={form.enabled}
        onChange={(enabled) => patch({ enabled })}
        label={t("alerts.channels.enabled")}
      />

      {error ? (
        <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
    </Dialog>
  );
}
