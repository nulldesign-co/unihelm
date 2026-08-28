import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Ban,
  Plus,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Trash2,
  X,
} from "lucide-react";
import { useState } from "react";
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
  endpoints,
  type BanRecord,
  type FirewallBackend,
  type FirewallResponse,
  type FirewallRule,
  type SentinelSettings,
} from "@/lib/api";
import { banRefusal, isCidr } from "@/lib/ip";

/**
 * Firewall and Sentinel (spec §11.9).
 *
 * Two ideas shape this page, both taken straight from the agent module it
 * fronts (`crates/ferrum-ops/src/fwops.rs`):
 *
 * **The backend is the truth; the panel record is the intent.** Every read is
 * a merge of the two, and where they disagree this page says so instead of
 * showing the comfortable half. A firewall page that draws a tidy table of
 * rules nobody is enforcing is worse than no page — it is a page that tells an
 * operator they are protected.
 *
 * **Nothing here may lock the operator out.** Sentinel ships off, the toggle
 * says why, and the manual ban form refuses loopback and the address the admin
 * is browsing from *by name* before the request is sent.
 */
export function FirewallPage() {
  const { t } = useTranslation();

  const firewall = useQuery({
    queryKey: ["firewall"],
    queryFn: endpoints.firewall,
    // Drift is created outside the panel (a flushed ruleset, a firewalld
    // reload), so a stale view here is exactly the view that misleads.
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("firewall.title")}</h1>
        <p className="mt-1 text-sm text-ink-muted">{t("firewall.subtitle")}</p>
      </header>

      {firewall.isPending ? (
        <div className="flex justify-center py-24 text-ink-muted">
          <Spinner className="h-6 w-6" />
        </div>
      ) : firewall.error ? (
        <LoadError error={firewall.error} />
      ) : (
        <>
          <BackendCard data={firewall.data!} />
          <RulesCard data={firewall.data!} />
          <BansCard backend={firewall.data!.backend} yourIp={firewall.data!.your_ip ?? null} />
          <SentinelCard backend={firewall.data!.backend} />
        </>
      )}
    </div>
  );
}

/**
 * A route the running panel does not serve, told apart from a real failure.
 *
 * `/api/firewall/*` is not registered in every build. An unmatched axum route
 * answers a bare 404 with no error body, which the client turns into
 * `unexpected_response` — worth its own sentence, because "this build has no
 * firewall API" and "the firewall API said no" need different fixes.
 */
export function isRouteMissing(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404 && error.slug === "unexpected_response";
}

function LoadError({ error }: { error: unknown }) {
  const { t } = useTranslation();
  const missing = isRouteMissing(error);
  return (
    <Card>
      <CardBody className="py-12 text-center">
        <ShieldAlert className="mx-auto mb-3 h-8 w-8 text-danger" aria-hidden />
        <p className="text-sm font-medium text-ink">
          {missing ? t("firewall.apiMissing") : t("firewall.loadFailed")}
        </p>
        <p className="mx-auto mt-1 max-w-md text-sm text-ink-muted">
          {missing
            ? t("firewall.apiMissingHint")
            : error instanceof ApiError
              ? error.message
              : String(error)}
        </p>
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// backend state
// ---------------------------------------------------------------------------

function BackendCard({ data }: { data: FirewallResponse }) {
  const { t } = useTranslation();
  const backendName = t(`firewall.backendName.${data.backend}`, { defaultValue: data.backend });

  // Three states, three different sentences. Collapsing "no firewall" into
  // "inactive" would hide the one case where installing something is the fix.
  if (data.backend === "none") {
    return (
      <Notice
        tone="danger"
        icon={<ShieldOff className="h-5 w-5" aria-hidden />}
        title={t("firewall.noneTitle")}
        body={t("firewall.noneBody")}
        hint={t("firewall.noneHint")}
      />
    );
  }

  if (!data.active) {
    return (
      <Notice
        tone="warning"
        icon={<AlertTriangle className="h-5 w-5" aria-hidden />}
        title={t("firewall.inactiveTitle", { backend: backendName })}
        body={t("firewall.inactiveBody")}
      />
    );
  }

  return (
    <Notice
      tone="success"
      icon={<ShieldCheck className="h-5 w-5" aria-hidden />}
      title={t("firewall.activeTitle", { backend: backendName })}
      body={t("firewall.activeBody", { count: data.rules.filter((r) => r.in_backend).length })}
    />
  );
}

function Notice({
  tone,
  icon,
  title,
  body,
  hint,
}: {
  tone: "danger" | "warning" | "success";
  icon: React.ReactNode;
  title: string;
  body: string;
  hint?: string;
}) {
  const styles = {
    danger: "border-danger/30 bg-danger-soft text-danger",
    warning: "border-warning/30 bg-warning-soft text-warning",
    success: "border-success/30 bg-success-soft text-success",
  } as const;

  return (
    <div
      // `role="status"` rather than `alert` for the healthy case would need two
      // components; a firewall banner is always worth announcing.
      role="status"
      className={`flex gap-3 rounded-card border px-4 py-3 ${styles[tone]}`}
    >
      <span className="mt-0.5 shrink-0">{icon}</span>
      <div className="min-w-0">
        <p className="text-sm font-medium text-ink">{title}</p>
        <p className="mt-0.5 text-sm text-ink-muted">{body}</p>
        {hint ? <p className="mt-1 text-sm text-ink-muted">{hint}</p> : null}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// managed port rules
// ---------------------------------------------------------------------------

/** Common holes, so nobody has to remember that SSH is 22/tcp at 3 a.m. */
const PRESETS: { key: string; port: number; proto: "tcp" }[] = [
  { key: "ssh", port: 22, proto: "tcp" },
  { key: "http", port: 80, proto: "tcp" },
  { key: "https", port: 443, proto: "tcp" },
  { key: "panel", port: 8443, proto: "tcp" },
];

function RulesCard({ data }: { data: FirewallResponse }) {
  const { t } = useTranslation();
  const [opening, setOpening] = useState(false);
  const unmanaged = data.backend === "none";
  // On a host with no backend every recorded rule is "missing from the
  // firewall" by definition, so a drift count there would be a second, weaker
  // way of saying what the red banner above already says plainly.
  const drifted = unmanaged ? 0 : data.rules.filter((rule) => rule.drift !== null).length;

  return (
    <Card>
      <CardHeader
        title={t("firewall.rules.title")}
        description={t("firewall.rules.hint")}
        action={
          <div className="flex items-center gap-2">
            {drifted > 0 ? (
              <Badge tone="warning" dot>
                {t("firewall.rules.drifted", { count: drifted })}
              </Badge>
            ) : null}
            <Button
              variant="primary"
              size="sm"
              onClick={() => setOpening(true)}
              disabled={unmanaged}
              title={unmanaged ? t("firewall.noneBody") : undefined}
            >
              <Plus className="h-3.5 w-3.5" aria-hidden />
              {t("firewall.rules.open")}
            </Button>
          </div>
        }
      />
      <CardBody>
        {/* The `none` case gets its own body rather than an empty table.
            An empty table means "nothing is open"; this host has nothing
            *closed*, which is the opposite claim. */}
        {unmanaged ? (
          <div className="py-10 text-center">
            <ShieldOff className="mx-auto mb-3 h-8 w-8 text-ink-subtle" aria-hidden />
            <p className="text-sm font-medium text-ink">{t("firewall.rules.unmanaged")}</p>
            <p className="mx-auto mt-1 max-w-md text-sm text-ink-muted">
              {t("firewall.rules.unmanagedHint")}
            </p>
          </div>
        ) : data.rules.length === 0 ? (
          <div className="py-10 text-center">
            <p className="text-sm font-medium text-ink">{t("firewall.rules.empty")}</p>
            <p className="mx-auto mt-1 max-w-md text-sm text-ink-muted">
              {t("firewall.rules.emptyHint")}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] border-collapse text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-ink-muted">
                  <th className="w-24 px-2 py-2 text-start font-medium">
                    {t("firewall.rules.port")}
                  </th>
                  <th className="w-40 px-2 py-2 text-start font-medium">
                    {t("firewall.rules.source")}
                  </th>
                  <th className="px-2 py-2 text-start font-medium">
                    {t("firewall.rules.comment")}
                  </th>
                  <th className="w-56 px-2 py-2 text-start font-medium">
                    {t("firewall.rules.state")}
                  </th>
                  <th className="w-28 px-2 py-2" />
                </tr>
              </thead>
              <tbody>
                {data.rules.map((rule) => (
                  <RuleRow key={`${rule.port}/${rule.proto}/${rule.source ?? ""}`} rule={rule} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardBody>

      <OpenPortDialog open={opening} onClose={() => setOpening(false)} />
    </Card>
  );
}

function RuleRow({ rule }: { rule: FirewallRule }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const close = useMutation({
    mutationFn: () =>
      endpoints.closePort({
        port: rule.port,
        proto: rule.proto,
        ...(rule.source ? { source: rule.source } : {}),
      }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["firewall"] }),
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <tr className="border-b border-border last:border-b-0 hover:bg-surface-muted">
      <td dir="ltr" className="px-2 py-2 text-start font-mono text-xs text-ink">
        {rule.port}/{rule.proto}
      </td>
      <td dir="ltr" className="max-w-0 px-2 py-2 text-start">
        <span className="block truncate font-mono text-xs text-ink-muted">
          {rule.source ?? t("firewall.rules.anywhere")}
        </span>
      </td>
      <td className="max-w-0 px-2 py-2">
        <span dir="auto" className="block truncate text-ink-muted">
          {rule.comment || "—"}
        </span>
      </td>
      <td className="px-2 py-2">
        <RuleState rule={rule} />
        {error ? (
          <p role="alert" className="mt-1 text-xs text-danger">
            {error}
          </p>
        ) : null}
      </td>
      <td className="px-2 py-2 text-end">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => close.mutate()}
          disabled={close.isPending}
          aria-label={t("firewall.rules.closeLabel", { port: rule.port, proto: rule.proto })}
        >
          {close.isPending ? <Spinner /> : <X className="h-3.5 w-3.5" aria-hidden />}
          {t("firewall.rules.close")}
        </Button>
      </td>
    </tr>
  );
}

function RuleState({ rule }: { rule: FirewallRule }) {
  const { t } = useTranslation();

  if (rule.drift === "missing_from_backend") {
    return (
      <div>
        <Badge tone="danger" dot>
          {t("firewall.rules.driftMissing")}
        </Badge>
        <p className="mt-1 text-xs text-ink-muted">{t("firewall.rules.driftMissingHint")}</p>
      </div>
    );
  }
  if (rule.drift === "unrecorded") {
    return (
      <div>
        <Badge tone="warning" dot>
          {t("firewall.rules.driftUnrecorded")}
        </Badge>
        <p className="mt-1 text-xs text-ink-muted">{t("firewall.rules.driftUnrecordedHint")}</p>
      </div>
    );
  }
  return (
    <Badge tone="success" dot>
      {t("firewall.rules.enforced")}
    </Badge>
  );
}

/**
 * The port form's checks, kept in step with `PortRule::validate` in the agent.
 *
 * Port 0 is not a port, and `source` is a literal address or CIDR — never a
 * hostname, because a rule whose meaning depends on DNS at apply time is a rule
 * nobody can audit (docs/operations.md, `fw.port.open`).
 */
export function portProblem(port: string, source: string): "port" | "source" | null {
  const trimmed = port.trim();
  if (!/^[1-9][0-9]{0,4}$/.test(trimmed) || Number(trimmed) > 65535) return "port";
  const from = source.trim();
  if (from !== "" && !isCidr(from)) return "source";
  return null;
}

function OpenPortDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [port, setPort] = useState("");
  const [proto, setProto] = useState<"tcp" | "udp">("tcp");
  const [source, setSource] = useState("");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  const problem = portProblem(port, source);

  const submit = useMutation({
    mutationFn: () =>
      endpoints.openPort({
        port: Number(port.trim()),
        proto,
        ...(source.trim() ? { source: source.trim() } : {}),
        ...(comment.trim() ? { comment: comment.trim() } : {}),
      }),
    onSuccess: () => {
      setPort("");
      setSource("");
      setComment("");
      setError(null);
      onClose();
      void queryClient.invalidateQueries({ queryKey: ["firewall"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("firewall.rules.open")}
      description={t("firewall.rules.openHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={() => submit.mutate()}
            disabled={submit.isPending || problem !== null}
          >
            {submit.isPending ? <Spinner /> : null}
            {t("firewall.rules.open")}
          </Button>
        </>
      }
    >
      <div className="mb-4 flex flex-wrap gap-2">
        {PRESETS.map((preset) => (
          <Button
            key={preset.key}
            variant="outline"
            size="sm"
            onClick={() => {
              setPort(String(preset.port));
              setProto(preset.proto);
            }}
          >
            {t(`firewall.presets.${preset.key}`)}
            <span dir="ltr" className="font-mono text-xs text-ink-subtle">
              {preset.port}/{preset.proto}
            </span>
          </Button>
        ))}
      </div>

      <Field
        label={t("firewall.rules.port")}
        htmlFor="fw-port"
        error={port !== "" && problem === "port" ? t("firewall.rules.portInvalid") : undefined}
      >
        <Input
          id="fw-port"
          dir="ltr"
          inputMode="numeric"
          placeholder="8080"
          value={port}
          aria-invalid={port !== "" && problem === "port"}
          onChange={(event) => setPort(event.target.value)}
        />
      </Field>

      <Field label={t("firewall.rules.proto")} htmlFor="fw-proto">
        <Select
          id="fw-proto"
          value={proto}
          onChange={(event) => setProto(event.target.value === "udp" ? "udp" : "tcp")}
        >
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </Select>
      </Field>

      <Field
        label={t("firewall.rules.source")}
        htmlFor="fw-source"
        error={problem === "source" ? t("firewall.rules.sourceInvalid") : undefined}
      >
        <Input
          id="fw-source"
          dir="ltr"
          placeholder="203.0.113.0/24"
          value={source}
          aria-describedby="fw-source-hint"
          aria-invalid={problem === "source"}
          onChange={(event) => setSource(event.target.value)}
        />
      </Field>
      <p id="fw-source-hint" className="-mt-1 mb-3 text-xs text-ink-muted">
        {t("firewall.rules.sourceHint")}
      </p>

      <Field label={t("firewall.rules.comment")} htmlFor="fw-comment">
        <Input
          id="fw-comment"
          dir="auto"
          value={comment}
          onChange={(event) => setComment(event.target.value)}
        />
      </Field>

      {error ? (
        <p role="alert" className="mt-1 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// bans
// ---------------------------------------------------------------------------

function BansCard({ backend, yourIp }: { backend: FirewallBackend; yourIp: string | null }) {
  const { t, i18n } = useTranslation();
  const [banning, setBanning] = useState(false);
  const unmanaged = backend === "none";

  const bans = useQuery({
    queryKey: ["firewall-bans"],
    queryFn: endpoints.bans,
    refetchInterval: 30_000,
  });

  const dateFormat = new Intl.DateTimeFormat(i18n.language, {
    dateStyle: "medium",
    timeStyle: "short",
  });

  const rows = bans.data?.bans ?? [];
  const unrecorded = bans.data?.unrecorded ?? [];

  return (
    <Card>
      <CardHeader
        title={t("firewall.bans.title")}
        description={t("firewall.bans.hint")}
        action={
          <Button
            variant="primary"
            size="sm"
            onClick={() => setBanning(true)}
            disabled={unmanaged}
            title={unmanaged ? t("firewall.noneBody") : undefined}
          >
            <Ban className="h-3.5 w-3.5" aria-hidden />
            {t("firewall.bans.add")}
          </Button>
        }
      />
      <CardBody className="space-y-4">
        {bans.isPending ? (
          <div className="flex justify-center py-10 text-ink-muted">
            <Spinner />
          </div>
        ) : bans.error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {isRouteMissing(bans.error)
              ? t("firewall.apiMissing")
              : bans.error instanceof ApiError
                ? bans.error.message
                : String(bans.error)}
          </p>
        ) : rows.length === 0 ? (
          <div className="py-10 text-center">
            <p className="text-sm font-medium text-ink">{t("firewall.bans.empty")}</p>
            <p className="mx-auto mt-1 max-w-md text-sm text-ink-muted">
              {t("firewall.bans.emptyHint")}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] border-collapse text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-ink-muted">
                  <th className="w-40 px-2 py-2 text-start font-medium">{t("firewall.bans.ip")}</th>
                  <th className="px-2 py-2 text-start font-medium">{t("firewall.bans.reason")}</th>
                  <th className="w-44 px-2 py-2 text-start font-medium">
                    {t("firewall.bans.expires")}
                  </th>
                  <th className="w-44 px-2 py-2 text-start font-medium">
                    {t("firewall.bans.state")}
                  </th>
                  <th className="w-28 px-2 py-2" />
                </tr>
              </thead>
              <tbody>
                {rows.map((ban) => (
                  <BanRow key={ban.id} ban={ban} dateFormat={dateFormat} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Addresses the kernel is dropping that the panel never recorded.
            Listed separately because this is how an operator finds out why a
            customer cannot reach a box they were never banned from. */}
        {unrecorded.length > 0 ? (
          <div className="rounded-lg border border-warning/30 bg-warning-soft px-3 py-2.5">
            <p className="text-sm font-medium text-ink">
              {t("firewall.bans.unrecorded", { count: unrecorded.length })}
            </p>
            <p className="mt-0.5 text-xs text-ink-muted">{t("firewall.bans.unrecordedHint")}</p>
            <ul className="mt-2 flex flex-wrap gap-1.5">
              {unrecorded.map((ip) => (
                <li key={ip}>
                  <Badge tone="neutral">
                    <span dir="ltr" className="font-mono">
                      {ip}
                    </span>
                  </Badge>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </CardBody>

      <BanDialog open={banning} onClose={() => setBanning(false)} yourIp={yourIp} />
    </Card>
  );
}

function BanRow({ ban, dateFormat }: { ban: BanRecord; dateFormat: Intl.DateTimeFormat }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const lifted = ban.lifted_at !== null;

  const unban = useMutation({
    mutationFn: () => endpoints.unban(ban.ip),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["firewall-bans"] }),
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <tr className="border-b border-border last:border-b-0 hover:bg-surface-muted">
      <td dir="ltr" className="px-2 py-2 text-start font-mono text-xs text-ink">
        {ban.ip}
      </td>
      <td className="max-w-0 px-2 py-2">
        <span dir="auto" className="block truncate text-ink-muted">
          {ban.reason}
        </span>
      </td>
      <td className="whitespace-nowrap px-2 py-2 text-ink-muted">
        {lifted
          ? t("firewall.bans.liftedAt", { at: dateFormat.format(new Date(ban.lifted_at!)) })
          : ban.expires_at === null
            ? t("firewall.bans.permanent")
            : dateFormat.format(new Date(ban.expires_at))}
      </td>
      <td className="px-2 py-2">
        {/* Three states, not two: a lifted ban, a ban the kernel is holding,
            and a ban the panel believes in that the backend has lost. The last
            one is the ban-list half of the same drift the rule table reports. */}
        {lifted ? (
          <Badge tone="neutral">{t("firewall.bans.lifted")}</Badge>
        ) : ban.in_backend ? (
          <Badge tone="danger" dot>
            {t("firewall.bans.blocking")}
          </Badge>
        ) : (
          <div>
            <Badge tone="warning" dot>
              {t("firewall.bans.notInBackend")}
            </Badge>
            <p className="mt-1 text-xs text-ink-muted">{t("firewall.bans.notInBackendHint")}</p>
          </div>
        )}
        {error ? (
          <p role="alert" className="mt-1 text-xs text-danger">
            {error}
          </p>
        ) : null}
      </td>
      <td className="px-2 py-2 text-end">
        {lifted ? null : (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => unban.mutate()}
            disabled={unban.isPending}
            aria-label={t("firewall.bans.unbanLabel", { ip: ban.ip })}
          >
            {unban.isPending ? <Spinner /> : <Trash2 className="h-3.5 w-3.5" aria-hidden />}
            {t("firewall.bans.unban")}
          </Button>
        )}
      </td>
    </tr>
  );
}

function BanDialog({
  open,
  onClose,
  yourIp,
}: {
  open: boolean;
  onClose: () => void;
  yourIp: string | null;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [ip, setIp] = useState("");
  const [minutes, setMinutes] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  // The refusal is computed on every keystroke rather than on submit: the point
  // is that an operator never gets as far as pressing a button that would lock
  // them out (spec §11.9).
  const refusal = ip.trim() === "" ? null : banRefusal(ip, yourIp);
  const minutesValid = minutes.trim() === "" || /^[0-9]{1,7}$/.test(minutes.trim());

  const submit = useMutation({
    mutationFn: () =>
      endpoints.ban({
        ip: ip.trim(),
        ...(minutes.trim() === "" ? {} : { minutes: Number(minutes.trim()) }),
        ...(reason.trim() ? { reason: reason.trim() } : {}),
      }),
    onSuccess: () => {
      setIp("");
      setMinutes("");
      setReason("");
      setError(null);
      onClose();
      void queryClient.invalidateQueries({ queryKey: ["firewall-bans"] });
    },
    // The agent's own refusal sentence names the address and the reason, so it
    // is shown verbatim: it covers the two cases a browser cannot check —
    // the server's own interface addresses, and the operator's allowlist.
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("firewall.bans.add")}
      description={t("firewall.bans.addHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="danger"
            onClick={() => submit.mutate()}
            disabled={submit.isPending || ip.trim() === "" || refusal !== null || !minutesValid}
          >
            {submit.isPending ? <Spinner /> : null}
            {t("firewall.bans.submit")}
          </Button>
        </>
      }
    >
      <Field label={t("firewall.bans.ip")} htmlFor="fw-ban-ip">
        <Input
          id="fw-ban-ip"
          dir="ltr"
          placeholder="203.0.113.42"
          value={ip}
          autoFocus
          aria-invalid={refusal !== null}
          aria-describedby="fw-ban-refusal"
          onChange={(event) => setIp(event.target.value)}
        />
      </Field>

      {/* Named refusals, not a generic "invalid": each one tells the operator
          what would have happened had the panel obeyed. */}
      <div id="fw-ban-refusal" aria-live="polite" className="-mt-1 mb-3">
        {refusal === null ? (
          yourIp ? (
            <p className="text-xs text-ink-muted">
              {t("firewall.bans.yourAddress", { ip: yourIp })}
            </p>
          ) : (
            <p className="text-xs text-ink-muted">{t("firewall.bans.yourAddressUnknown")}</p>
          )
        ) : (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {t(`firewall.bans.refuse.${refusal}`, { ip: ip.trim(), yourIp: yourIp ?? "" })}
          </p>
        )}
      </div>

      <Field
        label={t("firewall.bans.minutes")}
        htmlFor="fw-ban-minutes"
        error={minutesValid ? undefined : t("firewall.bans.minutesInvalid")}
      >
        <Input
          id="fw-ban-minutes"
          dir="ltr"
          inputMode="numeric"
          placeholder="60"
          value={minutes}
          aria-describedby="fw-ban-minutes-hint"
          aria-invalid={!minutesValid}
          onChange={(event) => setMinutes(event.target.value)}
        />
      </Field>
      <p id="fw-ban-minutes-hint" className="-mt-1 mb-3 text-xs text-ink-muted">
        {t("firewall.bans.minutesHint")}
      </p>

      <Field label={t("firewall.bans.reason")} htmlFor="fw-ban-reason">
        <Input
          id="fw-ban-reason"
          dir="auto"
          value={reason}
          onChange={(event) => setReason(event.target.value)}
        />
      </Field>

      {error ? (
        <p role="alert" className="mt-1 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Sentinel
// ---------------------------------------------------------------------------

export type SentinelField = "ssh_threshold" | "window_minutes" | "ban_minutes" | "allowlist";

/**
 * The same bounds `SentinelSettings::validate` enforces in the agent.
 *
 * These are not pedantry. A threshold of 0 bans every address that has ever
 * appeared in the log — including the operator's — and a window measured in
 * days lets one forgotten laptop accumulate a ban long after it was fixed.
 */
export function sentinelProblems(settings: SentinelSettings): SentinelField[] {
  const problems: SentinelField[] = [];
  if (!Number.isInteger(settings.ssh_threshold) || settings.ssh_threshold < 1) {
    problems.push("ssh_threshold");
  }
  if (
    !Number.isInteger(settings.window_minutes) ||
    settings.window_minutes < 1 ||
    settings.window_minutes > 1440
  ) {
    problems.push("window_minutes");
  }
  if (
    !Number.isInteger(settings.ban_minutes) ||
    settings.ban_minutes < 1 ||
    settings.ban_minutes > 525_600
  ) {
    problems.push("ban_minutes");
  }
  if (settings.allowlist.some((entry) => !isCidr(entry))) problems.push("allowlist");
  return problems;
}

function SentinelCard({ backend }: { backend: FirewallBackend }) {
  const { t } = useTranslation();

  const sentinel = useQuery({ queryKey: ["sentinel"], queryFn: endpoints.sentinel });

  return (
    <Card>
      <CardHeader title={t("firewall.sentinel.title")} description={t("firewall.sentinel.hint")} />
      <CardBody>
        {sentinel.isPending ? (
          <div className="flex justify-center py-10 text-ink-muted">
            <Spinner />
          </div>
        ) : sentinel.error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {isRouteMissing(sentinel.error)
              ? t("firewall.apiMissing")
              : sentinel.error instanceof ApiError
                ? sentinel.error.message
                : String(sentinel.error)}
          </p>
        ) : (
          <SentinelForm settings={sentinel.data!} backend={backend} />
        )}
      </CardBody>
    </Card>
  );
}

function SentinelForm({
  settings,
  backend,
}: {
  settings: SentinelSettings;
  backend: FirewallBackend;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  // Seeded once from the server. There is no polling on this query, so an
  // operator's half-typed threshold cannot be overwritten mid-edit.
  const [draft, setDraft] = useState<SentinelSettings>(settings);
  const [entry, setEntry] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const problems = sentinelProblems(draft);
  const has = (field: SentinelField) => problems.includes(field);

  const save = useMutation({
    mutationFn: () => endpoints.setSentinel(draft),
    onSuccess: (next) => {
      setDraft(next);
      setError(null);
      setSaved(true);
      void queryClient.invalidateQueries({ queryKey: ["sentinel"] });
    },
    onError: (e) => {
      setSaved(false);
      setError(e instanceof ApiError ? e.message : String(e));
    },
  });

  const patch = (change: Partial<SentinelSettings>) => {
    setSaved(false);
    setDraft((current) => ({ ...current, ...change }));
  };

  // An empty box reads as 0, which `sentinelProblems` already refuses — so the
  // operator sees the reason rather than a field that will not clear. Anything
  // that is not a digit never reaches the state, which keeps a stray keystroke
  // from turning the whole field into `NaN`.
  const shown = (value: number) => (Number.isFinite(value) && value !== 0 ? String(value) : "");
  const digits = (raw: string) => Number(raw.replace(/[^0-9]/g, ""));

  return (
    <div className="space-y-4">
      <Switch
        checked={draft.enabled}
        onChange={(enabled) => patch({ enabled })}
        label={t("firewall.sentinel.enable")}
        // The toggle carries the reason it ships off. Anyone about to turn on
        // an automatic banner needs the lockout warning at the moment they
        // reach for the switch, not in a docs page they will not open.
        description={t("firewall.sentinel.enableHint")}
      />

      {draft.enabled && backend === "none" ? (
        <p
          role="alert"
          className="rounded-lg border border-warning/30 bg-warning-soft px-3 py-2 text-sm text-ink-muted"
        >
          {t("firewall.sentinel.noBackend")}
        </p>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-3">
        <Field
          label={t("firewall.sentinel.threshold")}
          htmlFor="sentinel-threshold"
          error={has("ssh_threshold") ? t("firewall.sentinel.thresholdInvalid") : undefined}
        >
          <Input
            id="sentinel-threshold"
            dir="ltr"
            inputMode="numeric"
            value={shown(draft.ssh_threshold)}
            aria-invalid={has("ssh_threshold")}
            aria-describedby="sentinel-threshold-hint"
            onChange={(event) => patch({ ssh_threshold: digits(event.target.value) })}
          />
        </Field>
        <Field
          label={t("firewall.sentinel.window")}
          htmlFor="sentinel-window"
          error={has("window_minutes") ? t("firewall.sentinel.windowInvalid") : undefined}
        >
          <Input
            id="sentinel-window"
            dir="ltr"
            inputMode="numeric"
            value={shown(draft.window_minutes)}
            aria-invalid={has("window_minutes")}
            onChange={(event) => patch({ window_minutes: digits(event.target.value) })}
          />
        </Field>
        <Field
          label={t("firewall.sentinel.banMinutes")}
          htmlFor="sentinel-ban-minutes"
          error={has("ban_minutes") ? t("firewall.sentinel.banMinutesInvalid") : undefined}
        >
          <Input
            id="sentinel-ban-minutes"
            dir="ltr"
            inputMode="numeric"
            value={shown(draft.ban_minutes)}
            aria-invalid={has("ban_minutes")}
            onChange={(event) => patch({ ban_minutes: digits(event.target.value) })}
          />
        </Field>
      </div>
      <p id="sentinel-threshold-hint" className="-mt-2 text-xs text-ink-muted">
        {t("firewall.sentinel.thresholdHint")}
      </p>

      <fieldset>
        <legend className="block text-sm font-medium text-ink">
          {t("firewall.sentinel.allowlist")}
        </legend>
        <p className="mt-0.5 mb-2 text-xs text-ink-muted">
          {t("firewall.sentinel.allowlistHint")}
        </p>

        {draft.allowlist.length > 0 ? (
          <ul className="mb-2 flex flex-wrap gap-1.5">
            {draft.allowlist.map((item) => (
              <li key={item}>
                <Badge tone={isCidr(item) ? "accent" : "danger"}>
                  <span dir="ltr" className="font-mono">
                    {item}
                  </span>
                  <button
                    type="button"
                    className="ms-0.5 rounded-full hover:text-ink"
                    aria-label={t("firewall.sentinel.allowlistRemove", { entry: item })}
                    onClick={() =>
                      patch({ allowlist: draft.allowlist.filter((other) => other !== item) })
                    }
                  >
                    <X className="h-3 w-3" aria-hidden />
                  </button>
                </Badge>
              </li>
            ))}
          </ul>
        ) : null}

        <div className="flex items-start gap-2">
          <Input
            dir="ltr"
            className="max-w-xs"
            placeholder="203.0.113.0/24"
            value={entry}
            aria-label={t("firewall.sentinel.allowlistAdd")}
            aria-invalid={entry.trim() !== "" && !isCidr(entry)}
            onChange={(event) => setEntry(event.target.value)}
          />
          <Button
            variant="outline"
            onClick={() => {
              const value = entry.trim();
              if (value === "" || draft.allowlist.includes(value)) return;
              patch({ allowlist: [...draft.allowlist, value] });
              setEntry("");
            }}
            disabled={entry.trim() === "" || !isCidr(entry)}
          >
            <Plus className="h-3.5 w-3.5" aria-hidden />
            {t("firewall.sentinel.allowlistAdd")}
          </Button>
        </div>
        {entry.trim() !== "" && !isCidr(entry) ? (
          <p role="alert" className="mt-1.5 text-xs text-danger">
            {t("firewall.sentinel.allowlistInvalid")}
          </p>
        ) : null}
        {has("allowlist") ? (
          <p role="alert" className="mt-1.5 text-xs text-danger">
            {t("firewall.sentinel.allowlistInvalid")}
          </p>
        ) : null}
      </fieldset>

      {error ? (
        <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}

      <div className="flex items-center gap-3">
        <Button
          variant="primary"
          onClick={() => save.mutate()}
          disabled={save.isPending || problems.length > 0}
        >
          {save.isPending ? <Spinner /> : null}
          {t("firewall.sentinel.save")}
        </Button>
        {saved ? (
          <span role="status" className="text-sm text-success">
            {t("firewall.sentinel.saved")}
          </span>
        ) : null}
      </div>
    </div>
  );
}
