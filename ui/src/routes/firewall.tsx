import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Ban,
  MoreHorizontal,
  Plus,
  ShieldAlert,
  ShieldOff,
  Trash2,
  X,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { SectionHeader } from "@/components/ui/section-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { Menu, MenuItem } from "@/components/ui/menu";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, Td, Th, Tr } from "@/components/ui/table";
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
import { staggerStyle } from "@/lib/motion";

/**
 * The identity column stays put while the rest of the row scrolls.
 *
 * At 375px both tables are wider than the viewport and the state column — the
 * one an operator scrolls out to read — is on the far side. Without this, the
 * port or the address that state belongs to has scrolled away by the time they
 * get there. The hairline is what says "frozen" rather than "overlapping"; it
 * is drawn as an ::after rather than a border because a collapsed table border
 * on a sticky cell stays behind at the cell's unscrolled position.
 */
const STICKY_EDGE =
  "after:pointer-events-none after:absolute after:inset-y-0 after:end-0 after:w-px after:bg-border";
const STICKY_HEAD = `sticky start-0 z-10 ${STICKY_EDGE}`;
// No colour transition on the cell: it is the one opaque thing in the row, and
// fading it would leave the frozen column a beat behind the rest of the table
// every time the theme changes.
const STICKY_CELL = `sticky start-0 z-10 bg-surface group-hover/row:bg-surface-muted/60 ${STICKY_EDGE}`;

/**
 * Firewall and Sentinel (spec §11.9).
 *
 * Two ideas shape this page, both taken straight from the agent module it
 * fronts (`crates/unihelm-ops/src/fwops.rs`):
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
      <PageHeader title={t("firewall.title")} description={t("firewall.subtitle")} />

      {firewall.isPending ? (
        <FirewallSkeleton />
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
 * The page's own shape while it loads.
 *
 * One generic ghost standing in for a banner, two wide tables and a settings
 * form told the reader nothing about what was coming and then moved everything
 * when it arrived. These are the real headers and the real column rhythm, so
 * the only thing that changes on arrival is the text.
 */
function FirewallSkeleton() {
  return (
    <>
      <Skeleton className="h-[5.5rem] w-full rounded-card" />
      <section className="space-y-3">
        <SectionHeaderSkeleton />
        <RulesTableSkeleton />
      </section>
      <section className="space-y-3">
        <SectionHeaderSkeleton />
        <BansTableSkeleton />
      </section>
      <Card>
        {/* CardHeader's own rhythm, ghosted: its title and description are
            headings, and a placeholder div cannot live inside them. */}
        <div className="space-y-2 px-5 pt-4 pb-3">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-3.5 w-96 max-w-full" />
        </div>
        <CardBody>
          <SentinelFormSkeleton />
        </CardBody>
      </Card>
    </>
  );
}

function SectionHeaderSkeleton() {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="min-w-0 space-y-2">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-3.5 w-72 max-w-full" />
      </div>
      <Skeleton className="h-8 w-28 shrink-0 rounded-lg" />
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
    <EmptyState
      // The page's one empty vocabulary, tinted: the icon chip and the frame
      // carry the danger, so a firewall the panel cannot read does not look
      // like a firewall with nothing in it.
      className="border-danger/40 [&>div:first-child]:bg-danger-soft [&>div:first-child]:text-danger"
      icon={<ShieldAlert aria-hidden />}
      title={missing ? t("firewall.apiMissing") : t("firewall.loadFailed")}
      hint={
        missing
          ? t("firewall.apiMissingHint")
          : error instanceof ApiError
            ? error.message
            : String(error)
      }
    />
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
        badge={t("dashboard.firewallUnprotected")}
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
        badge={t("dashboard.firewallInactive")}
        title={t("firewall.inactiveTitle", { backend: backendName })}
        body={t("firewall.inactiveBody")}
      />
    );
  }

  return (
    <Notice
      tone="success"
      badge={t("dashboard.firewallActive")}
      title={t("firewall.activeTitle", { backend: backendName })}
      body={t("firewall.activeBody", { count: data.rules.filter((r) => r.in_backend).length })}
    />
  );
}

/**
 * The backend banner, on the panel's one standing-message component.
 *
 * `Callout` owns the tint and the icon, and raises `role="alert"` for the two
 * unhealthy tones only — which is the split this banner used to need two
 * components to express. The healthy state is information: worth reading, not
 * worth interrupting a screen reader mid-sentence for.
 */
function Notice({
  tone,
  badge,
  title,
  body,
  hint,
}: {
  tone: "danger" | "warning" | "success";
  /** The one-word state, next to the sentence — colour is never the only signal. */
  badge: string;
  title: string;
  body: string;
  hint?: string;
}) {
  return (
    <Callout
      tone={tone}
      title={
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          {title}
          <Badge tone={tone} dot>
            {badge}
          </Badge>
        </span>
      }
    >
      <p>{body}</p>
      {hint ? <p className="mt-1">{hint}</p> : null}
    </Callout>
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
    <section className="space-y-3">
      <SectionHeader
        title={t("firewall.rules.title")}
        description={t("firewall.rules.hint")}
        actions={
          <>
            {drifted > 0 ? (
              <Badge tone="warning" className="tnum" dot>
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
          </>
        }
      />

      {/* The `none` case gets its own body rather than an empty table.
          An empty table means "nothing is open"; this host has nothing
          *closed*, which is the opposite claim. */}
      {unmanaged ? (
        <EmptyState
          icon={<ShieldOff aria-hidden />}
          title={t("firewall.rules.unmanaged")}
          hint={t("firewall.rules.unmanagedHint")}
        />
      ) : data.rules.length === 0 ? (
        <EmptyState
          icon={<Plus aria-hidden />}
          title={t("firewall.rules.empty")}
          hint={t("firewall.rules.emptyHint")}
          action={
            <Button variant="primary" onClick={() => setOpening(true)}>
              <Plus className="h-3.5 w-3.5" aria-hidden />
              {t("firewall.rules.open")}
            </Button>
          }
        />
      ) : (
        <Table className="min-w-[640px]">
          <RulesHead />
          <tbody>
            {data.rules.map((rule, index) => (
              <RuleRow
                key={`${rule.port}/${rule.proto}/${rule.source ?? ""}`}
                rule={rule}
                index={index}
              />
            ))}
          </tbody>
        </Table>
      )}

      <OpenPortDialog open={opening} onClose={() => setOpening(false)} />
    </section>
  );
}

/** Shared by the table and its ghost, so the loading state has the real columns. */
function RulesHead() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th className={`${STICKY_HEAD} w-24`}>{t("firewall.rules.port")}</Th>
        <Th className="w-40">{t("firewall.rules.source")}</Th>
        <Th>{t("firewall.rules.comment")}</Th>
        <Th className="w-56">{t("firewall.rules.state")}</Th>
        <Th className="w-12">
          <span className="sr-only">{t("firewall.rules.close")}</span>
        </Th>
      </tr>
    </thead>
  );
}

function RulesTableSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite">
      <Table className="min-w-[640px]">
        <RulesHead />
        <tbody>
          {Array.from({ length: rows }, (_, i) => (
            <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
              <Td className={STICKY_CELL}>
                <Skeleton className="h-4 w-14" />
              </Td>
              <Td>
                <Skeleton className="h-4 w-24" />
              </Td>
              <Td>
                <Skeleton className={i % 2 === 0 ? "h-4 w-40" : "h-4 w-28"} />
              </Td>
              <Td>
                <Skeleton className="h-5 w-28 rounded-full" />
              </Td>
              <Td>
                <Skeleton className="ms-auto h-8 w-8 rounded-lg" />
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function RuleRow({ rule, index }: { rule: FirewallRule; index: number }) {
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

  const label = t("firewall.rules.closeLabel", { port: rule.port, proto: rule.proto });

  return (
    <Tr className="animate-rise-in stagger" style={staggerStyle(index)}>
      <Td className={`${STICKY_CELL} font-mono text-xs`}>
        {rule.port}/{rule.proto}
      </Td>
      <Td className="max-w-0">
        <span className="block truncate font-mono text-xs text-ink-muted">
          {rule.source ?? t("firewall.rules.anywhere")}
        </span>
      </Td>
      <Td className="max-w-0">
        <span className="block truncate text-ink-muted">{rule.comment || t("common.none")}</span>
      </Td>
      <Td>
        <RuleState rule={rule} />
        {error ? (
          <p role="alert" className="mt-1 text-xs text-danger">
            {error}
          </p>
        ) : null}
      </Td>
      <Td className="text-end">
        <Menu
          label={label}
          // The row keeps its control while the close is in flight. Swapping
          // the menu for a spinner changed the column's width and took the
          // button away at the one moment the operator is watching it.
          trigger={
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={label}
              aria-haspopup="menu"
              loading={close.isPending}
            >
              <MoreHorizontal className="h-4 w-4" aria-hidden />
            </Button>
          }
        >
          <MenuItem danger icon={<X />} disabled={close.isPending} onClick={() => close.mutate()}>
            {t("firewall.rules.close")}
          </MenuItem>
        </Menu>
      </Td>
    </Tr>
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
            loading={submit.isPending}
            disabled={problem !== null}
          >
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
            <span className="font-mono text-xs text-ink-subtle">
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
          className="tnum font-mono"
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
          className="font-mono"
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
          value={comment}
          onChange={(event) => setComment(event.target.value)}
        />
      </Field>

      {error ? (
        <Callout tone="danger" className="mt-1">
          {error}
        </Callout>
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
    <section className="space-y-3">
      <SectionHeader
        title={t("firewall.bans.title")}
        description={t("firewall.bans.hint")}
        actions={
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

      {bans.isPending ? (
        <BansTableSkeleton />
      ) : bans.error ? (
        <Callout tone="danger">
          {isRouteMissing(bans.error)
            ? t("firewall.apiMissing")
            : bans.error instanceof ApiError
              ? bans.error.message
              : String(bans.error)}
        </Callout>
      ) : rows.length === 0 ? (
        <EmptyState
          icon={<Ban aria-hidden />}
          title={t("firewall.bans.empty")}
          hint={t("firewall.bans.emptyHint")}
          action={
            unmanaged ? undefined : (
              <Button variant="primary" onClick={() => setBanning(true)}>
                <Ban className="h-3.5 w-3.5" aria-hidden />
                {t("firewall.bans.add")}
              </Button>
            )
          }
        />
      ) : (
        <Table className="min-w-[680px]">
          <BansHead />
          <tbody>
            {rows.map((ban, index) => (
              <BanRow key={ban.id} ban={ban} dateFormat={dateFormat} index={index} />
            ))}
          </tbody>
        </Table>
      )}

      {/* Addresses the kernel is dropping that the panel never recorded.
          Listed separately because this is how an operator finds out why a
          customer cannot reach a box they were never banned from. */}
      {unrecorded.length > 0 ? (
        <Callout
          tone="warning"
          title={
            <span className="tnum">
              {t("firewall.bans.unrecorded", { count: unrecorded.length })}
            </span>
          }
        >
          <p>{t("firewall.bans.unrecordedHint")}</p>
          <ul className="mt-2 flex flex-wrap gap-1.5">
            {unrecorded.map((ip) => (
              <li key={ip}>
                <Badge tone="neutral">
                  <span className="font-mono">{ip}</span>
                </Badge>
              </li>
            ))}
          </ul>
        </Callout>
      ) : null}

      <BanDialog open={banning} onClose={() => setBanning(false)} yourIp={yourIp} />
    </section>
  );
}

/** Shared by the table and its ghost, so the loading state has the real columns. */
function BansHead() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th className={`${STICKY_HEAD} w-40`}>{t("firewall.bans.ip")}</Th>
        <Th>{t("firewall.bans.reason")}</Th>
        <Th className="w-44">{t("firewall.bans.expires")}</Th>
        <Th className="w-44">{t("firewall.bans.state")}</Th>
        <Th className="w-12">
          <span className="sr-only">{t("firewall.bans.unban")}</span>
        </Th>
      </tr>
    </thead>
  );
}

function BansTableSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite">
      <Table className="min-w-[680px]">
        <BansHead />
        <tbody>
          {Array.from({ length: rows }, (_, i) => (
            <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
              <Td className={STICKY_CELL}>
                <Skeleton className="h-4 w-28" />
              </Td>
              <Td>
                <Skeleton className={i % 2 === 0 ? "h-4 w-40" : "h-4 w-32"} />
              </Td>
              <Td>
                <Skeleton className="h-4 w-32" />
              </Td>
              <Td>
                <Skeleton className="h-5 w-24 rounded-full" />
              </Td>
              <Td>
                <Skeleton className="ms-auto h-8 w-8 rounded-lg" />
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function BanRow({
  ban,
  dateFormat,
  index,
}: {
  ban: BanRecord;
  dateFormat: Intl.DateTimeFormat;
  index: number;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const lifted = ban.lifted_at !== null;

  const unban = useMutation({
    mutationFn: () => endpoints.unban(ban.ip),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["firewall-bans"] }),
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const label = t("firewall.bans.unbanLabel", { ip: ban.ip });

  return (
    <Tr className="animate-rise-in stagger" style={staggerStyle(index)}>
      <Td className={`${STICKY_CELL} font-mono text-xs`}>{ban.ip}</Td>
      <Td className="max-w-0">
        <span className="block truncate text-ink-muted">{ban.reason}</span>
      </Td>
      <Td className="whitespace-nowrap text-ink-muted">
        {lifted
          ? t("firewall.bans.liftedAt", { at: dateFormat.format(new Date(ban.lifted_at!)) })
          : ban.expires_at === null
            ? t("firewall.bans.permanent")
            : dateFormat.format(new Date(ban.expires_at))}
      </Td>
      <Td>
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
      </Td>
      <Td className="text-end">
        {lifted ? null : (
          <Menu
            label={label}
            // Same reason as the rule table: the control stays where it is
            // while the unban is in flight, and only turns busy.
            trigger={
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={label}
                aria-haspopup="menu"
                loading={unban.isPending}
              >
                <MoreHorizontal className="h-4 w-4" aria-hidden />
              </Button>
            }
          >
            <MenuItem
              danger
              icon={<Trash2 />}
              disabled={unban.isPending}
              onClick={() => unban.mutate()}
            >
              {t("firewall.bans.unban")}
            </MenuItem>
          </Menu>
        )}
      </Td>
    </Tr>
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
            loading={submit.isPending}
            disabled={ip.trim() === "" || refusal !== null || !minutesValid}
          >
            {t("firewall.bans.submit")}
          </Button>
        </>
      }
    >
      <Field label={t("firewall.bans.ip")} htmlFor="fw-ban-ip">
        <Input
          id="fw-ban-ip"
          className="font-mono"
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
          <Callout tone="danger">
            {t(`firewall.bans.refuse.${refusal}`, { ip: ip.trim(), yourIp: yourIp ?? "" })}
          </Callout>
        )}
      </div>

      <Field
        label={t("firewall.bans.minutes")}
        htmlFor="fw-ban-minutes"
        error={minutesValid ? undefined : t("firewall.bans.minutesInvalid")}
      >
        <Input
          id="fw-ban-minutes"
          className="tnum"
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
          value={reason}
          onChange={(event) => setReason(event.target.value)}
        />
      </Field>

      {error ? (
        <Callout tone="danger" className="mt-1">
          {error}
        </Callout>
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
          <SentinelFormSkeleton />
        ) : sentinel.error ? (
          <Callout tone="danger">
            {isRouteMissing(sentinel.error)
              ? t("firewall.apiMissing")
              : sentinel.error instanceof ApiError
                ? sentinel.error.message
                : String(sentinel.error)}
          </Callout>
        ) : (
          <SentinelForm settings={sentinel.data!} backend={backend} />
        )}
      </CardBody>
    </Card>
  );
}

/** The settings form's own shape: the switch, the three numbers, the allowlist. */
function SentinelFormSkeleton() {
  return (
    <div role="status" aria-live="polite" className="space-y-4">
      <Skeleton className="h-5 w-72 max-w-full" />
      <div className="grid gap-4 sm:grid-cols-3">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
      <Skeleton className="h-16 w-full max-w-xs" />
      <Skeleton className="h-9 w-44 rounded-lg" />
    </div>
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
  const invalidEntries = draft.allowlist.filter((item) => !isCidr(item));

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
        <Callout tone="warning">{t("firewall.sentinel.noBackend")}</Callout>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-3">
        <Field
          label={t("firewall.sentinel.threshold")}
          htmlFor="sentinel-threshold"
          error={has("ssh_threshold") ? t("firewall.sentinel.thresholdInvalid") : undefined}
        >
          <Input
            id="sentinel-threshold"
            className="tnum"
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
            className="tnum"
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
            className="tnum"
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
              <li key={item} className="animate-pop-in">
                {/* A chip the pointer can actually hit: the remove button is a
                    24px target rather than a 12px glyph, and a bad entry says
                    so with an icon — three red chips in a row of blue ones is
                    colour doing work that a word should. */}
                <Badge tone={isCidr(item) ? "accent" : "danger"} className="py-1">
                  {isCidr(item) ? null : (
                    <>
                      <AlertTriangle className="h-3 w-3" aria-hidden />
                      <span className="sr-only">{t("firewall.sentinel.allowlistInvalidTag")}</span>
                    </>
                  )}
                  <span className="font-mono">{item}</span>
                  <button
                    type="button"
                    className="-me-1.5 grid h-6 w-6 place-items-center rounded-full transition-colors hover:bg-ink/10 hover:text-ink"
                    aria-label={t("firewall.sentinel.allowlistRemove", { entry: item })}
                    onClick={() =>
                      patch({ allowlist: draft.allowlist.filter((other) => other !== item) })
                    }
                  >
                    <X className="h-3.5 w-3.5" aria-hidden />
                  </button>
                </Badge>
              </li>
            ))}
          </ul>
        ) : null}

        <div className="flex items-start gap-2">
          <Input
            className="max-w-xs font-mono"
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
        {/* Names the offending chips instead of repeating the draft field's
            sentence: one shared line under three chips left the colour to say
            which one was wrong. */}
        {has("allowlist") ? (
          <p role="alert" className="mt-1.5 text-xs text-danger">
            {t("firewall.sentinel.allowlistEntryInvalid", {
              count: invalidEntries.length,
              entries: invalidEntries.join(", "),
            })}
          </p>
        ) : null}
      </fieldset>

      {error ? <Callout tone="danger">{error}</Callout> : null}

      <div className="flex items-center gap-3">
        <Button
          variant="primary"
          onClick={() => save.mutate()}
          loading={save.isPending}
          disabled={problems.length > 0}
        >
          {t("firewall.sentinel.save")}
        </Button>
        {saved ? (
          <Badge tone="success" className="animate-pop-in" role="status" dot>
            {t("firewall.sentinel.saved")}
          </Badge>
        ) : null}
      </div>
    </div>
  );
}
