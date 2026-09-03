import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  ExternalLink,
  Globe,
  Monitor,
  Moon,
  ShieldCheck,
  Sun,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { TaskLogPanel } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { ApiError, api, type TaskAccepted } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import { useTheme, type Theme } from "@/lib/theme";
import { cn } from "@/lib/utils";

/**
 * Settings — the panel's own address, and its own appearance (spec §11.5).
 *
 * Two sections that have nothing to do with each other except that both are
 * about the panel rather than about anything it hosts, and both were previously
 * unreachable: the domain lived only in `panel.tls.issue` on the command line,
 * the theme only in the command palette, where a setting is something you find
 * by already knowing it exists.
 *
 * The decisions:
 *
 * 1. **Both warnings are stated before the button, and the second one again in
 *    a confirmation.** `panel.tls.issue` has two ways to surprise an operator:
 *    it needs DNS to already point here (the CA fetches the HTTP-01 challenge
 *    from wherever the name resolves, which the panel does not control), and on
 *    success nginx starts serving the panel on the new name — so the tab you
 *    clicked from is now on the *old* address. The first is a precondition and
 *    sits in the form permanently. The second is a consequence, so it is
 *    repeated in a dialog that names the exact URL to move to, because "the
 *    thing I am looking at is about to move" is not a sentence anyone reads
 *    twice on a form they have already decided to submit. That dialog appears
 *    only when the panel will actually move: re-issuing the certificate for the
 *    domain already in place moves nothing, and neither does a staging order —
 *    `write_issued` skips the write and `release_domain` hands the name back —
 *    and a confirmation for a consequence that does not happen is the one
 *    people learn to click through. The standing warning is conditional for
 *    the same reason: with staging on, "the panel's address changes" is not
 *    true, and a paragraph that contradicts the switch below it is worse than
 *    either sentence on its own.
 *
 * 2. **The log, not a chip.** The operation is a task, and its output *is* the
 *    answer: which directory it asked, whether the account registered, where
 *    the certificate was written, whether nginx reloaded onto it. A ninety
 *    second wait behind a "queued" badge, on an operation that ends by changing
 *    the address you are reading it on, is the wrong amount of information.
 *    `TaskLogPanel` for that reason (the backups page's argument, same shape).
 *
 * 3. **One theme preview, not three.** The obvious design is a miniature per
 *    option, each drawn in its own palette. It cannot be built honestly here:
 *    light is the token set on the document root and dark is a class that
 *    overrides it, so a *light* miniature nested inside a dark page has no way
 *    back to light values — custom properties inherit downwards and there is no
 *    `.light` scope to nest. Hardcoding the palette into this file to fake it
 *    would also be a second copy of a palette that white-label branding
 *    overwrites at runtime, which is the copy that goes stale. So there is one
 *    preview, drawn from the live tokens, and it is truthful in every
 *    combination: picking an option repaints the panel underneath it in the
 *    same frame.
 *
 * 4. **The two endpoints are typed here.** `/api/server/panel-tls` is not in
 *    `lib/api.ts`; this page calls `api.get`/`api.post` directly with the
 *    shapes from `routes/panel_tls.rs`, the way the site detail page reads
 *    `/api/certificates`. If a second caller ever appears, that is the moment
 *    it earns a place in the shared client.
 */
export function SettingsPage() {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <PageHeader title={t("settings.title")} description={t("settings.subtitle")} />
      <DomainCard />
      <ThemeCard />
    </div>
  );
}

// ---------------------------------------------------------------------------
// The panel's own domain
// ---------------------------------------------------------------------------

/** Every status `certificates.status` can hold — see `unihelm-db/certificates.rs`. */
type CertificateStatus =
  | "pending"
  | "active"
  | "superseded"
  | "expired"
  | "failed"
  | "revoked";

/** `GET /api/server/panel-tls` — see `unihelm-web/src/routes/panel_tls.rs`. */
interface PanelTlsStatus {
  /** Absent until the first issuance; present but failed after one that broke. */
  domain: string | null;
  certificate_status: CertificateStatus | null;
  /** Negative once the certificate has passed its expiry. */
  days_remaining: number | null;
  last_error?: string | null;
}

interface PanelTlsRequest {
  domain: string;
  contact_email?: string;
  staging: boolean;
}

const STATUS_TONE: Record<CertificateStatus, "success" | "accent" | "warning" | "danger"> = {
  active: "success",
  pending: "accent",
  superseded: "warning",
  expired: "danger",
  failed: "danger",
  revoked: "danger",
};

function DomainCard() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const status = useQuery({
    queryKey: ["panel-tls"],
    queryFn: () => api.get<PanelTlsStatus>("/api/server/panel-tls"),
  });

  const [domain, setDomain] = useState("");
  const [contact, setContact] = useState("");
  const [staging, setStaging] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // A field-tagged rejection belongs on the field. `panel_tls.rs` parses the
  // domain and the address before it queues anything precisely so this can
  // happen, and a banner would throw that away.
  const [fieldError, setFieldError] = useState<string | null>(null);

  // Seeded from the stored domain, and re-seeded when it changes — which is
  // what makes "re-issue" one click instead of retyping the name you are
  // already being served on. A successful issuance invalidates this query, so
  // the field follows the panel to its new name rather than holding the old.
  const current = status.data?.domain ?? null;
  useEffect(() => {
    setDomain(current ?? "");
  }, [current]);

  const trimmed = domain.trim();
  // A name the panel is not already answering on is what the button offers to
  // attach, and what its label has to say.
  const renaming = trimmed !== "" && trimmed !== current;
  // Whether the panel *moves* is a narrower question. A staging order installs
  // nothing — `write_issued` returns false before the vhost is touched and
  // `release_domain` puts the old name back — so it leaves the address alone
  // however different the name in the field is.
  const moving = renaming && !staging;

  const issue = useMutation({
    mutationFn: () =>
      api.post<TaskAccepted>("/api/server/panel-tls", {
        domain: trimmed,
        contact_email: contact.trim() === "" ? undefined : contact.trim(),
        staging,
      } satisfies PanelTlsRequest),
    onSuccess: (accepted) => {
      setError(null);
      setFieldError(null);
      setTaskId(accepted.task_id);
    },
    onError: (e) => {
      if (e instanceof ApiError && e.field === "domain") {
        setFieldError(e.message);
        setError(null);
        return;
      }
      setFieldError(null);
      setError(e instanceof ApiError ? e.message : String(e));
    },
  });

  return (
    <Card>
      <CardHeader
        title={t("settings.domain.title")}
        description={t("settings.domain.hint")}
        action={
          status.data?.certificate_status ? (
            <Badge tone={STATUS_TONE[status.data.certificate_status]} dot>
              {t(`settings.domain.status.${status.data.certificate_status}`)}
            </Badge>
          ) : null
        }
      />
      <CardBody className="space-y-4">
        {status.isPending ? (
          <DomainSkeleton />
        ) : status.error ? (
          <Callout tone="danger">
            {status.error instanceof ApiError ? status.error.message : String(status.error)}
          </Callout>
        ) : status.data?.domain ? (
          <CurrentDomain status={status.data} />
        ) : (
          <EmptyState
            icon={<Globe aria-hidden />}
            title={t("settings.domain.noneTitle")}
            hint={t("settings.domain.noneHint")}
            className="py-10"
          />
        )}

        {/* Standing facts about the form, not a problem with the server, so
            `info` rather than `warning` — a warning carries `role="alert"` and
            would interrupt a screen reader on every load to explain how the
            page works. The urgency belongs to the confirmation, which fires
            once, at the moment it is true.

            The challenge is fetched over the public internet either way, so
            the DNS precondition holds for both directories. What follows it
            does not: a staging order ends without installing anything. */}
        <Callout
          tone="info"
          title={staging ? t("settings.domain.stagingTitle") : t("settings.domain.beforeTitle")}
        >
          <p>{t("settings.domain.beforeDns")}</p>
          <p className="mt-1.5">
            {staging ? t("settings.domain.beforeStaging") : t("settings.domain.beforeMove")}
          </p>
        </Callout>

        <form
          className="space-y-1"
          onSubmit={(event) => {
            event.preventDefault();
            if (trimmed === "") {
              setFieldError(t("settings.domain.required"));
              return;
            }
            setFieldError(null);
            // A renewal of the name already in place moves nothing, and a
            // confirmation for a change that does not happen is the dialog
            // people learn to click through.
            if (moving) setConfirming(true);
            else issue.mutate();
          }}
        >
          <div className="grid gap-x-4 sm:grid-cols-2">
            <Field
              label={t("settings.domain.domainLabel")}
              htmlFor="panel-domain"
              error={fieldError ?? undefined}
            >
              <Input
                id="panel-domain"
                autoComplete="off"
                spellCheck={false}
                placeholder="panel.example.com"
                aria-invalid={fieldError ? true : undefined}
                value={domain}
                onChange={(e) => {
                  setDomain(e.target.value);
                  setFieldError(null);
                }}
              />
            </Field>
            <Field label={t("settings.domain.contactLabel")} htmlFor="panel-contact">
              <Input
                id="panel-contact"
                type="email"
                autoComplete="off"
                placeholder="admin@example.com"
                value={contact}
                onChange={(e) => setContact(e.target.value)}
              />
            </Field>
          </div>
          {/* The negative margin absorbs the line `Field` reserves for a
              validation message, so the hint sits against its inputs. */}
          <p className="-mt-1 mb-3 text-xs text-ink-muted">
            {t("settings.domain.contactHint")}
          </p>

          <Switch
            checked={staging}
            onChange={setStaging}
            label={t("settings.domain.staging")}
            description={t("settings.domain.stagingHint")}
          />

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Button type="submit" variant="primary" loading={issue.isPending}>
              <ShieldCheck className="h-4 w-4" aria-hidden />
              {/* "Re-issue" only when the name is the one already in place —
                  an empty field on a panel with no domain is still an attach. */}
              {renaming || current === null
                ? t("settings.domain.submit")
                : t("settings.domain.reissue")}
            </Button>
          </div>

          {error ? (
            <Callout tone="danger" className="mt-3">
              {error}
            </Callout>
          ) : null}

          {/* The ACME conversation, line by line. It is the only place that
              says which step of "order, challenge, write, reload" the panel
              actually reached. */}
          {taskId ? (
            <TaskLogPanel
              key={taskId}
              taskId={taskId}
              onSettled={() => void queryClient.invalidateQueries({ queryKey: ["panel-tls"] })}
            />
          ) : null}
        </form>
      </CardBody>

      <ConfirmMove
        open={confirming}
        domain={trimmed}
        onClose={() => setConfirming(false)}
        // Closed before the mutation, not after it: the log panel is on the
        // page behind this dialog, and it is the thing worth watching.
        onConfirm={() => {
          setConfirming(false);
          issue.mutate();
        }}
      />
    </Card>
  );
}

/** Ghosts shaped like the status block, so the card does not resize. */
function DomainSkeleton() {
  return (
    <div role="status" aria-live="polite" className="rounded-lg bg-surface-muted px-3 py-2.5">
      <Skeleton className="h-4 w-52 max-w-full" />
      <Skeleton className="mt-2 h-3.5 w-32" />
    </div>
  );
}

/**
 * What the panel is serving now — including a domain whose issuance failed.
 *
 * `panel.tls.issue` records the domain before it attempts anything, so this
 * reads "panel.example.com — issuance failed" rather than "no domain
 * configured", which is the distinction the operation goes out of its way to
 * preserve (see `release_domain`).
 */
function CurrentDomain({ status }: { status: PanelTlsStatus }) {
  const { t } = useTranslation();
  const days = status.days_remaining;
  const url = `https://${status.domain}`;

  return (
    <div className="rounded-lg bg-surface-muted px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <span className="font-mono text-sm break-all text-ink">{status.domain}</span>
        <a
          href={url}
          target="_blank"
          rel="noreferrer noopener"
          className="inline-flex items-center gap-1.5 text-sm text-ink-muted transition-colors hover:text-accent"
        >
          <ExternalLink className="h-3.5 w-3.5" aria-hidden />
          {t("settings.domain.open")}
        </a>
      </div>

      {days !== null ? (
        <p className="tnum mt-1 text-xs text-ink-muted">
          {days < 0 ? t("settings.domain.expiredAgo") : t("settings.domain.daysLeft", { count: days })}
        </p>
      ) : null}

      {/* The agent's own words. Paraphrasing an ACME failure discards the only
          precise thing in it. */}
      {status.last_error ? (
        <p className="mt-1.5 font-mono text-xs break-words text-danger">
          {t("settings.domain.lastError")} {status.last_error}
        </p>
      ) : null}
    </div>
  );
}

/**
 * The one thing that cannot be undone by clicking again.
 *
 * It names the URL rather than describing it: an operator who is about to lose
 * the address they are on should be able to read the new one, not reconstruct
 * it from a sentence.
 */
function ConfirmMove({
  open,
  domain,
  onClose,
  onConfirm,
}: {
  open: boolean;
  domain: string;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const { t } = useTranslation();
  const url = `https://${domain}`;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("settings.domain.confirmTitle", { domain })}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={onConfirm}>
            <ShieldCheck className="h-4 w-4" aria-hidden />
            {t("settings.domain.confirm")}
          </Button>
        </>
      }
    >
      <p className="text-sm text-ink-muted">{t("settings.domain.confirmMove")}</p>
      <p className="mt-2 rounded-lg bg-surface-muted px-3 py-2 font-mono text-sm break-all text-ink">
        {url}
      </p>
      <p className="mt-3 text-sm text-ink-muted">{t("settings.domain.confirmDns", { domain })}</p>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

const THEMES: { value: Theme; icon: LucideIcon }[] = [
  { value: "light", icon: Sun },
  { value: "dark", icon: Moon },
  { value: "system", icon: Monitor },
];

function ThemeCard() {
  const { t } = useTranslation();
  const { theme, resolved, setTheme } = useTheme();

  return (
    <Card>
      <CardHeader title={t("settings.theme.title")} description={t("settings.theme.hint")} />
      <CardBody>
        <fieldset className="grid gap-3 sm:grid-cols-3">
          <legend className="sr-only">{t("settings.theme.legend")}</legend>
          {THEMES.map(({ value, icon: Icon }, index) => (
            <ThemeOption
              key={value}
              value={value}
              Icon={Icon}
              selected={theme === value}
              index={index}
              onSelect={() => setTheme(value)}
            />
          ))}
        </fieldset>

        {/* "System" is the one option whose label does not tell you the
            outcome, so this line answers it for the machine in front of you. */}
        {theme === "system" ? (
          <p className="mt-3 text-xs text-ink-muted">
            {t("settings.theme.systemNow", { mode: t(`settings.theme.${resolved}`) })}
          </p>
        ) : null}

        <ThemePreview resolved={resolved} />
      </CardBody>
    </Card>
  );
}

/**
 * One choice, as a card you can click anywhere on.
 *
 * A real radio underneath — the panel's `Switch` makes the same bargain — so
 * arrow keys move between the three and a screen reader announces a group of
 * three rather than three unrelated buttons. The selected state is carried by
 * the border, the tinted mark *and* the check, because a border colour on its
 * own is colour as the only signal.
 */
function ThemeOption({
  value,
  Icon,
  selected,
  index,
  onSelect,
}: {
  value: Theme;
  Icon: LucideIcon;
  selected: boolean;
  index: number;
  onSelect: () => void;
}) {
  const { t } = useTranslation();

  return (
    <label
      className={cn(
        "stagger flex animate-rise-in cursor-pointer items-start gap-3 rounded-card border bg-surface p-3 shadow-card",
        "transition-[transform,box-shadow,border-color] duration-200 ease-standard",
        "hover:-translate-y-0.5 hover:shadow-card-hover motion-reduce:hover:translate-y-0",
        "has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-accent",
        selected ? "border-accent" : "border-border hover:border-border-strong",
      )}
      style={staggerStyle(index)}
    >
      <input
        type="radio"
        name="panel-theme"
        value={value}
        className="sr-only"
        checked={selected}
        onChange={onSelect}
      />
      <span
        aria-hidden
        className={cn(
          "grid h-8 w-8 shrink-0 place-items-center rounded-lg",
          selected ? "bg-accent-soft text-accent" : "bg-surface-muted text-ink-subtle",
        )}
      >
        <Icon className="h-4 w-4" />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-medium text-ink">{t(`settings.theme.${value}`)}</span>
        <span className="mt-0.5 block text-xs text-ink-muted">
          {t(`settings.theme.${value}Hint`)}
        </span>
      </span>
      {selected ? (
        <Check className="h-4 w-4 shrink-0 animate-pop-in text-accent" aria-hidden />
      ) : null}
    </label>
  );
}

/**
 * The panel, in miniature, in whichever palette is live.
 *
 * Every block here is a design token — canvas behind surface, the border that
 * separates them, muted ink for a heading, the accent for the primary button
 * and its glow — so this is not a picture of the theme, it is the theme. It
 * re-enters on `resolved` rather than transitioning its colours: the house
 * animates transform, opacity and filter, and `key` + `animate-pop-in` is how
 * the header's own theme toggle marks the same change.
 */
function ThemePreview({ resolved }: { resolved: "light" | "dark" }) {
  const { t } = useTranslation();

  return (
    <div className="mt-5">
      <p className="text-xs font-medium text-ink-muted">{t("settings.theme.preview")}</p>
      <div
        aria-hidden
        className="mt-1.5 rounded-card border border-border bg-canvas p-3 shadow-card"
      >
        <div key={resolved} className="flex animate-pop-in gap-3">
          <div className="w-14 shrink-0 space-y-1.5">
            <div className="h-1.5 w-8 rounded-full bg-accent" />
            <div className="h-1.5 w-full rounded-full bg-border-strong" />
            <div className="h-1.5 w-10 rounded-full bg-border-strong" />
            <div className="h-1.5 w-11 rounded-full bg-border-strong" />
          </div>
          <div className="min-w-0 flex-1 space-y-1.5 rounded-lg border border-border bg-surface p-2.5 shadow-card">
            <div className="h-1.5 w-1/3 rounded-full bg-ink-muted" />
            <div className="h-1.5 w-2/3 rounded-full bg-border-strong" />
            <div className="h-1.5 w-1/2 rounded-full bg-border-strong" />
            <div className="mt-2.5 h-3.5 w-14 rounded-md bg-accent shadow-glow" />
          </div>
        </div>
      </div>
      {/* The drawing is decoration; this is the sentence a screen reader gets. */}
      <p className="sr-only" role="status" aria-live="polite">
        {t("settings.theme.showing", { mode: t(`settings.theme.${resolved}`) })}
      </p>
    </div>
  );
}
