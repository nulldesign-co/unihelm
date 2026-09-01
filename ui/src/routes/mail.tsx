import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, ChevronRight, Copy, Mail, Send, ShieldAlert } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { TaskNotice } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  ApiError,
  endpoints,
  type MailDnsRecord,
  type MailRelayResponse,
  type MailTestReport,
  type TlsMode,
} from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import { cn } from "@/lib/utils";

/**
 * Outbound mail (spec §11.18).
 *
 * The page has to be honest about three things, and each one is a design
 * decision rather than a label:
 *
 * 1. **Unihelm runs no mail server.** This configures somebody else's SMTP
 *    relay and points every PHP site's `mail()` at it. There are no mailboxes
 *    to manage here and the page says so, because a "Mail" item in a hosting
 *    panel's navigation promises mailboxes to almost everybody who clicks it.
 * 2. **The password is write-only.** It cannot be read back from anywhere, so
 *    the field is left empty on load and an empty field means "keep the stored
 *    one". That is stated next to the input rather than discovered by an
 *    operator whose relay stopped working after they changed the port.
 * 3. **A failed test is an answer.** `mail.relay.test` returns 200 with
 *    `delivered: false`, the stage it reached and the relay's own words. The
 *    result panel renders the stage prominently, because "which step failed"
 *    is the entire difference between a wrong password and a wrong sender
 *    domain.
 *
 * SPF, DKIM and DMARC are shown as records to copy and are explicitly *not*
 * managed. The DKIM row has no value because only the relay provider knows the
 * selector; showing an empty value with an explanation is the truthful version
 * of that row.
 */
export function MailPage() {
  const { t } = useTranslation();
  const relay = useQuery({ queryKey: ["mail-relay"], queryFn: endpoints.mailRelay });

  return (
    <div className="space-y-6">
      <PageHeader title={t("mail.title")} description={t("mail.subtitle")} />

      <Callout tone="info">{t("mail.scopeNote")}</Callout>

      {relay.isPending ? (
        <MailSkeleton />
      ) : relay.error ? (
        <Callout tone="danger">
          {relay.error instanceof ApiError ? relay.error.message : String(relay.error)}
        </Callout>
      ) : (
        <>
          {relay.data && !relay.data.agent_installed ? (
            <AgentMissing agent={relay.data.agent} />
          ) : null}
          <RelayForm relay={relay.data!} />
          {relay.data?.configured ? <TestCard /> : null}
          <DnsCard dns={relay.data!.dns} />
        </>
      )}
    </div>
  );
}

/**
 * A note that belongs to the field above it.
 *
 * The negative top margin absorbs the line `Field` reserves for a validation
 * error, so a hint sits against its input instead of a row below it. Named once
 * here rather than hand-tuned at every field, which is how the six copies of it
 * drifted apart.
 */
function FieldNote({ id, children }: { id?: string; children: ReactNode }) {
  return (
    <p id={id} className="-mt-1 mb-3 text-xs text-ink-muted">
      {children}
    </p>
  );
}

/** Ghosts shaped like the relay form and the DNS card, so nothing jumps. */
function MailSkeleton() {
  return (
    <div role="status" aria-live="polite" className="space-y-6">
      {/* The shared Card, not a copy of its classes: a change to the card's
          border or radius has to reach the loading state too. */}
      <Card className="p-5">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="mt-2 h-3.5 w-72 max-w-full" />
        <div className="mt-6 grid gap-4 sm:grid-cols-2">
          <Skeleton className="h-9" />
          <Skeleton className="h-9" />
          <Skeleton className="h-9" />
          <Skeleton className="h-9" />
        </div>
        <Skeleton className="mt-6 h-9 w-32" />
      </Card>
      <Card className="p-5">
        <Skeleton className="h-4 w-40" />
        <div className="mt-4 space-y-3">
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
        </div>
      </Card>
    </div>
  );
}

/**
 * The relay is stored but PHP has nothing to hand a message to.
 *
 * Its own banner rather than a field note: no amount of correct relay
 * configuration makes mail work while this is true.
 */
function AgentMissing({ agent }: { agent: string }) {
  const { t } = useTranslation();
  return (
    <Callout tone="warning" title={t("mail.agentMissing")}>
      {t("mail.agentMissingHint", { agent })}
    </Callout>
  );
}

const TLS_MODES: TlsMode[] = ["starttls", "implicit", "none"];

/**
 * The one refusal this page makes for itself.
 *
 * The agent refuses the same combination and is the authority; saying it here
 * as well turns a round trip into an inline message, and — more usefully — puts
 * the reason next to the field that caused it. base64 is an encoding, not
 * encryption, so a credential configured against a plaintext relay is a
 * credential that would cross the network readable.
 *
 * Exported so the reasoning is testable rather than buried in a render.
 */
export function credentialNeedsTls(username: string, tlsMode: TlsMode): boolean {
  return username.trim() !== "" && tlsMode === "none";
}

function RelayForm({ relay }: { relay: MailRelayResponse }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [host, setHost] = useState(relay.host ?? "");
  const [port, setPort] = useState(String(relay.port ?? 587));
  const [tlsMode, setTlsMode] = useState<TlsMode>(relay.tls_mode ?? "starttls");
  const [username, setUsername] = useState(relay.username ?? "");
  // Always empty on load: the stored password cannot be read back, and
  // pre-filling a placeholder would make "did I change it?" unanswerable.
  const [password, setPassword] = useState("");
  const [fromAddress, setFromAddress] = useState(relay.from_address ?? "");
  const [fromName, setFromName] = useState(relay.from_name ?? "");
  const [enabled, setEnabled] = useState(relay.enabled);

  // Re-seed once the query settles, so a page opened before the fetch finished
  // does not keep an empty form.
  useEffect(() => {
    setHost(relay.host ?? "");
    setPort(String(relay.port ?? 587));
    setTlsMode(relay.tls_mode ?? "starttls");
    setUsername(relay.username ?? "");
    setFromAddress(relay.from_address ?? "");
    setFromName(relay.from_name ?? "");
    setEnabled(relay.enabled);
  }, [relay]);

  const credentialWithoutTls = credentialNeedsTls(username, tlsMode);

  const save = useMutation({
    mutationFn: () =>
      endpoints.setMailRelay({
        host: host.trim(),
        port: Number(port),
        tls_mode: tlsMode,
        username: username.trim() === "" ? undefined : username.trim(),
        // Absent means "keep the stored password". Sending "" would clear it.
        ...(password === "" ? {} : { password }),
        from_address: fromAddress.trim(),
        from_name: fromName.trim() === "" ? undefined : fromName.trim(),
        enabled,
      }),
    onSuccess: (accepted) => {
      setError(null);
      setPassword("");
      setTaskId(accepted.task_id);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Card>
      <CardHeader
        title={t("mail.relay.title")}
        description={t("mail.relay.hint")}
        action={
          relay.configured ? (
            <Badge tone={relay.enabled ? "success" : "neutral"} dot>
              {relay.enabled ? t("mail.relay.on") : t("mail.relay.off")}
            </Badge>
          ) : null
        }
      />
      <CardBody>
        <form
          className="space-y-1"
          onSubmit={(event) => {
            event.preventDefault();
            if (credentialWithoutTls) return;
            save.mutate();
          }}
        >
          <div className="grid gap-x-4 sm:grid-cols-[2fr_1fr]">
            <Field label={t("mail.relay.host")} htmlFor="mail-host">
              <Input
                id="mail-host"
                autoComplete="off"
                placeholder="smtp.example.net"
                value={host}
                onChange={(e) => setHost(e.target.value)}
              />
            </Field>
            <Field label={t("mail.relay.port")} htmlFor="mail-port">
              <Input
                id="mail-port"
                inputMode="numeric"
                className="tnum"
                value={port}
                onChange={(e) => setPort(e.target.value)}
              />
            </Field>
          </div>

          <Field label={t("mail.relay.tls")} htmlFor="mail-tls">
            <Select
              id="mail-tls"
              value={tlsMode}
              onChange={(e) => setTlsMode(e.target.value as TlsMode)}
            >
              {TLS_MODES.map((mode) => (
                <option key={mode} value={mode}>
                  {t(`mail.relay.tlsMode.${mode}`)}
                </option>
              ))}
            </Select>
          </Field>
          <FieldNote>{t(`mail.relay.tlsHint.${tlsMode}`)}</FieldNote>

          <div className="grid gap-x-4 sm:grid-cols-2">
            <Field label={t("mail.relay.username")} htmlFor="mail-user">
              <Input
                id="mail-user"
                autoComplete="off"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </Field>
            <Field label={t("mail.relay.password")} htmlFor="mail-pass">
              <Input
                id="mail-pass"
                type="password"
                autoComplete="new-password"
                placeholder={relay.has_password ? t("mail.relay.passwordStored") : ""}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
          </div>
          <FieldNote>{t("mail.relay.passwordHint")}</FieldNote>

          {credentialWithoutTls ? (
            <Callout tone="danger" className="mb-3">
              {t("mail.relay.credentialNeedsTls")}
            </Callout>
          ) : null}

          <div className="grid gap-x-4 sm:grid-cols-2">
            <Field label={t("mail.relay.fromAddress")} htmlFor="mail-from">
              <Input
                id="mail-from"
                autoComplete="off"
                placeholder="noreply@example.com"
                value={fromAddress}
                onChange={(e) => setFromAddress(e.target.value)}
              />
            </Field>
            <Field label={t("mail.relay.fromName")} htmlFor="mail-from-name">
              <Input
                id="mail-from-name"
                autoComplete="off"
                value={fromName}
                onChange={(e) => setFromName(e.target.value)}
              />
            </Field>
          </div>
          <FieldNote>{t("mail.relay.fromHint")}</FieldNote>

          <Switch
            checked={enabled}
            onChange={setEnabled}
            label={t("mail.relay.enabled")}
            description={t("mail.relay.enabledHint")}
          />

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Button
              type="submit"
              variant="primary"
              loading={save.isPending}
              disabled={credentialWithoutTls}
            >
              <Mail className="h-4 w-4" aria-hidden />
              {t("mail.relay.save")}
            </Button>
          </div>

          {error ? (
            <Callout tone="danger" className="mt-3">
              {error}
            </Callout>
          ) : null}

          {taskId ? (
            <TaskNotice
              taskId={taskId}
              onSettled={() => void queryClient.invalidateQueries({ queryKey: ["mail-relay"] })}
            />
          ) : null}
        </form>

        <div className="mt-4 flex gap-3 rounded-lg bg-surface-muted px-3 py-2.5">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
          <p className="text-xs text-ink-muted">{t("mail.credentialNote")}</p>
        </div>
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Sending a real message
// ---------------------------------------------------------------------------

function TestCard() {
  const { t } = useTranslation();
  const [to, setTo] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<MailTestReport | null>(null);

  const test = useMutation({
    mutationFn: () => endpoints.testMailRelay(to.trim() === "" ? undefined : to.trim()),
    onSuccess: (result) => {
      setError(null);
      setReport(result);
    },
    // Only a caller mistake or "no relay configured" lands here; a relay that
    // rejects the message answers 200 and is rendered as a report.
    onError: (e) => {
      setReport(null);
      setError(e instanceof ApiError ? e.message : String(e));
    },
  });

  return (
    <Card>
      <CardHeader title={t("mail.test.title")} description={t("mail.test.hint")} />
      <CardBody>
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            test.mutate();
          }}
        >
          {/* A plain label rather than `Field`: nothing validates this input
              inline, and Field's reserved error line is what used to force a
              magic offset on the button to keep it level — an offset that
              became an orphan gap the moment the row wrapped at 375px. */}
          <div className="min-w-56 flex-1 space-y-1.5">
            <label htmlFor="mail-test-to" className="block text-sm font-medium text-ink">
              {t("mail.test.to")}
            </label>
            <Input
              id="mail-test-to"
              autoComplete="off"
              placeholder={t("mail.test.toPlaceholder")}
              value={to}
              onChange={(e) => setTo(e.target.value)}
            />
          </div>
          <Button type="submit" variant="primary" loading={test.isPending}>
            <Send className="h-4 w-4" aria-hidden />
            {t("mail.test.send")}
          </Button>
        </form>

        {error ? (
          <Callout tone="danger" className="mt-4">
            {error}
          </Callout>
        ) : null}

        {report ? <TestReport report={report} /> : null}
      </CardBody>
    </Card>
  );
}

function TestReport({ report }: { report: MailTestReport }) {
  const { t } = useTranslation();
  return (
    // The Callout's icon and title carry the verdict, so the tint is
    // reinforcement rather than the only signal.
    <Callout
      tone={report.delivered ? "success" : "danger"}
      title={report.delivered ? t("mail.test.delivered") : t("mail.test.failed")}
      className="mt-4"
    >
      <div className="flex flex-wrap items-center gap-2">
        {/* The stage is the headline on a failure: it is the difference
            between a wrong password and a wrong sender domain. */}
        <Badge tone="neutral">{t(`mail.stage.${report.stage}`)}</Badge>
        <Badge tone={report.encrypted ? "success" : "warning"} dot>
          {report.encrypted ? t("mail.test.encrypted") : t("mail.test.plaintext")}
        </Badge>
      </div>

      {/* The relay's own words, verbatim: paraphrasing an SMTP reply throws
          away the only precise thing in the response. Tabular figures because
          every one of those replies opens with a three-digit code. */}
      <p className="tnum mt-2 font-mono text-xs break-words text-ink">{report.detail}</p>
      <p className="mt-1.5 text-xs">{t(`mail.stageHint.${report.stage}`)}</p>

      {report.transcript.length > 0 ? (
        <details className="group mt-2">
          <summary className="flex cursor-pointer list-none items-center gap-1 text-xs font-medium text-ink-muted [&::-webkit-details-marker]:hidden">
            <ChevronRight
              className="h-3 w-3 transition-transform duration-200 ease-standard group-open:rotate-90 motion-reduce:transition-none"
              aria-hidden
            />
            {t("mail.test.transcript")}
          </summary>
          {/* The body animates as it is revealed: `details` has no height
              transition, and 14rem of log arriving in one frame reads as a
              jump rather than as an expansion. */}
          <div className="mt-1.5 max-h-56 animate-slide-up overflow-y-auto rounded-lg bg-canvas p-2">
            {report.transcript.map((line, index) => (
              <div
                // The transcript is an ordered log with repeated lines; the
                // index is genuinely its identity here.
                key={index}
                className="tnum font-mono text-xs break-all whitespace-pre-wrap text-ink-muted"
              >
                {line}
              </div>
            ))}
          </div>
          <p className="mt-1 text-xs text-ink-subtle">{t("mail.test.transcriptNote")}</p>
        </details>
      ) : null}
    </Callout>
  );
}

// ---------------------------------------------------------------------------
// SPF / DKIM / DMARC — guidance, never management
// ---------------------------------------------------------------------------

function DnsCard({ dns }: { dns: { records: MailDnsRecord[]; advice: string } }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader title={t("mail.dns.title")} description={t("mail.dns.hint")} />
      <CardBody>
        <p className="mb-3 text-sm text-ink-muted">{dns.advice}</p>
        {dns.records.length === 0 ? (
          <EmptyState
            icon={<Mail aria-hidden />}
            title={t("mail.dns.noneTitle")}
            hint={t("mail.dns.none")}
            className="py-10"
          />
        ) : (
          <ul className="divide-y divide-border">
            {dns.records.map((record, index) => (
              <li
                key={`${record.record_type}-${record.name}`}
                className="stagger animate-rise-in py-4 first:pt-0 last:pb-0"
                style={staggerStyle(index)}
              >
                <RecordRow record={record} />
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}

function RecordRow({ record }: { record: MailDnsRecord }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    if (!record.value) return;
    try {
      await navigator.clipboard.writeText(record.value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // A denied clipboard permission is not worth an error banner; the value
      // is on screen and selectable.
      setCopied(false);
    }
  };

  return (
    <div>
      {/* The two badges share a row of their own and the name gets the next
          one. A long TXT name used to push the `ms-auto` badge onto a second
          line at 375px, which read as two unrelated fragments. */}
      <div className="flex items-center gap-2">
        <Badge tone="accent">{record.record_type}</Badge>
        {/* Stated on every row, not once at the top: this is the difference
            between a panel that manages DNS and one that suggests records. */}
        <Badge tone="neutral" className="ms-auto">
          {t("mail.dns.notManaged")}
        </Badge>
      </div>
      <p className="mt-1.5 font-mono text-xs break-all text-ink">{record.name}</p>

      {record.value ? (
        <div className="mt-2 flex items-start gap-2">
          <code className="flex-1 rounded-lg bg-surface-muted px-2 py-1.5 font-mono text-xs break-all text-ink">
            {record.value}
          </code>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void copy()}
            aria-label={copied ? t("mail.dns.copied") : t("mail.dns.copy")}
          >
            {copied ? (
              <Check className="h-3.5 w-3.5 text-success" aria-hidden />
            ) : (
              <Copy className="h-3.5 w-3.5" aria-hidden />
            )}
            {/* Both labels sit in one grid cell so the button keeps the wider
                one's width: a button that grows on "Copied" shoves the value
                the user just copied sideways. */}
            <span aria-hidden className="grid">
              <span
                className={cn(
                  "col-start-1 row-start-1 transition-opacity duration-150",
                  copied && "opacity-0",
                )}
              >
                {t("mail.dns.copy")}
              </span>
              <span
                className={cn(
                  "col-start-1 row-start-1 transition-opacity duration-150",
                  !copied && "opacity-0",
                )}
              >
                {t("mail.dns.copied")}
              </span>
            </span>
          </Button>
        </div>
      ) : (
        <p className="mt-2 rounded-lg bg-surface-muted px-2 py-1.5 text-xs text-ink-muted">
          {t("mail.dns.noValue")}
        </p>
      )}

      <p className="mt-1.5 text-xs text-ink-muted">{record.purpose}</p>
    </div>
  );
}
