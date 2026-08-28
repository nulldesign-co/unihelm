import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Copy, Mail, Send, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { TaskNotice } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import {
  ApiError,
  endpoints,
  type MailDnsRecord,
  type MailRelayResponse,
  type MailTestReport,
  type TlsMode,
} from "@/lib/api";

/**
 * Outbound mail (spec §11.18).
 *
 * The page has to be honest about three things, and each one is a design
 * decision rather than a label:
 *
 * 1. **Ferrum runs no mail server.** This configures somebody else's SMTP
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
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("mail.title")}</h1>
        <p className="mt-1 text-sm text-ink-muted">{t("mail.subtitle")}</p>
      </header>

      <p className="rounded-lg bg-surface-muted px-3 py-2.5 text-sm text-ink-muted">
        {t("mail.scopeNote")}
      </p>

      {relay.isPending ? (
        <div className="flex justify-center py-24 text-ink-muted">
          <Spinner className="h-6 w-6" />
        </div>
      ) : relay.error ? (
        <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {relay.error instanceof ApiError ? relay.error.message : String(relay.error)}
        </p>
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
 * The relay is stored but PHP has nothing to hand a message to.
 *
 * Its own banner rather than a field note: no amount of correct relay
 * configuration makes mail work while this is true.
 */
function AgentMissing({ agent }: { agent: string }) {
  const { t } = useTranslation();
  return (
    <div role="alert" className="flex gap-3 rounded-lg bg-warning-soft px-3 py-2.5">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
      <div className="text-sm">
        <p className="font-medium text-ink">{t("mail.agentMissing")}</p>
        <p className="mt-0.5 text-ink-muted">
          {t("mail.agentMissingHint", { agent })}
        </p>
      </div>
    </div>
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
            <Badge tone={relay.enabled ? "success" : "neutral"}>
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
                dir="ltr"
                autoComplete="off"
                placeholder="smtp.example.net"
                value={host}
                onChange={(e) => setHost(e.target.value)}
              />
            </Field>
            <Field label={t("mail.relay.port")} htmlFor="mail-port">
              <Input
                id="mail-port"
                dir="ltr"
                inputMode="numeric"
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
          <p className="-mt-1 mb-3 text-xs text-ink-muted">
            {t(`mail.relay.tlsHint.${tlsMode}`)}
          </p>

          <div className="grid gap-x-4 sm:grid-cols-2">
            <Field label={t("mail.relay.username")} htmlFor="mail-user">
              <Input
                id="mail-user"
                dir="ltr"
                autoComplete="off"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </Field>
            <Field label={t("mail.relay.password")} htmlFor="mail-pass">
              <Input
                id="mail-pass"
                type="password"
                dir="ltr"
                autoComplete="new-password"
                placeholder={relay.has_password ? t("mail.relay.passwordStored") : ""}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
          </div>
          <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("mail.relay.passwordHint")}</p>

          {credentialWithoutTls ? (
            <p role="alert" className="mb-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
              {t("mail.relay.credentialNeedsTls")}
            </p>
          ) : null}

          <div className="grid gap-x-4 sm:grid-cols-2">
            <Field label={t("mail.relay.fromAddress")} htmlFor="mail-from">
              <Input
                id="mail-from"
                dir="ltr"
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
          <p className="-mt-1 mb-3 text-xs text-ink-muted">{t("mail.relay.fromHint")}</p>

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
              disabled={save.isPending || credentialWithoutTls}
            >
              {save.isPending ? <Spinner /> : <Mail className="h-4 w-4" aria-hidden />}
              {t("mail.relay.save")}
            </Button>
          </div>

          {error ? (
            <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
              {error}
            </p>
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
          <div className="min-w-56 flex-1">
            <Field label={t("mail.test.to")} htmlFor="mail-test-to">
              <Input
                id="mail-test-to"
                dir="ltr"
                autoComplete="off"
                placeholder={t("mail.test.toPlaceholder")}
                value={to}
                onChange={(e) => setTo(e.target.value)}
              />
            </Field>
          </div>
          <Button type="submit" variant="primary" className="mb-6" disabled={test.isPending}>
            {test.isPending ? <Spinner /> : <Send className="h-4 w-4" aria-hidden />}
            {t("mail.test.send")}
          </Button>
        </form>

        {error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}

        {report ? <TestReport report={report} /> : null}
      </CardBody>
    </Card>
  );
}

function TestReport({ report }: { report: MailTestReport }) {
  const { t } = useTranslation();
  return (
    <div
      className={
        report.delivered
          ? "rounded-lg bg-success-soft px-3 py-2.5"
          : "rounded-lg bg-danger-soft px-3 py-2.5"
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={report.delivered ? "success" : "danger"} dot>
          {report.delivered ? t("mail.test.delivered") : t("mail.test.failed")}
        </Badge>
        {/* The stage is the headline on a failure: it is the difference
            between a wrong password and a wrong sender domain. */}
        <Badge tone="neutral">{t(`mail.stage.${report.stage}`)}</Badge>
        <Badge tone={report.encrypted ? "success" : "warning"}>
          {report.encrypted ? t("mail.test.encrypted") : t("mail.test.plaintext")}
        </Badge>
      </div>

      {/* The relay's own words, verbatim and LTR: paraphrasing an SMTP reply
          throws away the only precise thing in the response. */}
      <p dir="ltr" className="mt-2 font-mono text-xs break-words text-ink">
        {report.detail}
      </p>
      <p className="mt-1.5 text-xs text-ink-muted">{t(`mail.stageHint.${report.stage}`)}</p>

      {report.transcript.length > 0 ? (
        <details className="mt-2">
          <summary className="cursor-pointer text-xs font-medium text-ink-muted">
            {t("mail.test.transcript")}
          </summary>
          <div className="mt-1.5 max-h-56 overflow-y-auto rounded-lg bg-canvas p-2">
            {report.transcript.map((line, index) => (
              <div
                // The transcript is an ordered log with repeated lines; the
                // index is genuinely its identity here.
                key={index}
                dir="ltr"
                className="font-mono text-[11px] break-all whitespace-pre-wrap text-ink-muted"
              >
                {line}
              </div>
            ))}
          </div>
          <p className="mt-1 text-xs text-ink-subtle">{t("mail.test.transcriptNote")}</p>
        </details>
      ) : null}
    </div>
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
          <p className="text-sm text-ink-subtle">{t("mail.dns.none")}</p>
        ) : (
          <ul className="space-y-3">
            {dns.records.map((record) => (
              <li key={`${record.record_type}-${record.name}`}>
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
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // A denied clipboard permission is not worth an error banner; the value
      // is on screen and selectable.
      setCopied(false);
    }
  };

  return (
    <div className="rounded-lg border border-border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="accent">{record.record_type}</Badge>
        <span dir="ltr" className="font-mono text-xs break-all text-ink">
          {record.name}
        </span>
        {/* Stated on every row, not once at the top: this is the difference
            between a panel that manages DNS and one that suggests records. */}
        <Badge tone="neutral" className="ms-auto">
          {t("mail.dns.notManaged")}
        </Badge>
      </div>

      {record.value ? (
        <div className="mt-2 flex items-start gap-2">
          <code
            dir="ltr"
            className="flex-1 rounded bg-surface-muted px-2 py-1.5 font-mono text-xs break-all text-ink"
          >
            {record.value}
          </code>
          <Button variant="ghost" size="sm" onClick={() => void copy()}>
            <Copy className="h-3.5 w-3.5" aria-hidden />
            {copied ? t("mail.dns.copied") : t("mail.dns.copy")}
          </Button>
        </div>
      ) : (
        <p className="mt-2 rounded bg-surface-muted px-2 py-1.5 text-xs text-ink-muted">
          {t("mail.dns.noValue")}
        </p>
      )}

      <p className="mt-1.5 text-xs text-ink-muted">{record.purpose}</p>
    </div>
  );
}
