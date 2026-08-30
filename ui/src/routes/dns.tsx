import { useMutation, useQuery } from "@tanstack/react-query";
import { Globe, KeyRound, Search, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { TaskNotice } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import {
  ApiError,
  endpoints,
  type DnsCheckResponse,
  type DnsNameRecords,
  type DnsProviderResponse,
  type SiteView,
} from "@/lib/api";
import { useSession } from "@/lib/session";

/**
 * DNS (spec §11.13, §11.5).
 *
 * Three things that only look unrelated. Pointing a domain at this server is
 * the step every new site fails on; the Cloudflare token is what lets the panel
 * write a DNS-01 challenge; and a wildcard certificate is the thing that
 * requires both. They share a page because they share one question: does the
 * panel control this name yet?
 *
 * The token travels in one direction only. `PUT /api/dns/provider` seals it with
 * the master key and no endpoint returns it — not this page, not the audit log,
 * not an admin's export. So the form below writes and never reads: after a save
 * it can show Cloudflare's verdict and the zones the token administers, which is
 * the credential's blast radius, and nothing else.
 */
export function DnsPage() {
  const { t } = useTranslation();
  const { user } = useSession();
  // The endpoint itself requires `server.manage` and the agent re-checks it;
  // hiding the form from everyone else keeps a customer from filling in a
  // token only to be told they may not store it.
  const canManageProvider = user?.permissions.includes("server_manage") ?? false;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("dns.title")}</h1>
        <p className="mt-1 text-sm text-ink-muted">{t("dns.subtitle")}</p>
      </header>

      <DomainChecker />
      {canManageProvider ? <ProviderCard /> : null}
      <WildcardCard />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Is this domain pointed here?
// ---------------------------------------------------------------------------

function DomainChecker() {
  const { t } = useTranslation();
  const [domain, setDomain] = useState("");
  const [asked, setAsked] = useState<string | null>(null);

  const check = useQuery({
    queryKey: ["dns-check", asked],
    queryFn: () => endpoints.dnsCheck(asked!),
    enabled: asked !== null,
    // A DNS answer is a snapshot of the public internet a moment ago; refetching
    // it on every window focus would make the verdict flicker for no new
    // information. The button is the refresh.
    staleTime: 30_000,
    retry: false,
  });

  return (
    <Card>
      <CardHeader title={t("dns.check.title")} description={t("dns.check.hint")} />
      <CardBody>
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            const value = domain.trim().toLowerCase();
            if (value === "") return;
            // Setting the same value again would not re-run the query, so the
            // button doubles as a refresh through `refetch`.
            if (value === asked) void check.refetch();
            else setAsked(value);
          }}
        >
          <div className="min-w-56 flex-1">
            <Field label={t("dns.check.domain")} htmlFor="dns-domain">
              <Input
                id="dns-domain"
                dir="ltr"
                placeholder="example.com"
                autoComplete="off"
                spellCheck={false}
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
              />
            </Field>
          </div>
          <Button type="submit" variant="primary" className="mb-6" disabled={check.isFetching}>
            {check.isFetching ? <Spinner /> : <Search className="h-4 w-4" aria-hidden />}
            {t("dns.check.run")}
          </Button>
        </form>

        {check.error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {check.error instanceof ApiError ? check.error.message : String(check.error)}
          </p>
        ) : check.data ? (
          <CheckResult result={check.data} />
        ) : (
          <p className="text-sm text-ink-muted">{t("dns.check.idle")}</p>
        )}
      </CardBody>
    </Card>
  );
}

function CheckResult({ result }: { result: DnsCheckResponse }) {
  const { t } = useTranslation();

  // Three verdicts, not two. "Does not match" is *wrong* for a Cloudflare-proxied
  // domain, which resolves to Cloudflare's anycast addresses on purpose and
  // works perfectly — telling that operator to fix their DNS would be telling
  // them to break it.
  const verdict = result.matches_server
    ? { tone: "success" as const, label: t("dns.check.matches") }
    : result.proxied_hint
      ? { tone: "accent" as const, label: t("dns.check.proxied") }
      : { tone: "warning" as const, label: t("dns.check.noMatch") };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={verdict.tone} dot>
          {verdict.label}
        </Badge>
        <span dir="ltr" className="font-mono text-sm text-ink">
          {result.domain}
        </span>
      </div>

      {/* The advisory sentence is the server's, deliberately: the decision table
          behind it (proxied, partial, timed out) lives in `unihelm_ops::dns` and
          a second copy here would be a second copy to keep in step. */}
      <p dir="auto" className="rounded-lg bg-surface-muted px-3 py-2 text-sm text-ink">
        {result.advice}
      </p>

      {result.proxied_hint ? (
        <p className="text-xs text-ink-muted">{t("dns.check.proxiedHint")}</p>
      ) : null}

      <div className="overflow-x-auto">
        <table className="w-full min-w-lg text-start text-sm">
          <thead>
            <tr className="border-b border-border text-xs text-ink-subtle">
              <th className="py-2 pe-3 text-start font-medium">{t("dns.check.name")}</th>
              <th className="py-2 pe-3 text-start font-medium">A</th>
              <th className="py-2 pe-3 text-start font-medium">AAAA</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {result.records.map((record) => (
              <RecordRow key={record.name} record={record} serverAddresses={result.server_addresses} />
            ))}
          </tbody>
        </table>
      </div>

      <div>
        <p className="text-xs text-ink-subtle">{t("dns.check.serverAddresses")}</p>
        <ul className="mt-1 flex flex-wrap gap-1.5">
          {result.server_addresses.length === 0 ? (
            <li className="text-sm text-ink-muted">{t("common.none")}</li>
          ) : (
            result.server_addresses.map((address) => (
              <li key={address}>
                <Badge tone="neutral">
                  <span dir="ltr" className="font-mono">
                    {address}
                  </span>
                </Badge>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}

function RecordRow({
  record,
  serverAddresses,
}: {
  record: DnsNameRecords;
  serverAddresses: string[];
}) {
  const { t } = useTranslation();
  const here = new Set(serverAddresses);

  const cell = (values: string[]) =>
    values.length === 0 ? (
      <span className="text-ink-subtle">{t("common.none")}</span>
    ) : (
      <ul className="flex flex-wrap gap-1">
        {values.map((value) => (
          <li key={value}>
            {/* Marking the addresses that are this server's is the whole
                comparison; a bare list makes the reader do it by eye. */}
            <Badge tone={here.has(value) ? "success" : "neutral"}>
              <span dir="ltr" className="font-mono">
                {value}
              </span>
            </Badge>
          </li>
        ))}
      </ul>
    );

  return (
    <tr className="align-top">
      <td dir="ltr" className="py-2 pe-3 font-mono text-xs text-ink">
        {record.name}
      </td>
      <td className="py-2 pe-3">{cell(record.a)}</td>
      <td className="py-2 pe-3">
        {record.error ? (
          // NXDOMAIN and "the resolver timed out" are different problems with
          // different fixes, and an empty list says neither.
          <span dir="ltr" className="font-mono text-xs text-warning">
            {record.error}
          </span>
        ) : (
          cell(record.aaaa)
        )}
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// The Cloudflare credential
// ---------------------------------------------------------------------------

function ProviderCard() {
  const { t } = useTranslation();
  const [label, setLabel] = useState("");
  const [token, setToken] = useState("");
  const [saved, setSaved] = useState<DnsProviderResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () =>
      endpoints.setDnsProvider({ kind: "cloudflare", label: label.trim(), token: token.trim() }),
    onSuccess: (result) => {
      setSaved(result);
      setError(null);
      // The token leaves this browser's memory the moment it is stored. There is
      // no endpoint that could put it back, so keeping it in a React state for
      // the rest of the session would only widen where it can leak from.
      setToken("");
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <Card>
      <CardHeader title={t("dns.provider.title")} description={t("dns.provider.hint")} />
      <CardBody className="space-y-3">
        {/* Why a Global API Key is refused, said before the field rather than in
            the error afterwards: that key authenticates every action on every
            zone in the account, billing included, and cannot be scoped down. */}
        <div className="rounded-lg border border-border bg-surface-muted px-3 py-2.5">
          <p className="flex items-center gap-1.5 text-sm font-medium text-ink">
            <ShieldCheck className="h-4 w-4 shrink-0" aria-hidden />
            {t("dns.provider.tokenOnly")}
          </p>
          <p className="mt-1 text-sm text-ink-muted">{t("dns.provider.tokenOnlyWhy")}</p>
          <p className="mt-1.5 text-xs text-ink-muted">{t("dns.provider.tokenScopes")}</p>
        </div>

        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (label.trim() === "" || token.trim() === "") return;
            save.mutate();
          }}
        >
          <Field label={t("dns.provider.label")} htmlFor="dns-label">
            <Input
              id="dns-label"
              dir="ltr"
              placeholder="cloudflare-main"
              autoComplete="off"
              aria-describedby="dns-label-hint"
              value={label}
              onChange={(event) => setLabel(event.target.value)}
            />
          </Field>
          <p id="dns-label-hint" className="-mt-2 text-xs text-ink-muted">
            {t("dns.provider.labelHint")}
          </p>

          <Field label={t("dns.provider.token")} htmlFor="dns-token">
            <Input
              id="dns-token"
              dir="ltr"
              type="password"
              className="font-mono"
              // A credential field the browser offers to fill from a saved
              // website login would be filling it with the wrong secret.
              autoComplete="off"
              spellCheck={false}
              value={token}
              onChange={(event) => setToken(event.target.value)}
            />
          </Field>

          <Button
            type="submit"
            variant="primary"
            disabled={save.isPending || label.trim() === "" || token.trim() === ""}
          >
            {save.isPending ? <Spinner /> : <KeyRound className="h-4 w-4" aria-hidden />}
            {t("dns.provider.save")}
          </Button>
        </form>

        {error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
            {error}
          </p>
        ) : null}

        {saved ? (
          <div className="rounded-lg bg-success-soft px-3 py-2.5">
            <p className="text-sm font-medium text-success">
              {t("dns.provider.saved", { label: saved.label, status: saved.token_status })}
            </p>
            <p className="mt-1.5 text-xs text-ink-muted">{t("dns.provider.zonesHint")}</p>
            <ul className="mt-1 flex flex-wrap gap-1.5">
              {saved.zones.map((zone) => (
                <li key={zone}>
                  <Badge tone="neutral">
                    <span dir="ltr" className="font-mono">
                      {zone}
                    </span>
                  </Badge>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </CardBody>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Wildcard certificates
// ---------------------------------------------------------------------------

function WildcardCard() {
  const { t } = useTranslation();
  const [staging, setStaging] = useState(false);
  const sites = useQuery({ queryKey: ["sites"], queryFn: endpoints.sites });

  return (
    <Card>
      <CardHeader title={t("dns.wildcard.title")} description={t("dns.wildcard.hint")} />
      <CardBody className="space-y-3">
        {/* The most common wildcard mistake, stated where the button is: a
            `*.example.com` certificate does not match `example.com`, because a
            wildcard covers exactly one label. This issuance covers both. */}
        <p className="rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm text-ink-muted">
          {t("dns.wildcard.apexNote")}
        </p>

        <Switch
          checked={staging}
          onChange={setStaging}
          label={t("siteDetail.staging")}
          description={t("siteDetail.stagingHint")}
        />

        {sites.isPending ? (
          <div className="flex justify-center py-8 text-ink-muted">
            <Spinner />
          </div>
        ) : (sites.data?.sites.length ?? 0) === 0 ? (
          <p className="text-sm text-ink-muted">{t("dns.wildcard.noSites")}</p>
        ) : (
          <ul className="divide-y divide-border">
            {sites.data!.sites.map((site) => (
              <li key={site.id}>
                <WildcardRow site={site} staging={staging} />
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}

function WildcardRow({ site, staging }: { site: SiteView; staging: boolean }) {
  const { t } = useTranslation();
  const [taskId, setTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const issue = useMutation({
    mutationFn: () => endpoints.issueWildcardCertificate(site.id, staging),
    onSuccess: (accepted) => {
      setError(null);
      setTaskId(accepted.task_id);
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  return (
    <div className="py-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Globe className="h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
        <div className="min-w-0 flex-1">
          <span dir="ltr" className="block truncate font-medium text-ink">
            {site.domain}
          </span>
          <span dir="ltr" className="block truncate font-mono text-xs text-ink-subtle">
            *.{site.domain}
          </span>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => issue.mutate()}
          disabled={issue.isPending || site.status !== "active"}
        >
          {issue.isPending ? <Spinner /> : null}
          {t("dns.wildcard.issue")}
        </Button>
      </div>

      {error ? (
        <p role="alert" className="mt-2 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
      {taskId ? <TaskNotice key={taskId} taskId={taskId} /> : null}
    </div>
  );
}
