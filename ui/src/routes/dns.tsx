import { useMutation, useQuery } from "@tanstack/react-query";
import { Check, Globe, KeyRound, Network, Search, ShieldCheck, X } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { TaskNotice } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { ListSkeleton, Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import {
  ApiError,
  endpoints,
  type DnsCheckResponse,
  type DnsNameRecords,
  type DnsProviderResponse,
  type SiteView,
} from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
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
      <PageHeader title={t("dns.title")} description={t("dns.subtitle")} />

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
          {/* A plain label rather than `Field`: this input never shows an
              inline error — the failure is the banner below — and Field's
              reserved error line is what used to force a magic offset on the
              button to keep it level, one that left an orphan gap the moment
              the row wrapped at 375px. */}
          <div className="min-w-56 flex-1 space-y-1.5">
            <label htmlFor="dns-domain" className="block text-sm font-medium text-ink">
              {t("dns.check.domain")}
            </label>
            <Input
              id="dns-domain"
              placeholder="example.com"
              autoComplete="off"
              spellCheck={false}
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
            />
          </div>
          <Button type="submit" variant="primary" loading={check.isFetching}>
            <Search className="h-4 w-4" aria-hidden />
            {t("dns.check.run")}
          </Button>
        </form>

        <div className="mt-4">
          {check.error ? (
            <Callout tone="danger">
              {check.error instanceof ApiError ? check.error.message : String(check.error)}
            </Callout>
          ) : check.data ? (
            <CheckResult result={check.data} />
          ) : check.isFetching ? (
            // Shaped like the verdict, the table and the address pills below it,
            // so nothing on the page moves when the answer lands.
            <div role="status" aria-live="polite" className="space-y-4">
              <Skeleton className="h-20 w-full rounded-card" />
              <Skeleton className="h-28 w-full rounded-card" />
              <Skeleton className="h-6 w-64 rounded-full" />
            </div>
          ) : (
            <EmptyState
              icon={<Search aria-hidden />}
              title={t("dns.check.idle")}
              hint={t("dns.check.idleHint")}
              className="py-10"
            />
          )}
        </div>
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
      ? { tone: "info" as const, label: t("dns.check.proxied") }
      : { tone: "warning" as const, label: t("dns.check.noMatch") };

  return (
    <div className="space-y-4">
      {/* The verdict and the advisory sentence are one message, so they are one
          Callout — and its entrance is what keeps the card from growing 200px
          under the reader without warning. The sentence is the server's,
          deliberately: the decision table behind it (proxied, partial, timed
          out) lives in `unihelm_ops::dns` and a second copy here would be a
          second copy to keep in step. */}
      <Callout
        tone={verdict.tone}
        title={
          <span className="flex flex-wrap items-baseline gap-x-2">
            {verdict.label}
            <span className="font-mono text-xs font-normal text-ink-muted">
              {result.domain}
            </span>
          </span>
        }
      >
        <p>{result.advice}</p>
        {result.proxied_hint ? (
          <p className="mt-1.5 text-xs">{t("dns.check.proxiedHint")}</p>
        ) : null}
      </Callout>

      <Table className="min-w-[560px]" containerClassName="shadow-none">
        <thead>
          <tr>
            <Th>{t("dns.check.name")}</Th>
            <Th>A</Th>
            <Th>AAAA</Th>
          </tr>
        </thead>
        <tbody>
          {result.records.map((record, index) => (
            <RecordRow
              key={record.name}
              index={index}
              record={record}
              serverAddresses={result.server_addresses}
            />
          ))}
        </tbody>
      </Table>

      <div>
        <p className="text-xs text-ink-subtle">{t("dns.check.serverAddresses")}</p>
        <ul className="mt-1 flex flex-wrap gap-1.5">
          {result.server_addresses.length === 0 ? (
            <li className="text-sm text-ink-muted">{t("common.none")}</li>
          ) : (
            result.server_addresses.map((address) => (
              <li key={address}>
                <Badge tone="neutral">
                  <span className="tnum font-mono">{address}</span>
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
  index,
}: {
  record: DnsNameRecords;
  serverAddresses: string[];
  index: number;
}) {
  const { t } = useTranslation();
  const here = new Set(serverAddresses);

  const cell = (values: string[]) =>
    values.length === 0 ? (
      <span className="text-ink-subtle">{t("common.none")}</span>
    ) : (
      <ul className="flex flex-wrap gap-1">
        {values.map((value) => {
          const mine = here.has(value);
          return (
            <li key={value}>
              {/* Marking the addresses that are this server's is the whole
                  comparison; a bare list makes the reader do it by eye. The
                  tick — not the green — is what carries it: this is the one
                  judgement the card exists to make, and colour alone would
                  hide it from anyone who cannot see the difference. */}
              <Badge tone={mine ? "success" : "neutral"}>
                {mine ? <Check className="h-3 w-3" aria-hidden /> : null}
                <span className="tnum font-mono">{value}</span>
                {mine ? <span className="sr-only">{t("dns.check.thisServer")}</span> : null}
              </Badge>
            </li>
          );
        })}
      </ul>
    );

  return (
    <Tr className="stagger animate-rise-in" style={staggerStyle(index)}>
      <Td className="align-top font-mono text-xs">{record.name}</Td>
      <Td className="align-top">{cell(record.a)}</Td>
      <Td className="align-top">
        {record.error ? (
          // NXDOMAIN and "the resolver timed out" are different problems with
          // different fixes, and an empty list says neither.
          <span className="font-mono text-xs text-warning">{record.error}</span>
        ) : (
          cell(record.aaaa)
        )}
      </Td>
    </Tr>
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
            loading={save.isPending}
            disabled={label.trim() === "" || token.trim() === ""}
          >
            <KeyRound className="h-4 w-4" aria-hidden />
            {t("dns.provider.save")}
          </Button>
        </form>

        {error ? <Callout tone="danger">{error}</Callout> : null}

        {saved ? (
          // Dismissible, because the alternative is a success from twenty
          // minutes ago sitting above the form for the rest of the session.
          <Callout
            tone="success"
            title={t("dns.provider.saved", { label: saved.label, status: saved.token_status })}
            action={
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={t("common.dismiss")}
                onClick={() => setSaved(null)}
              >
                <X className="h-4 w-4" />
              </Button>
            }
          >
            <p className="text-xs">{t("dns.provider.zonesHint")}</p>
            <ul className="mt-1.5 flex flex-wrap gap-1.5">
              {saved.zones.map((zone) => (
                <li key={zone}>
                  <Badge tone="neutral">
                    <span className="font-mono">{zone}</span>
                  </Badge>
                </li>
              ))}
            </ul>
          </Callout>
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
          // The shared list ghost, stripped of its own card shell because it is
          // already standing inside one.
          <ListSkeleton rows={3} className="border-0 bg-transparent p-0 shadow-none" />
        ) : (sites.data?.sites.length ?? 0) === 0 ? (
          <EmptyState
            icon={<Network aria-hidden />}
            title={t("dns.wildcard.noSites")}
            hint={t("dns.wildcard.noSitesHint")}
          />
        ) : (
          <ul className="divide-y divide-border">
            {sites.data!.sites.map((site, index) => (
              <li
                key={site.id}
                className="stagger animate-rise-in transition-colors duration-150 hover:bg-surface-muted/60"
                style={staggerStyle(index)}
              >
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
          <span className="block truncate font-mono text-xs font-medium text-ink">
            {site.domain}
          </span>
          <span className="block truncate font-mono text-xs text-ink-subtle">*.{site.domain}</span>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => issue.mutate()}
          loading={issue.isPending}
          disabled={site.status !== "active"}
        >
          {t("dns.wildcard.issue")}
        </Button>
      </div>

      {error ? (
        <Callout tone="danger" className="mt-2">
          {error}
        </Callout>
      ) : null}
      {taskId ? <TaskNotice key={taskId} taskId={taskId} /> : null}
    </div>
  );
}
