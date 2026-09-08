import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Cloud,
  CloudOff,
  Globe,
  KeyRound,
  Network,
  Pencil,
  Plus,
  Search,
  ShieldCheck,
  Table2,
  Trash2,
  X,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { TaskNotice } from "@/components/task-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Field, Input } from "@/components/ui/input";
import { Menu, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
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
import {
  PRIORITY_TYPES,
  TTL_AUTOMATIC,
  TTL_CHOICES,
  dnsApi,
  type DnsRecord,
  type DnsRecordsResponse,
  type DnsStoredProvider,
} from "@/lib/dns-api";
import { staggerStyle } from "@/lib/motion";
import { useSession } from "@/lib/session";

/**
 * DNS (spec §11.13, §11.5).
 *
 * Four things that only look unrelated. Pointing a domain at this server is the
 * step every new site fails on; the records are what does the pointing; the
 * Cloudflare token is what lets the panel read and write them; and a wildcard
 * certificate is the thing that requires all three. They share a page because
 * they share one question: does the panel control this name yet?
 *
 * The token travels in one direction only. `PUT /api/dns/provider` seals it with
 * the master key, and the matching `GET` answers with the label, the Cloudflare
 * account and the zones — never the credential. That is what lets the card below
 * survive a page reload: before it existed, an operator who came back to this
 * page saw an empty form and concluded the token had not been saved, so they
 * generated another one.
 *
 * Nothing on this page polls Cloudflare. Every zone and record list is a live
 * API call made by the agent against a rate-limited endpoint, so the queries
 * fetch when a zone is chosen and when a write lands, and not on a timer or on
 * window focus.
 */
export function DnsPage() {
  const { t } = useTranslation();
  const { user } = useSession();
  // The endpoints re-check both of these in the agent; hiding a card the caller
  // may not use keeps somebody from filling in a token, or an MX record, only
  // to be told they were never allowed to.
  const canManageProvider = user?.permissions.includes("server_manage") ?? false;
  const canManageDns = user?.permissions.includes("dns_manage") ?? false;

  return (
    <div className="space-y-6">
      <PageHeader title={t("dns.title")} description={t("dns.subtitle")} />

      <DomainChecker />
      {canManageDns ? <RecordsCard /> : null}
      {canManageProvider ? <ProviderCard /> : null}
      <WildcardCard />
    </div>
  );
}

function errorText(error: unknown): string {
  return error instanceof ApiError ? error.message : String(error);
}

/**
 * How long a Cloudflare answer is treated as current.
 *
 * Long, and paired with `refetchOnWindowFocus: false` everywhere it is used.
 * Cloudflare rate-limits per token, and a zone list that refreshes every time
 * the operator alt-tabs spends that budget on information nobody asked for. A
 * write invalidates the record list, which is the refresh that matters.
 */
const CLOUDFLARE_STALE_MS = 5 * 60_000;

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
            <Callout tone="danger">{errorText(check.error)}</Callout>
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
// The records themselves
// ---------------------------------------------------------------------------

/** The record being written, before the agent has judged it. */
interface RecordDraft {
  kind: string;
  name: string;
  content: string;
  ttl: number;
  proxied: boolean;
  priority: string;
}

function draftFor(record: DnsRecord | null): RecordDraft {
  return {
    kind: record?.kind ?? "A",
    name: record?.name ?? "",
    content: record?.content ?? "",
    ttl: record?.ttl ?? TTL_AUTOMATIC,
    proxied: record?.proxied ?? false,
    priority: record?.priority == null ? "" : String(record.priority),
  };
}

function RecordsCard() {
  const { t } = useTranslation();
  const [chosen, setChosen] = useState<string | null>(null);
  const [editing, setEditing] = useState<DnsRecord | "new" | null>(null);
  const [removing, setRemoving] = useState<DnsRecord | null>(null);

  const zones = useQuery({
    queryKey: ["dns-zones"],
    queryFn: dnsApi.zones,
    staleTime: CLOUDFLARE_STALE_MS,
    refetchOnWindowFocus: false,
    retry: false,
  });

  // Derived rather than pushed into state by an effect: the first zone is the
  // default only until the operator picks one, and an effect that "corrects"
  // the selection is how a picker snaps back under somebody's cursor.
  const zone = chosen ?? zones.data?.zones[0]?.name ?? null;

  const records = useQuery({
    queryKey: ["dns-records", zone],
    queryFn: () => dnsApi.records(zone!),
    enabled: zone !== null,
    staleTime: CLOUDFLARE_STALE_MS,
    refetchOnWindowFocus: false,
    retry: false,
  });

  return (
    <Card>
      <CardHeader
        title={t("dns.records.title")}
        description={t("dns.records.hint")}
        action={
          <Button
            variant="primary"
            size="sm"
            // The dialog's type picker comes from the record list, so Add stays
            // out of reach until that has landed rather than opening a form
            // with no types in it.
            disabled={zone === null || records.data === undefined}
            onClick={() => setEditing("new")}
          >
            <Plus className="h-3.5 w-3.5" aria-hidden />
            {t("dns.records.add")}
          </Button>
        }
      />
      <CardBody className="space-y-3">
        {zones.isPending ? (
          <ListSkeleton rows={3} className="border-0 bg-transparent p-0 shadow-none" />
        ) : zones.error ? (
          <Callout tone="danger">{errorText(zones.error)}</Callout>
        ) : zones.data!.zones.length === 0 ? (
          <EmptyState
            icon={<Table2 aria-hidden />}
            title={t("dns.records.noZones")}
            hint={t("dns.records.noZonesHint")}
          />
        ) : (
          <>
            <div className="flex flex-wrap items-end gap-2">
              <div className="min-w-56 flex-1 space-y-1.5">
                <label htmlFor="dns-zone" className="block text-sm font-medium text-ink">
                  {t("dns.records.zone")}
                </label>
                <Select
                  id="dns-zone"
                  value={zone ?? ""}
                  onChange={(event) => setChosen(event.target.value)}
                >
                  {zones.data!.zones.map((z) => (
                    <option key={`${z.provider_label}:${z.id}`} value={z.name}>
                      {z.account ? `${z.name} — ${z.account}` : z.name}
                    </option>
                  ))}
                </Select>
              </div>
              <Button
                variant="outline"
                onClick={() => void records.refetch()}
                loading={records.isFetching}
              >
                {t("dns.records.reload")}
              </Button>
            </div>

            {/* A zone missing from the picker because one token is revoked looks
                exactly like a zone that was never delegated, and an operator
                will go and create it a second time. */}
            {zones.data!.unreachable.length > 0 ? (
              <Callout tone="warning" title={t("dns.records.unreachable")}>
                <ul className="space-y-0.5 font-mono text-xs">
                  {zones.data!.unreachable.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </Callout>
            ) : null}

            <RecordsTable
              query={records}
              onEdit={setEditing}
              onDelete={setRemoving}
              onAdd={() => setEditing("new")}
            />
          </>
        )}
      </CardBody>

      {editing && zone && records.data ? (
        <RecordDialog
          zone={zone}
          record={editing === "new" ? null : editing}
          types={records.data.record_types}
          proxyable={records.data.proxyable_types}
          onClose={() => setEditing(null)}
        />
      ) : null}
      {removing && zone ? (
        <DeleteRecordDialog
          zone={zone}
          record={removing}
          onClose={() => setRemoving(null)}
        />
      ) : null}
    </Card>
  );
}

function RecordsTable({
  query,
  onEdit,
  onDelete,
  onAdd,
}: {
  query: { isPending: boolean; error: unknown; data?: DnsRecordsResponse };
  onEdit: (record: DnsRecord) => void;
  onDelete: (record: DnsRecord) => void;
  onAdd: () => void;
}) {
  const { t } = useTranslation();

  if (query.isPending) {
    return <ListSkeleton rows={4} className="border-0 bg-transparent p-0 shadow-none" />;
  }
  if (query.error) return <Callout tone="danger">{errorText(query.error)}</Callout>;
  const data = query.data!;

  if (data.records.length === 0) {
    return (
      <EmptyState
        icon={<Table2 aria-hidden />}
        title={t("dns.records.empty")}
        hint={t("dns.records.emptyHint")}
        action={
          <Button variant="primary" size="sm" onClick={onAdd}>
            <Plus className="h-3.5 w-3.5" aria-hidden />
            {t("dns.records.add")}
          </Button>
        }
      />
    );
  }

  return (
    <div className="space-y-3">
      {/* Not decoration. A list that is short by fifty rows and looks whole is
          how an operator concludes a record is missing and adds a second. */}
      {data.truncated ? (
        <Callout tone="warning">{t("dns.records.truncated")}</Callout>
      ) : null}

      <Table className="min-w-[720px]" containerClassName="shadow-none">
        <thead>
          <tr>
            <Th>{t("dns.records.colName")}</Th>
            <Th>{t("dns.records.colType")}</Th>
            <Th>{t("dns.records.colContent")}</Th>
            <Th>{t("dns.records.colTtl")}</Th>
            <Th className="text-end">{t("files.actions")}</Th>
          </tr>
        </thead>
        <tbody>
          {data.records.map((record, index) => (
            <Tr
              key={record.id}
              className="stagger animate-rise-in"
              style={staggerStyle(index)}
            >
              <Td className="align-top font-mono text-xs">{record.name}</Td>
              <Td className="align-top">
                <Badge tone="neutral">{record.kind}</Badge>
              </Td>
              <Td className="align-top">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-xs break-all">{record.content}</span>
                  {/* The one judgement this table makes, carried by a word and
                      a tick rather than by a colour: a record answering with
                      this server's own address is the record a delete would
                      take a site off the internet with. */}
                  {record.points_here ? (
                    <Badge tone="success">
                      <Check className="h-3 w-3" aria-hidden />
                      {t("dns.records.pointsHere")}
                    </Badge>
                  ) : null}
                  {record.priority != null ? (
                    <Badge tone="neutral">
                      {t("dns.records.priority")}
                      <span className="tnum">{record.priority}</span>
                    </Badge>
                  ) : null}
                  {record.proxied === true ? (
                    <Badge tone="accent">
                      <Cloud className="h-3 w-3" aria-hidden />
                      {t("dns.records.proxied")}
                    </Badge>
                  ) : null}
                </div>
                {record.impact.length > 0 ? (
                  <p className="mt-1 text-xs text-warning">{record.impact[0]}</p>
                ) : null}
              </Td>
              <Td className="align-top tnum text-xs text-ink-muted">
                {record.ttl === TTL_AUTOMATIC ? t("dns.records.ttlAuto") : record.ttl}
              </Td>
              <Td className="align-top text-end">
                <Menu label={t("files.actions")}>
                  <MenuItem icon={<Pencil />} onClick={() => onEdit(record)}>
                    {t("dns.records.edit")}
                  </MenuItem>
                  <MenuSeparator />
                  <MenuItem danger icon={<Trash2 />} onClick={() => onDelete(record)}>
                    {t("dns.records.delete")}
                  </MenuItem>
                </Menu>
              </Td>
            </Tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function RecordDialog({
  zone,
  record,
  types,
  proxyable,
  onClose,
}: {
  zone: string;
  record: DnsRecord | null;
  types: string[];
  proxyable: string[];
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<RecordDraft>(() => draftFor(record));
  const [error, setError] = useState<ApiError | string | null>(null);

  const canProxy = proxyable.includes(draft.kind);
  const hasPriority = PRIORITY_TYPES.includes(draft.kind);
  const set = <K extends keyof RecordDraft>(key: K, value: RecordDraft[K]) =>
    setDraft((current) => ({ ...current, [key]: value }));

  const body = () => ({
    zone,
    kind: draft.kind,
    name: draft.name,
    content: draft.content,
    // A proxied record's TTL is Cloudflare's to choose, and the agent refuses a
    // request that sets both — so the switch owns the field while it is on.
    ttl: canProxy && draft.proxied ? TTL_AUTOMATIC : draft.ttl,
    proxied: canProxy ? draft.proxied : null,
    priority: hasPriority && draft.priority.trim() !== "" ? Number(draft.priority) : null,
    ...(record
      ? // What was on screen when Edit was opened. The agent re-reads the
        // record and refuses if somebody changed it in the Cloudflare dashboard
        // in the meantime, rather than overwriting a record nobody chose.
        { confirm_name: record.name, confirm_content: record.content }
      : {}),
  });

  const save = useMutation({
    mutationFn: () => (record ? dnsApi.updateRecord(record.id, body()) : dnsApi.createRecord(body())),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["dns-records", zone] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e : String(e)),
  });

  // The agent names the field it refused, so the message lands next to the
  // input that caused it instead of in a banner the reader has to map back.
  const fieldError = (field: string) =>
    error instanceof ApiError && error.field === field ? error.message : undefined;
  const generalError =
    error === null
      ? null
      : error instanceof ApiError
        ? ["kind", "name", "content", "ttl", "proxied", "priority"].includes(error.field ?? "")
          ? null
          : error.message
        : error;

  return (
    <Dialog
      open
      onClose={onClose}
      title={record ? t("dns.records.editTitle", { name: record.name }) : t("dns.records.addTitle", { zone })}
      description={record ? t("dns.records.editHint") : t("dns.records.addHint", { zone })}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={() => save.mutate()} loading={save.isPending}>
            {record ? t("dns.records.save") : t("dns.records.add")}
          </Button>
        </>
      }
    >
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <div className="grid gap-3 sm:grid-cols-[9rem_1fr]">
          <Field label={t("dns.records.fieldType")} htmlFor="dns-record-kind" error={fieldError("kind")}>
            <Select
              id="dns-record-kind"
              value={draft.kind}
              onChange={(event) => set("kind", event.target.value)}
            >
              {/* The agent's own list, sent with the records, so the picker
                  cannot offer a type the write would be refused for. */}
              {types.map((kind) => (
                <option key={kind} value={kind}>
                  {kind}
                </option>
              ))}
            </Select>
          </Field>

          <Field label={t("dns.records.fieldName")} htmlFor="dns-record-name" error={fieldError("name")}>
            <Input
              id="dns-record-name"
              className="font-mono"
              placeholder="www"
              autoComplete="off"
              spellCheck={false}
              aria-describedby="dns-record-name-hint"
              value={draft.name}
              onChange={(event) => set("name", event.target.value)}
            />
          </Field>
        </div>
        <p id="dns-record-name-hint" className="-mt-2 text-xs text-ink-muted">
          {t("dns.records.fieldNameHint", { zone })}
        </p>

        <Field
          label={t("dns.records.fieldContent")}
          htmlFor="dns-record-content"
          error={fieldError("content")}
        >
          <Input
            id="dns-record-content"
            className="font-mono"
            autoComplete="off"
            spellCheck={false}
            value={draft.content}
            onChange={(event) => set("content", event.target.value)}
          />
        </Field>

        {hasPriority ? (
          <Field
            label={t("dns.records.fieldPriority")}
            htmlFor="dns-record-priority"
            error={fieldError("priority")}
          >
            <Input
              id="dns-record-priority"
              inputMode="numeric"
              className="tnum"
              placeholder="10"
              aria-describedby="dns-record-priority-hint"
              value={draft.priority}
              onChange={(event) => set("priority", event.target.value)}
            />
          </Field>
        ) : null}
        {hasPriority ? (
          <p id="dns-record-priority-hint" className="-mt-2 text-xs text-ink-muted">
            {t("dns.records.fieldPriorityHint")}
          </p>
        ) : null}

        {canProxy ? (
          <Switch
            checked={draft.proxied}
            onChange={(next) => set("proxied", next)}
            label={t("dns.records.fieldProxy")}
            description={t("dns.records.fieldProxyHint")}
          />
        ) : null}

        {/* Hidden rather than disabled while the proxy is on: a TTL box that
            accepts a number Cloudflare will overwrite is the panel offering a
            setting it cannot honour. */}
        {canProxy && draft.proxied ? null : (
          <Field label={t("dns.records.fieldTtl")} htmlFor="dns-record-ttl" error={fieldError("ttl")}>
            <Select
              id="dns-record-ttl"
              value={String(draft.ttl)}
              onChange={(event) => set("ttl", Number(event.target.value))}
            >
              {TTL_CHOICES.map((ttl) => (
                <option key={ttl} value={ttl}>
                  {ttl === TTL_AUTOMATIC ? t("dns.records.ttlAuto") : t("dns.records.ttlSeconds", { ttl })}
                </option>
              ))}
            </Select>
          </Field>
        )}

        {record && record.impact.length > 0 ? (
          <Callout tone="warning" title={t("dns.records.impactTitle")}>
            <ul className="space-y-1">
              {record.impact.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </Callout>
        ) : null}

        {generalError ? <Callout tone="danger">{generalError}</Callout> : null}
      </form>
    </Dialog>
  );
}

function DeleteRecordDialog({
  zone,
  record,
  onClose,
}: {
  zone: string;
  record: DnsRecord;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: () => dnsApi.deleteRecord(record.id, zone, record),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["dns-records", zone] });
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("dns.records.deleteTitle", { kind: record.kind, name: record.name })}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="danger" onClick={() => remove.mutate()} loading={remove.isPending}>
            {t("dns.records.delete")}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {/* The record's own name and value, quoted back. Deleting the wrong one
            takes a site off the internet, and "are you sure?" over a row the
            reader has already scrolled away from is not a question anybody can
            answer. */}
        <div className="rounded-lg border border-border bg-surface-muted px-3 py-2.5">
          <p className="font-mono text-xs text-ink">
            {record.name} {record.kind} {record.content}
          </p>
          <p className="mt-1 text-xs text-ink-muted">
            {t("dns.records.deleteBody", { zone })}
          </p>
        </div>

        {/* The server's sentences, not a rule this dialog re-derives: whether a
            record is holding up a site or an ACME challenge needs the panel's
            own site list and this server's addresses. */}
        {record.impact.length > 0 ? (
          <Callout tone="danger" title={t("dns.records.impactTitle")}>
            <ul className="space-y-1">
              {record.impact.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </Callout>
        ) : null}

        {error ? <Callout tone="danger">{error}</Callout> : null}
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// The Cloudflare credential
// ---------------------------------------------------------------------------

function ProviderCard() {
  const { t } = useTranslation();
  const [rotating, setRotating] = useState(false);

  const stored = useQuery({
    queryKey: ["dns-provider"],
    queryFn: dnsApi.provider,
    // Each provider in the answer is one live Cloudflare call, so this is
    // fetched when the page opens and left alone after that.
    staleTime: CLOUDFLARE_STALE_MS,
    refetchOnWindowFocus: false,
    retry: false,
  });

  const configured = stored.data?.providers ?? [];
  const showForm = rotating || (stored.isSuccess && configured.length === 0);

  return (
    <Card>
      <CardHeader title={t("dns.provider.title")} description={t("dns.provider.hint")} />
      <CardBody className="space-y-3">
        {stored.isPending ? (
          <ListSkeleton rows={2} className="border-0 bg-transparent p-0 shadow-none" />
        ) : stored.error ? (
          <Callout tone="danger">{errorText(stored.error)}</Callout>
        ) : configured.length === 0 ? (
          <p className="text-sm text-ink-muted">{t("dns.provider.none")}</p>
        ) : (
          <ul className="space-y-2">
            {configured.map((provider) => (
              <li key={provider.id}>
                <StoredCredential provider={provider} />
              </li>
            ))}
          </ul>
        )}

        {showForm ? (
          <ProviderForm onDone={() => setRotating(false)} />
        ) : (
          <Button variant="outline" size="sm" onClick={() => setRotating(true)}>
            <KeyRound className="h-4 w-4" aria-hidden />
            {t("dns.provider.rotate")}
          </Button>
        )}
      </CardBody>
    </Card>
  );
}

function StoredCredential({ provider }: { provider: DnsStoredProvider }) {
  const { t } = useTranslation();

  return (
    <div className="rounded-lg border border-border bg-surface-muted px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-medium text-ink">{provider.label}</span>
        {/* Checked against Cloudflare on this request, not remembered from the
            day it was stored: a token revoked in the Cloudflare dashboard is
            still a row here, and "Connected" over a dead credential is the panel
            reporting something that is not true about every renewal. */}
        {provider.reachable ? (
          <Badge tone="success" dot>
            {t("dns.provider.connected")}
          </Badge>
        ) : (
          <Badge tone="danger">
            <CloudOff className="h-3 w-3" aria-hidden />
            {t("dns.provider.unreachable")}
          </Badge>
        )}
        {provider.accounts.map((account) => (
          <Badge key={account} tone="neutral">
            {account}
          </Badge>
        ))}
      </div>

      {provider.error ? (
        <p className="mt-1.5 text-xs text-danger">{provider.error}</p>
      ) : (
        <>
          <p className="mt-1.5 text-xs text-ink-muted">{t("dns.provider.zonesHint")}</p>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {provider.zones.length === 0 ? (
              <li className="text-sm text-ink-muted">{t("common.none")}</li>
            ) : (
              provider.zones.map((zone) => (
                <li key={zone}>
                  <Badge tone="neutral">
                    <span className="font-mono">{zone}</span>
                  </Badge>
                </li>
              ))
            )}
          </ul>
        </>
      )}
    </div>
  );
}

function ProviderForm({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
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
      // The stored-credential card above and the zone picker both change now.
      void queryClient.invalidateQueries({ queryKey: ["dns-provider"] });
      void queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
    },
    onError: (e) => setError(errorText(e)),
  });

  return (
    <div className="space-y-3">
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

        <div className="flex flex-wrap gap-2">
          <Button
            type="submit"
            variant="primary"
            loading={save.isPending}
            disabled={label.trim() === "" || token.trim() === ""}
          >
            <KeyRound className="h-4 w-4" aria-hidden />
            {t("dns.provider.save")}
          </Button>
          <Button variant="ghost" onClick={onDone}>
            {t("common.cancel")}
          </Button>
        </div>
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
    </div>
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
    onError: (e) => setError(errorText(e)),
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
