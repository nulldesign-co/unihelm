import { useQuery } from "@tanstack/react-query";
import { Lock, LockOpen, RotateCw, ScanSearch } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { SectionHeader } from "@/components/ui/section-header";
import { Skeleton } from "@/components/ui/skeleton";
import { api, ApiError } from "@/lib/api";
import { staggerStyle } from "@/lib/motion";
import { cn } from "@/lib/utils";

/**
 * Sites the panel did not create (`sites.discover`).
 *
 * This page exists for one moment: somebody installs Unihelm on a machine that
 * has been serving sites for years, opens the panel, and finds an empty list.
 * A control panel that cannot see what the server is already doing is one you
 * cannot trust to change it. Three decisions follow, and each is a decision
 * rather than a label:
 *
 * 1. **It reads, and says so before it shows anything.** The read-only note is
 *    the first thing under the header rather than a footnote under the list,
 *    because a column of domains inside a control panel is read as a list of
 *    things the panel controls. Nothing here is managed, adoption does not
 *    exist yet, and a row carrying an action would be promising one.
 * 2. **Every row ends at a file path.** Since the panel cannot act on these,
 *    the useful thing it can do is hand over the exact file to open — so
 *    `config_file` is on every row rather than behind a disclosure, and the
 *    rows are inert: no hover bar, no cursor change, nothing that reads as
 *    clickable, because there is nowhere to click to. The list elsewhere in
 *    the panel earns those affordances by leading somewhere.
 * 3. **`default_server` is reported as an explanation, not a warning.** Another
 *    vhost holding it is the ordinary state of a busy server and nothing is
 *    broken; it is worth saying only because it decides whether the panel's own
 *    catchall claims it, and an operator who does not know that will one day
 *    wonder why an unmatched name lands somewhere unexpected. Amber would
 *    describe a problem that is not there.
 *
 * The scan behind this is a text scan and not an nginx parser, so a vhost it
 * cannot place arrives as `unknown`. That gets its own badge and its own
 * sentence rather than being quietly folded into "static": guessing is the one
 * thing a page whose whole claim is "here is what we found" cannot afford.
 *
 * The same honesty applies to how far it looked. It reads `conf.d` and
 * `sites-enabled` and follows no `include`, so the line above the list names
 * those two directories instead of letting a count stand as "every vhost on
 * this machine" — an operator who keeps their vhosts elsewhere would otherwise
 * read a short list as proof the server is nearly empty and create a site on
 * top of a name that is already answering.
 */
export function DiscoverPage() {
  const { t } = useTranslation();
  const found = useQuery({ queryKey: ["sites-discover"], queryFn: discoverSites });
  const data = found.data;

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("discover.title")}
        description={t("discover.subtitle")}
        actions={
          // Reading again is the only button on the page, and it is safe to
          // press twice: the operator edits a vhost in a terminal and wants
          // the panel to agree. `isFetching`, not `isPending`, so a re-read
          // keeps the list on screen instead of dropping back to ghosts.
          <Button variant="outline" loading={found.isFetching} onClick={() => void found.refetch()}>
            <RotateCw className="h-4 w-4" aria-hidden />
            {t("discover.rescan")}
          </Button>
        }
      />

      <Callout tone="info" title={t("discover.readOnlyTitle")}>
        {t("discover.readOnly")}
      </Callout>

      {found.isPending ? (
        <DiscoverSkeleton />
      ) : found.error ? (
        <Callout tone="danger">
          {found.error instanceof ApiError ? found.error.message : String(found.error)}
        </Callout>
      ) : (
        <>
          {data!.yields_default_server ? (
            <DefaultServerNote files={data!.default_server_files} />
          ) : null}

          {data!.sites.length === 0 ? (
            <EmptyState
              icon={<ScanSearch aria-hidden />}
              title={t("discover.emptyTitle")}
              // Two different silences. Nothing found on a server with nginx
              // means the machine really is clean; nothing found with no nginx
              // to ask means the question was never put. Telling an operator
              // their server is empty when the panel simply could not look is
              // the sort of quiet wrong answer this page exists to avoid.
              hint={
                data!.nginx_version === null
                  ? t("discover.emptyNoNginx")
                  : t("discover.emptyHint")
              }
            />
          ) : (
            <section className="space-y-3">
              <SectionHeader
                // The count is the whole point of the page: twelve sites the
                // panel had been showing as nothing.
                title={t("discover.foundTitle", { count: data!.sites.length })}
                description={t("discover.foundHint")}
                actions={
                  data!.nginx_version ? (
                    <Badge tone="neutral" className="tnum">
                      {t("discover.nginxVersion", { version: data!.nginx_version })}
                    </Badge>
                  ) : null
                }
              />
              <Card>
                <ul className="divide-y divide-border">
                  {data!.sites.map((site, index) => (
                    <FoundRow key={site.domain} site={site} index={index} />
                  ))}
                </ul>
              </Card>
            </section>
          )}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// The operation
// ---------------------------------------------------------------------------

/**
 * One vhost as `sites.discover` reports it.
 *
 * Mirrors `DiscoveredSiteDto` in crates/unihelm-ops/src/nginx_survey.rs. `kind`
 * stays a plain string rather than a union: the agent may learn to recognise a
 * shape this build has never heard of, and a union would make that a type that
 * lies. `kindKey` below is where the unknown one is absorbed.
 */
export interface DiscoveredSite {
  domain: string;
  server_names: string[];
  kind: string;
  root: string | null;
  proxy_pass: string | null;
  fastcgi_pass: string | null;
  tls_certificate: string | null;
  config_file: string;
  listens: string[];
}

export interface DiscoverResponse {
  sites: DiscoveredSite[];
  /** Files outside Unihelm's own that already declare `default_server`. */
  default_server_files: string[];
  yields_default_server: boolean;
  /** `null` when nginx could not be asked — usually because it is not there. */
  nginx_version: string | null;
}

/** `sites.discover` is immediate, so this answers with data and never a task. */
const discoverSites = () => api.get<DiscoverResponse>("/api/sites/discover");

/** The kinds this build has words for. */
const KNOWN_KINDS = new Set(["php", "static", "proxy", "redirect", "unknown"]);

/**
 * The translation key for a reported kind.
 *
 * A kind added to the agent after this build shipped resolves to "Unclassified"
 * rather than rendering `discover.kind.whatever` on screen — which is the same
 * answer the scan itself gives when it cannot tell, and an honest one.
 */
function kindKey(kind: string): string {
  return KNOWN_KINDS.has(kind) ? kind : "unknown";
}

// ---------------------------------------------------------------------------
// The findings
// ---------------------------------------------------------------------------

function FoundRow({ site, index }: { site: DiscoveredSite; index: number }) {
  const { t } = useTranslation();
  const kind = kindKey(site.kind);
  // The domain is the first server_name; showing it twice would read as a
  // duplicate rather than as the alias list it is.
  const aliases = site.server_names.filter((name) => name !== site.domain);

  return (
    <li className="stagger animate-rise-in px-5 py-4" style={staggerStyle(index)}>
      {/* Wraps rather than truncates: there is no detail page behind this row
          to go and read the rest of a long name on. */}
      <p className="font-mono text-sm font-medium break-all text-ink">{site.domain}</p>
      {aliases.length > 0 ? (
        <p className="mt-0.5 text-xs text-ink-muted">
          {t("discover.alsoAnswers")}{" "}
          {/* Muted label, plain-ink value — the same split the detail list
              below uses, so the eye reads names as names on both. Comma-joined
              like the alias line on the Sites page rather than space-joined
              like the `server_name` directive: this is a list being read, not
              the config line being quoted. */}
          <span className="font-mono break-all text-ink">{aliases.join(", ")}</span>
        </p>
      ) : null}

      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        {/* Accent, not amber: an unclassified vhost is a limit of the scan, not
            a fault in the server, and this list has to keep amber free for the
            day something really is wrong. */}
        <Badge tone={kind === "unknown" ? "accent" : "neutral"}>
          {t(`discover.kind.${kind}`)}
        </Badge>
        <Badge tone={site.tls_certificate ? "success" : "neutral"}>
          {site.tls_certificate ? (
            <Lock className="h-3 w-3" aria-hidden />
          ) : (
            <LockOpen className="h-3 w-3" aria-hidden />
          )}
          {site.tls_certificate ? t("discover.tls") : t("discover.noTls")}
        </Badge>
        {site.listens.map((listen, position) => (
          // `listen 80;` and `listen [::]:80;` are different strings, but a
          // vhost may repeat one; the position disambiguates without pretending
          // the value is an id.
          <Badge key={`${listen}-${position}`} tone="neutral" className="tnum font-mono">
            {listen}
          </Badge>
        ))}
      </div>

      <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
        <Detail label={t("discover.root")} value={site.root} />
        <Detail label={t("discover.upstream")} value={site.proxy_pass} />
        <Detail label={t("discover.fpm")} value={site.fastcgi_pass} />
        <Detail label={t("discover.certificate")} value={site.tls_certificate} />
        {/* Last, and never omitted: it is the one thing on this page an
            operator can act on. */}
        <Detail label={t("discover.configFile")} value={site.config_file} />
      </dl>

      {kind === "unknown" ? (
        <p className="mt-2 text-xs text-ink-muted">{t("discover.unknownHint")}</p>
      ) : null}
    </li>
  );
}

/**
 * One `label → value` line, rendered only when the vhost has that field.
 *
 * An absent root on a proxy site is not an empty value to draw; it is a row
 * that does not belong on that site. A dash there would claim the scan looked
 * and found nothing, which is a different statement.
 */
function Detail({ label, value }: { label: string; value: string | null }) {
  if (!value) return null;
  return (
    <>
      <dt className="whitespace-nowrap text-ink-muted">{label}</dt>
      <dd className="font-mono break-all text-ink">{value}</dd>
    </>
  );
}

/**
 * Who holds `default_server`, and what the panel does about it.
 *
 * Reported wherever it is true, not only when the list is long: it is the
 * difference between a stack install that succeeds and one that fails
 * `nginx -t` and rolls back, and the operator deserves to have read it here
 * first rather than in a task log.
 */
function DefaultServerNote({ files }: { files: string[] }) {
  const { t } = useTranslation();
  return (
    <Callout tone="info" title={t("discover.defaultServerTitle")}>
      <p>{t("discover.defaultServer")}</p>
      {files.length > 0 ? (
        <>
          <p className="mt-1.5">{t("discover.defaultServerFiles")}</p>
          <ul className="mt-0.5 space-y-0.5">
            {files.map((file) => (
              <li key={file} className="font-mono text-xs break-all text-ink">
                {file}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </Callout>
  );
}

/**
 * Ghosts shaped like the section that is coming — heading, version pill, and a
 * card of rows with the same padding the real ones use.
 *
 * Built on the shared `Card`, not a copy of its classes, so a change to the
 * card's border or radius reaches the loading state too.
 */
function DiscoverSkeleton() {
  return (
    <div role="status" aria-live="polite" className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="space-y-1.5">
          <Skeleton className="h-4 w-56 max-w-full" />
          <Skeleton className="h-3.5 w-72 max-w-full" />
        </div>
        <Skeleton className="h-5 w-24 rounded-full" />
      </div>
      <Card>
        <ul className="divide-y divide-border">
          {Array.from({ length: 3 }, (_, i) => (
            <li key={i} className="stagger animate-rise-in px-5 py-4" style={staggerStyle(i)}>
              {/* Uneven widths: real domains are not all the same length, and a
                  perfectly regular ghost reads as a loading graphic rather than
                  as the shape of what is arriving. */}
              <Skeleton className={cn("h-4", i % 2 === 0 ? "w-56" : "w-40", "max-w-full")} />
              <div className="mt-2 flex gap-1.5">
                <Skeleton className="h-5 w-16 rounded-full" />
                <Skeleton className="h-5 w-24 rounded-full" />
              </div>
              <div className="mt-3 space-y-1">
                <Skeleton className="h-3 w-2/3" />
                <Skeleton className="h-3 w-1/2" />
              </div>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
