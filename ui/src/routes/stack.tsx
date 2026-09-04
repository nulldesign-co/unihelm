import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import {
  ApiError,
  EOL_PHP_VERSIONS,
  PHP_VERSIONS,
  endpoints,
  type ComponentState,
  type StackComponentRequest,
  type StackComponentView,
} from "@/lib/api";
import { staggerStyle } from "@/lib/motion";

const TONE: Record<ComponentState, "success" | "accent" | "danger" | "neutral"> = {
  installed: "success",
  installing: "accent",
  removing: "accent",
  failed: "danger",
  absent: "neutral",
  // Neutral, not success: it is there and working, but the panel did not put it
  // there and cannot vouch for how it is configured.
  unmanaged: "neutral",
};

/** What the install and remove endpoints take. */
type ComponentRequest = StackComponentRequest;

const requestFor = (slug: string): ComponentRequest =>
  slug === "nginx" || slug === "mariadb" || slug === "postgres"
    ? { component: slug }
    : { component: "php", version: slug.replace("php", "") };

/** The inverse, so a pending mutation can say which row it belongs to. */
const slugFor = (request: ComponentRequest | undefined): string | null =>
  request === undefined
    ? null
    : request.component === "php"
      ? `php${request.version}`
      : request.component;

/**
 * The Stack Manager (spec §11.1).
 *
 * A base install has none of this. Everything the server actually serves with
 * is installed here, on demand, from the vendor's own repository.
 */
export function StackPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const stack = useQuery({
    queryKey: ["stack"],
    queryFn: endpoints.stack,
    // Installs take minutes; keep the page honest while one is running.
    refetchInterval: (query) =>
      query.state.data?.components.some((c) => c.status === "installing" || c.status === "removing")
        ? 3_000
        : 20_000,
  });

  const install = useMutation({
    mutationFn: endpoints.installComponent,
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["stack"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  const remove = useMutation({
    mutationFn: endpoints.removeComponent,
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["stack"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : String(e)),
  });

  if (stack.isPending) {
    return (
      <div className="space-y-6">
        <PageHeader title={t("stack.title")} description={t("stack.subtitle")} />
        <section className="space-y-3">
          <SectionHeading title={t("stack.webServer")} hint={t("stack.webServerHint")} />
          <StackSkeleton rows={1} />
        </section>
        <section className="space-y-3">
          <SectionHeading title={t("stack.php")} hint={t("stack.phpHint")} />
          <StackSkeleton rows={PHP_VERSIONS.length} />
        </section>
      </div>
    );
  }

  const components = stack.data?.components ?? [];
  const nginx = components.find((c) => c.slug === "nginx");
  const php = components.filter((c) => c.slug.startsWith("php"));
  // The agent has offered these since the beginning; this page simply never
  // asked for them, so a database could not be installed from the panel at all
  // — and `db.create` refuses with "install it from the Stack Manager first",
  // pointing at a page that did not list it.
  const databases = components.filter((c) => c.slug === "mariadb" || c.slug === "postgres");
  const busy = install.isPending || remove.isPending;

  // Only the row the operator clicked should spin. The rest are merely disabled,
  // because the agent runs one package manager at a time.
  const acting = install.isPending
    ? slugFor(install.variables)
    : remove.isPending
      ? slugFor(remove.variables)
      : null;

  return (
    <div className="space-y-6">
      <PageHeader title={t("stack.title")} description={t("stack.subtitle")} />

      {error ? <Callout tone="danger">{error}</Callout> : null}

      <section aria-labelledby="stack-web-server" className="space-y-3">
        <SectionHeading
          id="stack-web-server"
          title={t("stack.webServer")}
          hint={t("stack.webServerHint")}
        />
        <Table className="min-w-[560px]">
          <ColumnHeadings />
          <tbody>
            {nginx ? (
              <ComponentRow
                component={nginx}
                busy={busy}
                pending={acting === nginx.slug}
                onInstall={() => install.mutate(requestFor(nginx.slug))}
                onRemove={() => remove.mutate(requestFor(nginx.slug))}
              />
            ) : null}
          </tbody>
        </Table>
      </section>

      <section aria-labelledby="stack-php" className="space-y-3">
        <SectionHeading id="stack-php" title={t("stack.php")} hint={t("stack.phpHint")} />
        <Table className="min-w-[560px]">
          <ColumnHeadings />
          <tbody>
            {PHP_VERSIONS.map((version, index) => {
              const component = php.find((c) => c.slug === `php${version}`);
              if (!component) return null;
              return (
                <ComponentRow
                  key={version}
                  component={component}
                  eol={EOL_PHP_VERSIONS.has(version)}
                  busy={busy}
                  pending={acting === component.slug}
                  index={index}
                  onInstall={() => install.mutate(requestFor(component.slug))}
                  onRemove={() => remove.mutate(requestFor(component.slug))}
                />
              );
            })}
          </tbody>
        </Table>
      </section>

      {databases.length > 0 ? (
        <section aria-labelledby="stack-db" className="space-y-3">
          <SectionHeading
            id="stack-db"
            title={t("stack.databases")}
            hint={t("stack.databasesHint")}
          />
          <Table className="min-w-[560px]">
            <ColumnHeadings />
            <tbody>
              {databases.map((component, index) => (
                <ComponentRow
                  key={component.slug}
                  component={component}
                  busy={busy}
                  pending={acting === component.slug}
                  index={index}
                  onInstall={() => install.mutate(requestFor(component.slug))}
                  onRemove={() => remove.mutate(requestFor(component.slug))}
                />
              ))}
            </tbody>
          </Table>
        </section>
      ) : null}

      {(stack.data?.unverified_pins.length ?? 0) > 0 ? (
        <Callout tone="warning" title={t("stack.pinsTitle")}>
          <p>{t("stack.pinsHint")}</p>
          <p className="mt-1.5 font-mono text-xs text-ink-subtle">
            {stack.data!.unverified_pins.join(", ")}
          </p>
        </Callout>
      ) : null}
    </div>
  );
}

/**
 * A section's label above its table.
 *
 * Deliberately not `CardHeader`: the table below brings its own card shell, and
 * a header nested inside it would put the label behind the same border as the
 * data it introduces.
 */
function SectionHeading({ id, title, hint }: { id?: string; title: string; hint: string }) {
  return (
    <div>
      <h2 id={id} className="text-sm font-semibold text-ink">
        {title}
      </h2>
      <p className="mt-0.5 text-sm text-ink-muted">{hint}</p>
    </div>
  );
}

/** Both tables carry the same four columns, so they name them the same way. */
function ColumnHeadings() {
  const { t } = useTranslation();
  return (
    <thead>
      <tr>
        <Th>{t("stack.component")}</Th>
        <Th className="w-40">{t("stack.version")}</Th>
        <Th className="w-40">{t("stack.status")}</Th>
        <Th className="w-32">
          <span className="sr-only">{t("stack.actions")}</span>
        </Th>
      </tr>
    </thead>
  );
}

/** Ghost rows in the real table shell, so nothing moves when the data lands. */
function StackSkeleton({ rows }: { rows: number }) {
  return (
    <div role="status" aria-live="polite">
      <Table className="min-w-[560px]">
        <ColumnHeadings />
        <tbody>
          {Array.from({ length: rows }, (_, i) => (
            <tr key={i} className="animate-rise-in stagger" style={staggerStyle(i)}>
              <Td>
                <Skeleton className="h-4 w-40" />
              </Td>
              <Td>
                <Skeleton className="h-3 w-16" />
              </Td>
              <Td>
                <Skeleton className="h-5 w-24 rounded-full" />
              </Td>
              <Td>
                <Skeleton className="ms-auto h-8 w-24 rounded-lg" />
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function ComponentRow({
  component,
  eol,
  busy,
  pending,
  index,
  onInstall,
  onRemove,
}: {
  component: StackComponentView;
  eol?: boolean;
  busy: boolean;
  /** This row is the one whose mutation is in flight right now. */
  pending: boolean;
  index?: number;
  onInstall: () => void;
  onRemove: () => void;
}) {
  const { t } = useTranslation();
  const inFlight = component.status === "installing" || component.status === "removing";
  const installed = component.status === "installed";
  // On the machine, but this panel did not put it there. Offering "Install"
  // invites an operator to add a vendor repository over a running nginx and
  // replace a configuration that is serving their sites; offering "Remove" is
  // worse. Neither is ours to press.
  const unmanaged = component.status === "unmanaged";
  const working = inFlight || pending;

  // Our bookkeeping and systemd can disagree if somebody removed a package by
  // hand. Say so rather than quietly showing one of the two.
  const disagrees = installed && !component.unit_active;

  return (
    <Tr
      className={index === undefined ? undefined : "animate-rise-in stagger"}
      style={index === undefined ? undefined : staggerStyle(index)}
    >
      <Td>
        <p className="text-sm font-medium text-ink">
          {component.display_name}
          {eol ? (
            <span className="ms-2 text-xs font-normal text-warning">{t("stack.eol")}</span>
          ) : null}
        </p>
        {component.last_error ? (
          <p className="mt-0.5 max-w-md font-mono text-xs break-words text-danger">
            {component.last_error}
          </p>
        ) : null}
        {disagrees ? (
          <p className="mt-0.5 text-xs text-warning">{t("stack.notRunning")}</p>
        ) : null}
        {working ? (
          // An install runs for minutes behind a 3s poll. A bar that keeps
          // sweeping says the agent is still working on it; a disabled button
          // on its own is indistinguishable from a page that has stopped.
          <div
            className="shimmer mt-2 h-0.5 w-40 max-w-full rounded-full bg-accent-soft"
            aria-hidden
          />
        ) : null}
      </Td>
      <Td className="font-mono text-xs text-ink-subtle">
        {component.installed_version ? component.installed_version : t("common.none")}
      </Td>
      <Td>
        <Badge tone={TONE[component.status]} dot>
          {t(`stack.state.${component.status}`)}
        </Badge>
      </Td>
      <Td className="text-end whitespace-nowrap">
        {unmanaged ? (
          <span className="text-xs text-ink-muted">{t("stack.unmanagedNote")}</span>
        ) : installed ? (
          <Button variant="danger" size="sm" loading={working} disabled={busy} onClick={onRemove}>
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
            {t("stack.remove")}
          </Button>
        ) : (
          <Button
            variant={component.status === "failed" ? "outline" : "primary"}
            size="sm"
            loading={working}
            disabled={busy}
            onClick={onInstall}
          >
            <Download className="h-3.5 w-3.5" aria-hidden />
            {component.status === "failed" ? t("common.retry") : t("stack.install")}
          </Button>
        )}
      </Td>
    </Tr>
  );
}
