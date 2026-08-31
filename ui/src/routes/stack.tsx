import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Download, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { ListSkeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Table, Td } from "@/components/ui/table";
import {
  ApiError,
  EOL_PHP_VERSIONS,
  PHP_VERSIONS,
  endpoints,
  type ComponentState,
  type StackComponentView,
} from "@/lib/api";

const TONE: Record<ComponentState, "success" | "accent" | "danger" | "neutral"> = {
  installed: "success",
  installing: "accent",
  removing: "accent",
  failed: "danger",
  absent: "neutral",
};

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
        <ListSkeleton rows={4} />
      </div>
    );
  }

  const components = stack.data?.components ?? [];
  const nginx = components.find((c) => c.slug === "nginx");
  const php = components.filter((c) => c.slug.startsWith("php"));
  const busy = install.isPending || remove.isPending;

  const request = (slug: string) =>
    slug === "nginx"
      ? ({ component: "nginx" } as const)
      : ({ component: "php", version: slug.replace("php", "") } as const);

  return (
    <div className="space-y-6">
      <PageHeader title={t("stack.title")} description={t("stack.subtitle")} />

      {error ? (
        <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}

      <section className="space-y-3">
        <div>
          <h2 className="text-sm font-semibold text-ink">{t("stack.webServer")}</h2>
          <p className="mt-0.5 text-sm text-ink-muted">{t("stack.webServerHint")}</p>
        </div>
        <Table>
          <tbody>
            {nginx ? (
              <ComponentRow
                component={nginx}
                busy={busy}
                onInstall={() => install.mutate(request(nginx.slug))}
                onRemove={() => remove.mutate(request(nginx.slug))}
              />
            ) : null}
          </tbody>
        </Table>
      </section>

      <section className="space-y-3">
        <div>
          <h2 className="text-sm font-semibold text-ink">{t("stack.php")}</h2>
          <p className="mt-0.5 text-sm text-ink-muted">{t("stack.phpHint")}</p>
        </div>
        <Table>
          <tbody>
            {PHP_VERSIONS.map((version) => {
              const component = php.find((c) => c.slug === `php${version}`);
              if (!component) return null;
              return (
                <ComponentRow
                  key={version}
                  component={component}
                  eol={EOL_PHP_VERSIONS.has(version)}
                  busy={busy}
                  onInstall={() => install.mutate(request(component.slug))}
                  onRemove={() => remove.mutate(request(component.slug))}
                />
              );
            })}
          </tbody>
        </Table>
      </section>

      {(stack.data?.unverified_pins.length ?? 0) > 0 ? (
        <Card className="border-warning/30">
          <CardBody className="flex gap-3 pt-5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
            <div>
              <p className="text-sm font-medium text-ink">{t("stack.pinsTitle")}</p>
              <p className="mt-0.5 text-sm text-ink-muted">{t("stack.pinsHint")}</p>
              <p className="mt-1.5 font-mono text-xs text-ink-subtle">
                {stack.data!.unverified_pins.join(", ")}
              </p>
            </div>
          </CardBody>
        </Card>
      ) : null}
    </div>
  );
}

function ComponentRow({
  component,
  eol,
  busy,
  onInstall,
  onRemove,
}: {
  component: StackComponentView;
  eol?: boolean;
  busy: boolean;
  onInstall: () => void;
  onRemove: () => void;
}) {
  const { t } = useTranslation();
  const inFlight = component.status === "installing" || component.status === "removing";
  const installed = component.status === "installed";

  // Our bookkeeping and systemd can disagree if somebody removed a package by
  // hand. Say so rather than quietly showing one of the two.
  const disagrees = installed && !component.unit_active;

  return (
    <tr className="transition-colors hover:bg-surface-muted/60">
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
        {installed ? (
          <Button variant="ghost" size="sm" disabled={busy || inFlight} onClick={onRemove}>
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
            {t("stack.remove")}
          </Button>
        ) : (
          <Button
            variant={component.status === "failed" ? "outline" : "primary"}
            size="sm"
            disabled={busy || inFlight}
            onClick={onInstall}
          >
            {inFlight ? <Spinner /> : <Download className="h-3.5 w-3.5" aria-hidden />}
            {component.status === "failed" ? t("common.retry") : t("stack.install")}
          </Button>
        )}
      </Td>
    </tr>
  );
}
