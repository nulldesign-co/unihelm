import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Download, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
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
      <div className="flex justify-center py-24 text-ink-muted">
        <Spinner className="h-6 w-6" />
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
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{t("stack.title")}</h1>
        <p className="mt-1 text-sm text-ink-muted">{t("stack.subtitle")}</p>
      </header>

      {error ? (
        <p role="alert" className="rounded-card bg-danger-soft px-4 py-3 text-sm text-danger">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader title={t("stack.webServer")} description={t("stack.webServerHint")} />
        <CardBody>
          {nginx ? (
            <ComponentRow
              component={nginx}
              busy={busy}
              onInstall={() => install.mutate(request(nginx.slug))}
              onRemove={() => remove.mutate(request(nginx.slug))}
            />
          ) : null}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title={t("stack.php")} description={t("stack.phpHint")} />
        <CardBody>
          <ul className="divide-y divide-border">
            {PHP_VERSIONS.map((version) => {
              const component = php.find((c) => c.slug === `php${version}`);
              if (!component) return null;
              return (
                <li key={version}>
                  <ComponentRow
                    component={component}
                    eol={EOL_PHP_VERSIONS.has(version)}
                    busy={busy}
                    onInstall={() => install.mutate(request(component.slug))}
                    onRemove={() => remove.mutate(request(component.slug))}
                  />
                </li>
              );
            })}
          </ul>
        </CardBody>
      </Card>

      {(stack.data?.unverified_pins.length ?? 0) > 0 ? (
        <Card className="border-warning/30">
          <CardBody className="flex gap-3 pt-5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
            <div>
              <p className="text-sm font-medium text-ink">{t("stack.pinsTitle")}</p>
              <p className="mt-0.5 text-sm text-ink-muted">{t("stack.pinsHint")}</p>
              <p dir="ltr" className="mt-1.5 font-mono text-xs text-ink-subtle">
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
    <div className="flex items-center gap-3 py-3 first:pt-0 last:pb-0">
      <Badge tone={TONE[component.status]} dot={inFlight}>
        {t(`stack.state.${component.status}`)}
      </Badge>

      <div className="min-w-0 flex-1">
        <p className="truncate text-sm text-ink">
          {component.display_name}
          {eol ? (
            <span className="ms-2 text-xs text-warning">{t("stack.eol")}</span>
          ) : null}
        </p>
        {component.installed_version ? (
          <p dir="ltr" className="font-mono text-xs text-ink-subtle">
            {component.installed_version}
          </p>
        ) : null}
        {component.last_error ? (
          <p dir="ltr" className="mt-0.5 font-mono text-xs text-danger">
            {component.last_error}
          </p>
        ) : null}
        {disagrees ? (
          <p className="mt-0.5 text-xs text-warning">{t("stack.notRunning")}</p>
        ) : null}
      </div>

      {installed ? (
        <Button variant="ghost" size="sm" disabled={busy || inFlight} onClick={onRemove}>
          <Trash2 className="h-3.5 w-3.5" />
          {t("stack.remove")}
        </Button>
      ) : (
        <Button
          variant={component.status === "failed" ? "outline" : "primary"}
          size="sm"
          disabled={busy || inFlight}
          onClick={onInstall}
        >
          {inFlight ? <Spinner /> : <Download className="h-3.5 w-3.5" />}
          {component.status === "failed" ? t("common.retry") : t("stack.install")}
        </Button>
      )}
    </div>
  );
}
