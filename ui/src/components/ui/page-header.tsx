import { ArrowLeft } from "lucide-react";
import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * The first thing on every page: what this is, what it does, and the one action
 * that creates more of it. One component so sixteen pages agree about it.
 */
export function PageHeader({
  title,
  description,
  actions,
  back,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  /** Optional parent to return to, e.g. `{ to: "/sites", label: t("nav.sites") }`. */
  back?: { to: string; label: string };
  className?: string;
}) {
  return (
    <header className={cn("flex flex-wrap items-start justify-between gap-x-4 gap-y-3", className)}>
      <div className="min-w-0">
        {back ? (
          <Link
            to={back.to}
            className="mb-1.5 inline-flex items-center gap-1.5 text-sm text-ink-muted transition-colors hover:text-ink"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
            {back.label}
          </Link>
        ) : null}
        <h1 className="truncate text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {description ? <p className="mt-1 text-sm text-ink-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}
