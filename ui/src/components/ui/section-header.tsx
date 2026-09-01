import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * The heading for a band of a page.
 *
 * `PageHeader` names the page; this names a section within it — the level that
 * pages like Backups and Firewall need three or four times each. There were
 * four private copies of it before this file existed, two byte-identical and
 * two differing only in a prop name, which is exactly how a heading ends up
 * with three different sizes in one product.
 *
 * It renders an `<h2>`, so a page's sections stay one level under its `<h1>`
 * and the document outline reads the way the layout looks.
 */
export function SectionHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  /** Buttons for the section as a whole — "Add repository", "Open port". */
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn("flex flex-wrap items-start justify-between gap-x-4 gap-y-2", className)}
    >
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {description ? <p className="mt-0.5 text-sm text-ink-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
