import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * An empty list that teaches (spec §4.2): what would live here, why it is
 * worth having, and the button that starts it. Dashed border on purpose — it
 * reads as a place where something belongs, not as missing data.
 */
export function EmptyState({
  icon,
  title,
  hint,
  action,
  className,
}: {
  icon?: ReactNode;
  title: ReactNode;
  hint?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "animate-pop-in rounded-card border border-dashed border-border-strong px-6 py-14 text-center",
        className,
      )}
    >
      {icon ? (
        <div
          className="mx-auto mb-4 grid h-11 w-11 place-items-center rounded-full bg-surface-muted text-ink-subtle [&>svg]:h-5 [&>svg]:w-5"
          aria-hidden
        >
          {icon}
        </div>
      ) : null}
      <p className="text-sm font-medium text-ink">{title}</p>
      {hint ? <p className="mx-auto mt-1 max-w-md text-sm text-ink-muted">{hint}</p> : null}
      {action ? <div className="mt-5 flex justify-center">{action}</div> : null}
    </div>
  );
}
