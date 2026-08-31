import { ChevronDown } from "lucide-react";
import { forwardRef, type SelectHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

/**
 * A native select in the panel's clothes: `appearance-none` plus our own
 * chevron, positioned with a logical inset so it sits on the correct side in
 * both directions. The menu itself stays the platform's — nothing beats it for
 * keyboard and screen-reader behaviour.
 */
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, ...props }, ref) => (
    <span className="relative block">
      <select
        ref={ref}
        className={cn(
          "h-9 w-full appearance-none rounded-lg border border-border bg-surface ps-3 pe-9 text-sm text-ink shadow-card",
          "transition-colors hover:border-border-strong",
          "focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-accent",
          className,
        )}
        {...props}
      />
      <ChevronDown
        className="pointer-events-none absolute end-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-subtle"
        aria-hidden
      />
    </span>
  ),
);
Select.displayName = "Select";
