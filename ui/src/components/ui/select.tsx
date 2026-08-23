import { forwardRef, type SelectHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, ...props }, ref) => (
    <select
      ref={ref}
      className={cn(
        "h-10 w-full rounded-lg border border-border-strong bg-surface px-3 text-sm text-ink",
        "focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-accent",
        className,
      )}
      {...props}
    />
  ),
);
Select.displayName = "Select";
