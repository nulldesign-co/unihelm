import type { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

/**
 * Tabular data, panel-wide.
 *
 * The card scrolls sideways so the page never does; the header stays lower
 * case and muted because a table's data, not its labels, is the point.
 */
export function Table({
  className,
  containerClassName,
  ...props
}: HTMLAttributes<HTMLTableElement> & { containerClassName?: string }) {
  return (
    <div
      className={cn(
        "overflow-x-auto rounded-card border border-border bg-surface shadow-card",
        containerClassName,
      )}
    >
      <table className={cn("w-full text-sm", className)} {...props} />
    </div>
  );
}

export function Th({ className, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope="col"
      className={cn(
        "border-b border-border px-4 py-2.5 text-start text-xs font-medium text-ink-muted",
        className,
      )}
      {...props}
    />
  );
}

export function Td({ className, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td
      className={cn(
        "border-b border-border px-4 py-3 align-middle text-ink last:border-b-0 [tr:last-child>&]:border-b-0",
        className,
      )}
      {...props}
    />
  );
}
