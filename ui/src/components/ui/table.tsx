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
        "border-b border-border bg-surface px-4 py-2.5 text-start text-xs font-medium text-ink-muted",
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

/**
 * A body row that answers the pointer.
 *
 * The tint alone is too quiet on a wide table — by the time the eye reaches
 * column six it has lost the row. The accent bar drawn in the first cell's
 * ::before is what keeps the row found, and it grows from the top so the
 * movement points along the row rather than at it.
 */
export function Tr({ className, ...props }: HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr
      className={cn(
        "group/row relative transition-colors duration-150 hover:bg-surface-muted/60",
        "[&>td:first-child]:before:absolute [&>td:first-child]:before:inset-y-1 [&>td:first-child]:before:start-0",
        "[&>td:first-child]:before:w-0.5 [&>td:first-child]:before:origin-top [&>td:first-child]:before:scale-y-0",
        "[&>td:first-child]:before:rounded-full [&>td:first-child]:before:bg-accent",
        "[&>td:first-child]:before:transition-transform [&>td:first-child]:before:duration-200",
        "hover:[&>td:first-child]:before:scale-y-100",
        className,
      )}
      {...props}
    />
  );
}
