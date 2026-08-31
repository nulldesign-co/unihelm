import { cn } from "@/lib/utils";

/**
 * Loading that keeps the page's shape.
 *
 * A centered spinner tells the reader "wait"; a skeleton tells them "this is
 * where your list will be", and nothing jumps when it arrives (CLS is a UX
 * bug, not just a metric).
 */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("animate-pulse rounded-md bg-surface-muted", className)} />;
}

/** A card of ghost rows, shaped like the list it stands in for. */
export function ListSkeleton({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn("rounded-card border border-border bg-surface p-4 shadow-card", className)}
    >
      <div className="space-y-4">
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className="flex items-center gap-3">
            <Skeleton className="h-8 w-8 rounded-lg" />
            <div className="min-w-0 flex-1 space-y-1.5">
              <Skeleton className="h-3.5 w-1/3" />
              <Skeleton className="h-3 w-1/2" />
            </div>
            <Skeleton className="h-6 w-16 rounded-full" />
          </div>
        ))}
      </div>
    </div>
  );
}

/** A row of ghost stat cards, for dashboards. */
export function StatSkeleton({ cards = 4, className }: { cards?: number; className?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn("grid gap-4 sm:grid-cols-2 lg:grid-cols-4", className)}
    >
      {Array.from({ length: cards }, (_, i) => (
        <div key={i} className="rounded-card border border-border bg-surface p-5 shadow-card">
          <Skeleton className="mb-3 h-3 w-16" />
          <Skeleton className="h-7 w-24" />
          <Skeleton className="mt-3 h-1.5 w-full rounded-full" />
        </div>
      ))}
    </div>
  );
}
