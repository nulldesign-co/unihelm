import { cn } from "@/lib/utils";

/**
 * A usage bar.
 *
 * Turns amber past 75% and red past 90%, because "the disk is nearly full" is
 * something an operator should notice without reading the number.
 */
export function Meter({ value, label }: { value: number; label: string }) {
  const pct = Math.min(100, Math.max(0, value));
  const tone = pct >= 90 ? "bg-danger" : pct >= 75 ? "bg-warning" : "bg-accent";

  return (
    <div
      role="meter"
      aria-valuenow={Math.round(pct)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
      className="h-1.5 w-full overflow-hidden rounded-full bg-surface-muted"
    >
      <div
        className={cn("h-full rounded-full transition-[width] duration-500", tone)}
        style={{ inlineSize: `${pct}%` }}
      />
    </div>
  );
}
