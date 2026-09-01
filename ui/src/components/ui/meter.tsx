import { cn } from "@/lib/utils";
import { useMounted } from "@/lib/motion";

/**
 * A usage bar.
 *
 * Turns amber past 75% and red past 90%, because "the disk is nearly full" is
 * something an operator should notice without reading the number. It fills
 * from empty on first paint — the sweep is what makes a row of four meters
 * legible as four different amounts at a glance, before any of them is read.
 */
export function Meter({ value, label, className }: { value: number; label: string; className?: string }) {
  const pct = Math.min(100, Math.max(0, value));
  const tone = pct >= 90 ? "bg-danger" : pct >= 75 ? "bg-warning" : "bg-accent";
  const mounted = useMounted();

  return (
    <div
      role="meter"
      aria-valuenow={Math.round(pct)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
      className={cn("h-1.5 w-full overflow-hidden rounded-full bg-surface-muted", className)}
    >
      <div
        className={cn(
          "h-full rounded-full transition-[width,background-color] duration-700 ease-out-quint",
          tone,
        )}
        style={{ inlineSize: `${mounted ? pct : 0}%` }}
      />
    </div>
  );
}
