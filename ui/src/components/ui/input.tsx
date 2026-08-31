import { forwardRef, type InputHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-9 w-full rounded-lg border border-border bg-surface px-3 text-sm text-ink shadow-card",
        "transition-colors placeholder:text-ink-subtle hover:border-border-strong",
        "focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-accent",
        "aria-[invalid=true]:border-danger",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";

export function Field({
  label,
  htmlFor,
  error,
  children,
}: {
  label: string;
  htmlFor: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-sm font-medium text-ink">
        {label}
      </label>
      {children}
      {/* aria-live so a screen reader announces validation without a focus jump. */}
      <p className="min-h-4 text-xs text-danger" aria-live="polite">
        {error ?? ""}
      </p>
    </div>
  );
}
