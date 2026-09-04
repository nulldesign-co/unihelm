import {
  cloneElement,
  forwardRef,
  isValidElement,
  type InputHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";

import { cn } from "@/lib/utils";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-9 w-full rounded-lg border border-border bg-surface px-3 text-sm text-ink shadow-card",
        "transition-[border-color,box-shadow,background-color] duration-150 placeholder:text-ink-subtle hover:border-border-strong",
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
  const errorId = `${htmlFor}-error`;
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-sm font-medium text-ink">
        {label}
      </label>
      {/* The control is the caller's, so the link to the message is made here
          rather than asking eighteen call sites to remember it. `describedby`
          is dropped when the field is valid — pointing at an empty paragraph
          makes a screen reader announce a description that is not there. */}
      {isValidElement<{ "aria-describedby"?: string }>(children)
        ? cloneElement(children, {
            "aria-describedby": error
              ? [children.props["aria-describedby"], errorId].filter(Boolean).join(" ")
              : children.props["aria-describedby"],
          })
        : children}
      {/* The box is always here so the layout does not jump when a message
          arrives; aria-live announces it without stealing focus. */}
      <p id={errorId} className="min-h-4 text-xs text-danger" aria-live="polite">
        {error ?? ""}
      </p>
    </div>
  );
}

/**
 * The multi-line sibling of `Input`.
 *
 * Lifted out of plans.tsx, where it had been defined privately — a second page
 * needing it is the moment a local component becomes a shared one, and two
 * copies of the same class list is how they drift.
 */
export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        "w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink shadow-card",
        "transition-[border-color,box-shadow] duration-150 placeholder:text-ink-subtle hover:border-border-strong",
        "focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-accent",
        "aria-[invalid=true]:border-danger",
        className,
      )}
      {...props}
    />
  ),
);
Textarea.displayName = "Textarea";
