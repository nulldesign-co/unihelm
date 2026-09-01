import { cva, type VariantProps } from "class-variance-authority";
import { forwardRef, type ButtonHTMLAttributes } from "react";

import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";

/**
 * The panel's button.
 *
 * The press is the point. Every variant lifts a pixel under the pointer and
 * settles back *below* its resting position when held, so a click feels like
 * touching something rather than repainting it — 120ms in, instant out, which
 * is the ratio that reads as responsive instead of springy. Under reduced
 * motion the transforms are dropped and only the colour changes.
 */
const button = cva(
  "relative inline-flex shrink-0 items-center justify-center gap-2 rounded-lg font-medium select-none " +
    "transition-[transform,box-shadow,background-color,border-color,color,opacity] duration-150 ease-standard " +
    "hover:-translate-y-px active:translate-y-0 active:scale-[0.97] active:duration-75 " +
    "motion-reduce:hover:translate-y-0 motion-reduce:active:scale-100 " +
    "disabled:pointer-events-none disabled:opacity-50 disabled:shadow-none",
  {
    variants: {
      variant: {
        primary: "bg-accent text-on-accent shadow-glow hover:bg-accent-hover",
        secondary:
          "border border-border bg-surface text-ink shadow-card hover:border-border-strong hover:bg-surface-muted hover:shadow-card-hover",
        ghost: "text-ink-muted shadow-none hover:bg-surface-muted hover:text-ink",
        danger: "bg-danger text-white shadow-card hover:brightness-110 hover:shadow-card-hover",
        outline:
          "border border-border-strong text-ink hover:border-accent hover:bg-accent-soft hover:text-accent",
      },
      size: {
        sm: "h-8 px-3 text-sm",
        md: "h-9 px-4 text-sm",
        lg: "h-11 px-5 text-base",
        icon: "h-9 w-9",
        "icon-sm": "h-8 w-8",
      },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {
  /**
   * Show a spinner and refuse further clicks.
   *
   * The label stays in place and keeps the button's width — a button that
   * shrinks to a spinner moves everything beside it at the exact moment the
   * user is watching to see whether their click worked.
   */
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, type = "button", loading, children, disabled, ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(button({ variant, size }), className)}
      {...props}
    >
      {loading ? (
        <>
          {/* The spinner is decoration here — `aria-busy` on the button is what
              carries "in flight" to a screen reader, and a second live region
              inside a button would just talk over it. */}
          <span className="absolute inset-0 grid place-items-center" aria-hidden>
            <Spinner className="h-4 w-4" />
          </span>
          {/* Transparent, not hidden: this span is still the button's
              accessible name. Marking it aria-hidden left the button nameless
              for exactly as long as the mutation ran. */}
          <span className="inline-flex items-center gap-2 opacity-0">{children}</span>
        </>
      ) : (
        children
      )}
    </button>
  ),
);
Button.displayName = "Button";
