import { cva, type VariantProps } from "class-variance-authority";
import { forwardRef, type ButtonHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

const button = cva(
  "inline-flex shrink-0 items-center justify-center gap-2 rounded-lg font-medium transition-colors " +
    "disabled:pointer-events-none disabled:opacity-50 select-none",
  {
    variants: {
      variant: {
        primary: "bg-accent text-on-accent shadow-card hover:bg-accent-hover",
        secondary: "border border-border bg-surface text-ink shadow-card hover:bg-surface-muted",
        ghost: "text-ink-muted hover:bg-surface-muted hover:text-ink",
        danger: "bg-danger text-white shadow-card hover:opacity-90",
        outline: "border border-border-strong text-ink hover:bg-surface-muted",
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
    VariantProps<typeof button> {}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, type = "button", ...props }, ref) => (
    <button ref={ref} type={type} className={cn(button({ variant, size }), className)} {...props} />
  ),
);
Button.displayName = "Button";
