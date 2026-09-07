import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * A surface that holds one idea.
 *
 * `interactive` is for cards that are themselves a link or a button: it adds
 * the lift and the border warm-up that tell a pointer "this whole thing is the
 * target". A card that merely contains buttons must not use it — a surface that
 * reacts to hover but does nothing when clicked is a small betrayal.
 */
export function Card({
  className,
  interactive,
  ...props
}: HTMLAttributes<HTMLDivElement> & { interactive?: boolean }) {
  return (
    <div
      className={cn(
        "rounded-card border border-border bg-surface shadow-card",
        interactive &&
          "transition-[transform,box-shadow,border-color] duration-200 ease-standard " +
            "hover:-translate-y-0.5 hover:border-border-strong hover:shadow-card-hover " +
            "motion-reduce:hover:translate-y-0",
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({
  title,
  description,
  action,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-4 px-5 pt-4 pb-3", className)}>
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {description ? <p className="mt-0.5 text-sm text-ink-muted">{description}</p> : null}
      </div>
      {action}
    </div>
  );
}

/**
 * The card's content well.
 *
 * The top inset is positional — `first:pt-5`, not a bare `pt-5` — because the
 * two shapes a body appears in want opposite things. After a `CardHeader` the
 * header's own `pb-3` is the gap, and a second inset on top of it opens a
 * gutter. As a card's *first* child there is nothing above it at all, and for
 * a long time this had no top padding for that case: the seven headerless
 * cards in the panel each pressed their first element against the card border,
 * most visibly the terminal's start panel, where a Callout sat wedged into the
 * corner. `first:` gets both cases from one rule instead of asking every call
 * site to remember which shape it is.
 *
 * A call site that wants a different first-child inset must say so with the
 * same variant (`first:pt-3`). A bare `pt-3` will not win: it is one class
 * against a class-plus-pseudo-class, and tailwind-merge leaves both in place
 * because they carry different modifiers.
 */
export function CardBody({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-5 pb-5 first:pt-5", className)} {...props} />;
}
