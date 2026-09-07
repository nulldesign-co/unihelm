import { ChevronDown } from "lucide-react";
import { forwardRef, type SelectHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

/**
 * A native select in the panel's clothes: `appearance-none` plus our own
 * chevron, positioned with a logical inset so it sits on the correct side in
 * both directions.
 *
 * ## The popup stays native, and that is the decision rather than the leftover
 *
 * It was reported as a bug that the open menu is the platform's own — white
 * ground, an OS-blue highlight, the system UI font — against the panel's dark
 * theme, with two suggested fixes: set `color-scheme: dark`, or replace this
 * with a custom listbox.
 *
 * The first is already done and is not where the problem was. `index.css` sets
 * `color-scheme: light` on `html` and `dark` on `html.dark`; `color-scheme` is
 * an inherited property, so this element and its popup already get the panel's
 * theme, and every current engine paints the menu chrome, the scrollbar and the
 * default option ground from it. Adding the declaration again here would be a
 * second place to keep in step with a theme switch that already works.
 *
 * The second is refused. A native `<select>` is the one control that is
 * complete on every input the panel is used from without us writing a line:
 * type-ahead, Home/End, PageUp/PageDown, the screen reader announcing "combo
 * box, 3 of 12", the OS wheel on a phone, and a menu that escapes the dialog's
 * own scroll container instead of being clipped by it. A hand-built listbox has
 * to earn all of that back through `aria-activedescendant`, a focus trap, a
 * portal and roving keyboard state — and the failure mode when it falls short
 * is a keyboard user who cannot choose a PHP version at all. Prettier is not
 * worth that trade; a dropdown that looks right and strands somebody is a worse
 * defect than one that looks like the OS.
 *
 * ## So what is actually fixed here
 *
 * The one part of a native popup an author can genuinely influence: the
 * `<option>` rows. `background-color` is not an inherited property, so the
 * `bg-surface` on the control below never reached them and they fell back to
 * the engine's own idea of a dark ground — near-black on Chromium, a grey on
 * Firefox, neither of them the panel's surface. Painting them explicitly puts
 * the list on the same two tokens as everything else in the panel, on the
 * engines that honour it (Chromium and Firefox on Windows and Linux), and is
 * ignored without harm on macOS, where the menu is drawn by the OS.
 *
 * What is still the platform's, honestly: the selection highlight, the popup's
 * border and shadow, and its animation. None of those are styleable from CSS on
 * a native menu today. `appearance: base-select` with `::picker(select)` would
 * make them so and is the thing to revisit here — once it is available on every
 * browser this panel supports, not before, because a half-supported switch
 * means two different dropdowns depending on who is logged in.
 */
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, ...props }, ref) => (
    <span className="relative block">
      <select
        ref={ref}
        className={cn(
          "h-9 w-full appearance-none rounded-lg border border-border bg-surface ps-3 pe-9 text-sm text-ink shadow-card",
          "transition-[border-color,box-shadow] duration-150 hover:border-border-strong",
          "focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-accent",
          // The rows of the native popup. `color` is inherited and would arrive
          // anyway; it is stated beside the background because the two are a
          // contrast pair and splitting them is how one gets changed alone.
          "[&_option]:bg-surface [&_option]:text-ink",
          className,
        )}
        {...props}
      />
      <ChevronDown
        className="pointer-events-none absolute end-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-subtle"
        aria-hidden
      />
    </span>
  ),
);
Select.displayName = "Select";
