import { MoreHorizontal } from "lucide-react";
import { createPortal } from "react-dom";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const MenuContext = createContext<{ close: () => void } | null>(null);

/**
 * A row's overflow menu.
 *
 * Three inline buttons per row is a control panel; one "⋯" is a row. Escape
 * and clicking anywhere else close it, and it is a real popover in the DOM
 * right after its trigger, so focus order stays sane without a portal.
 *
 * The panel is `fixed` and portalled to the body, and both halves are load
 * bearing. Every table in the app sits in an `overflow-x-auto` container, and
 * CSS makes the other axis `auto` too whenever one axis is not `visible`, so an
 * absolutely positioned menu on a table's last row was clipped by the card's
 * edge — the destructive action, hidden exactly where people reach for it.
 * `fixed` alone does not save it either: any ancestor with a transform becomes
 * the containing block for fixed descendants, and this app has plenty (a card
 * lifting on hover is one). The portal puts the panel beyond all of it.
 *
 * The cost of the portal is that the panel is no longer next to its trigger in
 * the tab order, so this manages focus itself: the first item takes focus on
 * open, arrows move between items, and focus returns to the trigger on close.
 */
export function Menu({
  label,
  trigger,
  align = "end",
  children,
}: {
  /** Accessible name for the trigger. */
  label: string;
  /** Custom trigger; defaults to a ⋯ icon button. */
  trigger?: ReactNode;
  align?: "start" | "end";
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLSpanElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<{ top: number; left: number; flip: boolean } | null>(
    null,
  );

  /**
   * Pin the panel under its trigger in viewport coordinates.
   *
   * Measured rather than declared, because `fixed` means the menu no longer
   * knows where its trigger is. The end-aligned case is anchored on the
   * trigger's trailing edge so the menu still hangs off the same corner it did
   * when it was absolutely positioned.
   */
  const place = useCallback(() => {
    const trigger = triggerRef.current;
    const panel = panelRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    // Flip above the trigger when there is not room below. A row menu on the
    // last row of a long table is the common case, and a menu that opens off
    // the bottom of the window is the same defect as one that is clipped.
    const height = panel?.offsetHeight ?? 0;
    const spaceBelow = window.innerHeight - rect.bottom;
    const flip = height > 0 && spaceBelow < height + 8 && rect.top > spaceBelow;
    setPosition({
      top: flip ? rect.top - 4 : rect.bottom + 4,
      left: align === "end" ? rect.right : rect.left,
      flip,
    });
  }, [align]);

  useLayoutEffect(() => {
    if (!open) {
      setPosition(null);
      return;
    }
    // Twice: the first pass mounts the panel so it has a height, the second
    // uses that height to decide whether it must open upward.
    place();
    const frame = requestAnimationFrame(place);
    return () => cancelAnimationFrame(frame);
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    // Capture phase: the scroll that moves the menu is usually the table's own
    // container, not the window, and a scroll event on it does not bubble.
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);
    return () => {
      window.removeEventListener("scroll", place, true);
      window.removeEventListener("resize", place);
    };
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      // The panel is portalled, so "outside" means outside both halves.
      if (rootRef.current?.contains(target) || panelRef.current?.contains(target)) return;
      setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        // Escape should land the caret back on the control it came from, not
        // on the body — the row menu is often reopened straight away.
        triggerRef.current?.querySelector("button")?.focus();
        return;
      }
      const items = panelRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]');
      if (!items?.length) return;
      if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
      event.preventDefault();
      const list = [...items];
      const at = list.indexOf(document.activeElement as HTMLElement);
      const next =
        event.key === "ArrowDown"
          ? list[(at + 1) % list.length]
          : list[(at - 1 + list.length) % list.length];
      next?.focus();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // The first item takes focus once the panel is placed, so a keyboard user
  // lands inside the menu they just opened rather than back at the document.
  useEffect(() => {
    if (!open || !position) return;
    panelRef.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
  }, [open, position]);

  return (
    <div ref={rootRef} className="relative inline-block">
      <span ref={triggerRef} onClick={() => setOpen((v) => !v)}>
        {trigger ?? (
          <Button variant="ghost" size="icon-sm" aria-label={label} aria-expanded={open}>
            <MoreHorizontal className="h-4 w-4" />
          </Button>
        )}
      </span>
      {open && createPortal(
        <div
          role="menu"
          aria-label={label}
          ref={panelRef}
          style={{
            top: position?.top ?? 0,
            left: position?.left ?? 0,
            // Two translates, neither of which needs a measured width or
            // height: `end` hangs the panel off the trigger's trailing edge,
            // and a flipped panel sits on its own bottom edge.
            transform: [
              align === "end" ? "translateX(-100%)" : "",
              position?.flip ? "translateY(-100%)" : "",
            ]
              .filter(Boolean)
              .join(" ") || undefined,
          }}
          className={cn(
            "fixed z-50 min-w-40 animate-pop-in rounded-lg border border-border bg-surface p-1 shadow-pop",
            // One frame is spent measuring the panel to decide whether it opens
            // upward; without this it would flash at the window's corner first.
            position ? "" : "invisible",
          )}
        >
          <MenuContext.Provider
            value={{
              close: () => {
                setOpen(false);
                triggerRef.current?.querySelector("button")?.focus();
              },
            }}
          >
            {children}
          </MenuContext.Provider>
        </div>,
        document.body,
      )}
    </div>
  );
}

export function MenuItem({
  className,
  danger,
  icon,
  children,
  onClick,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { danger?: boolean; icon?: ReactNode }) {
  const context = useContext(MenuContext);
  return (
    <button
      type="button"
      role="menuitem"
      className={cn(
        "flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-start text-sm transition-colors",
        danger ? "text-danger hover:bg-danger-soft" : "text-ink hover:bg-surface-muted",
        "disabled:pointer-events-none disabled:opacity-50",
        className,
      )}
      onClick={(event) => {
        onClick?.(event);
        context?.close();
      }}
      {...props}
    >
      {icon ? <span className="[&>svg]:h-4 [&>svg]:w-4" aria-hidden>{icon}</span> : null}
      {children}
    </button>
  );
}

export function MenuSeparator() {
  return <div role="separator" className="my-1 border-t border-border" />;
}
