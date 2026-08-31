import { MoreHorizontal } from "lucide-react";
import {
  createContext,
  useContext,
  useEffect,
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

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={rootRef} className="relative inline-block">
      <span onClick={() => setOpen((v) => !v)}>
        {trigger ?? (
          <Button variant="ghost" size="icon-sm" aria-label={label} aria-expanded={open}>
            <MoreHorizontal className="h-4 w-4" />
          </Button>
        )}
      </span>
      {open ? (
        <div
          role="menu"
          aria-label={label}
          className={cn(
            "absolute top-full z-40 mt-1 min-w-40 animate-pop-in rounded-lg border border-border bg-surface p-1 shadow-pop",
            align === "end" ? "end-0" : "start-0",
          )}
        >
          <MenuContext.Provider value={{ close: () => setOpen(false) }}>
            {children}
          </MenuContext.Provider>
        </div>
      ) : null}
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
