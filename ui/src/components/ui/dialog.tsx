import { X } from "lucide-react";
import { useEffect, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";

/**
 * A modal.
 *
 * Escape closes it and the backdrop is clickable, because a dialog you can only
 * leave by finding the right button is a dialog people learn to dread.
 */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const { t } = useTranslation();

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 pt-[8vh] backdrop-blur-[1px]"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div
        className="w-full max-w-lg rounded-card border border-border bg-surface shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
          <div>
            <h2 className="text-sm font-semibold text-ink">{title}</h2>
            {description ? <p className="mt-0.5 text-sm text-ink-muted">{description}</p> : null}
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} aria-label={t("common.close")}>
            <X className="h-4 w-4" />
          </Button>
        </header>

        <div className="px-5 py-4">{children}</div>

        {footer ? (
          <footer className="flex justify-end gap-2 border-t border-border px-5 py-3.5">{footer}</footer>
        ) : null}
      </div>
    </div>
  );
}
