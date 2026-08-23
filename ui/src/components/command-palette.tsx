import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { cn } from "@/lib/utils";

export interface Command {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

/**
 * ⌘K navigation (spec §4.2).
 *
 * Keyboard-first is not decoration here: the people who use a hosting panel all
 * day are the same people who live in a terminal.
 */
export function CommandPalette({
  open,
  onOpenChange,
  commands,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  commands: Command[];
}) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        onOpenChange(!open);
      }
      if (event.key === "Escape" && open) onOpenChange(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onOpenChange]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return commands;
    return commands.filter((c) => c.label.toLowerCase().includes(needle));
  }, [commands, query]);

  if (!open) return null;

  const choose = (index: number) => {
    const command = matches[index];
    if (!command) return;
    onOpenChange(false);
    command.run();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/30 pt-[12vh] backdrop-blur-[1px]"
      onClick={() => onOpenChange(false)}
      role="dialog"
      aria-modal="true"
      aria-label={t("nav.commandPalette")}
    >
      <div
        className="w-full max-w-lg overflow-hidden rounded-card border border-border bg-surface shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <input
          autoFocus
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActive(0);
          }}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") {
              event.preventDefault();
              setActive((i) => Math.min(i + 1, matches.length - 1));
            } else if (event.key === "ArrowUp") {
              event.preventDefault();
              setActive((i) => Math.max(i - 1, 0));
            } else if (event.key === "Enter") {
              event.preventDefault();
              choose(active);
            }
          }}
          placeholder={t("common.search")}
          aria-label={t("common.search")}
          className="w-full border-b border-border bg-transparent px-4 py-3.5 text-sm text-ink outline-none placeholder:text-ink-subtle"
        />

        <ul className="max-h-80 overflow-y-auto py-1.5">
          {matches.map((command, index) => (
            <li key={command.id}>
              <button
                onMouseEnter={() => setActive(index)}
                onClick={() => choose(index)}
                className={cn(
                  "flex w-full items-center justify-between gap-3 px-4 py-2 text-start text-sm",
                  index === active ? "bg-accent-soft text-accent" : "text-ink hover:bg-surface-muted",
                )}
              >
                <span>{command.label}</span>
                {command.hint ? (
                  <kbd className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-ink-subtle">
                    {command.hint}
                  </kbd>
                ) : null}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
