import { Search, SearchX, type LucideIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { cn } from "@/lib/utils";

export interface Command {
  id: string;
  label: string;
  hint?: string;
  icon?: LucideIcon;
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
      className="fixed inset-0 z-50 flex animate-fade-in items-start justify-center bg-black/40 pt-[12vh] backdrop-blur-[2px]"
      onClick={() => onOpenChange(false)}
      role="dialog"
      aria-modal="true"
      aria-label={t("nav.commandPalette")}
    >
      <div
        className="w-full max-w-lg animate-pop-in overflow-hidden rounded-card border border-border bg-surface shadow-pop"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center gap-2.5 border-b border-border px-4">
          <Search className="h-4 w-4 shrink-0 text-ink-subtle" aria-hidden />
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
            className="w-full bg-transparent py-3.5 text-sm text-ink outline-none placeholder:text-ink-subtle"
          />
          <kbd className="shrink-0 rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-ink-subtle">
            esc
          </kbd>
        </div>

        {matches.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-10 text-ink-muted">
            <SearchX className="h-5 w-5 text-ink-subtle" aria-hidden />
            <p className="text-sm">{t("common.noResults")}</p>
          </div>
        ) : (
          <ul className="max-h-80 overflow-y-auto p-1.5">
            {matches.map((command, index) => (
              <li key={command.id}>
                <button
                  onMouseEnter={() => setActive(index)}
                  onClick={() => choose(index)}
                  className={cn(
                    "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-start text-sm transition-colors",
                    index === active ? "bg-accent-soft text-accent" : "text-ink",
                  )}
                >
                  {command.icon ? (
                    <command.icon
                      className={cn("h-4 w-4 shrink-0", index === active ? "" : "text-ink-subtle")}
                      aria-hidden
                    />
                  ) : (
                    <span className="w-4 shrink-0" aria-hidden />
                  )}
                  <span className="min-w-0 flex-1 truncate">{command.label}</span>
                  {command.hint ? (
                    <kbd className="shrink-0 rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-ink-subtle">
                      {command.hint}
                    </kbd>
                  ) : null}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
