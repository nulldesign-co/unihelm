import { Search, SearchX, type LucideIcon } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { useFocusTrap } from "@/lib/focus";
import { cn } from "@/lib/utils";

export interface Command {
  id: string;
  label: string;
  hint?: string;
  icon?: LucideIcon;
  /**
   * Words an operator might type for this that the label does not contain —
   * "ssl" for TLS, "restore" for backups, "db" for databases.
   *
   * Never rendered: these are search aliases, not copy, which is why they are
   * written here rather than kept in the translation bundle.
   */
  keywords?: string[];
  /** Heading this command is listed under. */
  group?: string;
  run: () => void;
}

/** A heading and the commands under it, in the order they should be shown. */
export interface CommandGroup {
  label: string | null;
  commands: Command[];
}

/** How well one token matches one piece of text; 0 is "not at all". */
const EXACT = 100;
const PREFIX = 80;
const WORD_PREFIX = 60;
const SUBSTRING = 40;
const SCATTERED = 20;

/**
 * A keyword is a real match but a weaker signal than the label: typing "php"
 * should reach the Stack page, and should not outrank a page actually called
 * PHP if one is ever added.
 */
const KEYWORD_WEIGHT = 0.6;

/**
 * Below this, a scattered match is noise: the letters of "db" occur in that
 * order in "Dashboard" and in "Branding", so a two-letter query would return
 * half the menu and bury the page it actually names.
 */
const SCATTERED_MIN_LENGTH = 3;

/** Every letter of `token`, in order, somewhere in `text` — "dbs" → "Databases". */
function scattered(token: string, text: string): boolean {
  let at = 0;
  for (const letter of token) {
    at = text.indexOf(letter, at) + 1;
    if (at === 0) return false;
  }
  return true;
}

function scoreText(token: string, text: string): number {
  if (text === token) return EXACT;
  if (text.startsWith(token)) return PREFIX;
  if (text.split(/[\s-]+/).some((word) => word.startsWith(token))) return WORD_PREFIX;
  if (text.includes(token)) return SUBSTRING;
  if (token.length >= SCATTERED_MIN_LENGTH && scattered(token, text)) return SCATTERED;
  return 0;
}

/**
 * How well a command answers a query. 0 means it does not, and it is dropped.
 *
 * Every whitespace-separated token has to land somewhere — on the label or on
 * one of the keywords — so "backup restore" and "restore backup" both find the
 * Backups page and "backup docker" finds nothing rather than everything.
 */
export function scoreCommand(command: Command, query: string): number {
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return EXACT;

  const label = command.label.toLowerCase();
  const keywords = (command.keywords ?? []).map((keyword) => keyword.toLowerCase());

  let total = 0;
  for (const token of tokens) {
    const best = Math.max(
      scoreText(token, label),
      ...keywords.map((keyword) => scoreText(token, keyword) * KEYWORD_WEIGHT),
    );
    if (best === 0) return 0;
    total += best;
  }
  return total;
}

/**
 * The commands a query matches, best first, under their headings.
 *
 * Pure on purpose: this is the part that decides whether searching "ssl" finds
 * anything, and it should be provable without mounting a dialog.
 *
 * Groups come out in the order their best member scored, so the strongest match
 * is the first row of the first group — the one Enter runs — while everything
 * else stays gathered under a heading instead of interleaved. An empty query
 * keeps the order it was given, which is the order of the sidebar.
 */
export function searchCommands(commands: Command[], query: string): CommandGroup[] {
  const needle = query.trim();
  const ranked = commands
    .map((command, index) => ({ command, index, score: needle ? scoreCommand(command, needle) : 1 }))
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score || a.index - b.index);

  const groups: CommandGroup[] = [];
  for (const { command } of ranked) {
    const label = command.group ?? null;
    const group = groups.find((candidate) => candidate.label === label);
    if (group) group.commands.push(command);
    else groups.push({ label, commands: [command] });
  }
  return groups;
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
  const listRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  // The input takes focus itself; this is here for the return trip — closing the
  // palette should put the caret back on whatever the user was doing.
  useFocusTrap(open, panelRef);

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

  // Arrowing past the eighth command must not walk the highlight off the
  // bottom of a scrolling list. `nearest` scrolls only when it has to, so
  // moving within view does not jerk the list around.
  useEffect(() => {
    if (!open) return;
    const option = listRef.current?.querySelector<HTMLElement>(`[data-index="${active}"]`);
    option?.scrollIntoView({ block: "nearest" });
  }, [active, open]);

  const groups = useMemo(() => searchCommands(commands, query), [commands, query]);
  // The headings are a way of reading the list, not of moving through it: the
  // arrow keys and `aria-activedescendant` walk one flat sequence, in exactly
  // the order the groups render.
  const matches = useMemo(() => groups.flatMap((group) => group.commands), [groups]);

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
        ref={panelRef}
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
            role="combobox"
            aria-expanded
            aria-controls="command-palette-list"
            aria-activedescendant={matches[active] ? `command-${matches[active]!.id}` : undefined}
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
          <div
            id="command-palette-list"
            ref={listRef}
            role="listbox"
            aria-label={t("nav.commandPalette")}
            className="max-h-80 overflow-y-auto p-1.5"
          >
            {groups.map((group) => (
              // The heading is for the eye; the group carries the same words as
              // its accessible name, so a screen reader announces "Hosting,
              // Databases" instead of reading a stray line of text that sits
              // between two options and belongs to neither.
              <div key={group.label ?? "_"} role="group" aria-label={group.label ?? undefined}>
                {group.label ? (
                  <p className="px-2.5 pt-2 pb-1 text-[11px] font-medium tracking-wider text-ink-subtle uppercase">
                    {group.label}
                  </p>
                ) : null}
                {group.commands.map((command) => {
                  const index = matches.indexOf(command);
                  return (
                    <button
                      key={command.id}
                      id={`command-${command.id}`}
                      data-index={index}
                      role="option"
                      aria-selected={index === active}
                      onMouseEnter={() => setActive(index)}
                      onClick={() => choose(index)}
                      className={cn(
                        "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-start text-sm transition-colors duration-100",
                        index === active ? "bg-accent-soft text-accent" : "text-ink",
                      )}
                    >
                      {command.icon ? (
                        <command.icon
                          className={cn(
                            "h-4 w-4 shrink-0",
                            index === active ? "" : "text-ink-subtle",
                          )}
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
                  );
                })}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
