import {
  AlertTriangle,
  Archive,
  Download,
  File,
  FileArchive,
  FileCode,
  FileImage,
  FileText,
  Folder,
  KeySquare,
  Link2,
  MoreVertical,
  PackageOpen,
  Pencil,
  Copy as CopyIcon,
  Trash2,
} from "lucide-react";
import { useEffect, useRef, useState, type ComponentType } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import {
  archiveFormatOf,
  downloadUrl,
  formatMode,
  looksBinary,
  type FileEntry,
} from "@/lib/files-api";
import { cn, formatBytes } from "@/lib/utils";

export type RowAction =
  | "open"
  | "rename"
  | "copy"
  | "chmod"
  | "compress"
  | "extract"
  | "delete";

const CODE_EXTENSIONS = new Set([
  "js", "mjs", "cjs", "jsx", "ts", "tsx", "php", "phtml", "py", "rb", "rs", "go",
  "html", "htm", "css", "scss", "json", "xml", "svg", "sql", "yml", "yaml", "sh",
  "conf", "ini", "env", "toml", "lock", "vue", "twig",
]);
const IMAGE_EXTENSIONS = new Set(["png", "jpg", "jpeg", "gif", "webp", "avif", "ico", "bmp", "svg"]);

function iconFor(entry: FileEntry): ComponentType<{ className?: string }> {
  if (entry.kind === "dir") return Folder;
  if (entry.kind === "symlink") return Link2;
  if (entry.kind === "other") return File;
  if (archiveFormatOf(entry.name)) return FileArchive;
  const dot = entry.name.lastIndexOf(".");
  const ext = dot === -1 ? "" : entry.name.slice(dot + 1).toLowerCase();
  if (IMAGE_EXTENSIONS.has(ext)) return FileImage;
  if (CODE_EXTENSIONS.has(ext)) return FileCode;
  if (looksBinary(entry.name)) return File;
  return FileText;
}

/**
 * The directory listing. Directories sort before files because that is how
 * every file manager since the beginning of time has worked, and muscle
 * memory is a feature.
 *
 * Names render with `dir="auto"`: a Farsi file name reads right-to-left, a
 * Latin one left-to-right, and neither breaks the other's column.
 */
export function FileTable({
  entries,
  selected,
  onToggle,
  onToggleAll,
  onOpen,
  onAction,
}: {
  entries: FileEntry[];
  selected: Set<string>;
  onToggle: (path: string) => void;
  onToggleAll: () => void;
  onOpen: (entry: FileEntry) => void;
  onAction: (action: RowAction, entry: FileEntry) => void;
}) {
  const { t, i18n } = useTranslation();
  const allSelected = entries.length > 0 && entries.every((e) => selected.has(e.path));

  const dateFormat = new Intl.DateTimeFormat(i18n.language, {
    dateStyle: "medium",
    timeStyle: "short",
  });

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border text-start text-xs text-ink-muted">
            <th className="w-10 px-3 py-2">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={onToggleAll}
                aria-label={t("files.selectAll")}
                className="accent-[var(--color-accent)]"
              />
            </th>
            <th className="px-2 py-2 text-start font-medium">{t("files.name")}</th>
            <th className="w-24 px-2 py-2 text-end font-medium">{t("files.size")}</th>
            <th className="w-44 px-2 py-2 text-start font-medium">{t("files.modified")}</th>
            <th className="w-28 px-2 py-2 text-start font-medium">{t("files.permissions")}</th>
            <th className="w-20 px-2 py-2" />
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => {
            const Icon = iconFor(entry);
            const isSelected = selected.has(entry.path);
            return (
              <tr
                key={entry.path}
                className={cn(
                  "border-b border-border transition-colors last:border-b-0",
                  isSelected ? "bg-accent-soft/60" : "hover:bg-surface-muted",
                )}
              >
                <td className="px-3 py-2">
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => onToggle(entry.path)}
                    aria-label={t("files.selectItem", { name: entry.name })}
                    className="accent-[var(--color-accent)]"
                  />
                </td>
                <td className="max-w-0 px-2 py-2">
                  <button
                    type="button"
                    onClick={() => onOpen(entry)}
                    className="flex w-full min-w-0 items-center gap-2 text-start text-ink hover:text-accent"
                    // An escaping symlink is shown but inert: following it
                    // would read outside the home (spec §11.7 AC).
                    disabled={entry.escapes}
                  >
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0",
                        entry.kind === "dir" ? "text-accent" : "text-ink-subtle",
                      )}
                      aria-hidden
                    />
                    <span dir="auto" className="truncate font-medium">
                      {entry.name}
                    </span>
                    {entry.kind === "symlink" && entry.target ? (
                      <span dir="ltr" className="truncate font-mono text-xs text-ink-subtle">
                        → {entry.target}
                      </span>
                    ) : null}
                    {entry.escapes ? (
                      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-warning-soft px-2 py-0.5 text-[11px] text-warning">
                        <AlertTriangle className="h-3 w-3" aria-hidden />
                        {t("files.escapes")}
                      </span>
                    ) : null}
                  </button>
                </td>
                <td dir="ltr" className="px-2 py-2 text-end tabular-nums text-ink-muted">
                  {entry.kind === "dir" ? "—" : formatBytes(entry.size, i18n.language)}
                </td>
                <td className="whitespace-nowrap px-2 py-2 text-ink-muted">
                  {entry.modified === null || entry.modified === undefined
                    ? "—"
                    : dateFormat.format(new Date(entry.modified * 1000))}
                </td>
                <td dir="ltr" className="px-2 py-2 text-start font-mono text-xs text-ink-subtle">
                  {formatMode(entry.mode)}
                </td>
                <td className="px-2 py-2">
                  <div className="flex items-center justify-end gap-1">
                    {entry.kind === "file" ? (
                      <a
                        href={downloadUrl(entry.path)}
                        download={entry.name}
                        className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-ink-muted transition-colors hover:bg-surface-muted hover:text-ink"
                        aria-label={t("files.download")}
                        title={t("files.download")}
                      >
                        <Download className="h-4 w-4" aria-hidden />
                      </a>
                    ) : null}
                    <RowMenu entry={entry} onAction={onAction} />
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/**
 * A per-row actions menu. Hand-rolled because the design system has no
 * dropdown yet: a toggle button, an invisible backdrop that catches the
 * click-away, and Escape to close.
 */
function RowMenu({
  entry,
  onAction,
}: {
  entry: FileEntry;
  onAction: (action: RowAction, entry: FileEntry) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const items: { action: RowAction; label: string; icon: ComponentType<{ className?: string }> }[] =
    [
      { action: "rename", label: t("files.rename"), icon: Pencil },
      { action: "copy", label: t("files.copy"), icon: CopyIcon },
      { action: "chmod", label: t("files.chmod"), icon: KeySquare },
      { action: "compress", label: t("files.compress"), icon: Archive },
    ];
  if (entry.kind === "file" && archiveFormatOf(entry.name)) {
    items.push({ action: "extract", label: t("files.extract"), icon: PackageOpen });
  }

  return (
    <div ref={containerRef} className="relative">
      <Button
        variant="ghost"
        size="icon"
        className="h-8 w-8"
        aria-label={t("files.actions")}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <MoreVertical className="h-4 w-4" aria-hidden />
      </Button>
      {open ? (
        <>
          <div className="fixed inset-0 z-30" aria-hidden onClick={() => setOpen(false)} />
          <div
            role="menu"
            className="absolute end-0 top-9 z-40 w-44 rounded-lg border border-border bg-surface py-1 shadow-xl"
          >
            {items.map((item) => (
              <button
                key={item.action}
                type="button"
                role="menuitem"
                className="flex w-full items-center gap-2 px-3 py-1.5 text-start text-sm text-ink hover:bg-surface-muted"
                onClick={() => {
                  setOpen(false);
                  onAction(item.action, entry);
                }}
              >
                <item.icon className="h-3.5 w-3.5 text-ink-subtle" aria-hidden />
                {item.label}
              </button>
            ))}
            <div className="my-1 border-t border-border" />
            <button
              type="button"
              role="menuitem"
              className="flex w-full items-center gap-2 px-3 py-1.5 text-start text-sm text-danger hover:bg-danger-soft"
              onClick={() => {
                setOpen(false);
                onAction("delete", entry);
              }}
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
              {t("files.delete")}
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
}
