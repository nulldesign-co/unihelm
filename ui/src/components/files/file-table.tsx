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
  PackageOpen,
  Pencil,
  Copy as CopyIcon,
  Trash2,
} from "lucide-react";
import type { ComponentType } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Menu, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { Table, Td, Th } from "@/components/ui/table";
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
    <Table className="min-w-[640px]">
      <thead>
        <tr>
          <Th className="w-10 px-3">
            <input
              type="checkbox"
              checked={allSelected}
              onChange={onToggleAll}
              aria-label={t("files.selectAll")}
              className="accent-[var(--color-accent)]"
            />
          </Th>
          <Th>{t("files.name")}</Th>
          <Th className="w-24 text-end">{t("files.size")}</Th>
          <Th className="w-44">{t("files.modified")}</Th>
          <Th className="w-28">{t("files.permissions")}</Th>
          <Th className="w-20" />
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
                "transition-colors",
                isSelected ? "bg-accent-soft/50" : "hover:bg-surface-muted/60",
              )}
            >
              <Td className="px-3 py-2">
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => onToggle(entry.path)}
                  aria-label={t("files.selectItem", { name: entry.name })}
                  className="accent-[var(--color-accent)]"
                />
              </Td>
              <Td className="max-w-0 py-2">
                <button
                  type="button"
                  onClick={() => onOpen(entry)}
                  className="flex w-full min-w-0 items-center gap-2 text-start text-ink transition-colors hover:text-accent"
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
                  <span className="truncate font-medium">{entry.name}</span>
                  {entry.kind === "symlink" && entry.target ? (
                    <span className="truncate font-mono text-xs text-ink-subtle">
                      → {entry.target}
                    </span>
                  ) : null}
                  {entry.escapes ? (
                    <Badge tone="warning" className="shrink-0">
                      <AlertTriangle className="h-3 w-3" aria-hidden />
                      {t("files.escapes")}
                    </Badge>
                  ) : null}
                </button>
              </Td>
              <Td className="py-2 text-end text-xs tabular-nums text-ink-muted">
                {entry.kind === "dir" ? "—" : formatBytes(entry.size, i18n.language)}
              </Td>
              <Td className="whitespace-nowrap py-2 text-xs text-ink-muted">
                {entry.modified === null || entry.modified === undefined
                  ? "—"
                  : dateFormat.format(new Date(entry.modified * 1000))}
              </Td>
              <Td className="py-2 font-mono text-xs text-ink-subtle">
                {formatMode(entry.mode)}
              </Td>
              <Td className="py-2">
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
                  <Menu label={t("files.actions")}>
                    <MenuItem icon={<Pencil />} onClick={() => onAction("rename", entry)}>
                      {t("files.rename")}
                    </MenuItem>
                    <MenuItem icon={<CopyIcon />} onClick={() => onAction("copy", entry)}>
                      {t("files.copy")}
                    </MenuItem>
                    <MenuItem icon={<KeySquare />} onClick={() => onAction("chmod", entry)}>
                      {t("files.chmod")}
                    </MenuItem>
                    <MenuItem icon={<Archive />} onClick={() => onAction("compress", entry)}>
                      {t("files.compress")}
                    </MenuItem>
                    {entry.kind === "file" && archiveFormatOf(entry.name) ? (
                      <MenuItem icon={<PackageOpen />} onClick={() => onAction("extract", entry)}>
                        {t("files.extract")}
                      </MenuItem>
                    ) : null}
                    <MenuSeparator />
                    <MenuItem danger icon={<Trash2 />} onClick={() => onAction("delete", entry)}>
                      {t("files.delete")}
                    </MenuItem>
                  </Menu>
                </div>
              </Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}
