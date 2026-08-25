import { useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { useNavigate, useSearch } from "@tanstack/react-router";
import {
  Archive,
  ArrowLeft,
  Copy as CopyIcon,
  FolderOpen,
  FolderPlus,
  Trash2,
  Upload as UploadIcon,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Breadcrumbs } from "@/components/files/breadcrumbs";
import {
  ChmodDialog,
  CompressDialog,
  CopyDialog,
  DeleteDialog,
  ExtractDialog,
  MkdirDialog,
  RenameDialog,
} from "@/components/files/dialogs";
import { FileEditorOverlay } from "@/components/files/editor";
import { FileTable, type RowAction } from "@/components/files/file-table";
import { TrashView } from "@/components/files/trash-view";
import { UploadPanel, filesFromDrop, useUploader } from "@/components/files/upload";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { ApiError } from "@/lib/api";
import {
  cleanPath,
  filesApi,
  parentPath,
  type FileEntry,
  type SearchResponse,
} from "@/lib/files-api";
import { cn } from "@/lib/utils";

/**
 * The file manager (spec §11.7).
 *
 * The current directory lives in the URL (`?path=…`) so a reload, a bookmark
 * or a shared link lands in the same place. `validateSearch` cleans what the
 * URL claims — the server independently refuses anything that escapes the
 * tenant home, this only keeps the breadcrumb from rendering nonsense.
 */

export interface FilesSearch {
  /** Optional in the type so `<Link to="/files">` needs no search prop. */
  path?: string;
  view?: "trash";
}

export function validateFilesSearch(search: Record<string, unknown>): FilesSearch {
  const path = typeof search.path === "string" ? cleanPath(search.path) : "";
  return {
    path: path === "" ? undefined : path,
    view: search.view === "trash" ? "trash" : undefined,
  };
}

type DialogState =
  | { type: "mkdir" }
  | { type: "rename"; entry: FileEntry }
  | { type: "copy"; entries: FileEntry[] }
  | { type: "delete"; entries: FileEntry[] }
  | { type: "chmod"; entry: FileEntry }
  | { type: "compress"; entries: FileEntry[] }
  | { type: "extract"; entry: FileEntry };

type Banner = { kind: "info" | "error"; text: string } | null;

function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), ms);
    return () => window.clearTimeout(timer);
  }, [value, ms]);
  return debounced;
}

export function FilesPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const search = useSearch({ from: "/files" });
  const queryClient = useQueryClient();

  const path = search.path ?? "";
  const inTrash = search.view === "trash";

  const [hidden, setHidden] = useState(false);
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebounced(query.trim(), 300);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const [editing, setEditing] = useState<FileEntry | null>(null);
  const [banner, setBanner] = useState<Banner>(null);
  const [dragOver, setDragOver] = useState(false);
  const dragDepth = useRef(0);
  const pickerRef = useRef<HTMLInputElement>(null);

  const listing = useQuery({
    queryKey: ["files", path, hidden],
    queryFn: () => filesApi.list(path, hidden),
    enabled: !inTrash,
  });

  const searchActive = !inTrash && debouncedQuery.length >= 2;
  const searchResults = useQuery({
    queryKey: ["files-search", path, debouncedQuery],
    queryFn: () => filesApi.search(path, debouncedQuery),
    enabled: searchActive,
  });

  const goTo = (nextPath: string) =>
    void navigate({ to: "/files", search: { path: nextPath } });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["files"] });
    void queryClient.invalidateQueries({ queryKey: ["files-search"] });
  };

  const uploader = useUploader(() => refresh());

  // A new directory is a new selection context.
  useEffect(() => {
    setSelected(new Set());
    setQuery("");
  }, [path, inTrash]);

  const collator = useMemo(() => new Intl.Collator(i18n.language), [i18n.language]);
  const entries = useMemo(() => {
    const raw = listing.data?.entries ?? [];
    return [...raw].sort((a, b) => {
      const aDir = a.kind === "dir" ? 0 : 1;
      const bDir = b.kind === "dir" ? 0 : 1;
      return aDir - bDir || collator.compare(a.name, b.name);
    });
  }, [listing.data, collator]);

  const selectedEntries = entries.filter((e) => selected.has(e.path));

  const toggle = (entryPath: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(entryPath)) next.delete(entryPath);
      else next.add(entryPath);
      return next;
    });

  const toggleAll = () =>
    setSelected((prev) =>
      prev.size === entries.length ? new Set() : new Set(entries.map((e) => e.path)),
    );

  const openEntry = (entry: FileEntry) => {
    if (entry.escapes) return;
    if (entry.kind === "file") setEditing(entry);
    // Symlinks are navigated like directories: most tenant links point at
    // one, and a link to a file simply fails the next list with the server's
    // own message.
    else if (entry.kind === "dir" || entry.kind === "symlink") goTo(entry.path);
  };

  const onRowAction = (action: RowAction, entry: FileEntry) => {
    switch (action) {
      case "open":
        openEntry(entry);
        break;
      case "rename":
        setDialog({ type: "rename", entry });
        break;
      case "copy":
        setDialog({ type: "copy", entries: [entry] });
        break;
      case "chmod":
        setDialog({ type: "chmod", entry });
        break;
      case "compress":
        setDialog({ type: "compress", entries: [entry] });
        break;
      case "extract":
        setDialog({ type: "extract", entry });
        break;
      case "delete":
        setDialog({ type: "delete", entries: [entry] });
        break;
    }
  };

  const afterMutation = () => {
    setSelected(new Set());
    refresh();
  };

  const afterTask = (taskId?: string) => {
    afterMutation();
    if (taskId) setBanner({ kind: "info", text: t("files.taskStarted") });
  };

  // --- drag & drop ---------------------------------------------------------

  const onDragEnter = (event: React.DragEvent) => {
    if (inTrash || !event.dataTransfer.types.includes("Files")) return;
    event.preventDefault();
    dragDepth.current += 1;
    setDragOver(true);
  };
  const onDragLeave = (event: React.DragEvent) => {
    if (inTrash) return;
    event.preventDefault();
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setDragOver(false);
  };
  const onDrop = (event: React.DragEvent) => {
    if (inTrash) return;
    event.preventDefault();
    dragDepth.current = 0;
    setDragOver(false);
    uploader.enqueue(filesFromDrop(event.dataTransfer), path);
  };

  return (
    <div
      className="space-y-6"
      onDragEnter={onDragEnter}
      onDragOver={(event) => {
        if (!inTrash && event.dataTransfer.types.includes("Files")) event.preventDefault();
      }}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
    >
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-ink">
            {inTrash ? t("files.trash") : t("files.title")}
          </h1>
          <p className="mt-1 text-sm text-ink-muted">
            {inTrash ? t("files.trashSubtitle") : t("files.subtitle")}
          </p>
        </div>
        {inTrash ? (
          <Button
            variant="outline"
            onClick={() => void navigate({ to: "/files", search: { path } })}
          >
            <ArrowLeft className="h-4 w-4 rtl:rotate-180" />
            {t("files.backToFiles")}
          </Button>
        ) : (
          <Button
            variant="outline"
            onClick={() => void navigate({ to: "/files", search: { path, view: "trash" } })}
          >
            <Trash2 className="h-4 w-4" />
            {t("files.trash")}
          </Button>
        )}
      </header>

      {banner ? (
        <p
          role={banner.kind === "error" ? "alert" : "status"}
          className={cn(
            "flex items-center justify-between gap-3 rounded-lg px-3 py-2 text-sm",
            banner.kind === "error" ? "bg-danger-soft text-danger" : "bg-accent-soft text-accent",
          )}
        >
          {banner.text}
          <button
            type="button"
            onClick={() => setBanner(null)}
            aria-label={t("common.dismiss")}
            className="shrink-0 opacity-70 hover:opacity-100"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </p>
      ) : null}

      {inTrash ? (
        <TrashView />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <div className="min-w-0 flex-1">
              <Breadcrumbs path={path} onNavigate={goTo} />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={t("files.searchPlaceholder")}
                aria-label={t("files.searchPlaceholder")}
                className="h-8 w-48 text-sm"
              />
              <Button variant="outline" size="sm" onClick={() => setDialog({ type: "mkdir" })}>
                <FolderPlus className="h-3.5 w-3.5" />
                {t("files.newFolder")}
              </Button>
              <Button variant="primary" size="sm" onClick={() => pickerRef.current?.click()}>
                <UploadIcon className="h-3.5 w-3.5" />
                {t("files.upload")}
              </Button>
              <input
                ref={pickerRef}
                type="file"
                multiple
                className="hidden"
                onChange={(event) => {
                  uploader.enqueue(Array.from(event.target.files ?? []), path);
                  event.target.value = "";
                }}
              />
            </div>
          </div>

          {selectedEntries.length > 0 ? (
            <div className="flex flex-wrap items-center gap-2 rounded-lg bg-surface-muted px-3 py-2">
              <span className="text-sm text-ink-muted">
                {t("files.selected", { count: selectedEntries.length })}
              </span>
              <span className="ms-auto flex flex-wrap items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setDialog({ type: "copy", entries: selectedEntries })}
                >
                  <CopyIcon className="h-3.5 w-3.5" />
                  {t("files.copy")}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setDialog({ type: "compress", entries: selectedEntries })}
                >
                  <Archive className="h-3.5 w-3.5" />
                  {t("files.compress")}
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => setDialog({ type: "delete", entries: selectedEntries })}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  {t("files.delete")}
                </Button>
              </span>
            </div>
          ) : null}

          <Card className={cn("relative", dragOver && "outline-2 outline-dashed outline-accent")}>
            {dragOver ? (
              <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-card bg-accent-soft/80 text-sm font-medium text-accent">
                {t("files.dropHere")}
              </div>
            ) : null}

            {searchActive ? (
              <SearchResults
                query={debouncedQuery}
                results={searchResults}
                onOpenDir={(entry) => {
                  setQuery("");
                  goTo(entry.path);
                }}
                onOpenFile={(entry) => {
                  setQuery("");
                  goTo(parentPath(entry.path));
                  setEditing(entry);
                }}
              />
            ) : listing.isPending ? (
              <CardBody className="flex justify-center py-20 text-ink-muted">
                <Spinner className="h-6 w-6" />
              </CardBody>
            ) : listing.isError ? (
              <CardBody className="py-16 text-center">
                <p role="alert" className="text-sm text-danger">
                  {listing.error instanceof ApiError
                    ? listing.error.message
                    : String(listing.error)}
                </p>
                <div className="mt-4 flex justify-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => void listing.refetch()}>
                    {t("common.retry")}
                  </Button>
                  {path !== "" ? (
                    <Button variant="ghost" size="sm" onClick={() => goTo("")}>
                      {t("files.home")}
                    </Button>
                  ) : null}
                </div>
              </CardBody>
            ) : entries.length === 0 ? (
              <CardBody className="py-20 text-center">
                <FolderOpen className="mx-auto mb-3 h-8 w-8 text-ink-subtle" aria-hidden />
                <p className="text-sm font-medium text-ink">{t("files.empty")}</p>
                <p className="mt-1 text-sm text-ink-muted">{t("files.emptyHint")}</p>
              </CardBody>
            ) : (
              <FileTable
                entries={entries}
                selected={selected}
                onToggle={toggle}
                onToggleAll={toggleAll}
                onOpen={openEntry}
                onAction={onRowAction}
              />
            )}
          </Card>

          <div className="flex items-center justify-between gap-4">
            <Switch
              checked={hidden}
              onChange={setHidden}
              label={t("files.showHidden")}
            />
            {!searchActive && entries.length > 0 ? (
              <p className="text-xs text-ink-subtle">
                {t("files.itemCount", { count: entries.length })}
              </p>
            ) : null}
          </div>
        </>
      )}

      {/* --- dialogs -------------------------------------------------------- */}

      {dialog?.type === "mkdir" ? (
        <MkdirDialog dir={path} onClose={() => setDialog(null)} onDone={afterMutation} />
      ) : null}
      {dialog?.type === "rename" ? (
        <RenameDialog entry={dialog.entry} onClose={() => setDialog(null)} onDone={afterMutation} />
      ) : null}
      {dialog?.type === "copy" ? (
        <CopyDialog
          entries={dialog.entries}
          dir={path}
          onClose={() => setDialog(null)}
          onDone={afterMutation}
        />
      ) : null}
      {dialog?.type === "delete" ? (
        <DeleteDialog
          entries={dialog.entries}
          onClose={() => setDialog(null)}
          onDone={afterMutation}
        />
      ) : null}
      {dialog?.type === "chmod" ? (
        <ChmodDialog entry={dialog.entry} onClose={() => setDialog(null)} onDone={afterMutation} />
      ) : null}
      {dialog?.type === "compress" ? (
        <CompressDialog
          dir={path}
          entries={dialog.entries}
          onClose={() => setDialog(null)}
          onDone={afterTask}
        />
      ) : null}
      {dialog?.type === "extract" ? (
        <ExtractDialog
          entry={dialog.entry}
          dir={path}
          onClose={() => setDialog(null)}
          onDone={afterTask}
        />
      ) : null}

      {editing ? (
        <FileEditorOverlay
          entry={editing}
          onClose={() => setEditing(null)}
          onSaved={refresh}
        />
      ) : null}

      <UploadPanel
        items={uploader.items}
        onCancel={uploader.cancel}
        onResume={uploader.resume}
        onClearFinished={uploader.clearFinished}
      />
    </div>
  );
}

function SearchResults({
  query,
  results,
  onOpenDir,
  onOpenFile,
}: {
  query: string;
  results: UseQueryResult<SearchResponse, Error>;
  onOpenDir: (entry: FileEntry) => void;
  onOpenFile: (entry: FileEntry) => void;
}) {
  const { t } = useTranslation();

  if (results.isPending) {
    return (
      <CardBody className="flex items-center justify-center gap-3 py-16 text-sm text-ink-muted">
        <Spinner className="h-5 w-5" />
        {t("files.searching")}
      </CardBody>
    );
  }
  if (results.isError) {
    return (
      <CardBody className="py-16 text-center">
        <p role="alert" className="text-sm text-danger">
          {results.error instanceof ApiError ? results.error.message : String(results.error)}
        </p>
      </CardBody>
    );
  }

  const entries = results.data?.entries ?? [];
  if (entries.length === 0) {
    return (
      <CardBody className="py-16 text-center text-sm text-ink-muted">
        {t("files.searchNoResults", { query })}
      </CardBody>
    );
  }

  return (
    <CardBody className="pt-3">
      <p className="mb-2 text-xs text-ink-muted">
        {t("files.searchResults", { count: entries.length })}
        {results.data?.truncated ? ` ${t("files.searchTruncated")}` : ""}
      </p>
      <ul className="divide-y divide-border">
        {entries.map((entry) => (
          <li key={entry.path}>
            <button
              type="button"
              onClick={() => (entry.kind === "file" ? onOpenFile(entry) : onOpenDir(entry))}
              className="flex w-full items-center gap-3 px-1 py-2 text-start hover:bg-surface-muted"
            >
              <span dir="auto" className="shrink-0 text-sm font-medium text-ink">
                {entry.name}
              </span>
              <span dir="ltr" className="min-w-0 flex-1 truncate text-start font-mono text-xs text-ink-subtle">
                {entry.path}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </CardBody>
  );
}
