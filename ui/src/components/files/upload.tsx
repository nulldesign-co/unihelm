import { RotateCcw, X } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { ApiError } from "@/lib/api";
import {
  CHUNK_BYTES,
  baseName,
  blobToBase64,
  cleanPath,
  ensureDir,
  filesApi,
  joinPath,
  parentPath,
} from "@/lib/files-api";
import { cn, formatBytes } from "@/lib/utils";

/**
 * Chunked, resumable uploads (spec §11.7).
 *
 * Files go up in 4 MB base64 chunks so a 2 GB upload works on a 1 GB server:
 * neither side ever holds more than one chunk. Uploads run one at a time —
 * parallel streams to the same small server just fight each other for disk.
 *
 * Resume is within-session: the `File` handle lives only in this tab, so after
 * a failed chunk the retry asks the server how much it already has (by listing
 * the directory) and continues from that byte. A page reload starts over —
 * cross-session resume would need the user to re-pick the file anyway.
 *
 * A whole folder can be uploaded, by drop or by picker. Each file carries the
 * path it had relative to the folder that was dropped, and the queue creates
 * the directories on the way down before writing into them — the upload
 * endpoint takes a path and no `create_parents`, so an un-made parent is a
 * `NotFound` per file.
 */

export type UploadStatus = "queued" | "uploading" | "done" | "error" | "cancelled";

export interface UploadItem {
  id: string;
  /**
   * A folder row carries no bytes: it exists so an empty directory inside a
   * dropped tree is created rather than quietly dropped, and so its failure is
   * visible instead of being blamed on the files that would have gone in it.
   */
  kind: "file" | "folder";
  /** Base name — what `resume` matches against a fresh listing. */
  name: string;
  /** Path relative to the folder the upload was started in, for the panel. */
  display: string;
  size: number;
  /** The item's own parent directory, tenant-home-relative. */
  dir: string;
  /** Full target path. */
  path: string;
  sent: number;
  status: UploadStatus;
  error: string | null;
}

/** A file the user handed over, with the path it had inside the dropped tree. */
export interface PendingUpload {
  file: File;
  /** `/`-separated and relative to the drop target — `site/css/app.css`. */
  relativePath: string;
}

interface Job {
  id: string;
  /** Null for a folder job, which only has to exist. */
  file: File | null;
  dir: string;
  path: string;
  startAt: number;
  /**
   * The directory chain to make before writing, or null when the target
   * directory is the one the page is already showing — that one exists, and
   * walking it would cost a round trip per level per upload.
   */
  createDir: string | null;
}

let nextUploadId = 0;

export function useUploader(onFileDone: (dir: string) => void) {
  const { t } = useTranslation();
  const [items, setItems] = useState<UploadItem[]>([]);
  // A synchronous mirror of `items`, so event handlers can read the latest
  // state without putting side effects inside a state updater (StrictMode
  // runs updaters twice in dev, which would double-enqueue a resume).
  const itemsRef = useRef<UploadItem[]>(items);
  itemsRef.current = items;
  const filesRef = useRef(new Map<string, File>());
  const queueRef = useRef<Job[]>([]);
  const cancelledRef = useRef(new Set<string>());
  // Directories this session has already made. A 400-file folder shares a
  // handful of parents, and re-walking them would be a mkdir round trip per
  // level per file.
  const ensuredRef = useRef(new Set<string>());
  const pumpingRef = useRef(false);
  const onFileDoneRef = useRef(onFileDone);
  onFileDoneRef.current = onFileDone;

  const update = useCallback((id: string, patch: Partial<UploadItem>) => {
    setItems((prev) => prev.map((item) => (item.id === id ? { ...item, ...patch } : item)));
  }, []);

  const pump = useCallback(() => {
    if (pumpingRef.current) return;
    pumpingRef.current = true;
    void (async () => {
      try {
        for (;;) {
          const job = queueRef.current.shift();
          if (!job) break;
          if (cancelledRef.current.has(job.id)) continue;
          update(job.id, { status: "uploading" });
          let offset = job.startAt;
          try {
            // Before the first byte, not after a NotFound: the endpoint writes
            // to a path and will not make the folder on the way.
            if (job.createDir !== null && !ensuredRef.current.has(job.createDir)) {
              await ensureDir(job.createDir);
              ensuredRef.current.add(job.createDir);
            }
            const file = job.file;
            if (file === null) {
              // A folder job is finished the moment its directory exists.
              update(job.id, { status: "done", sent: 0 });
              onFileDoneRef.current(job.dir);
              continue;
            }
            if (file.size === 0) {
              await filesApi.uploadChunk({ path: job.path, offset: 0, content_b64: "", done: true });
            }
            while (offset < file.size) {
              if (cancelledRef.current.has(job.id)) break;
              const end = Math.min(offset + CHUNK_BYTES, file.size);
              const content_b64 = await blobToBase64(file.slice(offset, end));
              await filesApi.uploadChunk({
                path: job.path,
                offset,
                content_b64,
                done: end === file.size,
              });
              offset = end;
              update(job.id, { sent: offset });
            }
            if (cancelledRef.current.has(job.id)) {
              update(job.id, { status: "cancelled" });
            } else {
              update(job.id, { status: "done", sent: file.size });
              onFileDoneRef.current(job.dir);
            }
          } catch (e) {
            update(job.id, {
              status: "error",
              error: e instanceof ApiError ? e.message : String(e),
            });
          }
        }
      } finally {
        pumpingRef.current = false;
        // Something may have been enqueued while the last job was finishing.
        if (queueRef.current.length > 0) pump();
      }
    })();
  }, [update]);

  const enqueue = useCallback(
    /**
     * @param uploads   Files, each with the path it had inside the dropped tree.
     * @param dir       Where the tree lands, tenant-home-relative.
     * @param emptyDirs Directories in the tree that hold no files at any depth.
     *                  Nothing is ever written into them, so without their own
     *                  jobs they would vanish from a folder that "uploaded".
     */
    (uploads: PendingUpload[], dir: string, emptyDirs: string[] = []) => {
      const fresh: UploadItem[] = [];

      for (const relative of emptyDirs.map(cleanPath)) {
        if (relative === "") continue;
        const id = `u${nextUploadId++}`;
        const path = joinPath(dir, relative);
        const parent = parentPath(path);
        fresh.push({
          id,
          kind: "folder",
          name: baseName(relative),
          display: relative,
          size: 0,
          dir: parent,
          path,
          sent: 0,
          status: "queued",
          error: null,
        });
        queueRef.current.push({ id, file: null, dir: parent, path, startAt: 0, createDir: path });
      }

      for (const upload of uploads) {
        const id = `u${nextUploadId++}`;
        // A browser-supplied relative path is data, not a promise: cleaning is
        // what keeps a `..` in it from being joined onto the target folder.
        const relative = cleanPath(upload.relativePath);
        const path = joinPath(dir, relative);
        const parent = parentPath(path);
        if (relative === "") {
          // Nothing survived cleaning, so there is no name to write to. It goes
          // into the queue as a failure rather than onto the floor.
          fresh.push({
            id,
            kind: "file",
            name: upload.file.name,
            display: upload.file.name,
            size: upload.file.size,
            dir,
            path: dir,
            sent: 0,
            status: "error",
            error: t("files.uploadUnusableName", { name: upload.relativePath }),
          });
          continue;
        }
        filesRef.current.set(id, upload.file);
        fresh.push({
          id,
          kind: "file",
          name: baseName(relative),
          display: relative,
          size: upload.file.size,
          dir: parent,
          path,
          sent: 0,
          status: "queued",
          error: null,
        });
        queueRef.current.push({
          id,
          file: upload.file,
          dir: parent,
          path,
          startAt: 0,
          // Only a file that arrived from inside a folder needs one built; the
          // directory the page is showing is already there.
          createDir: parentPath(relative) === "" ? null : parent,
        });
      }

      if (fresh.length === 0) return;
      setItems((prev) => [...prev, ...fresh]);
      pump();
    },
    [pump, t],
  );

  const cancel = useCallback(
    (id: string) => {
      cancelledRef.current.add(id);
      // A queued job dies immediately; a running one stops at the next chunk
      // boundary, which is at most 4 MB away.
      setItems((prev) =>
        prev.map((item) =>
          item.id === id && (item.status === "queued" || item.status === "error")
            ? { ...item, status: "cancelled" }
            : item,
        ),
      );
    },
    [],
  );

  const resume = useCallback(
    (id: string) => {
      const item = itemsRef.current.find((i) => i.id === id);
      if (!item || (item.status !== "error" && item.status !== "cancelled")) return;
      cancelledRef.current.delete(id);
      // Whatever failed may have been the directory, so a retry rebuilds the
      // chain rather than trusting that this session already made it. On an
      // existing chain that is one `already_exists` per level, which is a fair
      // price for a button a person pressed on purpose.
      ensuredRef.current.delete(item.dir);
      ensuredRef.current.delete(item.path);

      if (item.kind === "folder") {
        update(id, { status: "queued", error: null });
        queueRef.current.push({
          id,
          file: null,
          dir: item.dir,
          path: item.path,
          startAt: 0,
          createDir: item.path,
        });
        pump();
        return;
      }

      const file = filesRef.current.get(id);
      if (!file) return;
      update(id, { status: "queued", error: null });
      void (async () => {
        // Ask the server how much of the file already landed and continue
        // from there — this is what makes a mid-upload network blip cost one
        // chunk, not the whole 2 GB.
        let startAt = 0;
        try {
          const listing = await filesApi.list(item.dir, true);
          const existing = listing.entries.find((e) => e.name === item.name && e.kind === "file");
          if (existing && existing.size <= file.size) startAt = existing.size;
        } catch {
          // The listing failing is not fatal; restart from zero.
        }
        update(id, { sent: startAt });
        queueRef.current.push({
          id,
          file,
          dir: item.dir,
          path: item.path,
          startAt,
          createDir: item.dir === "" ? null : item.dir,
        });
        pump();
      })();
    },
    [pump, update],
  );

  const clearFinished = useCallback(() => {
    setItems((prev) => {
      const keep = prev.filter(
        (item) => item.status === "queued" || item.status === "uploading" || item.status === "error",
      );
      for (const item of prev) {
        if (!keep.includes(item)) filesRef.current.delete(item.id);
      }
      return keep;
    });
  }, []);

  return { items, enqueue, cancel, resume, clearFinished };
}

// ---------------------------------------------------------------------------
// Getting files out of the browser
// ---------------------------------------------------------------------------

/** What a drop turned out to contain. */
export interface DropContents {
  uploads: PendingUpload[];
  /** Folders in the tree that hold no files at any depth. */
  emptyDirs: string[];
  /**
   * Names of dropped things this browser would not let us read. Never empty
   * silently: the whole point of reporting these is that a folder dropped on a
   * browser without the entries API used to look accepted and upload nothing.
   */
  unreadable: string[];
}

function fileOf(entry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => entry.file(resolve, reject));
}

/**
 * Every child of a directory entry.
 *
 * `readEntries` answers with *a batch*, not the directory — Chromium caps it at
 * 100 — and stops only when it hands back an empty one. Reading it once is the
 * classic way a folder upload silently loses everything past the hundredth
 * file, which is the same defect as losing all of them, just harder to notice.
 */
function readAllEntries(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
  return new Promise((resolve, reject) => {
    const all: FileSystemEntry[] = [];
    const next = () =>
      reader.readEntries((batch) => {
        if (batch.length === 0) {
          resolve(all);
          return;
        }
        all.push(...batch);
        next();
      }, reject);
    next();
  });
}

async function walkEntry(
  entry: FileSystemEntry,
  relativePath: string,
  into: { uploads: PendingUpload[]; emptyDirs: string[] },
): Promise<void> {
  if (entry.isFile) {
    into.uploads.push({ file: await fileOf(entry as FileSystemFileEntry), relativePath });
    return;
  }
  if (!entry.isDirectory) return;

  const children = await readAllEntries((entry as FileSystemDirectoryEntry).createReader());
  const before = into.uploads.length;
  for (const child of children) {
    await walkEntry(child, `${relativePath}/${child.name}`, into);
  }
  // A directory with no file anywhere under it is never named by any upload
  // path, so it needs a job of its own or it disappears from the copy.
  if (into.uploads.length === before) into.emptyDirs.push(relativePath);
}

/**
 * A dropped `File` that is really a directory.
 *
 * Only reachable on a browser with no `webkitGetAsEntry`, where a dropped
 * folder arrives as a zero-byte `File` and is indistinguishable from an empty
 * one until you try to read a byte — which fails for a directory. Uploading it
 * would create an empty file wearing the folder's name and call it done.
 */
async function isUnreadableDirectory(file: File): Promise<boolean> {
  if (file.size !== 0) return false;
  try {
    await file.slice(0, 1).arrayBuffer();
    return false;
  } catch {
    return true;
  }
}

/**
 * Everything a drop is offering, folders walked to the bottom.
 *
 * The handler must call this synchronously from the drop event: the browser
 * empties the drag data store as soon as that handler returns, so every
 * `webkitGetAsEntry` and `getAsFile` is taken here, before the first `await`.
 */
export async function filesFromDrop(dataTransfer: DataTransfer): Promise<DropContents> {
  const roots = Array.from(dataTransfer.items)
    .filter((item) => item.kind === "file")
    .map((item) => ({ entry: item.webkitGetAsEntry?.() ?? null, file: item.getAsFile() }));
  const loose = roots.length === 0 ? Array.from(dataTransfer.files) : [];

  const into = { uploads: [] as PendingUpload[], emptyDirs: [] as string[] };
  const unreadable: string[] = [];

  for (const root of roots) {
    if (root.entry) {
      try {
        await walkEntry(root.entry, root.entry.name, into);
      } catch {
        // The walk died partway: some of this folder may already be queued, so
        // naming it is the only honest thing left to do.
        unreadable.push(root.entry.name);
      }
    } else if (root.file) {
      if (await isUnreadableDirectory(root.file)) unreadable.push(root.file.name);
      else into.uploads.push({ file: root.file, relativePath: root.file.name });
    }
  }

  for (const file of loose) {
    if (await isUnreadableDirectory(file)) unreadable.push(file.name);
    else into.uploads.push({ file, relativePath: file.name });
  }

  return { uploads: into.uploads, emptyDirs: into.emptyDirs, unreadable };
}

/**
 * Files from an `<input type="file">`.
 *
 * `webkitRelativePath` is filled in by a `webkitdirectory` picker and empty for
 * a plain one, so both pickers come through here.
 */
export function filesFromPicker(files: FileList | null): PendingUpload[] {
  return Array.from(files ?? []).map((file) => ({
    file,
    relativePath: file.webkitRelativePath || file.name,
  }));
}

// ---------------------------------------------------------------------------

/**
 * How far along an item is, as a percentage.
 *
 * A folder job and a zero-byte file have no bytes to measure. They read as
 * nothing until they are actually finished — the bar used to sit at 100% for
 * both the moment they were queued, which is a full progress bar in front of
 * work that had not started.
 */
function percentOf(item: UploadItem): number {
  if (item.status === "done") return 100;
  if (item.size === 0) return 0;
  return Math.min(100, Math.floor((item.sent / item.size) * 100));
}

export function UploadPanel({
  items,
  onCancel,
  onResume,
  onClearFinished,
}: {
  items: UploadItem[];
  onCancel: (id: string) => void;
  onResume: (id: string) => void;
  onClearFinished: () => void;
}) {
  const { t, i18n } = useTranslation();
  if (items.length === 0) return null;

  const anyFinished = items.some(
    (item) => item.status === "done" || item.status === "cancelled",
  );

  return (
    <section
      aria-label={t("files.uploads")}
      className="fixed bottom-4 end-4 z-40 w-80 max-w-[calc(100vw-2rem)] animate-slide-up rounded-card border border-border bg-surface shadow-pop"
    >
      <header className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <h2 className="text-sm font-semibold text-ink">{t("files.uploads")}</h2>
        {anyFinished ? (
          <Button variant="ghost" size="sm" onClick={onClearFinished}>
            {t("files.clearFinished")}
          </Button>
        ) : null}
      </header>
      <ul className="max-h-64 space-y-3 overflow-y-auto px-4 py-3">
        {/* Rise in, but deliberately without `stagger`: this queue grows while
            the reader watches, and an item appended at index 8 would sit
            invisible for a third of a second before showing up. */}
        {items.map((item) => (
          <li key={item.id} className="animate-rise-in">
            <div className="flex items-center gap-2">
              {/* The path inside the dropped folder, not the bare name: forty
                  rows all reading `index.php` name nothing at all. */}
              <span className="min-w-0 flex-1 truncate text-sm text-ink" title={item.path}>
                {item.display}
              </span>
              {item.status === "uploading" ? <Spinner className="h-3.5 w-3.5" /> : null}
              {item.status === "error" || item.status === "cancelled" ? (
                <Button
                  variant="ghost"
                  size="icon-sm"
                  onClick={() => onResume(item.id)}
                  aria-label={t("files.resume")}
                  title={t("files.resume")}
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                </Button>
              ) : null}
              {item.status === "queued" || item.status === "uploading" || item.status === "error" ? (
                <Button
                  variant="ghost"
                  size="icon-sm"
                  onClick={() => onCancel(item.id)}
                  aria-label={t("common.cancel")}
                  title={t("common.cancel")}
                >
                  <X className="h-3.5 w-3.5" />
                </Button>
              ) : null}
            </div>
            <div
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={percentOf(item)}
              aria-label={item.display}
              className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-muted"
            >
              <div
                className={cn(
                  // Width only, and briefly: a chunk lands every few hundred
                  // milliseconds, so a longer tween would still be catching up
                  // with the previous one when the next arrives.
                  "h-full rounded-full transition-[width,background-color] duration-300 ease-standard",
                  item.status === "error"
                    ? "bg-danger"
                    : item.status === "done"
                      ? "bg-success"
                      : "bg-accent",
                )}
                style={{ width: `${percentOf(item)}%` }}
              />
            </div>
            <p className="tnum mt-1 text-xs text-ink-muted">
              {item.status === "error" ? (
                <span className="text-danger">{item.error ?? t("files.uploadFailed")}</span>
              ) : item.status === "cancelled" ? (
                t("files.uploadCancelled")
              ) : item.kind === "folder" ? (
                // A folder row has no bytes to count, and saying "0 B / 0 B"
                // beside it reads like an upload that went nowhere.
                item.status === "done" ? (
                  t("files.folderCreated")
                ) : (
                  t("files.creatingFolder")
                )
              ) : item.status === "done" ? (
                t("files.uploadDone")
              ) : (
                `${formatBytes(item.sent, i18n.language)} / ${formatBytes(item.size, i18n.language)}`
              )}
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
}
