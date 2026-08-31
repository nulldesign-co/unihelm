import { RotateCcw, X } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { ApiError } from "@/lib/api";
import { CHUNK_BYTES, blobToBase64, filesApi, joinPath } from "@/lib/files-api";
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
 */

export type UploadStatus = "queued" | "uploading" | "done" | "error" | "cancelled";

export interface UploadItem {
  id: string;
  name: string;
  size: number;
  /** Target directory, tenant-home-relative. */
  dir: string;
  /** Full target path. */
  path: string;
  sent: number;
  status: UploadStatus;
  error: string | null;
}

interface Job {
  id: string;
  file: File;
  dir: string;
  path: string;
  startAt: number;
}

let nextUploadId = 0;

export function useUploader(onFileDone: (dir: string) => void) {
  const [items, setItems] = useState<UploadItem[]>([]);
  // A synchronous mirror of `items`, so event handlers can read the latest
  // state without putting side effects inside a state updater (StrictMode
  // runs updaters twice in dev, which would double-enqueue a resume).
  const itemsRef = useRef<UploadItem[]>(items);
  itemsRef.current = items;
  const filesRef = useRef(new Map<string, File>());
  const queueRef = useRef<Job[]>([]);
  const cancelledRef = useRef(new Set<string>());
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
            if (job.file.size === 0) {
              await filesApi.uploadChunk({ path: job.path, offset: 0, content_b64: "", done: true });
            }
            while (offset < job.file.size) {
              if (cancelledRef.current.has(job.id)) break;
              const end = Math.min(offset + CHUNK_BYTES, job.file.size);
              const content_b64 = await blobToBase64(job.file.slice(offset, end));
              await filesApi.uploadChunk({
                path: job.path,
                offset,
                content_b64,
                done: end === job.file.size,
              });
              offset = end;
              update(job.id, { sent: offset });
            }
            if (cancelledRef.current.has(job.id)) {
              update(job.id, { status: "cancelled" });
            } else {
              update(job.id, { status: "done", sent: job.file.size });
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
    (files: File[], dir: string) => {
      const fresh: UploadItem[] = [];
      for (const file of files) {
        const id = `u${nextUploadId++}`;
        filesRef.current.set(id, file);
        const path = joinPath(dir, file.name);
        fresh.push({
          id,
          name: file.name,
          size: file.size,
          dir,
          path,
          sent: 0,
          status: "queued",
          error: null,
        });
        queueRef.current.push({ id, file, dir, path, startAt: 0 });
      }
      if (fresh.length === 0) return;
      setItems((prev) => [...prev, ...fresh]);
      pump();
    },
    [pump],
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
      const file = filesRef.current.get(id);
      const item = itemsRef.current.find((i) => i.id === id);
      if (!item || !file || (item.status !== "error" && item.status !== "cancelled")) return;
      cancelledRef.current.delete(id);
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
        queueRef.current.push({ id, file, dir: item.dir, path: item.path, startAt });
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

/** Files from a drop event; directories are skipped (folder upload is not v1). */
export function filesFromDrop(dataTransfer: DataTransfer): File[] {
  const out: File[] = [];
  if (dataTransfer.items.length > 0) {
    for (const item of Array.from(dataTransfer.items)) {
      if (item.kind !== "file") continue;
      const entry = item.webkitGetAsEntry?.();
      if (entry?.isDirectory) continue;
      const file = item.getAsFile();
      if (file) out.push(file);
    }
  } else {
    out.push(...Array.from(dataTransfer.files));
  }
  return out;
}

// ---------------------------------------------------------------------------

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
        {items.map((item) => (
          <li key={item.id}>
            <div className="flex items-center gap-2">
              <span className="min-w-0 flex-1 truncate text-sm text-ink">{item.name}</span>
              {item.status === "uploading" ? <Spinner className="h-3.5 w-3.5" /> : null}
              {item.status === "error" || item.status === "cancelled" ? (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
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
                  size="icon"
                  className="h-7 w-7"
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
              aria-valuenow={item.size === 0 ? 100 : Math.floor((item.sent / item.size) * 100)}
              aria-label={item.name}
              className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-muted"
            >
              <div
                className={cn(
                  "h-full rounded-full transition-all",
                  item.status === "error"
                    ? "bg-danger"
                    : item.status === "done"
                      ? "bg-success"
                      : "bg-accent",
                )}
                style={{
                  width: `${item.size === 0 ? 100 : Math.min(100, (item.sent / item.size) * 100)}%`,
                }}
              />
            </div>
            <p className="mt-1 text-xs tabular-nums text-ink-muted">
              {item.status === "error" ? (
                <span className="text-danger">{item.error ?? t("files.uploadFailed")}</span>
              ) : item.status === "cancelled" ? (
                t("files.uploadCancelled")
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
