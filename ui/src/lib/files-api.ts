/**
 * File-manager API client (spec §11.7).
 *
 * All paths here are **tenant-home-relative**, `/`-separated, with no leading
 * slash — the empty string is the home directory itself. The server joins and
 * canonicalises them under the tenant's own uid, so nothing the UI sends can
 * reach outside the home; the cleaning done here only keeps the URL bar and
 * the breadcrumb honest, it is not a security boundary.
 *
 * Bulk content crosses the wire as base64 in 4 MB chunks (`CHUNK_BYTES`) in
 * both directions, so a 2 GB upload never has to fit in the panel's memory —
 * that cap is part of the §11.7 acceptance criteria, not a tuning knob.
 */

import { ApiError, api, getCsrfToken, type ApiErrorBody, type TaskAccepted } from "@/lib/api";

// ---------------------------------------------------------------------------
// Wire shapes (mirrors unihelm-ops fsops proto)
// ---------------------------------------------------------------------------

export type FileKind = "file" | "dir" | "symlink" | "other";

export interface FileEntry {
  /** Path relative to the tenant home, `/`-separated. */
  path: string;
  name: string;
  kind: FileKind;
  size: number;
  /** Unix permission bits only (no file-type bits). */
  mode: number;
  /** Seconds since the epoch; null when the filesystem would not say. */
  modified: number | null;
  /** For a symlink, where it points — verbatim, not resolved. */
  target?: string | null;
  /** True when a symlink resolves outside the tenant home; never followed. */
  escapes?: boolean;
}

export interface FileListResponse {
  path: string;
  entries: FileEntry[];
}

export interface FileReadResponse {
  content_b64: string;
  /** Total size of the file, not of this chunk. */
  size: number;
  /** More bytes exist past this chunk — read again with a higher offset. */
  truncated: boolean;
  /** The file is not valid UTF-8 text; the editor must refuse it. */
  binary: boolean;
}

export interface SearchResponse {
  entries: FileEntry[];
  truncated?: boolean;
}

export interface TrashEntry {
  /** The entry's name inside the bin — what restore addresses it by. */
  name: string;
  kind: FileKind;
  size: number;
  deleted_at?: number | null;
  original_path?: string | null;
}

export interface TrashResponse {
  entries: TrashEntry[];
}

/** Matches `ArchiveFormat` on the Rust side (serde snake_case). */
export type ArchiveFormat = "zip" | "tar_gz" | "tar_zst";

export const ARCHIVE_FORMATS: { value: ArchiveFormat; label: string; ext: string }[] = [
  { value: "zip", label: "zip", ext: "zip" },
  { value: "tar_gz", label: "tar.gz", ext: "tar.gz" },
  { value: "tar_zst", label: "tar.zst", ext: "tar.zst" },
];

/** Upload/write chunk size in raw bytes, before base64 (spec §11.7). */
export const CHUNK_BYTES = 4 * 1024 * 1024;

/** The editor refuses files past this — download is the right tool there. */
export const MAX_EDIT_BYTES = 5 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/**
 * `PUT` with the same CSRF and error handling as the shared client.
 *
 * The shared `api` object deliberately stays minimal and `/api/files/write` is
 * the panel's only PUT so far, so the verb lives here rather than growing the
 * shared surface for one caller.
 */
async function putJson<T>(path: string, body: unknown): Promise<T> {
  const headers = new Headers({ "content-type": "application/json" });
  const csrf = getCsrfToken();
  if (csrf) headers.set("x-unihelm-csrf", csrf);

  const response = await fetch(path, {
    method: "PUT",
    headers,
    body: JSON.stringify(body),
    credentials: "same-origin",
  });

  if (!response.ok) {
    let errorBody: ApiErrorBody;
    try {
      errorBody = (await response.json()) as ApiErrorBody;
    } catch {
      errorBody = {
        code: `HTTP-${response.status}`,
        slug: "unexpected_response",
        message: response.statusText || "Request failed",
      };
    }
    throw new ApiError(response.status, errorBody);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export interface WriteRequest {
  path: string;
  append: boolean;
  content_b64: string;
  create_parents: boolean;
}

export interface UploadChunkRequest {
  path: string;
  /** Bytes of the file already on the server; the server rejects a mismatch. */
  offset: number;
  content_b64: string;
  /** Last chunk — the server finalises the file. */
  done: boolean;
}

export const filesApi = {
  list: (path: string, hidden: boolean) =>
    api.get<FileListResponse>(
      `/api/files/list?path=${encodeURIComponent(path)}&hidden=${hidden ? "true" : "false"}`,
    ),
  read: (path: string, offset: number) =>
    api.get<FileReadResponse>(`/api/files/read?path=${encodeURIComponent(path)}&offset=${offset}`),
  write: (body: WriteRequest) => putJson<{ size?: number }>("/api/files/write", body),
  uploadChunk: (body: UploadChunkRequest) =>
    api.post<{ size?: number }>("/api/files/upload", body),
  mkdir: (path: string) => api.post<unknown>("/api/files/mkdir", { path }),
  rename: (from: string, to: string) => api.post<unknown>("/api/files/rename", { from, to }),
  copy: (from: string, to: string) => api.post<unknown>("/api/files/copy", { from, to }),
  /** Moves to the per-tenant recycle bin — nothing is destroyed here. */
  del: (path: string) => api.post<unknown>("/api/files/delete", { path }),
  chmod: (path: string, mode: number, recursive: boolean) =>
    api.post<unknown>("/api/files/chmod", { path, mode, recursive }),
  search: (root: string, query: string) =>
    api.post<SearchResponse>("/api/files/search", { root, query }),
  // Compress/extract can outlive an HTTP request on big trees, so the server
  // may answer 202 with a task id (wave-1 contract); the caller treats the
  // fields as optional and refreshes either way.
  compress: (root: string, entries: string[], archive: string, format: ArchiveFormat) =>
    api.post<Partial<TaskAccepted>>("/api/files/compress", { root, entries, archive, format }),
  extract: (archive: string, dest: string) =>
    api.post<Partial<TaskAccepted>>("/api/files/extract", { archive, dest }),
  trash: () => api.get<TrashResponse>("/api/files/trash"),
  trashRestore: (name: string) => api.post<unknown>("/api/files/trash/restore", { name }),
  trashPurge: (olderThanDays: number) =>
    api.post<unknown>("/api/files/trash/purge", { older_than_days: olderThanDays }),
};

export function downloadUrl(path: string): string {
  return `/api/files/download?path=${encodeURIComponent(path)}`;
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/**
 * Normalise a home-relative path from the URL bar: collapse slashes and drop
 * `.`/`..` segments outright. The server re-validates with the real
 * canonicaliser; this only prevents the UI from rendering a breadcrumb for a
 * path it would never be allowed to list.
 */
export function cleanPath(raw: string): string {
  return raw
    .split("/")
    .filter((seg) => seg !== "" && seg !== "." && seg !== "..")
    .join("/");
}

export function joinPath(dir: string, name: string): string {
  return dir === "" ? name : `${dir}/${name}`;
}

export function parentPath(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx === -1 ? "" : path.slice(0, idx);
}

export function baseName(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx === -1 ? path : path.slice(idx + 1);
}

/** A file name typed into a dialog: one segment, no separators, no NUL. */
export function isValidName(name: string): boolean {
  return (
    name.length > 0 &&
    name !== "." &&
    name !== ".." &&
    !name.includes("/") &&
    !name.includes("\\") &&
    !name.includes("\0")
  );
}

export function archiveFormatOf(name: string): ArchiveFormat | null {
  const lower = name.toLowerCase();
  if (lower.endsWith(".zip")) return "zip";
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) return "tar_gz";
  if (lower.endsWith(".tar.zst") || lower.endsWith(".tzst")) return "tar_zst";
  return null;
}

/**
 * Extensions we refuse to open in the editor without even asking the server.
 * The server's `binary` flag is the real check; this just saves downloading
 * five megabytes of JPEG to learn it is a JPEG.
 */
const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "avif", "ico", "bmp",
  "woff", "woff2", "ttf", "otf", "eot",
  "zip", "gz", "tgz", "zst", "tzst", "bz2", "xz", "rar", "7z", "tar",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
  "mp3", "mp4", "mkv", "webm", "avi", "mov", "ogg", "wav", "flac",
  "so", "bin", "exe", "dll", "wasm", "sqlite", "db", "phar",
]);

export function looksBinary(name: string): boolean {
  const dot = name.lastIndexOf(".");
  if (dot === -1) return false;
  return BINARY_EXTENSIONS.has(name.slice(dot + 1).toLowerCase());
}

// ---------------------------------------------------------------------------
// Content encoding
// ---------------------------------------------------------------------------

/**
 * Base64 a chunk through `FileReader` rather than `btoa(String.fromCharCode…)`
 * — the latter builds a 4 M-argument call and overflows the stack exactly at
 * the chunk sizes we use.
 */
export function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.onload = () => {
      const url = reader.result as string;
      resolve(url.slice(url.indexOf(",") + 1));
    };
    reader.readAsDataURL(blob);
  });
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * Read a whole text file for the editor, following `truncated` across chunks.
 * Aborts as soon as the server declares the content binary or the running
 * total passes `MAX_EDIT_BYTES` — a file that grew between `list` and `read`
 * must not buffer without bound.
 */
export async function readFileContent(
  path: string,
): Promise<{ text: string; binary: boolean }> {
  const parts: Uint8Array[] = [];
  let offset = 0;
  for (;;) {
    const chunk = await filesApi.read(path, offset);
    if (chunk.binary) return { text: "", binary: true };
    const bytes = base64ToBytes(chunk.content_b64);
    parts.push(bytes);
    offset += bytes.length;
    if (offset > MAX_EDIT_BYTES) throw new FileTooLargeError();
    if (!chunk.truncated || bytes.length === 0) break;
  }
  const all = new Uint8Array(offset);
  let at = 0;
  for (const part of parts) {
    all.set(part, at);
    at += part.length;
  }
  // fatal: a lone surrogate would silently corrupt on save; refuse instead.
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(all), binary: false };
  } catch {
    return { text: "", binary: true };
  }
}

export class FileTooLargeError extends Error {
  constructor() {
    super("file too large to edit");
    this.name = "FileTooLargeError";
  }
}

/**
 * Save editor content: a single write when it fits one chunk, otherwise the
 * first chunk truncates the file (`append: false`) and the rest append —
 * mirroring how the upload endpoint builds files, so a 4–5 MB edit still
 * saves without tripping the per-request body cap.
 */
export async function writeFileContent(path: string, text: string): Promise<void> {
  const bytes = new TextEncoder().encode(text);
  const blob = new Blob([bytes]);
  let offset = 0;
  do {
    const slice = blob.slice(offset, Math.min(offset + CHUNK_BYTES, blob.size));
    const content_b64 = await blobToBase64(slice);
    await filesApi.write({ path, append: offset > 0, content_b64, create_parents: false });
    offset += slice.size;
  } while (offset < blob.size);
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/** `rwxr-xr-x` from permission bits — the spelling operators already read. */
export function formatMode(mode: number): string {
  const flags = ["r", "w", "x"];
  let out = "";
  for (let shift = 8; shift >= 0; shift--) {
    out += mode & (1 << shift) ? flags[(8 - shift) % 3] : "-";
  }
  return out;
}

export function modeToOctal(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(3, "0");
}

/** Parse a chmod dialog's octal field; null when it is not a safe mode. */
export function octalToMode(text: string): number | null {
  if (!/^[0-7]{3,4}$/.test(text)) return null;
  return parseInt(text, 8);
}
