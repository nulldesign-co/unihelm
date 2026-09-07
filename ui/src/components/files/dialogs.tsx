import { useMutation, useQuery } from "@tanstack/react-query";
import { ChevronRight, Folder, FolderTree, Keyboard } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Breadcrumbs } from "@/components/files/breadcrumbs";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ListSkeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { ApiError } from "@/lib/api";
import {
  ARCHIVE_FORMATS,
  cleanPath,
  filesApi,
  isValidName,
  joinPath,
  modeToOctal,
  moveRefusal,
  octalToMode,
  parentPath,
  type ArchiveFormat,
  type FileEntry,
} from "@/lib/files-api";

/**
 * The file-manager dialogs (spec §11.7).
 *
 * Every dialog owns its mutation and reports the server's message verbatim —
 * the API's error taxonomy already speaks in sentences, and rewrapping them
 * here would only hide the `UNI-xxxx` reference the operator might search for.
 */

function errorText(e: unknown): string {
  return e instanceof ApiError ? e.message : String(e);
}

function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  // Callout carries the alert role and the danger tone; this wrapper only
  // exists to keep the spacing consistent across all seven dialogs.
  return <Callout tone="danger" className="mt-3">{error}</Callout>;
}

// ---------------------------------------------------------------------------

/**
 * Choose a destination folder by browsing to it.
 *
 * Copy and Extract each took the destination as a bare text input, which meant
 * every destination anywhere but the current folder had to be typed from
 * memory, correctly, and a typo came back as the server's "not found" only
 * after the operator had pressed the button. Move — added at the same time —
 * would have been a third copy of that.
 *
 * Browsing *is* choosing: the folder on screen is the destination, so there is
 * no second "select" step to forget. Typing stays one click away, because
 * somebody who knows the path should not have to click through six levels to
 * reach it.
 */
function DestinationPicker({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  /** Raw, as typed — callers clean it themselves for the call and the preview. */
  value: string;
  onChange: (next: string) => void;
}) {
  const { t } = useTranslation();
  const [typing, setTyping] = useState(false);
  const here = cleanPath(value);

  const listing = useQuery({
    // The same key shape the files page uses, so one `invalidateQueries(["files"])`
    // after a mutation refreshes the picker too. `hidden: true` on purpose: a
    // folder the picker cannot reach is a folder that has to be typed, which is
    // the thing this exists to stop.
    queryKey: ["files", here, true],
    queryFn: () => filesApi.list(here, true),
    // A half-typed path is not a directory; asking about every keystroke would
    // be a burst of 404s on the way to a valid one.
    enabled: !typing,
  });

  // Directories only. The listing itself navigates symlinks because most tenant
  // links point at a folder, but a destination that turns out to be a link to a
  // file is a refusal after the fact — the typed path is the way to one of those.
  const dirs = (listing.data?.entries ?? [])
    .filter((entry) => entry.kind === "dir" && !entry.escapes)
    .sort((a, b) => a.name.localeCompare(b.name));

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-ink" id={`${id}-label`}>
          {label}
        </span>
        <Button variant="ghost" size="sm" onClick={() => setTyping((on) => !on)}>
          {typing ? (
            <FolderTree className="h-3.5 w-3.5" aria-hidden />
          ) : (
            <Keyboard className="h-3.5 w-3.5" aria-hidden />
          )}
          {typing ? t("files.pickerBrowse") : t("files.pickerType")}
        </Button>
      </div>

      {typing ? (
        <Input
          id={id}
          className="font-mono"
          autoFocus
          value={value}
          placeholder={t("files.home")}
          aria-labelledby={`${id}-label`}
          onChange={(event) => onChange(event.target.value)}
        />
      ) : (
        <div role="group" aria-labelledby={`${id}-label`} className="space-y-2">
          <Breadcrumbs path={here} onNavigate={onChange} />
          <div className="max-h-48 overflow-y-auto rounded-lg border border-border bg-surface p-1">
            {listing.isPending ? (
              <ListSkeleton rows={3} className="p-2" />
            ) : listing.isError ? (
              // Verbatim, and with a way back: a folder that cannot be listed
              // is usually a permission the operator can go and fix.
              <Callout
                tone="danger"
                className="border-0 bg-transparent"
                action={
                  <Button variant="outline" size="sm" onClick={() => void listing.refetch()}>
                    {t("common.retry")}
                  </Button>
                }
              >
                {errorText(listing.error)}
              </Callout>
            ) : dirs.length === 0 ? (
              <p className="px-2 py-3 text-center text-xs text-ink-muted">
                {t("files.pickerNoSubfolders")}
              </p>
            ) : (
              <ul>
                {dirs.map((dir) => (
                  <li key={dir.path}>
                    <button
                      type="button"
                      onClick={() => onChange(dir.path)}
                      className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-start text-sm text-ink transition-colors hover:bg-surface-muted"
                    >
                      <Folder className="h-4 w-4 shrink-0 text-accent" aria-hidden />
                      <span className="truncate">{dir.name}</span>
                      <ChevronRight className="ms-auto h-3.5 w-3.5 shrink-0 text-ink-subtle" aria-hidden />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/** Where the operation will land, spelled out under the picker. */
function DestinationNote({ path }: { path: string }) {
  const { t } = useTranslation();
  return (
    <p className="mt-3 truncate rounded-lg bg-surface-muted px-3 py-2 font-mono text-xs text-ink-subtle">
      {path === "" ? t("files.home") : path}
    </p>
  );
}

// ---------------------------------------------------------------------------

export function MkdirDialog({
  dir,
  onClose,
  onDone,
}: {
  dir: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const valid = isValidName(name.trim());

  const create = useMutation({
    mutationFn: () => filesApi.mkdir(joinPath(dir, name.trim())),
    onSuccess: () => {
      onDone();
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });

  const submit = () => {
    if (!valid) {
      setError(name.trim() === "" ? t("files.nameRequired") : t("files.nameInvalid"));
      return;
    }
    create.mutate();
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("files.newFolder")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={submit} loading={create.isPending}>
            {t("files.createFolder")}
          </Button>
        </>
      }
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <Field label={t("files.folderName")} htmlFor="mkdir-name">
          <Input
            id="mkdir-name"
            autoFocus
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
      </form>
      <ErrorNote error={error} />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

export function RenameDialog({
  entry,
  onClose,
  onDone,
}: {
  entry: FileEntry;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState(entry.name);
  const [error, setError] = useState<string | null>(null);

  const rename = useMutation({
    mutationFn: () => filesApi.rename(entry.path, joinPath(parentPath(entry.path), name.trim())),
    onSuccess: () => {
      onDone();
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });

  const submit = () => {
    const trimmed = name.trim();
    if (!isValidName(trimmed)) {
      setError(trimmed === "" ? t("files.nameRequired") : t("files.nameInvalid"));
      return;
    }
    if (trimmed === entry.name) {
      onClose();
      return;
    }
    rename.mutate();
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("files.renameTitle", { name: entry.name })}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={submit} loading={rename.isPending}>
            {t("files.rename")}
          </Button>
        </>
      }
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <Field label={t("files.newName")} htmlFor="rename-name">
          <Input
            id="rename-name"
            autoFocus
            value={name}
            onChange={(event) => setName(event.target.value)}
            onFocus={(event) => {
              // Select the stem, not the extension — that is the part people
              // rename.
              const dot = entry.name.lastIndexOf(".");
              event.target.setSelectionRange(0, dot > 0 ? dot : entry.name.length);
            }}
          />
        </Field>
      </form>
      <ErrorNote error={error} />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

export function CopyDialog({
  entries,
  dir,
  onClose,
  onDone,
}: {
  entries: FileEntry[];
  dir: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [dest, setDest] = useState(dir);
  const [error, setError] = useState<string | null>(null);

  const copy = useMutation({
    // One call per item, in order: the endpoint copies a single `from`→`to`
    // pair, and sequencing keeps a failure attributable to the exact file.
    mutationFn: async () => {
      const target = cleanPath(dest);
      for (const entry of entries) {
        await filesApi.copy(entry.path, joinPath(target, entry.name));
      }
    },
    onSuccess: () => {
      onDone();
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("files.copyTitle", { count: entries.length })}
      description={t("files.copyHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={() => copy.mutate()} loading={copy.isPending}>
            {t("files.copy")}
          </Button>
        </>
      }
    >
      <DestinationPicker
        id="copy-dest"
        label={t("files.copyDest")}
        value={dest}
        onChange={setDest}
      />
      <DestinationNote path={cleanPath(dest)} />
      <ErrorNote error={error} />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

/**
 * Move, which the panel had every part of except the button.
 *
 * `fs.rename` takes two tenant paths and does not care whether they share a
 * parent — deleting is itself a rename into `.trash/`. Without a Move action an
 * operator moving a file had to copy it and then delete the original: two audit
 * entries, twice the disk for the length of it, and a window where both copies
 * exist and the wrong one can be edited.
 */
export function MoveDialog({
  entries,
  dir,
  onClose,
  onDone,
}: {
  entries: FileEntry[];
  dir: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [dest, setDest] = useState(dir);
  const [error, setError] = useState<string | null>(null);
  const target = cleanPath(dest);
  const refusal = moveRefusal(entries, target);

  const move = useMutation({
    // One rename per item, in order, for the same reason Copy does it: the
    // endpoint moves a single `from`→`to` pair and sequencing keeps a failure
    // attributable to the exact file. A partial move leaves the rest where they
    // were, which is the recoverable half of the two.
    mutationFn: async () => {
      for (const entry of entries) {
        await filesApi.rename(entry.path, joinPath(target, entry.name));
      }
    },
    onSuccess: () => {
      onDone();
      onClose();
    },
    onError: (e) => {
      setError(errorText(e));
      // The listing is refreshed on the way out of a failure too: a move that
      // stopped on the third of five has already moved two, and a table still
      // showing all five where they were is the panel telling a lie about the
      // disk. The dialog stays open, with the server's sentence in it.
      onDone();
    },
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("files.moveTitle", { count: entries.length })}
      description={t("files.moveHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={() => move.mutate()}
            loading={move.isPending}
            disabled={refusal !== null}
          >
            {t("files.move")}
          </Button>
        </>
      }
    >
      <DestinationPicker
        id="move-dest"
        label={t("files.moveDest")}
        value={dest}
        onChange={setDest}
      />
      <DestinationNote path={target} />
      {/* Said while the folder is still on screen, not after the button. The
          server refuses both of these too, as `already exists` and as a bare
          errno, neither of which names the mistake that was made. */}
      {refusal === "sameFolder" ? (
        <Callout tone="warning" className="mt-3">
          {t("files.moveSameFolder")}
        </Callout>
      ) : refusal === "intoItself" ? (
        <Callout tone="warning" className="mt-3">
          {t("files.moveIntoItself")}
        </Callout>
      ) : null}
      <ErrorNote error={error} />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

export function DeleteDialog({
  entries,
  onClose,
  onDone,
}: {
  entries: FileEntry[];
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: async () => {
      for (const entry of entries) {
        await filesApi.del(entry.path);
      }
    },
    onSuccess: () => {
      onDone();
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("files.deleteTitle", { count: entries.length })}
      // Deliberately calm wording: this moves to the recycle bin, it does not
      // destroy anything — the scary dialog is the purge one.
      description={t("files.deleteHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="danger" onClick={() => remove.mutate()} loading={remove.isPending}>
            {t("files.deleteConfirm")}
          </Button>
        </>
      }
    >
      {/* The exact paths, boxed: this is the last screen before they move, and
          a bare list of grey text is easy to skim past. */}
      <ul className="max-h-40 space-y-1 overflow-y-auto rounded-lg border border-border bg-surface-muted px-3 py-2 font-mono text-xs text-ink-muted">
        {entries.map((entry) => (
          <li key={entry.path} className="truncate">
            {entry.path}
          </li>
        ))}
      </ul>
      <ErrorNote error={error} />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

const WHO = ["owner", "group", "others"] as const;
const WHAT = ["read", "write", "execute"] as const;

export function ChmodDialog({
  entry,
  onClose,
  onDone,
}: {
  entry: FileEntry;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [octal, setOctal] = useState(modeToOctal(entry.mode));
  const [recursive, setRecursive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mode = octalToMode(octal);

  const chmod = useMutation({
    mutationFn: () => filesApi.chmod(entry.path, mode!, recursive),
    onSuccess: () => {
      onDone();
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });

  // bit 8 = owner-read … bit 0 = others-execute.
  const bitFor = (who: number, what: number) => 1 << (8 - (who * 3 + what));
  const toggleBit = (bit: number) => {
    if (mode === null) return;
    setOctal(modeToOctal(mode ^ bit));
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("files.chmodTitle", { name: entry.name })}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={() => (mode === null ? setError(t("files.octalInvalid")) : chmod.mutate())}
            loading={chmod.isPending}
          >
            {t("files.chmodApply")}
          </Button>
        </>
      }
    >
      {/* Who the three rows actually are on *this* server — the part an
          operator gets wrong, and the reason "just chmod 777 it" is folklore.
          The panel's isolation model is one group: a site directory is
          `tenant:<web server group>` at 0710, so the group column is the web
          server's read-and-traverse and the others column is every other
          account on the machine, which needs nothing from these files. */}
      <p className="mb-4 text-xs text-ink-muted">{t("files.chmodWho")}</p>

      <div className="grid grid-cols-4 gap-x-4 gap-y-2 text-sm">
        <span />
        {WHAT.map((what) => (
          <span key={what} className="text-center text-xs font-medium text-ink-muted">
            {t(`files.${what}`)}
          </span>
        ))}
        {WHO.map((who, whoIndex) => (
          <div key={who} className="contents">
            <span className="text-sm text-ink">{t(`files.${who}`)}</span>
            {WHAT.map((what, whatIndex) => {
              const bit = bitFor(whoIndex, whatIndex);
              return (
                <span key={what} className="text-center">
                  <input
                    type="checkbox"
                    checked={mode !== null && (mode & bit) !== 0}
                    disabled={mode === null}
                    onChange={() => toggleBit(bit)}
                    aria-label={`${t(`files.${who}`)}: ${t(`files.${what}`)}`}
                    className="accent-[var(--color-accent)]"
                  />
                </span>
              );
            })}
          </div>
        ))}
      </div>

      <div className="mt-4">
        <Field label={t("files.octal")} htmlFor="chmod-octal" error={mode === null ? t("files.octalInvalid") : undefined}>
          <Input
            id="chmod-octal"
            className="tnum w-28 font-mono"
            value={octal}
            aria-invalid={mode === null}
            onChange={(event) => setOctal(event.target.value.trim())}
          />
        </Field>
      </div>

      {entry.kind === "dir" ? (
        <Switch
          checked={recursive}
          onChange={setRecursive}
          label={t("files.recursive")}
          description={t("files.recursiveHint")}
        />
      ) : null}
      <ErrorNote error={error} />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

export function CompressDialog({
  dir,
  entries,
  onClose,
  onDone,
}: {
  dir: string;
  entries: FileEntry[];
  onClose: () => void;
  onDone: (taskId?: string) => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("archive");
  const [format, setFormat] = useState<ArchiveFormat>("zip");
  const [error, setError] = useState<string | null>(null);

  const ext = ARCHIVE_FORMATS.find((f) => f.value === format)!.ext;

  const compress = useMutation({
    mutationFn: () =>
      filesApi.compress(
        dir,
        entries.map((e) => e.name),
        joinPath(dir, `${name.trim()}.${ext}`),
        format,
      ),
    onSuccess: (result) => {
      onDone(result.task_id);
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });

  const submit = () => {
    if (!isValidName(name.trim())) {
      setError(name.trim() === "" ? t("files.nameRequired") : t("files.nameInvalid"));
      return;
    }
    compress.mutate();
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("files.compressTitle", { count: entries.length })}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={submit} loading={compress.isPending}>
            {t("files.compress")}
          </Button>
        </>
      }
    >
      <div className="flex items-end gap-3">
        <div className="flex-1">
          <Field label={t("files.archiveName")} htmlFor="compress-name">
            <Input
              id="compress-name"
              className="font-mono"
              autoFocus
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
        </div>
        <div className="w-32">
          <Field label={t("files.format")} htmlFor="compress-format">
            <Select
              id="compress-format"
              value={format}
              onChange={(event) => setFormat(event.target.value as ArchiveFormat)}
            >
              {ARCHIVE_FORMATS.map((f) => (
                <option key={f.value} value={f.value}>
                  .{f.ext}
                </option>
              ))}
            </Select>
          </Field>
        </div>
      </div>
      {/* Where the archive will land, spelled out, so the name field and the
          format select read as one decision. */}
      <p className="truncate rounded-lg bg-surface-muted px-3 py-2 font-mono text-xs text-ink-subtle">
        {joinPath(dir, `${name.trim() || "…"}.${ext}`)}
      </p>
      <ErrorNote error={error} />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

/**
 * The archive's name with its extension taken off — `site.tar.gz` → `site`.
 *
 * Only the extensions the server recognises are stripped, and only from the
 * end: a file called `2024.backup.zip` keeps the dot in the middle, because the
 * folder is meant to be recognisable, not tidy.
 */
function archiveStem(name: string): string {
  const lower = name.toLowerCase();
  for (const ext of [".tar.gz", ".tar.zst", ".tgz", ".tzst", ".zip"]) {
    if (lower.endsWith(ext)) return name.slice(0, name.length - ext.length);
  }
  return name;
}

export function ExtractDialog({
  entry,
  dir,
  onClose,
  onDone,
}: {
  entry: FileEntry;
  dir: string;
  onClose: () => void;
  onDone: (taskId?: string) => void;
}) {
  const { t } = useTranslation();
  const [dest, setDest] = useState(dir);
  // On by default, and now possible: extracting into a folder named after the
  // archive used to fail with "not found", because the helper resolved the
  // destination as a path that had to exist already. So the choice was between
  // making the folder by hand first and letting an archive with no top-level
  // directory scatter itself across the current one.
  const [intoOwnFolder, setIntoOwnFolder] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const stem = archiveStem(entry.name).trim();
  // An archive whose whole name is its extension leaves nothing to name a
  // folder after; the switch has nothing to offer there.
  const canUseOwnFolder = isValidName(stem);
  const target = cleanPath(
    intoOwnFolder && canUseOwnFolder ? joinPath(cleanPath(dest), stem) : dest,
  );

  const extract = useMutation({
    mutationFn: () => filesApi.extract(entry.path, target),
    onSuccess: (result) => {
      onDone(result.task_id);
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("files.extractTitle", { name: entry.name })}
      // The server, not this dialog, is what guards against zip bombs and
      // crafted `../` entries (spec §11.7 AC) — the hint just tells the user
      // where the files will land.
      description={t("files.extractHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" onClick={() => extract.mutate()} loading={extract.isPending}>
            {t("files.extract")}
          </Button>
        </>
      }
    >
      <DestinationPicker
        id="extract-dest"
        label={t("files.extractDest")}
        value={dest}
        onChange={setDest}
      />
      {canUseOwnFolder ? (
        <Switch
          checked={intoOwnFolder}
          onChange={setIntoOwnFolder}
          label={t("files.extractOwnFolder", { name: stem })}
          description={t("files.extractOwnFolderHint")}
        />
      ) : null}
      {/* Where the files actually land, spelled out — the switch changes it, so
          the switch must not be the only thing that says where. */}
      <DestinationNote path={target} />
      <ErrorNote error={error} />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

export function PurgeDialog({
  onClose,
  onDone,
}: {
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [days, setDays] = useState("0");
  const [error, setError] = useState<string | null>(null);
  const parsed = /^\d{1,4}$/.test(days.trim()) ? Number(days.trim()) : null;

  const purge = useMutation({
    mutationFn: () => filesApi.trashPurge(parsed!),
    onSuccess: () => {
      onDone();
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });

  return (
    <Dialog
      open
      onClose={onClose}
      title={t("files.purgeTitle")}
      description={t("files.purgeHint")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="danger"
            onClick={() => (parsed === null ? setError(t("files.daysInvalid")) : purge.mutate())}
            loading={purge.isPending}
          >
            {t("files.purgeConfirm")}
          </Button>
        </>
      }
    >
      <Field
        label={t("files.purgeOlderThan")}
        htmlFor="purge-days"
        error={parsed === null ? t("files.daysInvalid") : undefined}
      >
        <Input
          id="purge-days"
          inputMode="numeric"
          className="tnum w-28"
          value={days}
          aria-invalid={parsed === null}
          onChange={(event) => setDays(event.target.value)}
        />
      </Field>
      <p className="text-xs text-ink-muted">{t("files.purgeOlderThanHint")}</p>
      <ErrorNote error={error} />
    </Dialog>
  );
}
