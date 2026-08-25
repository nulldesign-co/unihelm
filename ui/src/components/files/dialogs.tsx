import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { ApiError } from "@/lib/api";
import {
  ARCHIVE_FORMATS,
  cleanPath,
  filesApi,
  isValidName,
  joinPath,
  modeToOctal,
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
 * here would only hide the `FER-xxxx` reference the operator might search for.
 */

function errorText(e: unknown): string {
  return e instanceof ApiError ? e.message : String(e);
}

function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
      {error}
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
          <Button variant="primary" onClick={submit} disabled={create.isPending}>
            {create.isPending ? <Spinner /> : null}
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
            dir="auto"
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
          <Button variant="primary" onClick={submit} disabled={rename.isPending}>
            {rename.isPending ? <Spinner /> : null}
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
            dir="auto"
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
          <Button variant="primary" onClick={() => copy.mutate()} disabled={copy.isPending}>
            {copy.isPending ? <Spinner /> : null}
            {t("files.copy")}
          </Button>
        </>
      }
    >
      <Field label={t("files.copyDest")} htmlFor="copy-dest">
        <Input
          id="copy-dest"
          dir="ltr"
          autoFocus
          value={dest}
          placeholder={t("files.home")}
          onChange={(event) => setDest(event.target.value)}
        />
      </Field>
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
          <Button variant="danger" onClick={() => remove.mutate()} disabled={remove.isPending}>
            {remove.isPending ? <Spinner /> : null}
            {t("files.deleteConfirm")}
          </Button>
        </>
      }
    >
      <ul className="max-h-40 space-y-1 overflow-y-auto font-mono text-xs text-ink-muted" dir="ltr">
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
            disabled={chmod.isPending}
          >
            {chmod.isPending ? <Spinner /> : null}
            {t("files.chmodApply")}
          </Button>
        </>
      }
    >
      <div dir="ltr" className="grid grid-cols-4 gap-x-4 gap-y-2 text-sm">
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
            dir="ltr"
            className="w-28 font-mono"
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
          <Button variant="primary" onClick={submit} disabled={compress.isPending}>
            {compress.isPending ? <Spinner /> : null}
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
              dir="ltr"
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
      <p dir="ltr" className="font-mono text-xs text-ink-subtle">
        {joinPath(dir, `${name.trim() || "…"}.${ext}`)}
      </p>
      <ErrorNote error={error} />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

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
  const [error, setError] = useState<string | null>(null);

  const extract = useMutation({
    mutationFn: () => filesApi.extract(entry.path, cleanPath(dest)),
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
          <Button variant="primary" onClick={() => extract.mutate()} disabled={extract.isPending}>
            {extract.isPending ? <Spinner /> : null}
            {t("files.extract")}
          </Button>
        </>
      }
    >
      <Field label={t("files.extractDest")} htmlFor="extract-dest">
        <Input
          id="extract-dest"
          dir="ltr"
          autoFocus
          value={dest}
          placeholder={t("files.home")}
          onChange={(event) => setDest(event.target.value)}
        />
      </Field>
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
            disabled={purge.isPending}
          >
            {purge.isPending ? <Spinner /> : null}
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
          dir="ltr"
          inputMode="numeric"
          className="w-28"
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
