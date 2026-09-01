import { FileWarning, Save, X } from "lucide-react";
import { Suspense, lazy, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/lib/api";
import {
  FileTooLargeError,
  MAX_EDIT_BYTES,
  looksBinary,
  readFileContent,
  writeFileContent,
  type FileEntry,
} from "@/lib/files-api";
import { staggerStyle } from "@/lib/motion";
import { cn, formatBytes } from "@/lib/utils";

// The 350 KB initial-bundle budget (spec §3) is why this is a `lazy` import:
// CodeMirror and its grammars load as a separate chunk the first time a file
// is opened, never on the route itself.
const CodeEditor = lazy(() => import("@/components/files/code-editor"));

type Phase =
  | { kind: "loading" }
  | { kind: "refused"; message: string }
  | { kind: "ready"; text: string };

/**
 * Full-screen editor overlay (spec §11.7).
 *
 * Refusals are decided before any editing can start: files over 5 MB and
 * binary files get a clear message instead of an editor, because "the panel
 * corrupted my upload by saving it as UTF-8" is the bug this prevents.
 */
export function FileEditorOverlay({
  entry,
  onClose,
  onSaved,
}: {
  entry: FileEntry;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [savedFlash, setSavedFlash] = useState(false);
  const currentTextRef = useRef("");
  const dark = document.documentElement.classList.contains("dark");

  useEffect(() => {
    let alive = true;
    if (entry.size > MAX_EDIT_BYTES) {
      setPhase({
        kind: "refused",
        message: t("files.editorTooLarge", { limit: formatBytes(MAX_EDIT_BYTES, i18n.language) }),
      });
      return;
    }
    if (looksBinary(entry.name)) {
      setPhase({ kind: "refused", message: t("files.editorBinary") });
      return;
    }
    void (async () => {
      try {
        const result = await readFileContent(entry.path);
        if (!alive) return;
        if (result.binary) {
          setPhase({ kind: "refused", message: t("files.editorBinary") });
        } else {
          currentTextRef.current = result.text;
          setPhase({ kind: "ready", text: result.text });
        }
      } catch (e) {
        if (!alive) return;
        setPhase({
          kind: "refused",
          message:
            e instanceof FileTooLargeError
              ? t("files.editorTooLarge", { limit: formatBytes(MAX_EDIT_BYTES, i18n.language) })
              : e instanceof ApiError
                ? e.message
                : String(e),
        });
      }
    })();
    return () => {
      alive = false;
    };
  }, [entry.path, entry.size, entry.name, t, i18n.language]);

  const close = useCallback(() => {
    // One native confirm instead of a second dialog stacked on an overlay.
    if (dirty && !window.confirm(t("files.discardEdits"))) return;
    onClose();
  }, [dirty, onClose, t]);

  const save = useCallback(() => {
    if (phase.kind !== "ready" || saving) return;
    setSaving(true);
    setSaveError(null);
    void (async () => {
      try {
        await writeFileContent(entry.path, currentTextRef.current);
        setDirty(false);
        setSavedFlash(true);
        window.setTimeout(() => setSavedFlash(false), 2000);
        onSaved();
      } catch (e) {
        setSaveError(e instanceof ApiError ? e.message : String(e));
      } finally {
        setSaving(false);
      }
    })();
  }, [phase.kind, saving, entry.path, onSaved]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [close]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={entry.name}
      className="fixed inset-0 z-50 flex animate-fade-in flex-col bg-canvas"
    >
      <header className="flex items-center gap-3 border-b border-border bg-surface px-4 py-2.5">
        <p className="min-w-0 flex-1 truncate font-mono text-xs text-ink">{entry.path}</p>
        {dirty ? (
          <Badge tone="warning" dot>
            {t("files.unsaved")}
          </Badge>
        ) : savedFlash ? (
          <Badge role="status" tone="success" dot>
            {t("files.saved")}
          </Badge>
        ) : null}
        {phase.kind === "ready" ? (
          <Button variant="primary" size="sm" onClick={save} loading={saving} disabled={!dirty}>
            <Save className="h-3.5 w-3.5" aria-hidden />
            {t("files.save")}
          </Button>
        ) : null}
        <Button variant="ghost" size="icon" onClick={close} aria-label={t("common.close")}>
          <X className="h-4 w-4" />
        </Button>
      </header>

      {saveError ? <Callout tone="danger" className="mx-4 mt-3">{saveError}</Callout> : null}

      <div className="min-h-0 flex-1">
        {phase.kind === "loading" ? (
          <EditorSkeleton />
        ) : phase.kind === "refused" ? (
          <div className="grid h-full place-items-center p-6">
            {/* The refusal is the whole message — it already says why and what
                to do instead — so it is the title and there is no hint. */}
            <EmptyState
              className="max-w-lg bg-surface"
              icon={<FileWarning aria-hidden />}
              title={phase.message}
            />
          </div>
        ) : (
          <Suspense fallback={<EditorSkeleton />}>
            <CodeEditor
              initialValue={phase.text}
              filename={entry.name}
              dark={dark}
              onSave={save}
              onChange={(text) => {
                currentTextRef.current = text;
                setDirty(true);
              }}
            />
          </Suspense>
        )}
      </div>
    </div>
  );
}

/** Widths that read as code: uneven, with the odd blank line (an empty width). */
const GHOST_LINES = [
  "w-2/5", "w-3/5", "w-1/3", "w-4/5", "w-1/2", "", "w-2/3", "w-3/4",
  "w-1/4", "w-1/2", "w-3/5", "", "w-2/5", "w-2/3", "w-1/3", "w-1/2",
];

/**
 * The shape of a file, before the file.
 *
 * CodeMirror arrives as its own chunk, so this stands in twice — once while
 * the content is fetched and once while the editor's grammars load. Ghost
 * lines rather than a spinner: the gutter and the ragged right edge tell the
 * reader what is coming, and nothing jumps when it does.
 */
function EditorSkeleton() {
  const { t } = useTranslation();
  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={t("files.editorLoading")}
      className="h-full overflow-hidden bg-surface p-4"
    >
      <div className="space-y-3">
        {GHOST_LINES.map((width, index) => (
          <div
            key={index}
            className="flex animate-rise-in items-center gap-4 stagger"
            style={staggerStyle(index)}
          >
            <Skeleton className="h-3 w-5 shrink-0" />
            {width === "" ? null : <Skeleton className={cn("h-3", width)} />}
          </div>
        ))}
      </div>
    </div>
  );
}
