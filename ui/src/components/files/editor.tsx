import { Save, X } from "lucide-react";
import { Suspense, lazy, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { ApiError } from "@/lib/api";
import {
  FileTooLargeError,
  MAX_EDIT_BYTES,
  looksBinary,
  readFileContent,
  writeFileContent,
  type FileEntry,
} from "@/lib/files-api";
import { formatBytes } from "@/lib/utils";

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
      className="fixed inset-0 z-50 flex flex-col bg-canvas"
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
          <Button variant="primary" size="sm" onClick={save} disabled={saving || !dirty}>
            {saving ? <Spinner /> : <Save className="h-3.5 w-3.5" aria-hidden />}
            {t("files.save")}
          </Button>
        ) : null}
        <Button variant="ghost" size="icon" onClick={close} aria-label={t("common.close")}>
          <X className="h-4 w-4" />
        </Button>
      </header>

      {saveError ? (
        <p role="alert" className="border-b border-border bg-danger-soft px-4 py-2 text-sm text-danger">
          {saveError}
        </p>
      ) : null}

      <div className="min-h-0 flex-1">
        {phase.kind === "loading" ? (
          <EditorNotice>
            <Spinner className="h-5 w-5" />
            <span>{t("files.editorLoading")}</span>
          </EditorNotice>
        ) : phase.kind === "refused" ? (
          <EditorNotice>
            <p className="max-w-md text-center">{phase.message}</p>
          </EditorNotice>
        ) : (
          <Suspense
            fallback={
              <EditorNotice>
                <Spinner className="h-5 w-5" />
                <span>{t("files.editorLoading")}</span>
              </EditorNotice>
            }
          >
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

function EditorNotice({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 text-sm text-ink-muted">
      {children}
    </div>
  );
}
