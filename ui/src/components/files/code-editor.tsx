/**
 * The CodeMirror 6 editor surface — the whole `@codemirror/*` dependency tree
 * lives behind this module's dynamic `import()` so it becomes its own async
 * chunk. The initial route budget is 350 KB gzipped (spec §3); the editor is
 * allowed to blow past that only because nobody pays for it until they open a
 * file. Never import this file statically.
 */

import { indentWithTab } from "@codemirror/commands";
import { css } from "@codemirror/lang-css";
import { html } from "@codemirror/lang-html";
import { javascript } from "@codemirror/lang-javascript";
import { json } from "@codemirror/lang-json";
import { markdown } from "@codemirror/lang-markdown";
import { php } from "@codemirror/lang-php";
import { python } from "@codemirror/lang-python";
import { sql } from "@codemirror/lang-sql";
import { xml } from "@codemirror/lang-xml";
import { yaml } from "@codemirror/lang-yaml";
import { StreamLanguage } from "@codemirror/language";
import { nginx } from "@codemirror/legacy-modes/mode/nginx";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { EditorState, type Extension } from "@codemirror/state";
import { oneDark } from "@codemirror/theme-one-dark";
import { EditorView, keymap } from "@codemirror/view";
import { basicSetup } from "codemirror";
import { useEffect, useRef } from "react";

/** Pick a highlighter for the languages a web host actually serves. */
function languageFor(filename: string): Extension {
  const name = filename.toLowerCase();
  if (name === ".env" || name.endsWith(".env")) return StreamLanguage.define(shell);
  if (name.endsWith(".conf")) return StreamLanguage.define(nginx);

  const dot = name.lastIndexOf(".");
  const ext = dot === -1 ? "" : name.slice(dot + 1);
  switch (ext) {
    case "js":
    case "mjs":
    case "cjs":
      return javascript();
    case "jsx":
      return javascript({ jsx: true });
    case "ts":
      return javascript({ typescript: true });
    case "tsx":
      return javascript({ typescript: true, jsx: true });
    case "html":
    case "htm":
      return html();
    case "css":
    case "scss":
      return css();
    case "json":
      return json();
    case "php":
    case "phtml":
      return php();
    case "py":
      return python();
    case "md":
    case "markdown":
      return markdown();
    case "xml":
    case "svg":
      return xml();
    case "sql":
      return sql();
    case "yml":
    case "yaml":
      return yaml();
    case "sh":
    case "bash":
      return StreamLanguage.define(shell);
    default:
      return [];
  }
}

export interface CodeEditorProps {
  /** Initial document; later changes flow out through `onChange` only. */
  initialValue: string;
  filename: string;
  dark: boolean;
  onChange: (text: string) => void;
  /** Wired to Mod-S inside the editor so muscle memory works. */
  onSave: () => void;
}

export default function CodeEditor({
  initialValue,
  filename,
  dark,
  onChange,
  onSave,
}: CodeEditorProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  // Callbacks go through refs so a re-render never rebuilds the editor (which
  // would throw away cursor, scroll and undo history).
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  const onSaveRef = useRef(onSave);
  onSaveRef.current = onSave;

  useEffect(() => {
    if (!hostRef.current) return;
    const view = new EditorView({
      parent: hostRef.current,
      state: EditorState.create({
        doc: initialValue,
        extensions: [
          basicSetup,
          languageFor(filename),
          keymap.of([
            {
              key: "Mod-s",
              run: () => {
                onSaveRef.current();
                return true;
              },
            },
            indentWithTab,
          ]),
          EditorView.updateListener.of((update) => {
            if (update.docChanged) onChangeRef.current(update.state.doc.toString());
          }),
          // Code is LTR even when the chrome around it is Farsi.
          EditorView.theme({
            "&": { height: "100%", fontSize: "13px" },
            ".cm-scroller": { overflow: "auto", fontFamily: "var(--font-mono)" },
          }),
          ...(dark ? [oneDark] : []),
        ],
      }),
    });
    viewRef.current = view;
    view.focus();
    return () => {
      viewRef.current = null;
      view.destroy();
    };
    // The editor is created once per file/theme; `initialValue` on later
    // renders is deliberately ignored (the view owns the document).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filename, dark]);

  return <div ref={hostRef} dir="ltr" className="h-full min-h-0" />;
}
