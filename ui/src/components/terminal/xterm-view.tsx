/**
 * The xterm.js surface — the whole `@xterm/*` dependency tree and its stylesheet
 * live behind this module's dynamic `import()` so they become their own async
 * chunk. The initial route budget is 350 KB gzipped (spec §3); a terminal
 * emulator is allowed past it only because nobody pays for it until they open
 * one. **Never import this file statically.**
 *
 * Everything in here is presentation and byte-shuffling. Who may open a shell,
 * as which account, is decided in `ferrum_ops::terminal` and nowhere near the
 * browser.
 */

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useEffect, useImperativeHandle, useRef, type Ref } from "react";

export interface XtermHandle {
  /** Draw bytes the shell wrote. */
  write(data: Uint8Array): void;
  /** Draw a line of our own — a status note, not shell output. */
  notice(text: string): void;
  clear(): void;
  focus(): void;
  /** Current size in cells, for the resize message. */
  size(): { cols: number; rows: number };
}

export interface XtermViewProps {
  handleRef: Ref<XtermHandle>;
  /** Keystrokes and pasted text, already UTF-8 encoded by xterm. */
  onData: (data: string) => void;
  onResize: (cols: number, rows: number) => void;
  dark: boolean;
}

/**
 * A dark palette in both themes.
 *
 * A terminal is not a panel surface: programs inside it draw with the ANSI
 * colours, and those are designed against a dark ground. Following the panel's
 * light theme here would make half of `htop` unreadable, so the terminal keeps
 * its own colours and only its border belongs to the page.
 */
const THEME = {
  background: "#0b0f14",
  foreground: "#d7dde4",
  cursor: "#7dd3fc",
  selectionBackground: "#243b53",
};

export default function XtermView({ handleRef, onData, onResize, dark }: XtermViewProps) {
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  // Kept in refs so the effect below never re-runs — recreating the terminal
  // would wipe the scrollback the user is reading.
  const dataHandler = useRef(onData);
  const resizeHandler = useRef(onResize);
  dataHandler.current = onData;
  resizeHandler.current = onResize;

  useEffect(() => {
    if (!host.current) return;

    const terminal = new Terminal({
      convertEol: false,
      cursorBlink: true,
      fontFamily:
        'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
      fontSize: 13,
      // A shell can print a lot; this is the browser-side equivalent of the
      // agent's scrollback ring, and it is the memory ceiling for this tab.
      scrollback: 5000,
      theme: THEME,
      // The panel is RTL in Persian; a terminal never is. Programs inside it
      // position their own output by column, so mirroring would garble every
      // curses application.
      allowProposedApi: false,
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(host.current);
    fitAddon.fit();

    terminal.onData((data) => dataHandler.current(data));
    terminal.onResize(({ cols, rows }) => resizeHandler.current(cols, rows));

    term.current = terminal;
    fit.current = fitAddon;

    // Re-fit on any layout change, not only on a window resize: the sidebar
    // collapsing is the common case and does not resize the window.
    const observer = new ResizeObserver(() => {
      try {
        fitAddon.fit();
      } catch {
        // fit() throws while the element is detached or zero-sized, which is
        // exactly what happens for a frame during navigation.
      }
    });
    observer.observe(host.current);

    return () => {
      observer.disconnect();
      terminal.dispose();
      term.current = null;
      fit.current = null;
    };
  }, []);

  useImperativeHandle(
    handleRef,
    (): XtermHandle => ({
      write: (data) => term.current?.write(data),
      notice: (text) => term.current?.writeln(`\r\n\x1b[2m${text}\x1b[0m`),
      clear: () => term.current?.clear(),
      focus: () => term.current?.focus(),
      size: () => ({ cols: term.current?.cols ?? 80, rows: term.current?.rows ?? 24 }),
    }),
    [],
  );

  return (
    <div
      ref={host}
      // dir="ltr" unconditionally: see the theme note above. The surrounding
      // page is mirrored in Persian; the terminal inside it must not be.
      dir="ltr"
      className="h-full w-full"
      style={{ background: THEME.background }}
      data-theme={dark ? "dark" : "light"}
    />
  );
}
