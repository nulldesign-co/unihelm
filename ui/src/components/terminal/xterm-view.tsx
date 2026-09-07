/**
 * The xterm.js surface — the whole `@xterm/*` dependency tree and its stylesheet
 * live behind this module's dynamic `import()` so they become their own async
 * chunk. The initial route budget is 350 KB gzipped (spec §3); a terminal
 * emulator is allowed past it only because nobody pays for it until they open
 * one. **Never import this file statically.**
 *
 * Everything in here is presentation and byte-shuffling. Who may open a shell,
 * as which account, is decided in `unihelm_ops::terminal` and nowhere near the
 * browser.
 */

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useEffect, useImperativeHandle, useRef, type Ref } from "react";

export interface XtermHandle {
  /** Draw bytes the shell wrote. */
  write(data: Uint8Array): void;
  /**
   * Draw a line of our own — a status note, not shell output.
   *
   * Today that is one thing: the break where output the panel could not deliver
   * should have been. It has to be findable by somebody scrolling back through
   * a wall of build log, or the gap may as well not be drawn.
   */
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
  /**
   * Is a shell attached and reading what is typed?
   *
   * A prop rather than a method on the handle, and that is the fix: the caller
   * derives it from the session's phase, so *every* way out of a live session —
   * the operator ending it, the agent closing it, a refusal, a socket error —
   * lands here without anyone remembering to make a call. It used to be none of
   * them: the cursor went on blinking after the session was gone, which is the
   * one signal a terminal has for "type here", and the keystrokes went nowhere.
   */
  live: boolean;
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

/**
 * The cursor once nothing is reading it: still there, plainly not waiting.
 *
 * Dimmer than the foreground rather than invisible — a cursor that vanished
 * would leave the last line looking like output that had not finished arriving.
 */
const DEAD_CURSOR = "#475569";

/**
 * Make the terminal look like, and behave like, what it actually is.
 *
 * Three changes, because any one of them alone still misleads. The blink stops:
 * it is the universal "typing goes here" and it is the thing that kept claiming
 * a dead session was live. The block becomes a dim underline, so the difference
 * survives a still screenshot and a reader who never saw it blink. And
 * `disableStdin` makes it true rather than merely apparent — keystrokes are
 * refused by the emulator instead of being accepted and quietly dropped by a
 * socket that is no longer open.
 */
function applyLiveness(terminal: Terminal, live: boolean) {
  terminal.options.cursorBlink = live;
  terminal.options.cursorStyle = live ? "block" : "underline";
  terminal.options.disableStdin = !live;
  terminal.options.theme = { ...THEME, cursor: live ? THEME.cursor : DEAD_CURSOR };
}

export default function XtermView({ handleRef, onData, onResize, dark, live }: XtermViewProps) {
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  // Kept in refs so the effect below never re-runs — recreating the terminal
  // would wipe the scrollback the user is reading.
  const dataHandler = useRef(onData);
  const resizeHandler = useRef(onResize);
  dataHandler.current = onData;
  resizeHandler.current = onResize;
  // Same reason as the handlers: this chunk is fetched on demand, so it can
  // finish downloading after the session it belongs to has already opened —
  // or already ended. The effect below reads the value at mount, not the one
  // that was current when the effect was written.
  const liveness = useRef(live);
  liveness.current = live;

  useEffect(() => {
    if (!host.current) return;

    const terminal = new Terminal({
      convertEol: false,
      // Liveness is `applyLiveness`'s to set, a few lines down and before this
      // terminal is ever painted. Starting inert means the worst case is a
      // cursor that looks dead for a frame — never one that claims a shell is
      // listening when none is.
      cursorBlink: false,
      disableStdin: true,
      fontFamily:
        'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
      fontSize: 13,
      // A shell can print a lot; this is the browser-side equivalent of the
      // agent's scrollback ring, and it is the memory ceiling for this tab.
      scrollback: 5000,
      theme: THEME,
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
    applyLiveness(terminal, liveness.current);

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

  // Separate from the mount effect on purpose: recreating the terminal to
  // change a cursor would throw away the scrollback the operator is still
  // reading — which, after a session ends, is the only thing left of it.
  useEffect(() => {
    if (term.current) applyLiveness(term.current, live);
  }, [live]);

  useImperativeHandle(
    handleRef,
    (): XtermHandle => ({
      write: (data) => term.current?.write(data),
      // Yellow on its own line, where this used to be dim grey. Its only caller
      // is the message saying output went missing, and a break in the stream
      // that the eye slides over is the same as no break at all — the reader
      // still walks away with a log they think is whole.
      notice: (text) => term.current?.writeln(`\r\n\x1b[33m${text}\x1b[0m`),
      clear: () => term.current?.clear(),
      focus: () => term.current?.focus(),
      size: () => ({ cols: term.current?.cols ?? 80, rows: term.current?.rows ?? 24 }),
    }),
    [],
  );

  return (
    <div
      ref={host}
      // dir="ltr" unconditionally, whatever direction the page around it takes:
      // programs inside a terminal position their own output by column, so
      // mirroring it would garble every curses application.
      dir="ltr"
      className="h-full w-full"
      style={{ background: THEME.background }}
      data-theme={dark ? "dark" : "light"}
    />
  );
}
