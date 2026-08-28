/**
 * Behaviour tests for the terminal's byte handling (spec §11.16).
 *
 * The agent is the security boundary — it re-derives who may open a shell and
 * as which account, whatever this file does. What is pinned here is the part
 * the browser genuinely owns: the bytes. A terminal that mangles what a shell
 * printed, or what a user typed, is broken in a way no server-side check can
 * catch, and the two failure modes are opposite ends of the same bug: JSON
 * carries text, and a shell writes bytes.
 */

import { describe, expect, it, vi } from "vitest";

import { decodeBytes, encodeBytes, encodeText, websocketUrl } from "./terminal-api";

describe("terminal byte encoding", () => {
  it("round-trips bytes that are not valid UTF-8", () => {
    // Half a multi-byte sequence at a chunk boundary is routine terminal
    // output. If it went through a JSON string as text it would come back as
    // U+FFFD and the next chunk would render as garbage.
    const truncated = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xe2, 0x82]);
    expect(Array.from(decodeBytes(encodeBytes(truncated)))).toEqual(Array.from(truncated));
  });

  it("round-trips every byte value", () => {
    const all = new Uint8Array(256);
    for (let i = 0; i < 256; i += 1) all[i] = i;
    expect(Array.from(decodeBytes(encodeBytes(all)))).toEqual(Array.from(all));
  });

  it("encodes control characters as themselves, not as an escape", () => {
    // Ctrl-C is a byte, not the text "^C": the shell's line discipline is what
    // turns 0x03 into an interrupt, so it must arrive unaltered.
    expect(Array.from(decodeBytes(encodeText("")))).toEqual([0x03]);
    // A carriage return is what Enter sends; a newline would run nothing.
    expect(Array.from(decodeBytes(encodeText("\r")))).toEqual([0x0d]);
    // Escape sequences (arrow keys, function keys) must survive intact.
    expect(Array.from(decodeBytes(encodeText("[A")))).toEqual([0x1b, 0x5b, 0x41]);
  });

  it("encodes non-ASCII input as UTF-8", () => {
    // A Persian path typed into a shell is the everyday case here; encoding it
    // as anything but UTF-8 would produce a filename nobody can open.
    const encoded = encodeText("سلام");
    expect(Array.from(decodeBytes(encoded))).toEqual([
      0xd8, 0xb3, 0xd9, 0x84, 0xd8, 0xa7, 0xd9, 0x85,
    ]);
    expect(new TextDecoder().decode(decodeBytes(encoded))).toBe("سلام");
  });

  it("handles a paste larger than one call-argument batch", () => {
    // The chunked loop in `encodeBytes` exists because spreading a 200 KB array
    // into String.fromCharCode overflows the argument limit and throws.
    const big = new Uint8Array(200_000).fill(0x41);
    const back = decodeBytes(encodeBytes(big));
    expect(back.length).toBe(big.length);
    expect(back[0]).toBe(0x41);
    expect(back[back.length - 1]).toBe(0x41);
  });
});

describe("the websocket URL", () => {
  const withLocation = (protocol: string, host: string) => {
    vi.stubGlobal("window", { location: { protocol, host } });
  };

  it("follows the page's scheme so a panel behind TLS gets wss", () => {
    // Nobody configures this, so nobody can misconfigure it: a terminal that
    // silently downgraded to ws:// on an https panel would send keystrokes in
    // the clear.
    withLocation("https:", "panel.example.com");
    expect(websocketUrl("/api/terminal/ws?ticket=abc")).toBe(
      "wss://panel.example.com/api/terminal/ws?ticket=abc",
    );

    withLocation("http:", "127.0.0.1:8088");
    expect(websocketUrl("/api/terminal/ws?ticket=abc")).toBe(
      "ws://127.0.0.1:8088/api/terminal/ws?ticket=abc",
    );
    vi.unstubAllGlobals();
  });
});
