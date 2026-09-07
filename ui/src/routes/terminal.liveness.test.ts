/**
 * When the terminal admits it is no longer live (spec §11.16).
 *
 * A blinking cursor is the only signal a terminal has for "type here", and it
 * went on blinking after the session ended: a disconnected shell looked exactly
 * like a working one, and the operator kept typing into a socket that was gone.
 * The view is now told, and it is told by *deriving* the answer from the phase
 * rather than by a call each ending path has to remember — so these cases are
 * the contract that every phase which is not `open` is a dead terminal.
 */

import { describe, expect, it } from "vitest";

import { isLive, type Phase } from "./terminal";

/** Every shape the page can be in, so nothing new slips through as "live". */
const EVERY_PHASE: Phase[] = [
  { kind: "idle" },
  { kind: "connecting" },
  { kind: "open", account: "root" },
  { kind: "closed", reason: null },
  { kind: "closed", reason: "Session ended." },
  { kind: "denied", reason: "The terminal is not available for this account." },
];

describe("terminal liveness", () => {
  it("is true only while a shell is attached", () => {
    expect(isLive({ kind: "open", account: "root" })).toBe(true);
    expect(EVERY_PHASE.filter(isLive)).toEqual([{ kind: "open", account: "root" }]);
  });

  it("is false on every path that leaves the open state", () => {
    // The agent closing the session, the operator ending it, the socket
    // dropping, and a refusal. All four used to leave the cursor blinking.
    expect(isLive({ kind: "closed", reason: null })).toBe(false);
    expect(isLive({ kind: "closed", reason: "Session ended." })).toBe(false);
    expect(isLive({ kind: "closed", reason: "The connection to the panel failed." })).toBe(false);
    expect(isLive({ kind: "denied", reason: "not permitted" })).toBe(false);
  });

  it("is false before the agent has said the shell is open", () => {
    // `connecting` included: the ticket is minted and the socket may be up, but
    // nothing reads the keyboard until the agent answers. A cursor blinking
    // through the handshake would invite typing that goes nowhere.
    expect(isLive({ kind: "idle" })).toBe(false);
    expect(isLive({ kind: "connecting" })).toBe(false);
  });
});
