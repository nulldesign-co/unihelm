/**
 * The web terminal and the SSH key manager (spec §11.16).
 *
 * Two things live here that are not in `api.ts`: the two-step handshake a
 * WebSocket needs, and the little protocol that runs inside it.
 *
 * **Why two steps.** The browser's WebSocket API cannot set a request header,
 * so the upgrade cannot carry the panel's CSRF token. Opening a terminal is
 * therefore an ordinary CSRF-protected POST that returns a single-use ticket,
 * followed by a socket that presents it. A page on another origin cannot get
 * past the first step, and a ticket alone gets past neither — the server
 * requires the session cookie as well and checks the two name the same account.
 */

import { api } from "@/lib/api";

export type TerminalTargetKind = "root" | "tenant";

export interface OpenSessionRequest {
  target?: TerminalTargetKind;
  subscription_id?: number;
  cols?: number;
  rows?: number;
  /** Set to re-attach to a shell that is still running instead of starting one. */
  session_id?: string;
}

export interface OpenSessionResponse {
  session_id: string;
  ticket: string;
  expires_in: number;
  websocket_url: string;
}

export interface SshKey {
  fingerprint: string;
  algorithm: string;
  comment: string | null;
  bits: number | null;
}

export interface SshKeyListResponse {
  keys: SshKey[];
  /** The account has entries outside the panel-managed block. */
  has_unmanaged_keys: boolean;
}

export const terminalApi = {
  openSession: (body: OpenSessionRequest) =>
    api.post<OpenSessionResponse>("/api/terminal/sessions", body),
  sshKeys: (subscriptionId?: number) =>
    api.get<SshKeyListResponse>(
      `/api/ssh-keys${subscriptionId === undefined ? "" : `?subscription_id=${subscriptionId}`}`,
    ),
  addSshKey: (key: string, subscriptionId?: number) =>
    api.post<{ key: SshKey; count: number }>("/api/ssh-keys", {
      key,
      subscription_id: subscriptionId,
    }),
  removeSshKey: (fingerprint: string, subscriptionId?: number) =>
    api.del<{ removed: boolean; count: number }>(
      `/api/ssh-keys/${encodeURIComponent(fingerprint)}${
        subscriptionId === undefined ? "" : `?subscription_id=${subscriptionId}`
      }`,
    ),
};

/** What the socket sends us. */
export type ServerMessage =
  | { type: "output"; seq: number; data: string }
  | {
      type: "state";
      status: "open" | "closed" | "denied" | "lagged";
      detail: string | null;
      user: string | null;
    };

/**
 * Absolute `ws(s)://` URL for a path the server handed us.
 *
 * Built from `location` rather than from a configured host: the panel is served
 * from the same origin as its API (there is no separate API host to get wrong),
 * and deriving the scheme means a panel behind TLS gets `wss://` without anyone
 * remembering to configure it.
 */
export function websocketUrl(path: string): string {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${window.location.host}${path}`;
}

/** Bytes → base64, in chunks so a large paste does not blow the argument limit. */
export function encodeBytes(bytes: Uint8Array): string {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/** base64 → bytes. The shell writes bytes; only the terminal decodes them. */
export function decodeBytes(encoded: string): Uint8Array {
  const binary = atob(encoded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

const encoder = new TextEncoder();

export function encodeText(text: string): string {
  return encodeBytes(encoder.encode(text));
}
