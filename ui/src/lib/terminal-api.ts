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

/**
 * One subscription, as the terminal needs to name it.
 *
 * A slice of what `subscription.list` returns — an admin picking whose shell to
 * open recognises the Linux account and the customer behind it; the plan and
 * quota columns on that row are the plans page's business.
 */
export interface TerminalSubscription {
  id: number;
  linux_user: string;
  status: "active" | "suspended" | "pending_delete";
  /** Null when the owning user row has gone; the Linux account still names it. */
  customer_username: string | null;
}

export interface SubscriptionListResponse {
  subscriptions: TerminalSubscription[];
}

export const terminalApi = {
  openSession: (body: OpenSessionRequest) =>
    api.post<OpenSessionResponse>("/api/terminal/sessions", body),
  /**
   * The subscriptions this caller may see.
   *
   * The terminal needs it because `subscription_id` is not optional for an
   * administrator: their scope is the whole server, so the agent has no "my
   * subscription" to resolve and refuses a tenant shell that does not name one.
   * The page had no way to name one, so every admin "My account" terminal was a
   * 400 quoting a field the screen did not offer.
   */
  subscriptions: () => api.get<SubscriptionListResponse>("/api/subscriptions"),
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

/**
 * What the start panel should show for the accounts it found.
 *
 * Three outcomes, kept apart on purpose. One subscription is not a list to
 * choose from — making somebody pick the only option is a click that carries no
 * decision. None is not an empty picker with a 400 waiting behind it: it is a
 * statement that this server has no tenant accounts yet, and a pointer at where
 * they are made. A failed request is neither, and the caller must not fold it
 * into "none" — an empty list would be a claim about the server that this page
 * has not established.
 */
export type SubscriptionChoice =
  | { kind: "none" }
  | { kind: "only"; id: number; subscription: TerminalSubscription }
  | { kind: "pick"; options: TerminalSubscription[] };

export function subscriptionChoice(list: readonly TerminalSubscription[]): SubscriptionChoice {
  // By id, so the same server produces the same order on every load and the
  // option an operator reached for last time is where they left it.
  const options = [...list].sort((a, b) => a.id - b.id);
  const only = options[0];
  if (only === undefined) return { kind: "none" };
  if (options.length === 1) return { kind: "only", id: only.id, subscription: only };
  return { kind: "pick", options };
}

/**
 * Whose `authorized_keys` the SSH keys card is looking at.
 *
 * The card used to call the keys endpoint with no account at all. That works
 * for a customer — the agent resolves their own subscription — and cannot work
 * for an administrator, whose scope is the whole server: the agent refuses,
 * naming a `subscription_id` the card never offered. The whole card was a 400
 * for the one role most likely to open it.
 *
 * So the account is decided here, before any request goes out, and the states
 * are kept apart because they are different sentences on screen: a list still
 * arriving is not an empty server, an empty server is not a failed request, and
 * "there is one account" is not a list to choose from.
 *
 * `own` is the no-account call, and it is deliberately reachable only for
 * callers the agent has a default for. An administrator never falls back to it:
 * for them it is the exact request that fails.
 */
export type KeyAccount =
  | { kind: "loading" }
  /** Send no `subscription_id`; the agent resolves the caller's own. */
  | { kind: "own" }
  | { kind: "none" }
  | { kind: "failed"; message: string }
  /**
   * The accounts this caller may manage, and which of them is being shown.
   * `chosen: null` means nothing has been picked yet, which is a card that
   * asks — never a card that guesses and then names the wrong login.
   */
  | { kind: "list"; options: TerminalSubscription[]; chosen: TerminalSubscription | null };

export function sshKeyAccount(input: {
  /** Global scope: the agent has no "my subscription" for this caller. */
  isAdmin: boolean;
  loading: boolean;
  /** The server's own sentence about why the list did not arrive. */
  error: string | null;
  subscriptions: readonly TerminalSubscription[];
  /** The row the operator picked, if the list needed picking from. */
  picked: number | null;
}): KeyAccount {
  if (input.loading) return { kind: "loading" };
  // A list that failed to load leaves a customer exactly where they were —
  // sending no id still works for them — but an admin has nothing to fall back
  // to, so they get the reason instead of a request that cannot succeed.
  if (input.error !== null) {
    return input.isAdmin ? { kind: "failed", message: input.error } : { kind: "own" };
  }

  const choice = subscriptionChoice(input.subscriptions);
  if (choice.kind === "none") return { kind: "none" };
  // One account is not a list to choose from: it is chosen, and named on
  // screen. Making somebody pick the only option is a click that carries no
  // decision.
  if (choice.kind === "only") {
    return { kind: "list", options: [choice.subscription], chosen: choice.subscription };
  }
  // Looked up rather than trusted: a picked id whose account has since gone
  // would otherwise put a stale number on every call and a name on screen that
  // no longer belongs to it.
  const match = choice.options.find((option) => option.id === input.picked);
  return { kind: "list", options: choice.options, chosen: match ?? null };
}

/**
 * Whether the keys endpoint may be called yet, and for whom.
 *
 * The one rule this enforces is the bug it was written for: a request goes out
 * only once the card knows whose keys it is asking about. Every other state —
 * still loading, nothing to choose from, nothing chosen — sends nothing at all,
 * because a list rendered from a refusal reads as "this account has no keys",
 * which is a lie about somebody's login.
 */
export function keysRequest(account: KeyAccount): {
  enabled: boolean;
  subscriptionId?: number;
} {
  if (account.kind === "own") return { enabled: true };
  if (account.kind === "list" && account.chosen !== null) {
    return { enabled: true, subscriptionId: account.chosen.id };
  }
  return { enabled: false };
}

/**
 * How one subscription reads in the picker.
 *
 * Both halves are identifiers — a Linux account and a panel username — so there
 * is nothing here to translate; the id is appended because two customers can
 * share a name in the operator's head but never in the database.
 */
export function subscriptionLabel(s: TerminalSubscription): string {
  // Truthiness, not a null check: a row whose owning user has gone can arrive
  // with the name null or missing, and neither should print "null" at an
  // operator choosing a root-capable shell.
  const who = s.customer_username ? `${s.linux_user} · ${s.customer_username}` : s.linux_user;
  return `${who} (#${s.id})`;
}

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
