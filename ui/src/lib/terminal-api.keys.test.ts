/**
 * Whose `authorized_keys` the SSH keys card is about (spec §11.16).
 *
 * Keys are installed per Linux account, and the card used to name none: every
 * call went out without a `subscription_id`. A customer's scope has a default
 * the agent can resolve, so it worked for them and could never work for an
 * administrator, whose scope is the whole server — the card was one refusal,
 * quoting a field it did not offer, for the role most likely to open it.
 *
 * What is pinned here is the decision that fixed it: no request leaves the card
 * until the account is known, and the account it names is one that is actually
 * on the list.
 */

import { describe, expect, it } from "vitest";

import { keysRequest, sshKeyAccount, type TerminalSubscription } from "./terminal-api";

const sub = (id: number, linuxUser: string): TerminalSubscription => ({
  id,
  linux_user: linuxUser,
  status: "active",
  customer_username: "client",
});

const admin = {
  isAdmin: true,
  loading: false,
  error: null,
  subscriptions: [] as TerminalSubscription[],
  picked: null as number | null,
};

describe("the account the SSH keys card acts on", () => {
  it("never lets an administrator ask for keys without naming an account", () => {
    // Every state an admin can be in before they have picked. Each one used to
    // fire the request that the agent refuses, so the card showed a 400 where
    // a key list belongs.
    const two = [sub(1, "uh_alpha"), sub(2, "uh_beta")];
    const before = [
      { ...admin, loading: true },
      { ...admin, error: "the accounts could not be loaded" },
      { ...admin, subscriptions: [] },
      { ...admin, subscriptions: two, picked: null },
    ];
    for (const state of before) {
      expect(keysRequest(sshKeyAccount(state))).toEqual({ enabled: false });
    }

    // And once an account is named, the id goes with the call.
    expect(keysRequest(sshKeyAccount({ ...admin, subscriptions: two, picked: 2 }))).toEqual({
      enabled: true,
      subscriptionId: 2,
    });
  });

  it("chooses the only account rather than asking about it", () => {
    // A list of one is not a decision. The card still names it on screen — a
    // key installed on an account nobody named is the failure this whole
    // picker exists to avoid.
    const account = sshKeyAccount({ ...admin, subscriptions: [sub(7, "uh_only")] });
    expect(account).toEqual({
      kind: "list",
      options: [sub(7, "uh_only")],
      chosen: sub(7, "uh_only"),
    });
    expect(keysRequest(account)).toEqual({ enabled: true, subscriptionId: 7 });
  });

  it("says the server has no accounts instead of offering an empty picker", () => {
    // A server with no tenants yet is a fact about the server, not a failure —
    // and the card can point at where accounts are made.
    expect(sshKeyAccount({ ...admin, subscriptions: [] })).toEqual({ kind: "none" });
  });

  it("keeps a failed list apart from an empty one, for the caller who can act on it", () => {
    // Folding a failed request into "no accounts" would be the card claiming
    // something about the server it has not established.
    expect(sshKeyAccount({ ...admin, error: "the agent is offline" })).toEqual({
      kind: "failed",
      message: "the agent is offline",
    });

    // A customer loses nothing when that list fails: sending no id is exactly
    // what worked before, because the agent resolves their own subscription.
    // Only an administrator has no fallback, which is why only they see the
    // failure instead of their keys.
    const account = sshKeyAccount({ ...admin, isAdmin: false, error: "the agent is offline" });
    expect(account).toEqual({ kind: "own" });
    expect(keysRequest(account)).toEqual({ enabled: true });
  });

  it("drops a pick whose account is no longer on the list", () => {
    // A subscription can be deleted while the card is open. Sending the stale
    // id would either 404 or, worse, name an account on screen that the list
    // no longer contains.
    const account = sshKeyAccount({
      ...admin,
      subscriptions: [sub(1, "uh_alpha"), sub(2, "uh_beta")],
      picked: 99,
    });
    expect(account).toEqual({
      kind: "list",
      options: [sub(1, "uh_alpha"), sub(2, "uh_beta")],
      chosen: null,
    });
    expect(keysRequest(account)).toEqual({ enabled: false });
  });

  it("orders the picker by id so the row an operator reached for stays put", () => {
    const account = sshKeyAccount({
      ...admin,
      subscriptions: [sub(9, "uh_late"), sub(2, "uh_early")],
      picked: 9,
    });
    expect(account.kind === "list" && account.options.map((o) => o.id)).toEqual([2, 9]);
    expect(keysRequest(account)).toEqual({ enabled: true, subscriptionId: 9 });
  });

  it("asks nothing of a caller who is still waiting for the list", () => {
    expect(sshKeyAccount({ ...admin, loading: true })).toEqual({ kind: "loading" });
    expect(sshKeyAccount({ ...admin, isAdmin: false, loading: true })).toEqual({ kind: "loading" });
  });
});
