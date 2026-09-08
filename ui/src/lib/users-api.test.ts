/**
 * The Users page's client, where it makes a claim of its own.
 *
 * Two of those are worth pinning.
 *
 * `changePassword` replaces the session it was called from — the server revokes
 * every session for the account and issues a new one on the response — so the
 * CSRF token the tab is holding is dead the moment the promise resolves. If
 * this client forgets to store the new one, the page looks fine and the
 * operator's *next* save fails with `csrf_invalid` for no reason they can see.
 *
 * `refusalFor` repeats what `unihelm_ops::users` enforces, so the last
 * administrator's Delete is greyed out with a reason instead of refused after
 * the click. A mirror that drifts is worse than no mirror: it either offers an
 * action the server will refuse, or hides one it would have allowed.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { getCsrfToken, setCsrfToken } from "./api";
import {
  MAX_PASSWORD_BYTES,
  MIN_PASSWORD_CHARS,
  confirmationMatches,
  newPasswordProblem,
  owned,
  passwordProblem,
  refusalFor,
  usersApi,
  type PanelUser,
} from "./users-api";

function account(overrides: Partial<PanelUser> = {}): PanelUser {
  return {
    id: 2,
    role: "customer",
    username: "client",
    email: "client@example.com",
    full_name: null,
    status: "active",
    reseller_id: null,
    created_at: "2026-09-01T10:00:00Z",
    last_login_at: null,
    subscriptions: 0,
    owned_plans: 0,
    customers: 0,
    ...overrides,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken(null);
});

describe("changing your own password", () => {
  it("stores the CSRF token the new session came with", async () => {
    setCsrfToken("token-for-the-session-being-replaced");
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(
          JSON.stringify({ sessions_ended: 2, csrf_token: "token-for-the-new-one" }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await usersApi.changePassword("old-password-here", "new-password-here");

    expect(result.sessions_ended).toBe(2);
    expect(getCsrfToken()).toBe("token-for-the-new-one");

    // And the request itself carried the old token, since it was still the
    // live session when it was sent.
    const [, init] = fetchMock.mock.calls[0]!;
    const headers = new Headers(init?.headers);
    expect(headers.get("x-unihelm-csrf")).toBe("token-for-the-session-being-replaced");
  });

  it("leaves the old token in place when the change was refused", async () => {
    setCsrfToken("still-the-live-session");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            code: "UNI-1100",
            slug: "invalid_credentials",
            message: "that is not the password on this account",
          }),
          { status: 401, headers: { "content-type": "application/json" } },
        ),
      ),
    );

    await expect(usersApi.changePassword("wrong", "new-password-here")).rejects.toThrow();
    expect(getCsrfToken()).toBe("still-the-live-session");
  });
});

describe("the password policy, as the panel enforces it", () => {
  it("counts characters against the floor and bytes against the ceiling", () => {
    expect(passwordProblem("")).toBe("required");
    expect(passwordProblem("a".repeat(MIN_PASSWORD_CHARS - 1))).toBe("tooShort");
    expect(passwordProblem("a".repeat(MIN_PASSWORD_CHARS))).toBeNull();
    // Eleven code points that are more than eleven bytes each: the floor is a
    // character count in `check_strength`, so this is short, not long.
    expect(passwordProblem("🔑".repeat(11))).toBe("tooShort");
    expect(passwordProblem("🔑".repeat(12))).toBeNull();
    expect(passwordProblem("a".repeat(MAX_PASSWORD_BYTES + 1))).toBe("tooLong");
  });

  it("refuses a new password that is the one already in use", () => {
    const same = "a-long-enough-password";
    expect(newPasswordProblem(same, same, same)).toBe("same");
  });

  it("catches a mistyped repeat before the round trip", () => {
    expect(newPasswordProblem("old-password-here", "new-password-here", "new-password-her")).toBe(
      "mismatch",
    );
    expect(
      newPasswordProblem("old-password-here", "new-password-here", "new-password-here"),
    ).toBeNull();
  });
});

describe("which actions the server would refuse", () => {
  it("answers your own account first, whatever else is true of it", () => {
    const me = account({ id: 7, role: "admin", username: "admin" });
    const viewer = { id: 7, adminCount: 4 };
    for (const action of ["role", "suspend", "delete"] as const) {
      expect(refusalFor(action, me, viewer)).toBe("self");
    }
  });

  it("protects the only administrator who can still sign in", () => {
    const onlyAdmin = account({ id: 1, role: "admin", username: "admin" });
    const viewer = { id: 9, adminCount: 1 };
    expect(refusalFor("delete", onlyAdmin, viewer)).toBe("lastAdmin");
    expect(refusalFor("role", onlyAdmin, viewer)).toBe("lastAdmin");
    expect(refusalFor("suspend", onlyAdmin, viewer)).toBe("lastAdmin");

    // A second one, and the rule stops applying.
    expect(refusalFor("delete", onlyAdmin, { id: 9, adminCount: 2 })).toBeNull();
    // A suspended administrator is not holding the panel up, so it is not what
    // the rule is counting — and the server counts it the same way.
    const suspended = account({ id: 1, role: "admin", status: "suspended" });
    expect(refusalFor("delete", suspended, viewer)).toBeNull();
  });

  it("blocks only deletion for an account that still owns things", () => {
    const owner = account({ subscriptions: 2 });
    const viewer = { id: 9, adminCount: 3 };
    expect(refusalFor("delete", owner, viewer)).toBe("owns");
    // Suspending somebody who owns sites is exactly what an operator does
    // about an unpaid invoice, so it is not refused.
    expect(refusalFor("suspend", owner, viewer)).toBeNull();
    expect(refusalFor("role", owner, viewer)).toBeNull();
  });

  it("says nothing stands in the way of an ordinary account", () => {
    expect(refusalFor("delete", account(), { id: 9, adminCount: 2 })).toBeNull();
  });

  it("treats a reseller's missing admin count as no administrators of its own", () => {
    // `admin_count` is null for a reseller, whose list holds no administrators
    // at all — so the rule can never be what stops them, and every row they
    // can see is a customer.
    expect(refusalFor("delete", account(), { id: 9, adminCount: null })).toBeNull();
    expect(
      refusalFor("delete", account({ role: "admin" }), { id: 9, adminCount: null }),
    ).toBe("lastAdmin");
  });
});

describe("what an account holds", () => {
  it("lists only what is non-zero, in the order the refusal names them", () => {
    expect(owned(account())).toEqual([]);
    expect(owned(account({ subscriptions: 1, owned_plans: 0, customers: 3 }))).toEqual([
      { kind: "subscriptions", count: 1 },
      { kind: "customers", count: 3 },
    ]);
  });
});

describe("the delete confirmation", () => {
  it("matches the username the way the agent compares it", () => {
    expect(confirmationMatches("  client  ", "client")).toBe(true);
    expect(confirmationMatches("clientt", "client")).toBe(false);
    expect(confirmationMatches("Client", "client")).toBe(false);
    expect(confirmationMatches("", "client")).toBe(false);
  });
});
