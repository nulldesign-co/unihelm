/**
 * Behaviour tests for the database-management client logic (spec §11.4).
 *
 * The agent is the security boundary — it re-parses every identifier and
 * re-checks every scope. What is pinned down here are the claims this client
 * makes on its own: that a destructive action cannot be armed without the exact
 * name retyped, that a grant picker never proposes (or even lists) another
 * tenant's user, and that a failed clipboard write is reported as a failure
 * rather than swallowed — because the password it failed to copy is one the
 * panel cannot show again.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  confirmsName,
  copyToClipboard,
  dbNameProblem,
  grantableUsers,
  type DatabaseRow,
  type DbEngine,
  type DbUserRow,
} from "./databases-api";

function database(name: string, engine: DbEngine, subscriptionId: number): DatabaseRow {
  return {
    id: 1,
    subscription_id: subscriptionId,
    engine,
    name,
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-01T00:00:00Z",
  };
}

function dbUser(
  username: string,
  engine: DbEngine,
  subscriptionId: number,
  id = 1,
): DbUserRow {
  return {
    id,
    subscription_id: subscriptionId,
    engine,
    username,
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-01T00:00:00Z",
  };
}

describe("dbNameProblem", () => {
  it("refuses the names the engines keep for themselves", () => {
    for (const reserved of [
      "mysql",
      "MySQL",
      "information_schema",
      "performance_schema",
      "sys",
      "postgres",
      "template0",
      "template1",
      "pg_catalog",
      "PG_toast",
    ]) {
      expect(dbNameProblem(reserved), reserved).toBe("reserved");
    }
  });

  it("refuses anything that is not an unquoted identifier in both engines", () => {
    expect(dbNameProblem("shop-main")).toBe("charset");
    expect(dbNameProblem("shop main")).toBe("charset");
    expect(dbNameProblem("shop`main")).toBe("charset");
    expect(dbNameProblem("shop;drop")).toBe("charset");
    expect(dbNameProblem("shop_فروشگاه")).toBe("charset");
  });

  it("refuses a name that does not start with a letter or underscore", () => {
    expect(dbNameProblem("1shop")).toBe("start");
    expect(dbNameProblem("_shop")).toBeNull();
    // Checked in the agent's order — first character first — so a non-ASCII
    // name reports the rule it actually broke first, exactly as the server
    // would have. Two validators disagreeing about *which* rule failed is how
    // a "fix" that still gets rejected happens.
    expect(dbNameProblem("فروشگاه")).toBe("start");
  });

  it("refuses an empty name and one past the engines' length limit", () => {
    expect(dbNameProblem("")).toBe("required");
    expect(dbNameProblem("   ")).toBe("required");
    expect(dbNameProblem("a".repeat(63))).toBeNull();
    expect(dbNameProblem("a".repeat(64))).toBe("tooLong");
  });

  it("accepts an ordinary tenant database name, surrounding spaces and all", () => {
    expect(dbNameProblem("shop_main")).toBeNull();
    expect(dbNameProblem("  shop_main  ")).toBeNull();
    expect(dbNameProblem("wp_2026")).toBeNull();
  });
});

describe("confirmsName", () => {
  it("stays disarmed until the whole name is retyped", () => {
    expect(confirmsName("", "shop_main")).toBe(false);
    expect(confirmsName("shop", "shop_main")).toBe(false);
    expect(confirmsName("shop_main_2", "shop_main")).toBe(false);
  });

  it("does not accept a different database that only differs in case", () => {
    // MySQL can be case-insensitive about database names depending on the
    // filesystem; the confirmation must not be, or "type SHOP to drop shop"
    // would arm on a name the operator never verified.
    expect(confirmsName("SHOP_MAIN", "shop_main")).toBe(false);
  });

  it("forgives the whitespace a copy-paste picks up, and nothing else", () => {
    expect(confirmsName("  shop_main\n", "shop_main")).toBe(true);
    expect(confirmsName("shop _main", "shop_main")).toBe(false);
  });
});

describe("grantableUsers", () => {
  const db = database("shop_main", "mysql", 7);

  it("never offers a user belonging to another subscription", () => {
    const users = [dbUser("theirs", "mysql", 8, 1), dbUser("ours", "mysql", 7, 2)];
    expect(grantableUsers(db, users).map((u) => u.username)).toEqual(["ours"]);
  });

  it("never offers a user from the other engine", () => {
    const users = [dbUser("pg_side", "postgres", 7, 1), dbUser("my_side", "mysql", 7, 2)];
    expect(grantableUsers(db, users).map((u) => u.username)).toEqual(["my_side"]);
  });

  it("offers nothing at all rather than a wrong pairing when nothing matches", () => {
    expect(grantableUsers(db, [dbUser("elsewhere", "postgres", 9)])).toEqual([]);
  });
});

describe("copyToClipboard", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reports failure when the browser exposes no clipboard at all", async () => {
    // Plain HTTP on a LAN address: `navigator.clipboard` is simply absent, and
    // a dialog that claimed success here would leave the operator without the
    // one copy of the password that will ever exist.
    vi.stubGlobal("navigator", {});
    await expect(copyToClipboard("s3cret")).resolves.toBe(false);
  });

  it("reports failure when the write is refused", async () => {
    vi.stubGlobal("navigator", {
      clipboard: { writeText: () => Promise.reject(new Error("denied")) },
    });
    await expect(copyToClipboard("s3cret")).resolves.toBe(false);
  });

  it("reports success and passes the text through untouched", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    await expect(copyToClipboard("s3cret")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("s3cret");
  });
});
