/**
 * Behaviour tests for the task history's filter plumbing (spec §11.17).
 *
 * The server does the filtering and answers `invalid_input` for anything it
 * cannot parse. What is pinned here is that this page never *sends* one of
 * those, and that a date range means what a date picker looks like it means —
 * a "to the 5th" filter that dropped everything logged on the 5th is a control
 * that lies, and on a history page that reads as data loss.
 */

import { describe, expect, it } from "vitest";

import { taskQueryString } from "@/lib/api";
import { dateInput, endOfDay, startOfDay } from "./tasks";

describe("the date filters", () => {
  it("turns a picked day into an RFC 3339 range the API accepts", () => {
    expect(startOfDay("2026-08-28")).toBe("2026-08-28T00:00:00Z");
    expect(endOfDay("2026-08-28")).toBe("2026-08-28T23:59:59Z");
  });

  it("makes the end of the range inclusive of that whole day", () => {
    // Midnight would exclude everything that ran during the day the user
    // picked, which is every task they were looking for.
    expect(endOfDay("2026-08-28")).not.toBe("2026-08-28T00:00:00Z");
    expect(endOfDay("2026-08-28")!.startsWith("2026-08-28T23:59")).toBe(true);
  });

  it("treats a cleared picker as no filter rather than an empty string", () => {
    expect(startOfDay("")).toBeUndefined();
    expect(endOfDay("")).toBeUndefined();
  });

  it("round-trips back into the picker's own format", () => {
    expect(dateInput(startOfDay("2026-08-28"))).toBe("2026-08-28");
    expect(dateInput(undefined)).toBe("");
  });
});

describe("the task query string", () => {
  it("omits every filter that is not set", () => {
    // An empty `status=` is a value the server refuses, so a cleared control
    // must disappear from the URL rather than travel as the empty string.
    expect(taskQueryString({})).toBe("");
    expect(taskQueryString({ op: "", status: "", since: undefined })).toBe("");
  });

  it("sends the filters that are set", () => {
    const query = taskQueryString({
      op: "site.create",
      status: "failed",
      since: "2026-08-01T00:00:00Z",
      limit: 50,
      offset: 100,
    });
    const params = new URLSearchParams(query.slice(1));
    expect(params.get("op")).toBe("site.create");
    expect(params.get("status")).toBe("failed");
    expect(params.get("since")).toBe("2026-08-01T00:00:00Z");
    expect(params.get("limit")).toBe("50");
    expect(params.get("offset")).toBe("100");
  });

  it("escapes a filter value rather than letting it add parameters", () => {
    // The op list comes from the server, but nothing stops a caller from
    // constructing one; a value that could smuggle `&limit=…` would let the
    // page ask for something it never meant to.
    const query = taskQueryString({ op: "site.create&limit=9999" });
    const params = new URLSearchParams(query.slice(1));
    expect(params.get("op")).toBe("site.create&limit=9999");
    expect(params.get("limit")).toBeNull();
  });
});
