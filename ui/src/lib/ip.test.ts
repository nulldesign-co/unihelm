/**
 * Behaviour tests for the ban form's lockout guard (spec §11.9).
 *
 * The claim under test is narrow and worth stating: this browser-side check
 * must never *accept* an address the agent would refuse for loopback or
 * self-ban reasons, and must never *refuse* an ordinary attacker address the
 * agent would happily drop. A guard that disagrees with the server in either
 * direction is worse than none — one direction lies to the operator, the other
 * blocks the feature.
 */

import { describe, expect, it } from "vitest";

import { banRefusal, canonicalIp, isCidr, parseIp, sameIp } from "./ip";

describe("parsing an address", () => {
  it("reads the spellings that actually appear in an auth log", () => {
    expect(parseIp("203.0.113.7")?.family).toBe(4);
    expect(parseIp("::1")?.family).toBe(6);
    expect(parseIp("2001:db8::1")?.family).toBe(6);
    expect(parseIp("fe80::1234:5678:9abc:def0")?.family).toBe(6);
    expect(parseIp("  203.0.113.7  ")?.family).toBe(4);
    expect(parseIp("0:0:0:0:0:0:0:1")?.family).toBe(6);
  });

  it("refuses what the agent's parser refuses, so the form cannot offer an impossible ban", () => {
    for (const bad of [
      "",
      "   ",
      "example.com",
      "203.0.113.7.8",
      "203.0.113",
      "256.0.0.1",
      // A leading zero is octal to some resolvers and decimal to others; Rust
      // refuses it outright, so an operator must not be able to type it here.
      "010.0.0.1",
      "203.0.113.+7",
      "1::2::3",
      "fe80::1%eth0",
      "12345::1",
      "gggg::1",
      "1:2:3:4:5:6:7",
      "1:2:3:4:5:6:7:8:9",
      "1:2:3:4:5:6:7::8",
      ":1:2:3:4:5:6:7:8",
    ]) {
      expect(parseIp(bad), bad).toBeNull();
    }
  });

  it("treats an IPv4-mapped address as the IPv4 host it is", () => {
    const mapped = parseIp("::ffff:127.0.0.1");
    expect(mapped).not.toBeNull();
    expect(canonicalIp(mapped!)).toEqual({ family: 4, bytes: [127, 0, 0, 1] });
    expect(sameIp(mapped!, parseIp("127.0.0.1")!)).toBe(true);
  });

  it("does not confuse a v6 address with the v4 address that shares its digits", () => {
    expect(sameIp(parseIp("::1")!, parseIp("0.0.0.1")!)).toBe(false);
  });
});

describe("the ban form's refusal", () => {
  it("refuses every spelling of loopback, because banning it cuts the panel off from itself", () => {
    for (const loopback of ["127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1", "0:0:0:0:0:0:0:1"]) {
      expect(banRefusal(loopback, "203.0.113.9"), loopback).toBe("loopback");
    }
  });

  it("refuses the address this admin is browsing from, whichever way it is written", () => {
    expect(banRefusal("203.0.113.9", "203.0.113.9")).toBe("self");
    // The server reports what the connection carried; an admin on a dual-stack
    // link may well type the other spelling of the same host.
    expect(banRefusal("::ffff:203.0.113.9", "203.0.113.9")).toBe("self");
    expect(banRefusal("203.0.113.9", "::ffff:203.0.113.9")).toBe("self");
    expect(banRefusal("2001:db8::5", "2001:db8:0:0:0:0:0:5")).toBe("self");
  });

  it("refuses addresses that are not one host, which a backend would widen", () => {
    for (const wide of ["0.0.0.0", "::", "255.255.255.255", "224.0.0.1", "ff02::1"]) {
      expect(banRefusal(wide, "203.0.113.9"), wide).toBe("not_a_host");
    }
  });

  it("says `malformed` rather than a generic error when the field is not an address", () => {
    expect(banRefusal("not-an-ip", "203.0.113.9")).toBe("malformed");
    expect(banRefusal("", "203.0.113.9")).toBe("malformed");
  });

  it("still refuses loopback when the server never told us our own address", () => {
    // `your_ip` absent must weaken only the self-ban explanation, never the
    // checks this browser can make on its own.
    expect(banRefusal("127.0.0.1", null)).toBe("loopback");
    expect(banRefusal("::", undefined)).toBe("not_a_host");
    expect(banRefusal("203.0.113.9", null)).toBeNull();
  });

  it("lets an ordinary attacker address through to the server", () => {
    for (const fine of ["203.0.113.42", "198.51.100.7", "2001:db8::dead:beef", "10.0.0.5"]) {
      expect(banRefusal(fine, "203.0.113.9"), fine).toBeNull();
    }
  });
});

describe("the Sentinel allowlist", () => {
  it("accepts the address and CIDR forms the agent stores", () => {
    for (const entry of ["203.0.113.9", "203.0.113.0/24", "10.0.0.0/8", "2001:db8::/32", "::1/128"]) {
      expect(isCidr(entry), entry).toBe(true);
    }
  });

  it("refuses a typo instead of storing an entry that would protect nothing", () => {
    // The agent's `cidr_contains` returns false for an unparseable entry, so a
    // stored typo is an allowlist row that silently covers no address at all.
    for (const bad of ["203.0.113.0/33", "203.0.113.0/", "203.0.113.0/-1", "office-lan", "", "/24", "2001:db8::/129"]) {
      expect(isCidr(bad), bad).toBe(false);
    }
  });
});
