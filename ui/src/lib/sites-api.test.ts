/**
 * Behaviour tests for the alias client logic (spec §11.2).
 *
 * Aliases are the one field on the site page where a client-side mistake turns
 * into a domain the panel says it serves and does not. Two claims are worth
 * pinning down: that a typed name is normalised the way the agent normalises it
 * — otherwise the row is written under one spelling and the remove button looks
 * for another — and that the field refuses exactly what `Domain::parse` refuses,
 * so the operator is told at the keyboard rather than by a task that fails.
 */

import { describe, expect, it } from "vitest";

import { aliasProblem, normalizeDomain } from "./sites-api";

const site = { domain: "example.com", aliases: ["www.example.com"] };

describe("normalizeDomain", () => {
  it("lowercases, trims and drops the root dot, the way Domain::parse does", () => {
    expect(normalizeDomain("  Shop.Example.COM. ")).toBe("shop.example.com");
  });

  it("drops every trailing dot, not just one", () => {
    // Rust's `trim_end_matches('.')` strips them all. A client that stopped at
    // one would send a name with an empty last label and be told, correctly but
    // unhelpfully, that the domain has an empty label.
    expect(normalizeDomain("example.com...")).toBe("example.com");
  });

  it("leaves an ordinary name exactly as it is", () => {
    expect(normalizeDomain("www.example.com")).toBe("www.example.com");
  });
});

describe("aliasProblem", () => {
  it("accepts the names people actually attach", () => {
    for (const ok of ["shop.example", "www.example.net", "a-b.example.co.uk", "xn--80ak6aa92e.com"]) {
      expect(aliasProblem(ok, site)).toBeNull();
    }
  });

  it("refuses an empty field rather than posting a blank domain", () => {
    expect(aliasProblem("", site)).toBe("required");
    expect(aliasProblem("   ", site)).toBe("required");
  });

  it("refuses the site's own name, which is not an additional name for it", () => {
    // The agent refuses it too; catching it here is what keeps the message
    // under the field the operator got wrong.
    expect(aliasProblem("example.com", site)).toBe("sameAsSite");
    expect(aliasProblem("  EXAMPLE.com.  ", site)).toBe("sameAsSite");
  });

  it("refuses a name already in the list in front of the operator", () => {
    expect(aliasProblem("www.example.com", site)).toBe("alreadyAttached");
    expect(aliasProblem("WWW.example.com.", site)).toBe("alreadyAttached");
  });

  it("refuses what Domain::parse refuses, and says which rule was broken", () => {
    expect(aliasProblem("localhost", site)).toBe("needsDot");
    expect(aliasProblem("a..example", site)).toBe("needsDot");
    expect(aliasProblem("192.0.2.1", site)).toBe("ipAddress");
    expect(aliasProblem("-x.example", site)).toBe("hyphen");
    expect(aliasProblem("x-.example", site)).toBe("hyphen");
    expect(aliasProblem("under_score.example", site)).toBe("charset");
    expect(aliasProblem("*.example.com", site)).toBe("charset");
    expect(aliasProblem(`${"a".repeat(64)}.example`, site)).toBe("labelTooLong");
    expect(aliasProblem(`${"a".repeat(60)}.`.repeat(5) + "example", site)).toBe("tooLong");
  });

  it("refuses an international domain that has not been punycoded", () => {
    // nginx matches `server_name` against what DNS resolves, which is the
    // punycode form; storing the Unicode spelling would produce a vhost that
    // answers for nothing.
    expect(aliasProblem("مثال.com", site)).toBe("charset");
    expect(aliasProblem("münchen.example", site)).toBe("charset");
  });
});
