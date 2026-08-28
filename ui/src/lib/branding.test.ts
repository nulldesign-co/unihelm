/**
 * Behaviour tests for the branding the browser applies (spec §11.19).
 *
 * The server validates every one of these values and the database validates
 * two of them again. What is pinned here is the *third* check — the one that
 * runs immediately before the value reaches a DOM sink — because a defence
 * nobody tests is a defence that quietly stops matching the sink it guards.
 */

import { describe, expect, it } from "vitest";

import { assetUrl, readableInk, safeSupportUrl, type PublicBranding } from "./branding";

describe("the support link", () => {
  it("accepts the two schemes a support page actually uses", () => {
    expect(safeSupportUrl("https://support.example.com/help")).toBe(
      "https://support.example.com/help",
    );
    expect(safeSupportUrl(" http://intranet.example/help ")).toBe("http://intranet.example/help");
  });

  it("refuses every scheme that would execute when the link is clicked", () => {
    // It becomes an anchor's href on the login page, which anyone can reach.
    for (const bad of [
      "javascript:alert(1)",
      "JavaScript:alert(1)",
      "  javascript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "vbscript:msgbox",
      "file:///etc/passwd",
    ]) {
      expect(safeSupportUrl(bad), bad).toBeNull();
    }
  });

  it("refuses a relative or scheme-less URL, which is not a support page", () => {
    for (const bad of ["/support", "//evil.example", "support.example.com", "", null, undefined]) {
      expect(safeSupportUrl(bad), String(bad)).toBeNull();
    }
  });
});

describe("choosing readable text for a brand colour", () => {
  it("puts dark ink on light backgrounds and light ink on dark ones", () => {
    expect(readableInk("#ffffff")).toBe("#111827");
    expect(readableInk("#000000")).toBe("#ffffff");
  });

  it("uses relative luminance, not an average, so yellow gets dark text", () => {
    // (r+g+b)/3 puts white on #ffd700 at a contrast of about 1.6:1, which is
    // the case an operator picking a brand colour is most likely to hit.
    expect(readableInk("#ffd700")).toBe("#111827");
    expect(readableInk("#00ff00")).toBe("#111827");
    // And blue, whose average is identical to yellow's but whose luminance is
    // not, still gets white.
    expect(readableInk("#0000ff")).toBe("#ffffff");
  });

  it("handles the panel's own accent and a typical brand blue", () => {
    expect(readableInk("#3b82f6")).toBe("#ffffff");
  });
});

describe("asset URLs", () => {
  const branding = (assets: PublicBranding["assets"]): PublicBranding => ({
    panel_name: null,
    support_url: null,
    primary_color: null,
    assets,
  });

  it("carries the etag so a replaced image is a different URL to the browser", () => {
    // Without it a customer who uploads a new logo keeps seeing the old one
    // until their cache expires, which would undo "applies with no restart"
    // from the client's side.
    const url = assetUrl(
      branding([
        { kind: "logo", url: "/api/branding/assets/logo", content_type: "image/png", etag: "a b/c" },
      ]),
      "logo",
    );
    expect(url).toBe("/api/branding/assets/logo?v=a%20b%2Fc");
  });

  it("is null for a kind that does not resolve, so the caller falls back", () => {
    expect(assetUrl(branding([]), "logo")).toBeNull();
    expect(assetUrl(undefined, "favicon")).toBeNull();
  });
});
