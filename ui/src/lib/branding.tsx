import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";

import { api } from "@/lib/api";

/**
 * White-label branding, applied live (spec §11.19).
 *
 * `GET /api/branding` is the panel's one unauthenticated read: the login page
 * has to show the reseller's name, colour and logo *before* anybody has a
 * session. It answers with a name, a support URL, a hex colour and up to three
 * image URLs, and nothing else — no identifiers, and the same shape whether or
 * not the `Host` header matched a reseller, so it cannot be used to find out
 * which resellers exist.
 *
 * The whole feature applies with no restart because branding is data: the
 * server reads rows, this hook reads the endpoint, and the CSS variable and
 * `<title>` are set from the answer. There is nothing to reload on either side.
 *
 * ## Why the colour is validated again here
 *
 * The server refuses anything that is not exactly `#rrggbb`, and the database
 * refuses it a second time. This file refuses it a third, because the value
 * ends up in `style.setProperty` — a sink where `#fff; background: url(...)`
 * would be a stylesheet injection. A client-side check cannot be a security
 * boundary on its own, but it costs one regular expression and it means no
 * single mistake on the server reaches a CSS parser.
 */

export interface BrandingAssetLink {
  kind: "logo" | "favicon" | "login_background";
  url: string;
  content_type: string;
  etag: string;
}

export interface PublicBranding {
  panel_name: string | null;
  support_url: string | null;
  primary_color: string | null;
  assets: BrandingAssetLink[];
}

const EMPTY: PublicBranding = {
  panel_name: null,
  support_url: null,
  primary_color: null,
  assets: [],
};

/** Exactly `#rrggbb`, in either case. Nothing else reaches a CSS property. */
const HEX = /^#[0-9a-fA-F]{6}$/;

/** Only `https:` and `http:`. A `javascript:` href is one click from script. */
export function safeSupportUrl(value: string | null | undefined): string | null {
  if (!value) return null;
  const lowered = value.trim().toLowerCase();
  return lowered.startsWith("https://") || lowered.startsWith("http://") ? value.trim() : null;
}

export function assetUrl(
  branding: PublicBranding | undefined,
  kind: BrandingAssetLink["kind"],
): string | null {
  const asset = branding?.assets.find((a) => a.kind === kind);
  // The ETag rides in the query string so a replaced image is a different URL
  // to the browser. Without it a customer who uploads a new logo sees the old
  // one until their cache expires, which would undo "no restart" from the
  // client's side.
  return asset ? `${asset.url}?v=${encodeURIComponent(asset.etag)}` : null;
}

/**
 * Fetch the public branding.
 *
 * Never throws into the tree: an unbranded panel is a working panel, and a
 * login page that will not render because a branding query failed is worse than
 * one showing the product's own name.
 */
export function useBranding(): PublicBranding {
  const query = useQuery({
    queryKey: ["branding"],
    queryFn: () => api.get<PublicBranding>("/api/branding"),
    // It changes when an operator changes it, which is rarely, and it is
    // fetched on the login page where every millisecond is visible.
    staleTime: 60_000,
    retry: false,
  });
  return query.data ?? EMPTY;
}

/**
 * Apply branding to the document: the accent colour, the tab title and the
 * favicon.
 *
 * The three derived accent variables are mixed against the theme's own tokens
 * rather than against fixed white and black, so one hex colour produces a
 * coherent hover and tint in both light and dark mode without the operator
 * picking four colours.
 */
export function useApplyBranding(branding: PublicBranding) {
  const colour = branding.primary_color;
  const name = branding.panel_name;
  const favicon = assetUrl(branding, "favicon");

  useEffect(() => {
    const root = document.documentElement;
    const vars = [
      "--color-accent",
      "--color-accent-hover",
      "--color-accent-soft",
      "--color-on-accent",
    ];
    if (!colour || !HEX.test(colour)) {
      // Back to the product palette. Removing rather than re-setting keeps the
      // stylesheet the single source of the default.
      vars.forEach((name) => root.style.removeProperty(name));
      return;
    }
    root.style.setProperty("--color-accent", colour);
    root.style.setProperty(
      "--color-accent-hover",
      `color-mix(in oklab, ${colour} 86%, var(--color-ink))`,
    );
    root.style.setProperty(
      "--color-accent-soft",
      `color-mix(in oklab, ${colour} 14%, var(--color-surface))`,
    );
    root.style.setProperty("--color-on-accent", readableInk(colour));
    return () => vars.forEach((name) => root.style.removeProperty(name));
  }, [colour]);

  useEffect(() => {
    if (!name) return;
    const previous = document.title;
    document.title = name;
    return () => {
      document.title = previous;
    };
  }, [name]);

  useEffect(() => {
    if (!favicon) return;
    const link = document.createElement("link");
    link.rel = "icon";
    link.href = favicon;
    document.head.append(link);
    return () => link.remove();
  }, [favicon]);
}

/**
 * Black or white text on this background.
 *
 * WCAG relative luminance, with the sRGB transfer function — the cheap
 * `(r+g+b)/3` version puts white text on a mid-yellow button, which is exactly
 * the case an operator picking a brand colour is most likely to hit.
 */
export function readableInk(hex: string): string {
  const channel = (offset: number) => {
    const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  const luminance = 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
  return luminance > 0.4 ? "#111827" : "#ffffff";
}
