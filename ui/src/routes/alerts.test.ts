/**
 * Behaviour tests for the alerts page's own judgement (spec §11.11).
 *
 * Three claims are pinned here, each of which would be a real defect if it
 * slipped:
 *
 * - a channel edit that does not touch the secret must send **no** `config`
 *   key, because the API never returns the stored one and an empty or null
 *   value would destroy a working bot token;
 * - the history renders spans, so an alert that is still firing sorts above
 *   last week's resolved ones and its duration is the time so far;
 * - the rule form refuses exactly the thresholds `validate_rule` refuses.
 */

import { describe, expect, it } from "vitest";

import type { AlertEvent, NotifyChannel } from "@/lib/api";

import { buildChannelRequest, formatSpan, ruleProblem, toSpans, type ChannelForm } from "./alerts";

const channel: NotifyChannel = {
  id: 7,
  kind: "telegram",
  label: "night shift",
  enabled: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const form = (over: Partial<ChannelForm> = {}): ChannelForm => ({
  kind: "webhook",
  label: "ops room",
  enabled: true,
  url: "",
  botToken: "",
  chatId: "",
  ...over,
});

describe("saving a notifier channel", () => {
  it("omits the config entirely when an edit leaves the secret untouched", () => {
    const built = buildChannelRequest(form({ kind: "telegram", label: "renamed" }), channel);
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    // Present-but-null would read as "seal this" on the server; absent is the
    // only spelling that means "keep the stored credential".
    expect("config" in built.request).toBe(false);
    expect(built.request).toEqual({ id: 7, label: "renamed", enabled: true });
  });

  it("refuses to create a channel with no configuration at all", () => {
    const built = buildChannelRequest(form(), null);
    expect(built).toEqual({ ok: false, problem: "config" });
  });

  it("sends the kind on create and never on an edit, because the server forbids changing it", () => {
    const created = buildChannelRequest(form({ url: "https://hooks.example/x" }), null);
    expect(created.ok && created.request.kind).toBe("webhook");

    const edited = buildChannelRequest(form({ kind: "telegram", url: "" }), channel);
    expect(edited.ok && "kind" in edited.request).toBe(false);
  });

  it("requires both halves of a Telegram credential or neither", () => {
    expect(buildChannelRequest(form({ kind: "telegram", botToken: "123:abc" }), channel)).toEqual({
      ok: false,
      problem: "config",
    });
    expect(buildChannelRequest(form({ kind: "telegram", chatId: "-100" }), channel)).toEqual({
      ok: false,
      problem: "config",
    });

    const complete = buildChannelRequest(
      form({ kind: "telegram", botToken: "123:abc", chatId: "-100" }),
      channel,
    );
    expect(complete.ok && complete.request.config).toEqual({
      bot_token: "123:abc",
      chat_id: "-100",
    });
  });

  it("requires a label, since it is the only thing the audit log can record", () => {
    expect(buildChannelRequest(form({ label: "   ", url: "https://x.test/y" }), null)).toEqual({
      ok: false,
      problem: "label",
    });
  });

  it("trims what it sends so a pasted token with a trailing space is not stored broken", () => {
    const built = buildChannelRequest(form({ label: " ops ", url: " https://x.test/y " }), null);
    expect(built.ok && built.request.label).toBe("ops");
    expect(built.ok && built.request.config).toEqual({ url: "https://x.test/y" });
  });
});

const event = (over: Partial<AlertEvent>): AlertEvent => ({
  id: 1,
  rule_id: 1,
  subject: "/",
  message: "disk / at 93%",
  value: 93,
  raised_at: "2026-08-28T10:00:00Z",
  resolved_at: null,
  notified: 1,
  ...over,
});

describe("the alert history", () => {
  const now = Date.parse("2026-08-28T12:00:00Z");

  it("floats what is still firing above what has already resolved", () => {
    const spans = toSpans(
      [
        event({ id: 1, raised_at: "2026-08-28T11:00:00Z", resolved_at: "2026-08-28T11:30:00Z" }),
        event({ id: 2, raised_at: "2026-08-28T09:00:00Z" }),
        event({ id: 3, raised_at: "2026-08-27T09:00:00Z", resolved_at: "2026-08-27T10:00:00Z" }),
      ],
      now,
    );
    expect(spans.map((s) => s.event.id)).toEqual([2, 1, 3]);
    expect(spans[0]!.open).toBe(true);
  });

  it("measures an open span up to now and a closed one to when it resolved", () => {
    const [open, closed] = toSpans(
      [
        event({ id: 1, raised_at: "2026-08-28T09:00:00Z" }),
        event({ id: 2, raised_at: "2026-08-28T08:00:00Z", resolved_at: "2026-08-28T08:45:00Z" }),
      ],
      now,
    );
    expect(open!.seconds).toBe(3 * 3600);
    expect(closed!.seconds).toBe(45 * 60);
    expect(closed!.endedAt).not.toBeNull();
  });

  it("never renders a negative duration when the clock stepped backwards", () => {
    // A resolve timestamp before its raise is corrupt data, not a reason to
    // print "-4h" next to an outage.
    const [span] = toSpans(
      [event({ raised_at: "2026-08-28T10:00:00Z", resolved_at: "2026-08-28T06:00:00Z" })],
      now,
    );
    expect(span!.seconds).toBe(0);
  });

  it("reads a duration the way an operator scans one", () => {
    expect(formatSpan(45)).toBe("45s");
    expect(formatSpan(12 * 60)).toBe("12m");
    expect(formatSpan(4 * 3600 + 12 * 60)).toBe("4h 12m");
    expect(formatSpan(3 * 86400 + 4 * 3600)).toBe("3d 4h");
    expect(formatSpan(0)).toBe("0s");
  });
});

describe("the rule form", () => {
  it("refuses a threshold that would fire on every filesystem the moment it is saved", () => {
    expect(ruleProblem("disk_pct", "", "0")).toBe("threshold_range");
    expect(ruleProblem("disk_pct", "", "101")).toBe("threshold_range");
    expect(ruleProblem("disk_pct", "", "90")).toBeNull();
  });

  it("keeps a cert rule below the length of the certificate it watches", () => {
    // Above 89 days the rule fires the instant a 90-day certificate is issued.
    expect(ruleProblem("cert_expiry_days", "", "90")).toBe("threshold_range");
    expect(ruleProblem("cert_expiry_days", "example.com", "14")).toBeNull();
  });

  it("makes a service rule name its service and takes no threshold", () => {
    expect(ruleProblem("service_down", "", "")).toBe("target_required");
    expect(ruleProblem("service_down", "nginx", "")).toBeNull();
  });

  it("refuses a target on the rules that watch the whole server", () => {
    expect(ruleProblem("mem_pct", "/var", "90")).toBe("target_not_allowed");
    expect(ruleProblem("load", "cpu0", "8")).toBe("target_not_allowed");
    expect(ruleProblem("load", "", "8")).toBeNull();
  });

  it("insists a disk target is a mount point rather than a device or a label", () => {
    expect(ruleProblem("disk_pct", "sda1", "90")).toBe("target_not_a_mount");
    expect(ruleProblem("disk_pct", "/var", "90")).toBeNull();
    // Empty means every filesystem, which is the useful default.
    expect(ruleProblem("disk_pct", "", "90")).toBeNull();
  });

  it("asks for a threshold before it checks the range, so the message is the useful one", () => {
    expect(ruleProblem("load", "", "")).toBe("threshold_required");
    expect(ruleProblem("load", "", "not a number")).toBe("threshold_range");
  });
});
