/**
 * The three decisions the process page's client makes on its own (issue 46).
 *
 * Everything else on that page is the agent's answer rendered. These are the
 * bits with judgement in them, and each one has a failure mode that is silent:
 * a poll interval the page invented, a confirmation that echoes the row back
 * instead of what the operator typed, and an owner column that names somebody
 * for a uid with no account behind it.
 */

import { describe, expect, it } from "vitest";

import {
  DEFAULT_REFRESH_SECONDS,
  MIN_POLL_MS,
  confirmsCommand,
  killRequest,
  ownerLabel,
  pollIntervalMs,
  type ProcessRow,
} from "./processes-api";

function row(overrides: Partial<ProcessRow> = {}): ProcessRow {
  // Only the fields these functions read are meaningful; the rest exist so the
  // object is a real `ProcessRow` rather than a shape that drifts from one.
  return {
    pid: 4123,
    ppid: 1,
    command: "php-fpm",
    cmdline: "/usr/sbin/php-fpm8.3 --nodaemonize",
    uid: 1000,
    user: "uh_abc123",
    state: "sleeping",
    kernel_thread: false,
    memory_bytes: 8_388_608,
    memory_source: "anonymous",
    cpu_pct: 12.5,
    unit: "unihelm-fpm-uh_abc123.service",
    ...overrides,
  };
}

describe("the poll interval", () => {
  it("is the server's, because the CPU figures are two of its samples divided", () => {
    expect(pollIntervalMs(5)).toBe(5_000);
    expect(pollIntervalMs(30)).toBe(30_000);
  });

  it("never polls faster than the floor, whatever the server says", () => {
    // A sweep reads four small files per process on a machine somebody already
    // thinks is slow. Being told to ask ten times a second is not a reason to.
    expect(pollIntervalMs(0.1)).toBe(MIN_POLL_MS);
    expect(pollIntervalMs(1)).toBe(MIN_POLL_MS);
  });

  it("falls back to the default rather than to as-fast-as-possible", () => {
    // An older agent, or a body that lost the field on the way here. The
    // dangerous reading of a missing interval is zero.
    for (const missing of [undefined, null, 0, -5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(pollIntervalMs(missing)).toBe(DEFAULT_REFRESH_SECONDS * 1_000);
    }
  });
});

describe("the kill confirmation", () => {
  it("sends what the operator typed, not what the row said", () => {
    // The agent compares this against the process actually behind the pid, and
    // that check is the only thing standing between a stale row and a kill of
    // whatever now holds the number. Echoing `row.command` back would make it a
    // comparison of the server's answer with itself.
    const target = row();
    const request = killRequest(target, "php-fpm", "term");
    expect(request).toEqual({
      pid: 4123,
      confirm_command: "php-fpm",
      confirm_user: "uh_abc123",
      signal: "term",
    });

    const wrong = killRequest(target, "postgres", "term");
    expect(wrong.confirm_command).toBe("postgres");
  });

  it("sends an empty owner for a uid with no passwd entry, and not a made-up one", () => {
    const request = killRequest(row({ user: undefined, uid: 1007 }), "php-fpm", "kill");
    expect(request.confirm_user).toBe("");
    expect(request.signal).toBe("kill");
  });

  it("forgives surrounding whitespace and nothing else", () => {
    // A pasted value carries it, and refusing that is a puzzle rather than a
    // guard. A prefix match, on the other hand, would confirm `php` for
    // `php-fpm`.
    expect(confirmsCommand("  php-fpm \n", "php-fpm")).toBe(true);
    expect(confirmsCommand("php", "php-fpm")).toBe(false);
    expect(confirmsCommand("php-fpm ", "php-fpm ")).toBe(true);
    expect(confirmsCommand("PHP-FPM", "php-fpm")).toBe(false);
    expect(confirmsCommand("", "php-fpm")).toBe(false);
    // The trimmed value is what travels, so the two agree about the same string.
    expect(killRequest(row(), "  php-fpm  ", "term").confirm_command).toBe("php-fpm");
  });
});

describe("the owner column", () => {
  it("shows the number when there is no account behind the uid", () => {
    // Inventing a name would put a stranger on the row somebody is deciding
    // whether to kill.
    expect(ownerLabel(row())).toBe("uh_abc123");
    expect(ownerLabel(row({ user: undefined, uid: 1007 }))).toBe("uid 1007");
  });
});
