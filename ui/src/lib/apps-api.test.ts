/**
 * Behaviour tests for the applications command rules (spec §11.10).
 *
 * The agent is the boundary — it re-splits every command and re-applies the
 * systemd rules whatever this file does. What is pinned here is that the
 * form's copy does not *disagree* with the server's: a command the agent would
 * refuse must not sail through the field and come back as a failed task, and an
 * ordinary `npm start` must not be blocked by a check the server never made.
 *
 * The round trip is the other claim. The unit holds `/usr/bin/npm start`
 * because systemd does no path lookup; the field takes `npm start`, because a
 * `/` in the first word is exactly what the agent refuses. If those two drifted
 * apart, opening the dialog on an app that starts with a command would show an
 * error on a value the panel wrote itself.
 */

import { describe, expect, it } from "vitest";

import { en } from "@/i18n/en";

import {
  COMMAND_PROBLEM_KEYS,
  MAX_COMMAND_CHARS,
  commandForEditing,
  commandProblem,
  takesStartCommand,
} from "./apps-api";

describe("the command check", () => {
  it("accepts the commands people actually deploy with", () => {
    for (const ok of [
      "npm start",
      "npm run start:prod",
      "node dist/server.js",
      "node --max-old-space-size=512 dist/server.js",
      "bun run start",
      "pnpm start",
      'npm run "build all"',
      // Empty is not a problem: both fields are optional, and at the two
      // places this is called an empty box means "leave it" or "the entry
      // file", never "run nothing".
      "",
      "   ",
    ]) {
      expect(commandProblem(ok), ok).toBeNull();
    }
  });

  it("refuses what only a shell could run, because the panel starts no shell", () => {
    // Handed to execve, `&&` reaches npm as an argument, npm ignores what it
    // does not recognise, and half the work never happens under a panel
    // reporting success. That is the failure this check exists to prevent one
    // round trip earlier than the agent does.
    for (const hostile of [
      "npm run build && npm test",
      "npm run build || true",
      "npm run build; npm test",
      "npm run build | tee out.log",
      "npm run build > out.log",
      "npm run $(whoami)",
      "npm run `whoami`",
      "npm start ~/app",
      "npm run build.*",
      // systemd expands `%` in ExecStart as a specifier before the line is a
      // command at all, so the agent refuses it rather than escaping it.
      "npm run 100%build",
    ]) {
      expect(commandProblem(hostile)?.key, hostile).toBe("shell");
    }
  });

  it("refuses a first word that is a path, and says the interpreter goes first", () => {
    for (const hostile of ["./bin/server", "/usr/bin/npm start", "dist/server.js"]) {
      expect(commandProblem(hostile)?.key, hostile).toBe("path");
    }
    // …while a path in a *later* word is the ordinary case and stays legal.
    expect(commandProblem("node dist/server.js")).toBeNull();
  });

  it("refuses a quote with no closing one rather than guessing where the word ended", () => {
    expect(commandProblem('npm run "build')?.key).toBe("quote");
    expect(commandProblem('npm run "build all"')).toBeNull();
  });

  it("refuses a command longer than the agent will take", () => {
    expect(commandProblem(`npm run ${"a".repeat(MAX_COMMAND_CHARS)}`)?.key).toBe("long");
  });

  it("names every refusal in a key the bundle actually has", () => {
    // A problem key with no translation renders as `apps.commandProblem.shell`
    // under the field, which is worse than no message at all. Resolved by
    // walking the bundle rather than by indexing it, the way the apps page's
    // own coverage test does: a key family built from a template literal is
    // invisible to the type checker either way, so the check has to be a real
    // lookup at run time.
    const lookup = (key: string): unknown =>
      key
        .split(".")
        .reduce<unknown>(
          (node, part) =>
            typeof node === "object" && node !== null
              ? (node as Record<string, unknown>)[part]
              : undefined,
          en,
        );

    for (const key of COMMAND_PROBLEM_KEYS) {
      expect(typeof lookup(`apps.commandProblem.${key}`), key).toBe("string");
    }
  });
});

describe("re-opening a command for editing", () => {
  it("undoes the agent's program resolution so the field holds what was typed", () => {
    // The unit holds an absolute path because ExecStart does no lookup; the
    // field must not, because the agent refuses a `/` in the first word. A
    // prefill that failed its own check is a dialog that opens showing an error
    // on a value this panel wrote.
    expect(commandForEditing("/usr/bin/npm start")).toBe("npm start");
    expect(commandForEditing("/usr/local/bin/bun run start")).toBe("bun run start");
    expect(commandForEditing('/usr/bin/npm run "build all"')).toBe('npm run "build all"');
    expect(commandProblem(commandForEditing("/usr/bin/npm start"))).toBeNull();

    // An app with no start command opens on an empty field, which is what
    // "runs its entry file" means at this control.
    expect(commandForEditing(undefined)).toBe("");
  });
});

describe("which applications can be given a start command", () => {
  it("is the host only, because a container has no unit file to hold one", () => {
    // The agent refuses it outright, so a form that offered the field to a
    // container would be offering a control whose only ending is a red task.
    expect(takesStartCommand("host")).toBe(true);
    expect(takesStartCommand("container")).toBe(false);
  });
});
