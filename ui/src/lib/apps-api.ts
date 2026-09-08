/**
 * The applications API, for the parts an app is more than an entry file.
 *
 * `api.ts` describes an application as a name, a path and a port, which is what
 * one was: the panel ran `node <entry>` and nothing else. A real Node
 * application is a `package.json` with a `start` script, a dependency tree that
 * has to be installed, and often a build before either means anything — so
 * there are two more things to say to the server, and they live here rather
 * than growing `api.ts` a third time.
 *
 * Both mirror agent rules this file deliberately duplicates:
 *
 * - **What starts an application.** It goes into a systemd unit, so the agent
 *   refuses anything a shell would read and anything systemd would expand.
 *   `startCommandProblem` is that rule again, and only for the message — the
 *   agent re-checks every character and its answer is the one that counts. A
 *   red line under the field beats a red task thirty seconds later.
 * - **Building.** A task, never a request: `npm install` on a cold cache is
 *   minutes, and the output is the answer rather than a detail of it.
 */

import {
  api,
  type AppMode,
  type AppView,
  type CreateAppRequest,
  type TaskAccepted,
  type UpdateAppRuntimeRequest,
} from "@/lib/api";

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

/** An app row, plus what it actually starts with. */
export interface AppWithStart extends AppView {
  /**
   * The `ExecStart` line, when it is not the app's entry file.
   *
   * Absent is the entry-file case — which is what every application created
   * before start commands existed is, and what a container always is. Read by
   * the agent out of the unit file, because the row has no column for it.
   */
  start_command?: string;
}

export interface CreateAppBody extends CreateAppRequest {
  /**
   * What starts it, instead of running the entry file. Omitted lets the server
   * use `package.json`'s start script when there is one.
   */
  start_command?: string;
}

export interface UpdateAppBody extends UpdateAppRuntimeRequest {
  /**
   * Absent leaves whatever it starts with alone; `null` puts it back on its
   * entry file. The two must not collapse, or going back is unreachable — the
   * same distinction `runtime_version` makes one field up.
   */
  start_command?: string | null;
}

export interface BuildAppRequest {
  /** Run this instead of the build command `package.json` declares. */
  command?: string;
  /** Install dependencies first. Omitted means yes. */
  install?: boolean;
}

export const appEndpoints = {
  createApp: (body: CreateAppBody) => api.post<TaskAccepted>("/api/apps", body),
  updateApp: (id: number, body: UpdateAppBody) =>
    api.post<TaskAccepted>(`/api/apps/${id}/runtime`, body),
  buildApp: (id: number, body: BuildAppRequest) =>
    api.post<TaskAccepted>(`/api/apps/${id}/build`, body),
};

// ---------------------------------------------------------------------------
// The command rules, for the message only
// ---------------------------------------------------------------------------

/** Why a command cannot be sent. Same shape the cron builder uses. */
export interface CommandProblem {
  key: string;
}

/** Every refusal `startCommandProblem` can emit, for a translation check. */
export const COMMAND_PROBLEM_KEYS = ["shell", "path", "quote", "long"] as const;

/** The agent's cap, so the field says so before the server does. */
export const MAX_COMMAND_CHARS = 512;

/**
 * Everything a shell would read and the panel will not.
 *
 * The panel starts the program itself — there is no shell anywhere on that
 * path — so each of these means something to a program that is not going to
 * run. `%` is here for a different reason: systemd expands it as a specifier in
 * `ExecStart` before the line is a command at all.
 */
const SHELL_SYNTAX = /[&;|<>$`\\(){}*?[\]~#!'%]/;

/**
 * Check a start or build command the way the agent checks it.
 *
 * `null` means it would be accepted. An empty string is not a problem here:
 * both fields are optional, and "leave it alone" is what empty means at the
 * only two places this is called.
 */
export function commandProblem(raw: string): CommandProblem | null {
  const value = raw.trim();
  if (value === "") return null;
  if (value.length > MAX_COMMAND_CHARS) return { key: "long" };
  if (SHELL_SYNTAX.test(value)) return { key: "shell" };

  // An odd number of double quotes leaves one open, which the agent refuses
  // rather than guessing where the word ended.
  if ((value.match(/"/g) ?? []).length % 2 !== 0) return { key: "quote" };

  // The first word names a program on the server, not a file in the
  // application: `node dist/server.js`, never `./dist/server.js`.
  const first = value.replace(/"/g, "").split(/\s+/)[0] ?? "";
  if (first.includes("/")) return { key: "path" };

  return null;
}

/**
 * The `ExecStart` line, back in the form somebody would type it.
 *
 * The unit holds `/usr/bin/npm start`, because systemd does no path lookup and
 * the agent resolves the program against a fixed list of trusted directories.
 * The field takes `npm start`, because that is what the agent accepts — a `/`
 * in the first word is refused there. Stripping the directory is exactly the
 * inverse of that resolution, so the round trip is lossless for every command
 * this panel wrote.
 *
 * A unit somebody hand-edited could hold anything, and this would then offer an
 * edit of something else. That is the same file the agent refuses to overwrite
 * once it has been touched by hand, so the edit it offers is one the server
 * will decline — a refusal, not a silent replacement.
 */
export function commandForEditing(execStart: string | undefined): string {
  if (!execStart) return "";
  const [program, ...rest] = execStart.split(" ");
  const name = program?.slice(program.lastIndexOf("/") + 1) ?? "";
  return [name, ...rest].join(" ");
}

/**
 * Whether an application of this mode can be given a start command.
 *
 * A container's command is built from its image and its entry file, and a
 * `docker run` has no unit file to put one in — the agent refuses rather than
 * accepting the field and starting something else. The page has to know the
 * same thing, or it offers a control whose only ending is a red task.
 */
export function takesStartCommand(mode: AppMode): boolean {
  return mode === "host";
}
