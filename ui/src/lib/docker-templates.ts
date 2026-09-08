/**
 * The curated container catalogue, and the draft that fills the create form in.
 *
 * Starting a container used to mean knowing an image, a tag, two port numbers,
 * a data path and four environment variables by heart and typing all of it into
 * empty boxes. `docker.template.list` is the answer sheet and
 * `docker.template.prepare` is one page of it filled in for this machine — a
 * generated password where the image needs one, and a host port that is
 * actually free.
 *
 * Kept out of `lib/api.ts` for the reason `sites-api.ts` is: that file is the
 * client every page imports, and this is one page's surface.
 *
 * Three things this module will not do:
 *
 * 1. **It does not carry its own copy of the catalogue.** The list is compiled
 *    into the agent, because a template names an image and an image runs as
 *    root on the server a moment later. A copy here would be a second list to
 *    keep in step, and the one the operator reads would be the one nobody
 *    verified.
 * 2. **It does not generate the password.** The agent mints it, hands it over
 *    once and keeps no copy — so `draftSecrets` exists to let the page say that
 *    out loud beside the field, not to make one.
 * 3. **It does not decide who can reach a port.** Every draft port arrives with
 *    `public: false` and the loopback address it will answer on; opening one is
 *    the operator's own switch in the create form, with the sentence about
 *    Docker's rule outrunning the firewall attached to it.
 */

import { api } from "@/lib/api";

// ---------------------------------------------------------------------------
// What the agent sends
// ---------------------------------------------------------------------------

/**
 * Who can sign in the moment a container from this template starts.
 *
 * `wizard` is the honest awkward case: there is no account at all until
 * somebody opens the page, so the first browser to arrive makes one. That is
 * contained on loopback and a giveaway on a published port, and the page says
 * so rather than leaving it to be discovered.
 */
export type FirstRun =
  | { kind: "wizard" }
  | { kind: "credential"; user: string; variable: string };

export interface TemplatePort {
  host: number;
  container: number;
  /** What answers on it, in the agent's words. */
  purpose: string;
}

export interface TemplateVolume {
  path: string;
  /** What is in it — which is what an operator needs before deleting it. */
  holds: string;
}

/** `value` is null for a generated one, never an empty string. */
export interface TemplateEnv {
  key: string;
  value: string | null;
  generated: boolean;
}

export interface ContainerTemplate {
  id: string;
  display_name: string;
  summary: string;
  /** Repository and pinned tag: `grafana/grafana:13.2.1`. */
  image: string;
  suggested_name: string;
  ports: TemplatePort[];
  volumes: TemplateVolume[];
  env: TemplateEnv[];
  first_run: FirstRun;
  after_start: string;
  /** True where the agent will mint a secret it keeps no copy of. */
  generates_secret: boolean;
}

export interface DraftPort {
  host: number;
  container: number;
  udp: boolean;
  /** Always false out of the agent. The form's own switch is what opens one. */
  public: boolean;
  purpose: string;
  /** The address it answers on while `public` is false: `127.0.0.1:3001`. */
  address: string;
}

export interface DraftEnv {
  key: string;
  value: string;
  /** True where the panel minted this value and kept no copy of it. */
  generated: boolean;
}

export interface DraftVolume {
  volume: string;
  path: string;
  holds: string;
}

/** One template, filled in: everything `docker.create` takes. */
export interface TemplateDraft {
  template: string;
  display_name: string;
  image: string;
  name: string;
  ports: DraftPort[];
  env: DraftEnv[];
  volumes: DraftVolume[];
  restart: "no" | "on-failure" | "always" | "unless-stopped";
  first_run: FirstRun;
  after_start: string;
  /** One line per port the agent had to move, naming what already held it. */
  port_notes: string[];
}

export const dockerTemplatesApi = {
  /** Every template the panel ships. A constant; nothing about this machine. */
  list: () => api.get<{ templates: ContainerTemplate[] }>("/api/server/docker/templates"),
  /**
   * Fill one in.
   *
   * A POST for something that changes nothing, because the answer carries a
   * freshly generated password: it must not sit in a URL, a proxy's cache or a
   * browser's history.
   */
  prepare: (id: string, name?: string) =>
    api.post<TemplateDraft>(`/api/server/docker/templates/${encodeURIComponent(id)}/prepare`, {
      name: name ?? null,
    }),
};

// ---------------------------------------------------------------------------
// A draft, in the shape the create form holds it
// ---------------------------------------------------------------------------

/**
 * The create form's fields, as text.
 *
 * The dialog's three list fields are textareas of one entry per line, and they
 * stay textareas after a template fills them: the operator can move a port,
 * drop a variable or rename a volume before pressing the button, and a
 * pre-filled form they cannot edit would be a worse form than the empty one.
 * That means everything below has to be written in the grammar the dialog's own
 * parsers read back — `host:container`, `KEY=value`, `name:/path` — which is
 * what `docker-templates.test.ts` pins.
 */
export interface DraftForm {
  image: string;
  name: string;
  ports: string;
  env: string;
  volumes: string;
  restart: TemplateDraft["restart"];
}

export function draftToForm(draft: TemplateDraft): DraftForm {
  return {
    image: draft.image,
    name: draft.name,
    // `/udp` only where it is really UDP: the parser reads a bare line as TCP,
    // and a `/tcp` suffix that means the same thing is one more token for an
    // operator to wonder about.
    ports: draft.ports.map((p) => `${p.host}:${p.container}${p.udp ? "/udp" : ""}`).join("\n"),
    env: draft.env.map((e) => `${e.key}=${e.value}`).join("\n"),
    volumes: draft.volumes.map((v) => `${v.volume}:${v.path}`).join("\n"),
    restart: draft.restart,
  };
}

/**
 * The variables the panel generated and did not keep.
 *
 * The page needs these to say so before the operator closes the dialog. A
 * container's secret is not an engine's: nothing seals it, nothing stores it,
 * and the only copy that will ever exist outside the container is the one in
 * front of them right now.
 */
export function draftSecrets(draft: TemplateDraft): DraftEnv[] {
  return draft.env.filter((e) => e.generated);
}

/**
 * Every address a draft will answer on, as the operator would type it.
 *
 * Loopback, because that is what the agent asked for — and the page prints
 * these rather than the bare port numbers so "reachable from this server only"
 * is a thing you can see rather than a claim underneath it.
 */
export function draftAddresses(draft: TemplateDraft): string[] {
  return draft.ports.map((p) => `${p.address} (${p.purpose})`);
}
