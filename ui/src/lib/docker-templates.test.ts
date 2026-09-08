/**
 * The seam between a prepared template and the create form (issue 41).
 *
 * A draft arrives as structured JSON and lands in three textareas the operator
 * can still edit, so the form re-parses what this module wrote. That round trip
 * is the whole risk: a mapping written in a grammar the dialog's own parser
 * does not read comes back as `NaN:NaN`, and a container created without the
 * port somebody was promised is the panel reporting a success that did not
 * happen. So the assertions drive the page's own `lines` and `parsePorts`
 * rather than a copy of their grammar, because a second copy is exactly the
 * thing that drifts.
 *
 * The other claims are about what the page must be able to say: which addresses
 * a draft will answer on, and which variables hold a password the panel minted
 * and kept no copy of.
 */

import { describe, expect, it } from "vitest";

import { lines, parsePorts } from "@/routes/docker";

import {
  draftAddresses,
  draftSecrets,
  draftToForm,
  type TemplateDraft,
} from "./docker-templates";

function draft(overrides: Partial<TemplateDraft> = {}): TemplateDraft {
  return {
    template: "grafana",
    display_name: "Grafana",
    image: "grafana/grafana:13.2.1",
    name: "grafana",
    ports: [
      {
        host: 3002,
        container: 3000,
        udp: false,
        public: false,
        purpose: "the web interface",
        address: "127.0.0.1:3002",
      },
    ],
    env: [
      { key: "GF_SECURITY_ADMIN_USER", value: "admin", generated: false },
      { key: "GF_SECURITY_ADMIN_PASSWORD", value: "s3cretGeneratedValue", generated: true },
    ],
    volumes: [
      { volume: "grafana-data", path: "/var/lib/grafana", holds: "every dashboard" },
    ],
    restart: "unless-stopped",
    first_run: { kind: "credential", user: "admin", variable: "GF_SECURITY_ADMIN_PASSWORD" },
    after_start: "Sign in as admin.",
    port_notes: [],
    ...overrides,
  };
}

describe("a prepared template filling the create form", () => {
  it("writes ports the page's own parser reads back to the same numbers", () => {
    const filled = draftToForm(
      draft({
        ports: [
          {
            host: 3002,
            container: 3000,
            udp: false,
            public: false,
            purpose: "the web interface",
            address: "127.0.0.1:3002",
          },
          {
            host: 5353,
            container: 53,
            udp: true,
            public: false,
            purpose: "DNS",
            address: "127.0.0.1:5353",
          },
        ],
      }),
    );

    expect(parsePorts(filled.ports).map((p) => ({ host: p.host, container: p.container, udp: p.udp }))).toEqual([
      { host: 3002, container: 3000, udp: false },
      { host: 5353, container: 53, udp: true },
    ]);
  });

  it("writes environment and volumes the page splits back into the same pairs", () => {
    const filled = draftToForm(draft());

    // The dialog's own split: everything before the first separator is the key,
    // everything after it is the value. A generated password can contain no
    // `=` today, but the reader must not be the thing that assumes so.
    const env = lines(filled.env).map((line) => {
      const at = line.indexOf("=");
      return { key: line.slice(0, at), value: line.slice(at + 1) };
    });
    expect(env).toEqual([
      { key: "GF_SECURITY_ADMIN_USER", value: "admin" },
      { key: "GF_SECURITY_ADMIN_PASSWORD", value: "s3cretGeneratedValue" },
    ]);

    const volumes = lines(filled.volumes).map((line) => {
      const at = line.indexOf(":");
      return { volume: line.slice(0, at), path: line.slice(at + 1) };
    });
    expect(volumes).toEqual([{ volume: "grafana-data", path: "/var/lib/grafana" }]);
  });

  it("carries the image, the name and the restart policy through unchanged", () => {
    const filled = draftToForm(draft());
    expect(filled.image).toBe("grafana/grafana:13.2.1");
    expect(filled.name).toBe("grafana");
    expect(filled.restart).toBe("unless-stopped");
  });

  /**
   * A draft with nothing to mount must not put a blank line in the box: the
   * page sends every non-empty line and the agent refuses a volume it cannot
   * parse, so one stray newline would refuse a container that was correct.
   */
  it("leaves a field a template does not use completely empty", () => {
    const filled = draftToForm(draft({ env: [], volumes: [] }));
    expect(filled.env).toBe("");
    expect(filled.volumes).toBe("");
    expect(lines(filled.env)).toEqual([]);
  });
});

describe("what the page has to be able to say about a draft", () => {
  it("names the generated variables and nothing else", () => {
    expect(draftSecrets(draft()).map((e) => e.key)).toEqual(["GF_SECURITY_ADMIN_PASSWORD"]);
    expect(draftSecrets(draft({ env: [] }))).toEqual([]);
  });

  it("reports the loopback address a port answers on, not the bare number", () => {
    // "3002" is a number an operator cannot type into a browser; the address is
    // the thing they can, and it is also the claim — reachable from this server
    // and nowhere else until they open it.
    expect(draftAddresses(draft())).toEqual(["127.0.0.1:3002 (the web interface)"]);
  });
});
