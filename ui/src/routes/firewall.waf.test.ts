/**
 * The WAF card's one judgement (spec §11.9).
 *
 * The card has no controls, so everything it can get wrong is in this function.
 * The state it exists for is `claimed`: the panel holding `enabled: true` for a
 * rule engine written entirely for nginx — nginx's ModSecurity connector,
 * `nginx -t`, an nginx reload — on a machine where nginx is not what answers
 * port 80. Drawn as an ordinary enabled WAF, that is the panel reporting a
 * protection nobody has, which is the failure this project treats as its worst.
 */

import { describe, expect, it } from "vitest";

import { wafState, type WafStatus } from "./firewall";

const status = (over: Partial<WafStatus> = {}): WafStatus => ({
  enabled: false,
  available: true,
  web_server: "nginx",
  blockers: [],
  default_mode: "detect",
  default_paranoia: 1,
  ...over,
});

/** What `waf.status` answers from a machine Apache is serving. */
const apache = (): Partial<WafStatus> => ({
  available: false,
  web_server: "apache",
  blockers: [
    {
      code: "not_nginx",
      detail: "this machine serves its sites with Apache.",
      remedy: "Switch this machine back to nginx and enable the WAF there, or leave it off.",
    },
  ],
});

describe("what the WAF card says about a server", () => {
  it("reports on and off plainly where the WAF can actually run", () => {
    expect(wafState(status({ enabled: true }))).toBe("on");
    expect(wafState(status({ enabled: false }))).toBe("off");
  });

  it("does not call an enabled WAF on an Apache machine 'on'", () => {
    // The whole issue: the setting says on, the rules are nginx's, and httpd
    // reads none of them. Every request reaches the sites unexamined while the
    // page shows the paranoia level somebody chose.
    expect(wafState(status({ enabled: true, ...apache() }))).toBe("claimed");
  });

  it("says only 'unavailable' when nobody has claimed the WAF is on", () => {
    // The same server with nothing being misreported. That is a limitation to
    // explain, not an alarm to raise.
    expect(wafState(status({ enabled: false, ...apache() }))).toBe("unavailable");
  });

  it("treats a lost connector the same way as the wrong web server", () => {
    // `available` is the agent's whole answer, not a proxy for the web server:
    // an nginx machine whose ModSecurity module was uninstalled after the WAF
    // was switched on is inspecting exactly as little as the Apache one.
    expect(
      wafState(
        status({
          enabled: true,
          available: false,
          blockers: [
            {
              code: "module_missing",
              detail: "no ModSecurity connector for nginx.",
              remedy: "The WAF can only run where nginx and the connector come from one source.",
            },
          ],
        }),
      ),
    ).toBe("claimed");
  });
});
