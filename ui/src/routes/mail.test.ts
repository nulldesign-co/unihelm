/**
 * Behaviour tests for the mail page's own judgement (spec §11.18).
 *
 * The agent owns every rule about a relay and refuses the same combination
 * this file refuses; what is pinned here is that the page does not quietly
 * stop mirroring it. A form that let an operator submit a credential for a
 * plaintext relay would put the password on the wire before the refusal came
 * back — the request is sent either way.
 */

import { describe, expect, it } from "vitest";

import { credentialNeedsTls , mailIsFlowing} from "./mail";

describe("a relay credential", () => {
  it("is refused on a plaintext relay, because base64 is not encryption", () => {
    expect(credentialNeedsTls("token-user", "none")).toBe(true);
    expect(credentialNeedsTls("  token-user  ", "none")).toBe(true);
  });

  it("is fine on either encrypted mode", () => {
    expect(credentialNeedsTls("token-user", "starttls")).toBe(false);
    expect(credentialNeedsTls("token-user", "implicit")).toBe(false);
  });

  it("does not object to a plaintext relay with no credential at all", () => {
    // Authorising by source IP is how most in-datacentre relays work, and the
    // refusal is specifically about sending a secret in the clear.
    expect(credentialNeedsTls("", "none")).toBe(false);
    expect(credentialNeedsTls("   ", "none")).toBe(false);
  });
});

describe("whether the badge may say this server is sending", () => {
  const flowing = {
    agent: "postfix",
    installed: true,
    configured: true,
    drifted: false,
    running: true,
    relay_live: true,
    queued: 0,
    legacy_files: 0,
    submission: "127.0.0.1:25",
    containers: {
      docker_installed: false,
      daemon_answered: false,
      submission: null,
      relayed_for: [],
      uncovered: [],
      unsupported: [],
    },
    summary: "This server sends through relay.example.com.",
  };

  it("says so only when every part of it holds", () => {
    expect(mailIsFlowing(flowing)).toBe(true);
  });

  it("does not say so while the unit is down", () => {
    expect(mailIsFlowing({ ...flowing, running: false })).toBe(false);
  });

  it("does not say so with no relay behind it", () => {
    // The MTA accepts the message either way; without a relay it goes into a
    // queue nothing drains, which is not sending.
    expect(mailIsFlowing({ ...flowing, relay_live: false })).toBe(false);
  });

  it("does not say so when the configuration on disk is not ours", () => {
    // `drifted` means the settings on this page are not the ones in force, so a
    // green badge would be describing a file the panel does not control.
    expect(mailIsFlowing({ ...flowing, drifted: true })).toBe(false);
  });

  it("does not say so before the panel has configured anything", () => {
    expect(mailIsFlowing({ ...flowing, configured: false })).toBe(false);
  });
});
