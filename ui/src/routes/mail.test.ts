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

import { credentialNeedsTls } from "./mail";

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
