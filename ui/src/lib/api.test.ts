import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, endpoints, setUnauthorizedHandler } from "./api";

/**
 * A 401 from the server means this session is over, and the UI has to act on it.
 *
 * Before this hook existed the 401 was thrown like any other error and each
 * screen rendered it as its own failure, so an operator whose session expired
 * sat on a dashboard where nothing loaded and no screen ever mentioned logging
 * in. The tab looked broken rather than logged out.
 */
describe("unauthorized handling", () => {
  afterEach(() => {
    setUnauthorizedHandler(null);
    vi.unstubAllGlobals();
  });

  function respondWith(status: number) {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ code: "UNI-1", slug: "no", message: "no" }), {
          status,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
  }

  it("tells the session layer when the server rejects the session", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    respondWith(401);

    await expect(endpoints.me()).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("does not treat a wrong password as an expired session", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    respondWith(401);

    // The login form answers its own 401. Bouncing here would clear the session
    // the operator is trying to start and hide the "wrong password" message.
    await expect(endpoints.login("someone", "wrong")).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("leaves other failures to the caller", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    respondWith(500);

    await expect(endpoints.me()).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});
