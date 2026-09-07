/**
 * Behaviour tests for the cron command builder (spec §11.8).
 *
 * The builder writes a shell line on somebody's behalf, which is the whole
 * hazard: a command the operator did not type is a command they cannot check
 * by eye, so what is pinned here is that the line it writes means what the
 * dialog says it means. Two claims carry the rest — that a value the shell
 * would read as syntax is refused rather than smuggled through the quoting,
 * and that a stored command is only ever re-opened in a template that would
 * reproduce it byte for byte.
 */

import { describe, expect, it } from "vitest";

import {
  OWN_SUBSCRIPTION,
  PHP_BINARY,
  SUBSCRIPTION_BY_ID,
  chosenSubscription,
  composeCommand,
  customDraft,
  draftProblem,
  recogniseCommand,
  runsEveryMinute,
  subscriptionDomains,
  type JobDraft,
} from "./cron-api";
import { checkCommand } from "./cron-schedule";

function draft(overrides: Partial<JobDraft> = {}): JobDraft {
  return { kind: "custom", url: "", path: "", custom: "", ...overrides };
}

describe("composing a command", () => {
  it("writes the line each template promises", () => {
    expect(composeCommand(draft({ kind: "url", url: "https://example.com/cron.php" }))).toBe(
      "curl -fsS -o /dev/null 'https://example.com/cron.php'",
    );
    expect(composeCommand(draft({ kind: "wordpress", path: "/home/uh_a/example.com" }))).toBe(
      `cd '/home/uh_a/example.com' && ${PHP_BINARY} wp-cron.php`,
    );
    expect(composeCommand(draft({ kind: "laravel", path: "/home/uh_a/app" }))).toBe(
      `cd '/home/uh_a/app' && ${PHP_BINARY} artisan schedule:run`,
    );
  });

  it("wraps a query string so the shell does not background the job at the &", () => {
    // `curl https://x/wp-cron.php?doing_wp_cron&x=1` unquoted ends at the `&`:
    // curl is backgrounded with half the address and `x=1` becomes a command
    // that does not exist. The job would look installed and fetch the wrong URL.
    const line = composeCommand(
      draft({ kind: "url", url: "https://example.com/wp-cron.php?doing_wp_cron&x=1" }),
    );
    expect(line).toBe("curl -fsS -o /dev/null 'https://example.com/wp-cron.php?doing_wp_cron&x=1'");
  });

  it("stores a custom command verbatim, because that is what the escape hatch is", () => {
    const line = "  /usr/bin/php8.3 /home/uh_a/tools/report.php --weekly  ";
    expect(composeCommand(draft({ kind: "custom", custom: line }))).toBe(
      "/usr/bin/php8.3 /home/uh_a/tools/report.php --weekly",
    );
  });

  it("hands the agent's own checker a line it accepts", () => {
    // The builder changes nothing about how a command is validated or stored;
    // if it could compose a line `checkCommand` refuses, the dialog would be
    // offering a job that cannot be saved.
    for (const composed of [
      composeCommand(draft({ kind: "url", url: "https://example.com/cron.php" })),
      composeCommand(draft({ kind: "wordpress", path: "/home/uh_a/example.com" })),
      composeCommand(draft({ kind: "laravel", path: "/home/uh_a/app" })),
    ]) {
      expect(composed).not.toBeNull();
      expect(checkCommand(composed ?? ""), composed ?? "").toBeNull();
    }
  });

  it("composes nothing while a field is still wrong", () => {
    // A composed line shown beside a red field is a command nobody will run,
    // and showing it is the only reason the preview exists.
    expect(composeCommand(draft({ kind: "url", url: "" }))).toBeNull();
    expect(composeCommand(draft({ kind: "wordpress", path: "~/example.com" }))).toBeNull();
  });
});

describe("what a draft refuses", () => {
  it("insists on an address it can actually fetch", () => {
    expect(draftProblem(draft({ kind: "url", url: "" }))?.key).toBe("urlRequired");
    expect(draftProblem(draft({ kind: "url", url: "example.com/cron.php" }))?.key).toBe("urlScheme");
    expect(draftProblem(draft({ kind: "url", url: "ftp://example.com/x" }))?.key).toBe("urlScheme");
    expect(draftProblem(draft({ kind: "url", url: "https://example .com/x" }))?.key).toBe(
      "urlSpace",
    );
  });

  it("refuses the one character that would break out of the quoting", () => {
    // `'https://x/';id;#'` inside single quotes closes the quote and starts a
    // second command. Refusing it is checkable in a way that escaping is not.
    expect(draftProblem(draft({ kind: "url", url: "https://x/';id;#" }))?.key).toBe("urlQuote");
    expect(draftProblem(draft({ kind: "wordpress", path: "/home/uh_a/o'brien" }))?.key).toBe(
      "pathQuote",
    );
  });

  it("insists on a full path, because quoting stops ~ expanding", () => {
    expect(draftProblem(draft({ kind: "laravel", path: "" }))?.key).toBe("pathRequired");
    expect(draftProblem(draft({ kind: "laravel", path: "~/app" }))?.key).toBe("pathAbsolute");
    expect(draftProblem(draft({ kind: "laravel", path: "app" }))?.key).toBe("pathAbsolute");
    expect(draftProblem(draft({ kind: "laravel", path: "/home/uh_a/app" }))).toBeNull();
  });

  it("has nothing of its own to say about a custom command", () => {
    // Custom is stored verbatim, so the only rules it answers to are the ones
    // the agent enforces, which `checkCommand` mirrors for every kind alike.
    expect(draftProblem(customDraft(""))).toBeNull();
    expect(draftProblem(customDraft("anything at all"))).toBeNull();
  });
});

describe("re-opening a stored command", () => {
  it("recognises a line it could have composed itself", () => {
    const url = recogniseCommand("curl -fsS -o /dev/null 'https://example.com/cron.php'");
    expect(url.kind).toBe("url");
    expect(url.url).toBe("https://example.com/cron.php");

    const wp = recogniseCommand(`cd '/home/uh_a/example.com' && ${PHP_BINARY} wp-cron.php`);
    expect(wp.kind).toBe("wordpress");
    expect(wp.path).toBe("/home/uh_a/example.com");

    const laravel = recogniseCommand(`cd '/home/uh_a/app' && ${PHP_BINARY} artisan schedule:run`);
    expect(laravel.kind).toBe("laravel");
    expect(laravel.path).toBe("/home/uh_a/app");
  });

  it("falls back to custom for a command that only looks like one of its own", () => {
    // The trap this avoids: opening `curl -s …` in the URL mode, where saving
    // would rewrite it to the panel's own flags — the dialog would be showing
    // one command while a different one stayed installed until Save.
    for (const line of [
      "curl -s https://example.com/cron.php",
      "curl -fsS -o /dev/null https://example.com/cron.php",
      `cd /home/uh_a/app && ${PHP_BINARY} artisan schedule:run`,
      "cd '/home/uh_a/app' && php8.3 artisan schedule:run",
      "/usr/bin/php /home/uh_a/cron.php",
      "",
    ]) {
      const recognised = recogniseCommand(line);
      expect(recognised.kind, line).toBe("custom");
      expect(recognised.custom, line).toBe(line.trim());
    }
  });

  it("round-trips every line it composes", () => {
    for (const original of [
      draft({ kind: "url", url: "https://example.com/wp-cron.php?doing_wp_cron" }),
      draft({ kind: "wordpress", path: "/home/uh_a/example.com/public_html" }),
      draft({ kind: "laravel", path: "/home/uh_a/app" }),
    ]) {
      const line = composeCommand(original);
      expect(line).not.toBeNull();
      const recognised = recogniseCommand(line ?? "");
      expect(recognised.kind).toBe(original.kind);
      expect(composeCommand(recognised)).toBe(line);
    }
  });
});

describe("the Laravel scheduler's every-minute rule", () => {
  it("reads spacing the way the agent stores it", () => {
    expect(runsEveryMinute("* * * * *")).toBe(true);
    expect(runsEveryMinute("  *  * * *  * ")).toBe(true);
  });

  it("knows the schedules that would silently skip the app's due tasks", () => {
    // `artisan schedule:run` only dispatches what is due when it runs, so an
    // hourly crontab line runs the app's every-minute tasks once an hour.
    expect(runsEveryMinute("0 * * * *")).toBe(false);
    expect(runsEveryMinute("*/5 * * * *")).toBe(false);
  });
});

describe("what the subscription picker resolves to", () => {
  it("omits the id for the caller's own subscription", () => {
    // An absent `subscription_id` is how the agent is told "mine"; a number
    // would be a request to create the job somewhere else.
    expect(chosenSubscription(OWN_SUBSCRIPTION, "")).toEqual({ kind: "own" });
    expect(chosenSubscription(OWN_SUBSCRIPTION, "7")).toEqual({ kind: "own" });
  });

  it("sends the id of a subscription picked from the list", () => {
    expect(chosenSubscription("4", "")).toEqual({ kind: "id", id: 4 });
  });

  it("refuses “by number” with nothing usable typed, rather than falling back to mine", () => {
    // The silent fallback is the defect this rules out: the operator asked for
    // another tenant, and a job created under themselves instead is a job in
    // the wrong crontab that the dialog reported as a success.
    for (const typed of ["", "   ", "abc", "12x", "-1", "1234567890123456789"]) {
      expect(chosenSubscription(SUBSCRIPTION_BY_ID, typed), typed).toEqual({ kind: "problem" });
    }
    expect(chosenSubscription(SUBSCRIPTION_BY_ID, " 12 ")).toEqual({ kind: "id", id: 12 });
  });
});

describe("naming a subscription in a picker", () => {
  const subscription = (live: string[], other: string[] = []) => ({
    id: 4,
    liveDomains: live,
    otherDomains: other,
  });

  it("leads with the domains that are actually serving", () => {
    const { shown, more } = subscriptionDomains(subscription(["b.example"], ["a.example"]));
    expect(shown).toEqual(["b.example", "a.example"]);
    expect(more).toBe(0);
  });

  it("cuts a long list short rather than pushing the id off the line", () => {
    const { shown, more } = subscriptionDomains(
      subscription(["a.example", "b.example", "c.example", "d.example", "e.example"]),
    );
    expect(shown).toEqual(["a.example", "b.example", "c.example"]);
    expect(more).toBe(2);
  });
});
