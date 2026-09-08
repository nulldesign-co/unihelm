/**
 * Behaviour tests for the WordPress page's client-side reasoning (spec §11.12).
 *
 * The agent is the security boundary — it re-parses every one of these values
 * and its copy is the one that decides. What is pinned here is the other half:
 * that the page's copy of those rules does not *disagree* with the server's, and
 * that the three places this page could quietly lie do not.
 *
 * The three:
 *
 * 1. A 202 is a receipt, not an outcome. `queuedTaskId` is what keeps
 *    "installed" from being printed over a download that has not started.
 * 2. A plugin the panel could not read must not disappear from the table.
 *    A plugin nobody can see is a plugin nobody updates.
 * 3. A backup of the panel is not a backup of a tenant's site. Counting one
 *    before replacing a live site's core files is the worst answer this page
 *    could give.
 */

import { describe, expect, it } from "vitest";

import type { BackupRun } from "@/lib/api";
import {
  adminUserProblem,
  cliArgProblem,
  cliProblem,
  coreVersionProblem,
  emailProblem,
  hasUpdate,
  lastFileBackup,
  localeProblem,
  queuedTaskId,
  readPluginList,
  splitCliArgs,
  subdirectoryProblem,
  titleProblem,
} from "@/lib/wordpress-api";

import { servesPhp } from "./wordpress";

/**
 * `ops::invoke` answers 202 with a task id or 200 with the operation's own
 * data, and the client cannot know which in advance. Reading the receipt as the
 * outcome is the specific failure this page exists to avoid.
 */
describe("telling a queued task from a finished one", () => {
  it("finds the task id in a 202 receipt", () => {
    expect(queuedTaskId({ task_id: "9f1c", task_url: "/api/tasks/9f1c" })).toBe("9f1c");
  });

  it("reports no task for an operation that finished inside the request", () => {
    // `wp.install`'s own output. Nothing here is a task id, and inventing one
    // would put a log panel on the page polling a task that does not exist.
    expect(
      queuedTaskId({
        install_id: 7,
        site_id: 3,
        path: "/home/tenant/public_html",
        version: "6.8.2",
      }),
    ).toBeNull();
  });

  it("is not fooled by a body with no task id, or no body at all", () => {
    expect(queuedTaskId(null)).toBeNull();
    expect(queuedTaskId(undefined)).toBeNull();
    expect(queuedTaskId("9f1c")).toBeNull();
    // An empty string is not a task id, and `/api/tasks/` is not a task.
    expect(queuedTaskId({ task_id: "" })).toBeNull();
    expect(queuedTaskId({ task_id: 12 })).toBeNull();
  });
});

/**
 * `wp.plugin.list` passes WP-CLI's JSON through unmodelled, deliberately, so
 * this page has to read whatever WordPress decides to send. The failure worth
 * pinning is the quiet one: a row this build cannot parse must be *counted*,
 * never dropped, and an answer that is not a list at all must not render as an
 * empty table saying the site has no plugins.
 */
describe("reading WP-CLI's plugin list", () => {
  it("reads the ordinary shape WP-CLI sends", () => {
    const reading = readPluginList([
      { name: "akismet", status: "inactive", version: "5.3", update: "none" },
      {
        name: "woocommerce",
        status: "active",
        version: "9.4.1",
        update: "available",
        update_version: "9.5.0",
      },
    ]);
    expect(reading.kind).toBe("plugins");
    if (reading.kind !== "plugins") return;
    expect(reading.unreadable).toBe(0);
    expect(reading.plugins.map((p) => p.name)).toEqual(["akismet", "woocommerce"]);
    expect(reading.plugins[1]?.update_version).toBe("9.5.0");
    // Absent optional fields are absent, not guessed at.
    expect(reading.plugins[0]?.update_version).toBeNull();
  });

  it("refuses to call an answer that is not a list an empty plugin list", () => {
    // A site with no plugins and a site whose WP-CLI answered with something
    // else are different facts, and only one of them is "no plugins".
    for (const notAList of [{}, "", null, 3, { plugins: [] }]) {
      expect(readPluginList(notAList).kind, JSON.stringify(notAList)).toBe("unreadable");
    }
  });

  it("counts the rows it could not read instead of dropping them", () => {
    const reading = readPluginList([
      { name: "akismet", status: "active" },
      // No name: it cannot be shown and cannot be handed to wp.plugin.update
      // as a slug, so it is counted rather than silently skipped.
      { status: "active", version: "1.0" },
      null,
      "woocommerce",
      { name: "", status: "active" },
    ]);
    expect(reading.kind).toBe("plugins");
    if (reading.kind !== "plugins") return;
    expect(reading.plugins).toHaveLength(1);
    expect(reading.unreadable).toBe(4);
  });

  it("reads an empty list as a site with no plugins", () => {
    const reading = readPluginList([]);
    expect(reading.kind).toBe("plugins");
    if (reading.kind !== "plugins") return;
    expect(reading.plugins).toHaveLength(0);
    expect(reading.unreadable).toBe(0);
  });

  it("offers an update button only for WP-CLI's own word for one", () => {
    const plugin = (update: string | null) => ({
      name: "x",
      status: "active",
      version: "1.0",
      update,
      update_version: null,
    });
    expect(hasUpdate(plugin("available"))).toBe(true);
    // `version higher than expected` is a plugin *ahead* of its directory
    // listing; offering "Update" there would install an older release over a
    // newer one.
    for (const quiet of ["none", "unavailable", "version higher than expected", "", null]) {
      expect(hasUpdate(plugin(quiet)), String(quiet)).toBe(false);
    }
  });
});

/**
 * The backup line printed above a button that replaces a live site's files.
 *
 * A panel-scope run holds `panel.db`, `/etc/unihelm` and the panel's state
 * directory. It contains nothing of a tenant home, so counting one as "you have
 * a backup" would be a lie told at the exact moment it costs the most.
 */
describe("finding a backup that actually covers a site's files", () => {
  const run = (over: Partial<BackupRun>): BackupRun =>
    ({
      id: 1,
      schedule_id: null,
      repo_id: 1,
      scope: "subscription",
      subscription_id: 4,
      started_at: "2026-09-01T00:00:00Z",
      finished_at: "2026-09-01T00:10:00Z",
      status: "ok",
      snapshot_id: "abc",
      bytes: 100,
      error: null,
      ...over,
    }) as BackupRun;

  it("finds the newest successful run for this subscription", () => {
    const found = lastFileBackup(
      [
        run({ id: 1, finished_at: "2026-09-01T00:10:00Z" }),
        run({ id: 2, finished_at: "2026-09-07T03:00:00Z" }),
      ],
      4,
    );
    expect(found?.id).toBe(2);
  });

  it("does not depend on the order the server happened to return", () => {
    const found = lastFileBackup(
      [
        run({ id: 2, finished_at: "2026-09-07T03:00:00Z" }),
        run({ id: 1, finished_at: "2026-09-01T00:10:00Z" }),
      ],
      4,
    );
    expect(found?.id).toBe(2);
  });

  it("never counts a panel-scope run, which holds no tenant files at all", () => {
    expect(
      lastFileBackup([run({ scope: "panel", subscription_id: null })], 4),
    ).toBeNull();
  });

  it("never counts another subscription's backup", () => {
    expect(lastFileBackup([run({ subscription_id: 9 })], 4)).toBeNull();
  });

  it("never counts a run that failed or is still going", () => {
    expect(lastFileBackup([run({ status: "failed" })], 4)).toBeNull();
    expect(lastFileBackup([run({ status: "running", finished_at: null })], 4)).toBeNull();
  });

  it("answers null for an empty history rather than inventing one", () => {
    expect(lastFileBackup([], 4)).toBeNull();
  });
});

/**
 * The claim `wp.cli` has to earn, mirrored on this side of the wire.
 *
 * The agent refuses all of this again — twice, in fact, since the
 * privilege-dropping helper re-checks the reserved flags where the privilege
 * actually changes. What the mirror buys is a message under the field instead
 * of a round trip, and it is only worth having if it agrees with the server:
 * an argument the agent would refuse must not sail through the form, and an
 * ordinary argument must not be blocked by a rule the server never made.
 */
describe("the WP-CLI argument check", () => {
  it("refuses the two flags that are `run any PHP` spelled as options", () => {
    expect(cliArgProblem("--require=/tmp/pwn.php")).toBe("reservedFlag");
    expect(cliArgProblem("--exec=system('id');")).not.toBeNull();
  });

  it("refuses the flags the panel decides on the caller's behalf", () => {
    for (const reserved of [
      "--path=/etc",
      "--ssh=root@elsewhere",
      "--http=http://example.com",
      "--prompt",
      "--context=admin",
    ]) {
      expect(cliArgProblem(reserved), reserved).toBe("reservedFlag");
    }
  });

  it("refuses the negated and mis-cased spellings, or the list is decoration", () => {
    // `--no-path` strips to the same flag; `--PATH` is not a well-formed
    // WP-CLI flag at all, which is the agent's own reason for refusing it.
    expect(cliArgProblem("--no-path=/etc")).toBe("reservedFlag");
    expect(cliArgProblem("--PATH=/etc")).toBe("malformedFlag");
    expect(cliArgProblem("--")).toBe("malformedFlag");
    expect(cliArgProblem("--=x")).toBe("malformedFlag");
  });

  it("refuses shell metacharacters, which WP-CLI's own `wp db` would re-expose", () => {
    // Inert through argv — but WP-CLI builds its own mysql and mysqldump
    // command lines for parts of `wp db`, and the panel's argv discipline does
    // not reach into another program's spawning.
    for (const hostile of [
      "blogname; rm -rf /",
      "$(id)",
      "`id`",
      "a|b",
      "a&b",
      "a>b",
      "a<b",
      "a*b",
      "a?b",
      "a!b",
      "a\\b",
      'a"b',
      "a'b",
      "a{b}",
      "a[b]",
      "a(b)",
    ]) {
      expect(cliArgProblem(hostile), hostile).toBe("metacharacter");
    }
  });

  it("refuses control characters and anything outside ASCII", () => {
    // In the agent's own order, which is what makes this the message the
    // server would have given: ASCII first, then control characters, then
    // metacharacters. A tab is both of the last two and is named a control
    // character, because that is the check `validate_arg` reaches first.
    expect(cliArgProblem("a\u00e9b")).toBe("nonAscii");
    expect(cliArgProblem("a\u0000b")).toBe("control");
    expect(cliArgProblem("ab")).toBe("control");
    // A site title may be Persian; an administrative WP-CLI argument may not,
    // which removes a whole class of homoglyph questions from the boundary.
    expect(cliArgProblem("وبلاگ")).toBe("nonAscii");
  });

  it("refuses an empty argument and a short flag, which WP-CLI does not have", () => {
    expect(cliArgProblem("")).toBe("empty");
    expect(cliArgProblem("-")).toBe("shortFlag");
    expect(cliArgProblem("-x")).toBe("shortFlag");
  });

  it("refuses an argument past the agent's own byte limit", () => {
    expect(cliArgProblem("a".repeat(512))).toBeNull();
    expect(cliArgProblem("a".repeat(513))).toBe("tooLong");
  });

  it("accepts the ordinary shapes, including one that legitimately holds a space", () => {
    // The positive half of the claim. A space is not a metacharacter precisely
    // because argv makes word splitting impossible: this stays one argument.
    for (const fine of [
      "version",
      "get",
      "blogname",
      "--format=json",
      "--skip-plugins",
      "--no-color",
      "--title=My Blog",
      "update",
      "user_2",
    ]) {
      expect(cliArgProblem(fine), fine).toBeNull();
    }
  });
});

describe("the whole WP-CLI request", () => {
  it("refuses the interactive second-level command that would hang until timeout", () => {
    // `wp db cli` opens an interactive mysql session. With no terminal it
    // blocks until the 25-second ceiling kills it, which looks like the panel
    // hanging rather than like a command that cannot work here.
    expect(cliProblem("db", ["cli"])).toEqual({ kind: "interactive" });
    // Only as the second-level command: `wp option get cli` is an ordinary
    // read of an option that happens to be called cli.
    expect(cliProblem("option", ["get", "cli"])).toBeNull();
    expect(cliProblem("db", ["export", "cli"])).toBeNull();
  });

  it("refuses more arguments than the agent will take", () => {
    expect(cliProblem("core", Array.from({ length: 32 }, () => "a"))).toBeNull();
    expect(cliProblem("core", Array.from({ length: 33 }, () => "a"))).toEqual({ kind: "tooMany" });
  });

  it("names which argument is the problem, so the message can point at a line", () => {
    expect(cliProblem("option", ["get", "--exec=x"])).toEqual({
      kind: "arg",
      index: 1,
      problem: "reservedFlag",
    });
  });
});

describe("splitting typed arguments", () => {
  it("never splits one argument on its spaces", () => {
    // `--title=My Blog` is one argv element. Splitting on whitespace would
    // make it two, and the operator would be debugging our parser.
    expect(splitCliArgs("update\n--title=My Blog")).toEqual(["update", "--title=My Blog"]);
  });

  it("drops blank lines and trims the rest", () => {
    expect(splitCliArgs("  version  \n\n\n  --format=json\n")).toEqual([
      "version",
      "--format=json",
    ]);
  });

  it("reads an empty box as no arguments at all", () => {
    expect(splitCliArgs("")).toEqual([]);
    expect(splitCliArgs("   \n  ")).toEqual([]);
  });
});

/**
 * The install form's fields, each mirroring the newtype the agent parses them
 * into. The interesting half is where the rules differ from one another: a
 * title is prose and may be Persian, a login name is an identifier and may not.
 */
describe("the site title check", () => {
  it("accepts prose, including a title that is not English", () => {
    // The panel's interface is English; a site's own title is its owner's
    // business, and the operation takes it as one argv element.
    expect(titleProblem("My Blog")).toBeNull();
    expect(titleProblem("وبلاگ من")).toBeNull();
    expect(titleProblem("Café Ünïcode")).toBeNull();
  });

  it("refuses what would end a line or a shell word", () => {
    expect(titleProblem("My; rm -rf / Blog")).toBe("metacharacter");
    expect(titleProblem("Two $(id) words")).toBe("metacharacter");
    // A newline is both a control character and a metacharacter, and
    // `validate_title` reaches the control check first. Following its order
    // keeps the two messages from swapping places against the server's.
    expect(titleProblem("My\nBlog")).toBe("control");
  });

  it("requires a title and caps it where the agent caps it", () => {
    expect(titleProblem("")).toBe("required");
    expect(titleProblem("   ")).toBe("required");
    expect(titleProblem("a".repeat(200))).toBeNull();
    expect(titleProblem("a".repeat(201))).toBe("tooLong");
    // Characters, not bytes: the agent counts `chars().count()`, so a 200-
    // character Persian title fits where a byte count would refuse it.
    expect(titleProblem("ب".repeat(200))).toBeNull();
  });
});

describe("the administrator login check", () => {
  it("accepts the shapes Username::parse accepts", () => {
    for (const fine of ["siteadmin", "site.admin", "site_admin", "site-admin", "a1b", "  Admin  "]) {
      expect(adminUserProblem(fine), fine).toBeNull();
    }
  });

  it("applies the same length and first-character rules the agent does", () => {
    expect(adminUserProblem("ab")).toBe("length");
    expect(adminUserProblem("a".repeat(33))).toBe("length");
    expect(adminUserProblem("_admin")).toBe("start");
    expect(adminUserProblem(".admin")).toBe("start");
    expect(adminUserProblem("-admin")).toBe("start");
  });

  it("refuses characters that would not survive the newtype", () => {
    expect(adminUserProblem("site admin")).toBe("charset");
    expect(adminUserProblem("site@admin")).toBe("charset");
    // `Username::parse` tests the first *byte*, so a non-ASCII name is refused
    // for not starting with a letter or digit rather than for its alphabet.
    // The mirror says the same thing, or the field would contradict the agent.
    expect(adminUserProblem("مدیر")).toBe("start");
    expect(adminUserProblem("")).toBe("required");
  });
});

describe("the administrator email check", () => {
  it("accepts an ordinary address", () => {
    expect(emailProblem("admin@example.com")).toBeNull();
    expect(emailProblem("  Admin@Example.COM ")).toBeNull();
    expect(emailProblem("first.last+tag@mail.example.co.uk")).toBeNull();
  });

  it("refuses the shapes the agent refuses", () => {
    expect(emailProblem("")).toBe("required");
    expect(emailProblem("not-an-email")).toBe("shape");
    expect(emailProblem("@example.com")).toBe("shape");
    expect(emailProblem("admin@localhost")).toBe("shape");
    // Refused rather than escaped, because these are header separators.
    expect(emailProblem("admin@example.com, root@example.com")).toBe("charset");
    expect(emailProblem("admin@example.com\nBcc: x@y.z")).toBe("charset");
  });
});

describe("the subdirectory check", () => {
  it("treats an empty value as the document root, which is the default", () => {
    expect(subdirectoryProblem("")).toBeNull();
    expect(subdirectoryProblem("   ")).toBeNull();
  });

  it("refuses the traversal payloads that never become a TenantPath", () => {
    expect(subdirectoryProblem("../../etc")).toBe("traversal");
    expect(subdirectoryProblem("blog/../../etc")).toBe("traversal");
    expect(subdirectoryProblem("/etc/passwd")).toBe("absolute");
    expect(subdirectoryProblem("blog\u0000/x")).toBe("control");
    expect(subdirectoryProblem("blog\\x")).toBe("backslash");
    expect(subdirectoryProblem("blog//x")).toBe("emptyComponent");
    expect(subdirectoryProblem(`blog/${"a".repeat(256)}`)).toBe("tooLong");
  });

  it("accepts the ordinary folder names people actually use", () => {
    for (const fine of ["blog", "shop/store", "wp", "sub.dir", "a-b_c"]) {
      expect(subdirectoryProblem(fine), fine).toBeNull();
    }
  });
});

describe("the WordPress locale check", () => {
  it("treats an empty value as unchosen, so the key is omitted and en_US applies", () => {
    expect(localeProblem("")).toBeNull();
    expect(localeProblem("  ")).toBeNull();
  });

  it("accepts the locales WpLocale accepts", () => {
    for (const fine of ["en_US", "de_DE", "fa_IR", "pt", "nl_NL"]) {
      expect(localeProblem(fine), fine).toBeNull();
    }
  });

  it("refuses anything that is not a locale", () => {
    for (const bad of ["e", "en_US_extra", "en-US", "en US", "a".repeat(9)]) {
      expect(localeProblem(bad), bad).toBe("shape");
    }
  });
});

describe("the core version check", () => {
  it("treats an empty value as the latest release, which is what the agent does", () => {
    expect(coreVersionProblem("")).toBeNull();
  });

  it("accepts a WordPress version", () => {
    expect(coreVersionProblem("6.8.2")).toBeNull();
    expect(coreVersionProblem("6.8")).toBeNull();
    expect(coreVersionProblem("6.8.2-beta1".replace("beta1", "1"))).toBeNull();
  });

  it("refuses anything that is not one, including the word people expect to work", () => {
    // `latest` is not a version to `wp core update --version=`, and the agent
    // refuses it; the message under the field is cheaper than a failed task.
    expect(coreVersionProblem("latest")).toBe("shape");
    expect(coreVersionProblem("6.8.2; id")).toBe("shape");
    expect(coreVersionProblem("--exec=x")).toBe("shape");
  });
});

/**
 * Which sites are offered an install.
 *
 * `wp.install` does not look at the site type and would lay WordPress down in a
 * static site's root, where nginx hands `index.php` to the browser as a
 * download rather than running it. A site's type cannot be changed from the
 * panel, so this is a refusal with a reason rather than a control.
 */
describe("which sites can serve a WordPress", () => {
  const site = (site_type: string) => ({ site_type }) as never;

  it("offers an install on a PHP site", () => {
    expect(servesPhp(site("php"))).toBe(true);
  });

  it("offers none where the document root would never run PHP", () => {
    for (const kind of ["static", "proxy", "redirect"]) {
      expect(servesPhp(site(kind)), kind).toBe(false);
    }
  });
});
