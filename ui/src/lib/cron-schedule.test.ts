/**
 * Behaviour tests for the client-side cron grammar (spec §11.8).
 *
 * The agent is the authority — `unihelm_ops::cron::validate_schedule` re-parses
 * everything this file accepts, and `render_crontab` validates a third time on
 * the way out. What is pinned here is that the two copies do not *disagree*:
 * a schedule the agent refuses must not sail through the form and come back as
 * a 400, and an ordinary schedule must not be blocked by a rule the agent never
 * had. Every case below is lifted from a rule the Rust states out loud.
 */

import { describe, expect, it } from "vitest";

import { en } from "../i18n/en";
import {
  PHRASE_KEYS,
  PROBLEM_KEYS,
  checkCommand,
  checkSchedule,
  describeSchedule,
  formatSchedule,
} from "./cron-schedule";

function problem(schedule: string) {
  const check = checkSchedule(schedule);
  expect(check.ok, `expected ${schedule} to be refused`).toBe(false);
  return check.ok ? null : check.problem;
}

describe("the schedule check", () => {
  it("accepts the shapes the grammar documents", () => {
    for (const fine of [
      "* * * * *",
      "*/15 * * * *",
      "0 3 * * *",
      "30 2 * * 0",
      "0 0 1 1 *",
      "0,30 * * * *",
      "0 9-17 * * 1-5",
      "0 0-23/2 * * *",
      "59 23 31 12 7",
    ]) {
      expect(checkSchedule(fine).ok, fine).toBe(true);
    }
  });

  it("refuses the @-aliases, which would run before the tenant's limits exist", () => {
    // `@reboot` runs when cron starts at boot — before the agent has applied
    // the tenant's slice and disk quota. Every alias is refused with it so
    // there is one rule rather than a special case.
    for (const alias of ["@reboot", "@daily", "@hourly", "@midnight", "@yearly"]) {
      expect(problem(alias)?.key, alias).toBe("alias");
    }
  });

  it("counts the fields, because four fields is a job that never runs", () => {
    expect(problem("0 3 * *")?.key).toBe("fieldCount");
    expect(problem("0 3 * *")?.params?.count).toBe(4);
    expect(problem("0 3 * * * *")?.params?.count).toBe(6);
  });

  it("holds every field to its own range", () => {
    expect(problem("60 * * * *")?.field).toBe("minute");
    expect(problem("* 24 * * *")?.field).toBe("hour");
    expect(problem("* * 32 * *")?.field).toBe("dayOfMonth");
    expect(problem("* * * 13 *")?.field).toBe("month");
    expect(problem("* * * * 8")?.field).toBe("dayOfWeek");
    // Day-of-month starts at 1, not 0 — a zeroth day does not exist.
    expect(problem("* * 0 * *")?.key).toBe("outOfRange");
  });

  it("accepts 7 as the second spelling of Sunday, which cron does", () => {
    expect(checkSchedule("0 0 * * 7").ok).toBe(true);
  });

  it("refuses what parse_number refuses, not what parseInt accepts", () => {
    // `parseInt` is happy with every one of these and cron is happy with none.
    for (const hostile of ["+5 * * * *", "005 * * * *", "5.0 * * * *", "٥ * * * *"]) {
      expect(problem(hostile)?.key, hostile).toBe("notANumber");
    }
  });

  it("refuses a step on a bare number, which the two crons spell differently", () => {
    const refused = problem("5/10 * * * *");
    expect(refused?.key).toBe("stepNeedsRange");
    // The message has to be able to suggest the two spellings that do work.
    expect(refused?.params).toMatchObject({ step: "10", value: 5, max: 59 });
    expect(checkSchedule("5-59/10 * * * *").ok).toBe(true);
    expect(checkSchedule("*/10 * * * *").ok).toBe(true);
  });

  it("refuses a step that selects nothing or walks past its own range", () => {
    expect(problem("*/0 * * * *")?.key).toBe("stepZero");
    expect(problem("*/611 * * * *")?.key).toBe("notAStep"); // over two digits
    // A step exactly as wide as its range still selects the first value.
    expect(checkSchedule("*/60 * * * 1").ok).toBe(true);
    expect(problem("0-4/9 * * * *")?.key).toBe("stepTooWide");
  });

  it("refuses a range that runs backwards", () => {
    const refused = problem("0 17-9 * * *");
    expect(refused?.key).toBe("backwards");
    expect(refused?.params).toMatchObject({ from: 17, to: 9 });
  });

  it("refuses every empty list entry, which cron's parsers disagree about", () => {
    for (const hostile of ["1,,2 * * * *", ",1 * * * *", "1, * * * *"]) {
      expect(problem(hostile)?.key, hostile).toBe("emptyItem");
    }
  });

  it("canonicalises the spacing so two spellings are not two jobs", () => {
    const check = checkSchedule("  0\t3   *  * * ");
    expect(check.ok && check.canonical).toBe("0 3 * * *");
  });

  it("refuses an empty schedule and a schedule longer than the agent stores", () => {
    expect(problem("")?.key).toBe("required");
    expect(problem("   ")?.key).toBe("required");
    expect(problem(`${"1,".repeat(200)}1 * * * *`)?.key).toBe("tooLong");
  });
});

describe("the command check", () => {
  it("refuses a newline, which would smuggle a second job into the crontab", () => {
    // The security-relevant one: a crontab line ends at the newline, so this
    // would be a second job on a schedule nobody approved.
    expect(checkCommand("backup.sh\n* * * * * /tmp/backdoor")?.key).toBe("newline");
    expect(checkCommand("backup.sh\r\n/tmp/backdoor")?.key).toBe("newline");
  });

  it("refuses a NUL and the other control characters", () => {
    expect(checkCommand("backup.sh\u0000rm -rf /")?.key).toBe("nul");
    expect(checkCommand("backup.sh\u0007")?.key).toBe("control");
    expect(checkCommand("backup.sh\u001b[31m")?.key).toBe("control");
  });

  it("refuses a trailing backslash, which cron and the shell disagree about", () => {
    expect(checkCommand("/usr/bin/php cron.php \\")?.key).toBe("trailingBackslash");
  });

  it("accepts an ordinary command, percent signs included", () => {
    // `%` is escaped by the renderer rather than refused: `date +%F` is a
    // perfectly normal thing to schedule, and refusing it would be a rule the
    // agent never had.
    expect(checkCommand("/usr/bin/php /home/uh_ab12cd34/cron.php")).toBeNull();
    expect(checkCommand("/usr/bin/date +%F >> log.txt")).toBeNull();
    expect(checkCommand("  spaced.sh  ")).toBeNull();
  });

  it("requires a command and caps it where the agent caps it", () => {
    expect(checkCommand("")?.key).toBe("required");
    expect(checkCommand("x".repeat(1024))).toBeNull();
    expect(checkCommand("x".repeat(1025))?.key).toBe("tooLong");
  });
});

describe("the plain-language preview", () => {
  it("reads the everyday schedules the way a person would say them", () => {
    expect(describeSchedule("* * * * *")).toEqual({
      time: { key: "everyMinute" },
      days: { key: "everyDay" },
    });
    expect(describeSchedule("*/15 * * * *")).toEqual({
      time: { key: "everyNMinutes", count: 15 },
      days: { key: "everyDay" },
    });
    expect(describeSchedule("30 3 * * *")).toEqual({
      time: { key: "atTimes", times: ["03:30"] },
      days: { key: "everyDay" },
    });
    expect(describeSchedule("0 * * * *")).toEqual({
      time: { key: "hourlyAt", minutes: [0] },
      days: { key: "everyDay" },
    });
    expect(describeSchedule("0 9-17 * * 1-5")).toEqual({
      time: { key: "hourlyDuring", minutes: [0], from: 9, to: 17 },
      days: { key: "weekdayRange", from: 1, to: 5 },
    });
    expect(describeSchedule("0 0,12 * * *")).toEqual({
      time: { key: "atTimes", times: ["00:00", "12:00"] },
      days: { key: "everyDay" },
    });
  });

  it("keeps an hour range as a range instead of reciting every hour in it", () => {
    expect(describeSchedule("* 9-17 * * *")?.time).toEqual({
      key: "everyMinuteDuring",
      from: 9,
      to: 17,
    });
    expect(describeSchedule("0 */6 * * *")?.time).toEqual({
      key: "everyNHoursAt",
      count: 6,
      minutes: [0],
    });
  });

  it("says `or` when both day fields are set, because that is what cron does", () => {
    // The classic trap: `0 0 1 * 1` runs on the 1st **and** on every Monday,
    // not on Mondays that fall on the 1st. A preview that said "on the 1st, on
    // Monday" would be describing a schedule cron does not have.
    expect(describeSchedule("0 0 1 * 1")?.days).toEqual({
      key: "onDaysOrWeekdays",
      days: [1],
      weekdays: [1],
    });
  });

  it("folds 7 back onto Sunday so `0,7` is one day and not two", () => {
    expect(describeSchedule("0 0 * * 0,7")?.days).toEqual({ key: "onWeekdays", weekdays: [0] });
  });

  it("treats */1 as every unit rather than as a step of one", () => {
    expect(describeSchedule("*/1 */1 * * *")?.time).toEqual({ key: "everyMinute" });
  });

  it("mentions the months only when the schedule is limited to some", () => {
    expect(describeSchedule("0 0 1 * *")?.months).toBeUndefined();
    expect(describeSchedule("0 0 1 1,7 *")?.months).toEqual({ key: "inMonths", months: [1, 7] });
  });

  it("falls back to the raw field rather than reciting fifty values", () => {
    // A "preview" listing every odd minute is not a preview. Showing the field
    // itself at least does not pretend to be readable.
    expect(describeSchedule("1-59/2 * * * *")?.time).toEqual({
      key: "rawTime",
      minute: "1-59/2",
      hour: "*",
    });
  });

  it("has nothing to say about a schedule that is not valid", () => {
    expect(describeSchedule("0 3 * *")).toBeNull();
    expect(describeSchedule("@daily")).toBeNull();
  });
});

describe("the preview's translations", () => {
  /** A `t` that reports the key it was asked for, so word order is visible. */
  const echo = (key: string) => key.split(".").pop() ?? key;

  it("renders through the combine strings rather than a hard-coded order", () => {
    // English leads with the time, Persian with the day. That decision lives in
    // the `combine` string, which is why this asserts a rendering rather than a
    // concatenation.
    expect(formatSchedule("30 3 * * *", echo, "en")).toBe("combine");
    expect(formatSchedule("0 0 1 1 *", echo, "en")).toBe("combineMonths");
    expect(formatSchedule("nonsense", echo, "en")).toBeNull();
  });

  it("has a string for every phrase it can emit", () => {
    // The failure this prevents is the ordinary one: a new phrase key added to
    // the describer with no string written for it, shipping as a raw key.
    for (const key of PHRASE_KEYS) {
      expect(en.cron.preview, `en: ${key}`).toHaveProperty(key);
    }
    for (const key of PROBLEM_KEYS) {
      expect(en.cron.problem, `en: ${key}`).toHaveProperty(key);
    }
    for (const day of [0, 1, 2, 3, 4, 5, 6]) {
      expect(en.cron.weekday, `en weekday ${day}`).toHaveProperty(String(day));
    }
    for (let month = 1; month <= 12; month += 1) {
      expect(en.cron.month, `en month ${month}`).toHaveProperty(String(month));
    }
  });
});
