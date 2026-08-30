/**
 * The five-field cron grammar, mirrored from the agent (spec §11.8).
 *
 * The server is the authority and stays it: `unihelm_ops::cron::validate_schedule`
 * re-parses every schedule and refuses anything this file waved through. What
 * this copy buys is the round trip — a cron expression is the one setting in the
 * panel that people routinely get *silently* wrong, and "0 3 * *" (four fields,
 * runs never) should be a red line under the field rather than a saved job that
 * quietly does nothing.
 *
 * The rules are kept in lock-step with the Rust deliberately: the same field
 * ranges (day-of-week runs to 7 because cron accepts 7 as a second spelling of
 * Sunday), the same refusal of `@`-aliases, the same "a step needs a range to
 * walk" rule, and the same one-or-two-ASCII-digits number parser — `+5`, `٥`
 * and `005` are numbers to `parseInt` and are not numbers to cron.
 * `cron-schedule.test.ts` pins each of those against the shapes the agent
 * refuses, so a drift between the two copies fails a test rather than a user.
 *
 * Nothing here is a security boundary. The agent re-validates on the way in and
 * `render_crontab` validates again on the way out, so a schedule this file
 * mis-parses becomes an error, never a crontab line.
 */

/** The agent's own bound, so a megabyte of commas never becomes parser work. */
export const MAX_SCHEDULE_CHARS = 256;

/** `unihelm_ops::cron::MAX_COMMAND_CHARS` — beyond it a cron daemon may truncate. */
export const MAX_COMMAND_CHARS = 1024;

/** Which field a problem is about; the UI translates it for the message. */
export type FieldName = "minute" | "hour" | "dayOfMonth" | "month" | "dayOfWeek";

interface FieldSpec {
  name: FieldName;
  min: number;
  max: number;
}

/** Minute, hour, day-of-month, month, day-of-week — in crontab order. */
const FIELDS: readonly FieldSpec[] = [
  { name: "minute", min: 0, max: 59 },
  { name: "hour", min: 0, max: 23 },
  { name: "dayOfMonth", min: 1, max: 31 },
  { name: "month", min: 1, max: 12 },
  { name: "dayOfWeek", min: 0, max: 7 },
];

/** One comma-separated entry of one field. */
export type Item =
  | { kind: "all"; step?: number }
  | { kind: "range"; from: number; to: number; step?: number }
  | { kind: "value"; value: number };

/**
 * Why a schedule was refused: an i18n key plus what to interpolate.
 *
 * A key rather than a sentence so the message is Persian on a Persian page. The
 * agent's own refusal is English prose; when it disagrees with this file the
 * agent's text is what the user sees, because the agent is the one that decides.
 */
export interface ScheduleProblem {
  key: string;
  field?: FieldName;
  params?: Record<string, string | number>;
}

export type ScheduleCheck =
  | { ok: true; canonical: string; fields: Item[][] }
  | { ok: false; problem: ScheduleProblem };

/**
 * One or two ASCII digits and nothing else.
 *
 * Hand-rolled for the same reason the Rust is: `Number("+5")`, `Number(" 5")`
 * and `Number("٥")` all produce 5, and cron accepts none of them.
 */
function parseNumber(text: string): number | null {
  if (text.length === 0 || text.length > 2 || !/^[0-9]+$/.test(text)) return null;
  return Number(text);
}

function parseValue(text: string, spec: FieldSpec): number | ScheduleProblem {
  const value = parseNumber(text);
  if (value === null) {
    return { key: "notANumber", field: spec.name, params: { text } };
  }
  if (value < spec.min || value > spec.max) {
    return {
      key: "outOfRange",
      field: spec.name,
      params: { value, min: spec.min, max: spec.max },
    };
  }
  return value;
}

function parseItem(text: string, spec: FieldSpec): { item: Item } | { problem: ScheduleProblem } {
  const bad = (key: string, params?: Record<string, string | number>) => ({
    problem: { key, field: spec.name, params },
  });

  // What `1,,2`, `,1` and `1,` all produce. Cron's own parsers disagree about
  // each of the three, so one rule refuses all three.
  if (text === "") return bad("emptyItem");

  const slash = text.indexOf("/");
  const base = slash === -1 ? text : text.slice(0, slash);
  const stepText = slash === -1 ? null : text.slice(slash + 1);

  // `null` for `*`, otherwise the range the base selects (a bare number is the
  // one-wide range `n-n`, which is what makes the width arithmetic uniform).
  let range: { from: number; to: number; explicit: boolean } | null = null;

  if (base !== "*") {
    const dash = base.indexOf("-");
    if (dash === -1) {
      const value = parseValue(base, spec);
      if (typeof value !== "number") return { problem: value };
      range = { from: value, to: value, explicit: false };
    } else {
      const lo = parseValue(base.slice(0, dash), spec);
      if (typeof lo !== "number") return { problem: lo };
      const hi = parseValue(base.slice(dash + 1), spec);
      if (typeof hi !== "number") return { problem: hi };
      range = { from: lo, to: hi, explicit: true };
    }
    if (range.from > range.to) return bad("backwards", { from: range.from, to: range.to });
    // A step on a bare number is Vixie's `n-max/step`. It is a coin flip whether
    // the author meant that or `*/step`, and cron's two families have spelled it
    // differently, so it is refused rather than guessed at.
    if (stepText !== null && !range.explicit) {
      return bad("stepNeedsRange", { step: stepText, value: range.from, max: spec.max });
    }
  }

  let step: number | undefined;
  if (stepText !== null) {
    const width = range === null ? spec.max - spec.min + 1 : range.to - range.from + 1;
    const parsed = parseNumber(stepText);
    if (parsed === null) return bad("notAStep", { text: stepText });
    if (parsed === 0) return bad("stepZero");
    if (parsed > width) return bad("stepTooWide", { step: parsed, width });
    step = parsed;
  }

  if (range === null) return { item: step === undefined ? { kind: "all" } : { kind: "all", step } };
  if (!range.explicit) return { item: { kind: "value", value: range.from } };
  return {
    item:
      step === undefined
        ? { kind: "range", from: range.from, to: range.to }
        : { kind: "range", from: range.from, to: range.to, step },
  };
}

function parseField(
  text: string,
  spec: FieldSpec,
): { items: Item[] } | { problem: ScheduleProblem } {
  const items: Item[] = [];
  for (const entry of text.split(",")) {
    const parsed = parseItem(entry, spec);
    if ("problem" in parsed) return parsed;
    items.push(parsed.item);
  }
  return { items };
}

/**
 * Validate a schedule and return its canonical spelling and parsed fields.
 *
 * Canonical means the five fields separated by exactly one space, which is what
 * the agent stores — so `"0  3 * * *"` previews identically to `"0 3 * * *"`
 * rather than looking like a different job.
 */
export function checkSchedule(raw: string): ScheduleCheck {
  const trimmed = raw.trim();
  if (trimmed === "") return { ok: false, problem: { key: "required" } };
  if ([...trimmed].length > MAX_SCHEDULE_CHARS) {
    return { ok: false, problem: { key: "tooLong", params: { max: MAX_SCHEDULE_CHARS } } };
  }
  // One check covers `@reboot`, `@daily` and whatever alias a particular cron
  // has added. `@reboot` is the one that matters: it runs at boot, before the
  // agent has re-applied the tenant's slice and disk quota.
  if (trimmed.startsWith("@")) return { ok: false, problem: { key: "alias" } };

  const parts = trimmed.split(/\s+/);
  if (parts.length !== 5) {
    return { ok: false, problem: { key: "fieldCount", params: { count: parts.length } } };
  }

  const fields: Item[][] = [];
  for (let index = 0; index < FIELDS.length; index += 1) {
    const parsed = parseField(parts[index]!, FIELDS[index]!);
    if ("problem" in parsed) return { ok: false, problem: parsed.problem };
    fields.push(parsed.items);
  }
  return { ok: true, canonical: parts.join(" "), fields };
}

/** Why a command was refused. Same shape, same reason, as `ScheduleProblem`. */
export interface CommandProblem {
  key: string;
  params?: Record<string, string | number>;
}

/**
 * Validate a command the way the agent does.
 *
 * The command is not parsed — it is a shell command line, which is exactly what
 * a crontab command field is. What is checked is anything that changes the
 * meaning of the crontab *file*: a newline is a second job on a schedule nobody
 * approved, a NUL truncates the line at whatever reads it first, and a trailing
 * backslash is a typo far more often than it is a plan.
 */
export function checkCommand(raw: string): CommandProblem | null {
  const command = raw.trim();
  if (command === "") return { key: "required" };
  if ([...command].length > MAX_COMMAND_CHARS) {
    return { key: "tooLong", params: { max: MAX_COMMAND_CHARS } };
  }
  for (const ch of command) {
    const code = ch.codePointAt(0)!;
    // The Unicode control classes, which is what Rust's `char::is_control` is.
    if (code > 0x1f && code !== 0x7f && !(code >= 0x80 && code <= 0x9f)) continue;
    if (ch === "\n" || ch === "\r") return { key: "newline" };
    if (ch === "\0") return { key: "nul" };
    return { key: "control" };
  }
  if (command.endsWith("\\")) return { key: "trailingBackslash" };
  return null;
}

// ---------------------------------------------------------------------------
// Plain-English (and plain-Persian) preview
// ---------------------------------------------------------------------------

/**
 * The preview is returned as *structure*, not prose: a key and its numbers.
 *
 * Prose is built by the caller through `formatSchedule`, which puts the pieces
 * in the order the language wants — English leads with the time ("at 03:30
 * every day") and Persian leads with the day ("هر روز ساعت ۰۳:۳۰"). A function
 * that returned a sentence would have to pick one of those orders and be wrong
 * in the other, and the structure is what the tests can assert without prose.
 */
export type TimePhrase =
  | { key: "everyMinute" }
  | { key: "everyNMinutes"; count: number }
  | { key: "hourlyAt"; minutes: number[] }
  | { key: "everyNHoursAt"; count: number; minutes: number[] }
  | { key: "atTimes"; times: string[] }
  | { key: "everyMinuteOfHours"; hours: number[] }
  | { key: "everyMinuteDuring"; from: number; to: number }
  | { key: "hourlyDuring"; minutes: number[]; from: number; to: number }
  | { key: "rawTime"; minute: string; hour: string };

export type DayPhrase =
  | { key: "everyDay" }
  | { key: "onWeekdays"; weekdays: number[] }
  | { key: "weekdayRange"; from: number; to: number }
  | { key: "onDaysOfMonth"; days: number[] }
  | { key: "onDaysOrWeekdays"; days: number[]; weekdays: number[] }
  | { key: "rawDays"; dayOfMonth: string; dayOfWeek: string };

export type MonthPhrase = { key: "inMonths"; months: number[] } | { key: "rawMonths"; month: string };

export interface SchedulePhrases {
  time: TimePhrase;
  days: DayPhrase;
  /** Absent when the schedule runs in every month, which is the usual case. */
  months?: MonthPhrase;
}

/** Every phrase key this module can emit; the i18n test walks it. */
export const PHRASE_KEYS = [
  "everyMinute",
  "everyNMinutes",
  "hourlyAt",
  "everyNHoursAt",
  "atTimes",
  "everyMinuteOfHours",
  "everyMinuteDuring",
  "hourlyDuring",
  "rawTime",
  "everyDay",
  "onWeekdays",
  "weekdayRange",
  "onDaysOfMonth",
  "onDaysOrWeekdays",
  "rawDays",
  "inMonths",
  "rawMonths",
] as const;

/** Every refusal key `checkSchedule` and `checkCommand` can emit. */
export const PROBLEM_KEYS = [
  "required",
  "tooLong",
  "alias",
  "fieldCount",
  "emptyItem",
  "notANumber",
  "outOfRange",
  "backwards",
  "stepNeedsRange",
  "notAStep",
  "stepZero",
  "stepTooWide",
  "newline",
  "nul",
  "control",
  "trailingBackslash",
] as const;

function isEvery(field: Item[]): boolean {
  if (field.length !== 1) return false;
  const item = field[0]!;
  return item.kind === "all" && item.step === undefined;
}

/** The step of a whole-field star (`star slash n`), or null for anything else. */
function everyStep(field: Item[]): number | null {
  if (field.length !== 1) return null;
  const item = field[0]!;
  return item.kind === "all" && item.step !== undefined ? item.step : null;
}

/**
 * The concrete values a field selects, or null when there are too many to read
 * as a list. A preview that says "on day 1, 3, 5, 7, 9, 11, …" is not a
 * preview; past the limit the raw field is shown instead, which at least does
 * not pretend.
 */
function expand(field: Item[], limit: number): number[] | null {
  const values = new Set<number>();
  for (const item of field) {
    if (item.kind === "all") return null;
    if (item.kind === "value") {
      values.add(item.value);
    } else {
      for (let value = item.from; value <= item.to; value += item.step ?? 1) {
        values.add(value);
        if (values.size > limit) return null;
      }
    }
    if (values.size > limit) return null;
  }
  if (values.size === 0) return null;
  return [...values].sort((a, b) => a - b);
}

/** A field that is exactly one plain `a-b`, which reads better as "a to b". */
function soleRange(field: Item[]): { from: number; to: number } | null {
  if (field.length !== 1) return null;
  const item = field[0]!;
  return item.kind === "range" && item.step === undefined
    ? { from: item.from, to: item.to }
    : null;
}

const pad = (value: number) => String(value).padStart(2, "0");

function describeTime(minute: Item[], hour: Item[], rawMinute: string, rawHour: string): TimePhrase {
  // `*/1` is every unit; treating it as a step would render "every 1 minutes".
  const minuteEvery = isEvery(minute) || everyStep(minute) === 1;
  const hourEvery = isEvery(hour) || everyStep(hour) === 1;
  const minuteStep = everyStep(minute);
  const hourStep = everyStep(hour);
  const minutes = expand(minute, 6);
  const hours = expand(hour, 6);
  // `9-17` is the business-hours schedule everybody writes, and nine hour
  // numbers in a row is not something anybody reads. Kept as a range.
  const hourRange = soleRange(hour);

  if (minuteEvery && hourEvery) return { key: "everyMinute" };
  if (!minuteEvery && minuteStep !== null && hourEvery) {
    return { key: "everyNMinutes", count: minuteStep };
  }
  if (minuteEvery && hourRange) {
    return { key: "everyMinuteDuring", from: hourRange.from, to: hourRange.to };
  }
  if (minuteEvery && hours) return { key: "everyMinuteOfHours", hours };
  if (minutes && hourEvery) return { key: "hourlyAt", minutes };
  if (minutes && !hourEvery && hourStep !== null) {
    return { key: "everyNHoursAt", count: hourStep, minutes };
  }
  if (minutes && hourRange) {
    return { key: "hourlyDuring", minutes, from: hourRange.from, to: hourRange.to };
  }
  if (minutes && hours && minutes.length * hours.length <= 6) {
    const times: string[] = [];
    for (const h of hours) for (const m of minutes) times.push(`${pad(h)}:${pad(m)}`);
    times.sort();
    return { key: "atTimes", times };
  }
  return { key: "rawTime", minute: rawMinute, hour: rawHour };
}

/** 7 is cron's second spelling of Sunday, so `0,7` is one day and not two. */
const normaliseWeekdays = (days: number[] | null) =>
  days === null ? null : [...new Set(days.map((day) => day % 7))].sort((a, b) => a - b);

function describeDays(
  dayOfMonth: Item[],
  dayOfWeek: Item[],
  rawDayOfMonth: string,
  rawDayOfWeek: string,
): DayPhrase {
  const domEvery = isEvery(dayOfMonth) || everyStep(dayOfMonth) === 1;
  const dowEvery = isEvery(dayOfWeek) || everyStep(dayOfWeek) === 1;
  if (domEvery && dowEvery) return { key: "everyDay" };

  const weekdays = normaliseWeekdays(expand(dayOfWeek, 7));
  const days = expand(dayOfMonth, 6);

  if (domEvery) {
    const range = soleRange(dayOfWeek);
    if (range) return { key: "weekdayRange", from: range.from, to: range.to };
    if (weekdays) return { key: "onWeekdays", weekdays };
  } else if (dowEvery) {
    if (days) return { key: "onDaysOfMonth", days };
  } else if (days && weekdays) {
    // Both restricted is cron's notorious OR: the job runs when *either*
    // matches, so `0 0 1 * 1` is the 1st **and** every Monday. Saying "or"
    // out loud here is the whole reason this case is not folded into the
    // others.
    return { key: "onDaysOrWeekdays", days, weekdays };
  }
  return { key: "rawDays", dayOfMonth: rawDayOfMonth, dayOfWeek: rawDayOfWeek };
}

function describeMonths(month: Item[], rawMonth: string): MonthPhrase | undefined {
  if (isEvery(month) || everyStep(month) === 1) return undefined;
  const months = expand(month, 6);
  return months ? { key: "inMonths", months } : { key: "rawMonths", month: rawMonth };
}

/** The structured preview for a schedule, or null when it is not valid. */
export function describeSchedule(schedule: string): SchedulePhrases | null {
  const check = checkSchedule(schedule);
  if (!check.ok) return null;
  const raw = check.canonical.split(" ");
  const phrases: SchedulePhrases = {
    time: describeTime(check.fields[0]!, check.fields[1]!, raw[0]!, raw[1]!),
    days: describeDays(check.fields[2]!, check.fields[4]!, raw[2]!, raw[4]!),
  };
  const months = describeMonths(check.fields[3]!, raw[3]!);
  if (months) phrases.months = months;
  return phrases;
}

/** The narrow slice of i18next's `t` this module needs. */
export type Translate = (key: string, params?: Record<string, unknown>) => string;

/** Join a list the way the reader's language joins lists. */
function joinList(parts: string[], locale: string): string {
  try {
    return new Intl.ListFormat(locale, { style: "long", type: "conjunction" }).format(parts);
  } catch {
    // Older engines, or a locale Intl does not know. A comma is not elegant but
    // it is never wrong.
    return parts.join(", ");
  }
}

/**
 * Render a schedule as a sentence, or null when it is not a valid schedule.
 *
 * The word order lives in the `combine` strings rather than here, so Persian can
 * lead with the day and English with the time without this function knowing
 * which language it is in.
 */
export function formatSchedule(schedule: string, t: Translate, locale: string): string | null {
  const phrases = describeSchedule(schedule);
  if (!phrases) return null;

  const list = (parts: string[]) => joinList(parts, locale);
  const numbers = (values: number[]) => list(values.map(String));
  const weekdayNames = (values: number[]) => list(values.map((d) => t(`cron.weekday.${d % 7}`)));
  const monthNames = (values: number[]) => list(values.map((m) => t(`cron.month.${m}`)));
  const phrase = (key: string, params?: Record<string, unknown>) =>
    t(`cron.preview.${key}`, params);

  const time = ((p: TimePhrase): string => {
    switch (p.key) {
      case "everyMinute":
        return phrase(p.key);
      case "everyNMinutes":
        return phrase(p.key, { count: p.count });
      case "hourlyAt":
        return phrase(p.key, { count: p.minutes.length, minutes: numbers(p.minutes) });
      case "everyNHoursAt":
        return phrase(p.key, {
          count: p.count,
          minutes: numbers(p.minutes),
        });
      case "atTimes":
        return phrase(p.key, { count: p.times.length, times: list(p.times) });
      case "everyMinuteOfHours":
        return phrase(p.key, { count: p.hours.length, hours: numbers(p.hours) });
      case "everyMinuteDuring":
        return phrase(p.key, { from: pad(p.from), to: pad(p.to) });
      case "hourlyDuring":
        return phrase(p.key, {
          count: p.minutes.length,
          minutes: numbers(p.minutes),
          from: pad(p.from),
          to: pad(p.to),
        });
      case "rawTime":
        return phrase(p.key, { minute: p.minute, hour: p.hour });
    }
  })(phrases.time);

  const days = ((p: DayPhrase): string => {
    switch (p.key) {
      case "everyDay":
        return phrase(p.key);
      case "onWeekdays":
        return phrase(p.key, { count: p.weekdays.length, days: weekdayNames(p.weekdays) });
      case "weekdayRange":
        return phrase(p.key, {
          from: t(`cron.weekday.${p.from % 7}`),
          to: t(`cron.weekday.${p.to % 7}`),
        });
      case "onDaysOfMonth":
        return phrase(p.key, { count: p.days.length, days: numbers(p.days) });
      case "onDaysOrWeekdays":
        return phrase(p.key, {
          days: numbers(p.days),
          weekdays: weekdayNames(p.weekdays),
        });
      case "rawDays":
        return phrase(p.key, { dayOfMonth: p.dayOfMonth, dayOfWeek: p.dayOfWeek });
    }
  })(phrases.days);

  if (!phrases.months) return phrase("combine", { time, days });

  const months =
    phrases.months.key === "inMonths"
      ? phrase("inMonths", {
          count: phrases.months.months.length,
          months: monthNames(phrases.months.months),
        })
      : phrase("rawMonths", { month: phrases.months.month });

  return phrase("combineMonths", { time, days, months });
}
