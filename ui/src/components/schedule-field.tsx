import { CalendarClock } from "lucide-react";
import { useCallback } from "react";
import { useTranslation } from "react-i18next";

import { Input } from "@/components/ui/input";
import { checkSchedule, formatSchedule, type Translate } from "@/lib/cron-schedule";
import { cn } from "@/lib/utils";

/**
 * A cron expression field that answers while you type (spec §11.8).
 *
 * Two jobs, and the second is the one that matters. The first is the red line:
 * the agent refuses a bad schedule, but learning that from a round trip after
 * pressing Save is learning it late. The second is the sentence underneath —
 * a valid cron expression can still be the wrong one, and `0 3 * * 0` looks
 * exactly as plausible as `0 3 * * *` right up until the backup runs weekly.
 * Reading it back in words is how someone catches that before it matters.
 *
 * Shared by the cron page and the backup schedule form, which take the same
 * five fields to the same parser in the agent.
 */

/** The schedules people actually write, offered as one click each. */
const PRESETS = ["*/15 * * * *", "0 * * * *", "0 3 * * *", "0 9-17 * * 1-5", "0 0 * * 0", "0 0 1 * *"];

/** Render a schedule as a sentence in the reader's language, or null. */
export function useScheduleText(): (schedule: string) => string | null {
  const { t, i18n } = useTranslation();
  const language = i18n.language;
  return useCallback(
    (schedule: string) => {
      const translate: Translate = (key, params) => t(key, params ?? {});
      return formatSchedule(schedule, translate, language);
    },
    [t, language],
  );
}

/**
 * Why a schedule is refused, in the reader's language, or null when it is fine.
 *
 * The field name is interpolated rather than baked into each message so
 * "minute" is one string translated once, not twelve.
 */
export function useScheduleProblem(): (schedule: string) => string | null {
  const { t } = useTranslation();
  return useCallback(
    (schedule: string) => {
      const check = checkSchedule(schedule);
      if (check.ok) return null;
      const { key, field, params } = check.problem;
      return t(`cron.problem.${key}`, {
        ...params,
        field: field ? t(`cron.field.${field}`) : "",
      });
    },
    [t],
  );
}

export function ScheduleField({
  id,
  label,
  value,
  onChange,
  /**
   * Whether to show the refusal at all. A caller passes `submitted || value
   * !== ""` so an untouched empty field is not red before anyone has typed —
   * but "enter a schedule" still appears the moment Save is pressed, which is
   * the one case a blanket empty-is-fine rule would silently swallow.
   */
  showProblem = true,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (next: string) => void;
  showProblem?: boolean;
}) {
  const { t } = useTranslation();
  const problemOf = useScheduleProblem();
  const textOf = useScheduleText();

  const problem = problemOf(value);
  const preview = problem ? null : textOf(value);

  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium text-ink">
        {label}
      </label>

      {/* A cron expression is machine text: LTR and monospaced whatever the
          page direction is, or the five fields stop lining up. */}
      <Input
        id={id}
        dir="ltr"
        className="font-mono"
        placeholder="*/15 * * * *"
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-invalid={Boolean(problem) && showProblem}
        aria-describedby={`${id}-verdict ${id}-legend`}
        onKeyDown={(event) => {
          // Enter inside a dialog form would submit; a schedule is fiddly
          // enough that a stray Enter should not save a half-typed one.
          if (event.key === "Enter") event.preventDefault();
        }}
      />

      <p id={`${id}-legend`} dir="ltr" className="font-mono text-[11px] text-ink-subtle">
        {t("cron.legend")}
      </p>

      {/* aria-live so the verdict is announced without moving focus. */}
      <p
        id={`${id}-verdict`}
        aria-live="polite"
        className={cn("flex min-h-8 items-start gap-1.5 text-xs", problem ? "text-danger" : "text-ink-muted")}
      >
        {problem ? (
          showProblem ? (
            <span>{problem}</span>
          ) : null
        ) : preview ? (
          <>
            <CalendarClock className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
            {/* `dir="auto"` because the sentence is Persian on a Persian page
                but carries Latin times and day numbers inside it. */}
            <span dir="auto">{t("cron.runs", { description: preview })}</span>
          </>
        ) : null}
      </p>

      <ul className="flex flex-wrap gap-1.5">
        {PRESETS.map((preset) => (
          <li key={preset}>
            <button
              type="button"
              dir="ltr"
              onClick={() => onChange(preset)}
              title={textOf(preset) ?? preset}
              className={cn(
                "rounded-full border border-border px-2.5 py-0.5 font-mono text-[11px] text-ink-muted",
                "hover:border-border-strong hover:text-ink",
                value.trim() === preset && "border-accent text-accent",
              )}
            >
              {preset}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The same sentence, read-only, for a row that shows a schedule it did not ask for. */
export function ScheduleText({ schedule, className }: { schedule: string; className?: string }) {
  const textOf = useScheduleText();
  const text = textOf(schedule);
  if (!text) return null;
  return (
    <span dir="auto" className={className}>
      {text}
    </span>
  );
}
