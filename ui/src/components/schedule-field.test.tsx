/**
 * Behaviour tests for the schedule field's preset chips (spec §11.8).
 *
 * The chips are the part of the dialog a non-technical operator actually uses,
 * and they used to be labelled with the cron expression itself — the readable
 * sentence existed, but only in a `title`, which is a hover on a desktop and
 * nothing at all on a phone. Somebody choosing "every 15 minutes" was reading
 * punctuation and guessing. What is pinned here is that the sentence is the
 * label and the expression is the small print, not the other way round.
 */

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import "../i18n";
import { ScheduleField } from "./schedule-field";

/** The chips as rendered, with the real English bundle behind them. */
function markup(value = "0 3 * * *"): string {
  return renderToStaticMarkup(
    <ScheduleField id="test-schedule" label="Schedule" value={value} onChange={() => {}} />,
  );
}

/** The text a reader sees, with the tags taken out. */
function visibleText(html: string): string {
  return html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
}

describe("the preset chips", () => {
  it("labels each preset with the sentence, not the expression", () => {
    const text = visibleText(markup());
    // The three shapes the six presets cover: a step, a time of day, and a
    // day of the week. Each has to be readable without knowing cron.
    expect(text).toContain("every 15 minutes");
    expect(text).toContain("at 03:00 every day");
    expect(text).toContain("on Sunday");
  });

  it("keeps the expression visible, because somebody who reads cron wants it", () => {
    // The fix is not "hide the expression": it is which one is the label. The
    // five fields still have to be checkable at a glance before a chip writes
    // them into the input above.
    const text = visibleText(markup());
    expect(text).toContain("0 3 * * *");
    expect(text).toContain("0 9-17 * * 1-5");
  });

  it("does not leave the sentence behind a hover", () => {
    // A `title` was the whole defect: the readable version existed and nobody
    // ever saw it. Nothing in this field should depend on hovering now.
    expect(markup()).not.toContain("title=");
  });

  it("marks the chip matching the current value as the one that is set", () => {
    expect(markup("0 3 * * *")).toContain('aria-pressed="true"');
    // A schedule none of the presets covers leaves every chip unpressed rather
    // than claiming one of them describes it.
    expect(markup("7 4 * * 2")).not.toContain('aria-pressed="true"');
  });
});
