/**
 * Behaviour tests for the select, and for the decision behind it.
 *
 * The reported defect was that the open menu is the platform's own rather than
 * the panel's. The decision recorded in `select.tsx` is to keep it native — a
 * hand-built listbox is a large amount of code that usually ends up worse for a
 * keyboard or screen-reader user — and to fix the one part of a native popup
 * CSS can genuinely reach: the option rows, whose background never inherited
 * the control's `bg-surface` and so fell back to the engine's own dark grey.
 *
 * Both halves are pinned here. The first half is the part that would have
 * failed before the fix; the second is the part a future "let's just use a
 * custom dropdown" would trip over on its way in.
 */

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Select } from "./select";

function markup(className?: string): string {
  return renderToStaticMarkup(
    <Select className={className} defaultValue="8.3">
      <option value="8.3">PHP 8.3</option>
      <option value="8.4">PHP 8.4</option>
    </Select>,
  );
}

/**
 * The classes React puts on the `<select>` itself, as tokens.
 *
 * `&` comes back HTML-escaped from the static renderer, so the arbitrary
 * variants read as `[&amp;_option]:...` — decoded here rather than asserted in
 * that form, which would pin an encoding rather than a class.
 */
function selectClasses(className?: string): string[] {
  const match = /<select[^>]*class="([^"]*)"/.exec(markup(className));
  return match?.[1] ? match[1].replaceAll("&amp;", "&").split(" ") : [];
}

describe("the native popup's option rows", () => {
  it("paints them from the panel's own surface and ink", () => {
    // `background-color` is not inherited, so `bg-surface` on the control never
    // reached the rows: the popup was the engine's dark grey beside a panel
    // that is not that colour. Chromium and Firefox honour an option's own
    // background; macOS draws the menu itself and ignores this without harm.
    expect(selectClasses()).toEqual(
      expect.arrayContaining(["[&_option]:bg-surface", "[&_option]:text-ink"]),
    );
  });

  it("keeps the control on the same two tokens, so the list and the field match", () => {
    expect(selectClasses()).toEqual(expect.arrayContaining(["bg-surface", "text-ink"]));
  });

  it("does not restate color-scheme, which index.css already sets and inherits", () => {
    // `html` / `html.dark` carry it and it is an inherited property. A second
    // declaration here would be a second place to keep in step with the theme
    // toggle, for no behaviour that is not already there.
    expect(selectClasses().join(" ")).not.toMatch(/scheme/);
  });
});

describe("the control itself", () => {
  it("is a real <select> with real <option>s", () => {
    // The accessibility argument for keeping it native is only true while it is
    // native. A custom listbox rewrite has to delete this line, which is the
    // point: `role="combobox"` on a div owes type-ahead, Home/End, PageUp/Down,
    // a portal and roving focus before it is equivalent, and a dropdown a
    // keyboard user cannot operate is a worse defect than one that looks like
    // the OS.
    const html = markup();
    expect(html).toContain("<select");
    expect(html).toContain('<option value="8.3"');
    expect(html).toContain("PHP 8.3</option>");
    expect(html).not.toContain('role="listbox"');
  });

  it("hides its own chevron from assistive technology", () => {
    // The native control already announces itself as a combo box; a second
    // "image" in the accessibility tree is noise read out on every field.
    expect(markup()).toContain('aria-hidden="true"');
  });

  it("lets a call site override the option colours with the same variant", () => {
    const classes = selectClasses("[&_option]:bg-surface-muted");
    expect(classes).toContain("[&_option]:bg-surface-muted");
    expect(classes).not.toContain("[&_option]:bg-surface");
  });
});
