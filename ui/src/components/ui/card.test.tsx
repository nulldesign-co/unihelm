/**
 * Behaviour tests for the card's insets.
 *
 * Which side of the card a padding lands on is CSS and not testable here; what
 * is testable is the class list the component composes, and that is where the
 * bug was. `CardBody` carried `px-5 pb-5` and nothing on top, which is right
 * after a `CardHeader` and wrong as a card's first child — the seven headerless
 * cards in the panel each had their first element flush against the border.
 *
 * The second half of the file pins the hazard the fix introduces: `first:pt-5`
 * outranks a bare `pt-*` from a call site, so an override has to use the same
 * variant or it silently does nothing.
 */

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { CardBody } from "./card";

/** The classes React actually puts on the element, as tokens. */
function bodyClasses(className?: string): string[] {
  const markup = renderToStaticMarkup(<CardBody className={className} />);
  const match = /class="([^"]*)"/.exec(markup);
  return match?.[1] ? match[1].split(" ") : [];
}

describe("CardBody's top inset", () => {
  it("insets the top only when the body is the card's first child", () => {
    expect(bodyClasses()).toContain("first:pt-5");
    // Unconditional top padding is the other half of the bug: it would open a
    // gutter under every CardHeader, whose own pb-3 is already the gap.
    expect(bodyClasses()).not.toContain("pt-5");
  });

  it("keeps the side and bottom insets it always had", () => {
    expect(bodyClasses()).toEqual(expect.arrayContaining(["px-5", "pb-5"]));
  });

  it("lets a call site replace the first-child inset with the same variant", () => {
    const classes = bodyClasses("first:pt-3");
    expect(classes).toContain("first:pt-3");
    expect(classes).not.toContain("first:pt-5");
  });

  it("does not let a bare pt-* replace it, which is why overrides need the variant", () => {
    // tailwind-merge keys on the modifier, so `pt-3` and `first:pt-5` are
    // different utilities to it and both survive — and then `first:pt-5` wins
    // in the browser on specificity. A call site that means "less inset here"
    // must write `first:pt-3`, not `pt-3`.
    expect(bodyClasses("pt-3")).toEqual(expect.arrayContaining(["pt-3", "first:pt-5"]));
  });
});
