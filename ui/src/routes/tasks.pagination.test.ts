/**
 * How much of the history one page shows (spec §11.17).
 *
 * The size was a constant with no control on screen, so "show me more" had no
 * answer and the range label's arithmetic was right only because the constant
 * never moved. Both halves are pinned here: the label counts in whatever size
 * is in use, and changing the size cannot leave the reader on a page number
 * that was counted in the old one — page 4 of fifty is row 151, page 4 of a
 * hundred is row 301, and the difference is an empty page that reads as the
 * end of the history.
 */

import { describe, expect, it } from "vitest";

import { DEFAULT_PAGE_SIZE, PAGE_SIZES, firstPageOf, pageSizeFrom, pageWindow } from "./tasks";

describe("the rows-per-page choice", () => {
  it("keeps the size this page has always used as the default", () => {
    // Changing the default would silently change what every existing operator
    // sees on a page they have read a hundred times.
    expect(DEFAULT_PAGE_SIZE).toBe(50);
    expect(PAGE_SIZES).toContain(DEFAULT_PAGE_SIZE);
  });

  it("offers something smaller and something larger than the default", () => {
    expect(Math.min(...PAGE_SIZES)).toBeLessThan(DEFAULT_PAGE_SIZE);
    expect(Math.max(...PAGE_SIZES)).toBeGreaterThan(DEFAULT_PAGE_SIZE);
  });

  it("returns to the first page whenever the size changes", () => {
    expect(firstPageOf(100)).toEqual({ page: 0, size: 100 });
    expect(firstPageOf(25)).toEqual({ page: 0, size: 25 });
  });

  it("refuses a size it never offered rather than asking for NaN rows", () => {
    // The value arrives as a string off a DOM event. `limit=NaN` is a 400, and
    // a history that went blank on a 400 looks exactly like a history with
    // nothing in it.
    expect(pageSizeFrom("100")).toBe(100);
    expect(pageSizeFrom("")).toBe(DEFAULT_PAGE_SIZE);
    expect(pageSizeFrom("9999")).toBe(DEFAULT_PAGE_SIZE);
    expect(pageSizeFrom("fifty")).toBe(DEFAULT_PAGE_SIZE);
  });
});

describe("the showing-X-to-Y label", () => {
  it("counts in the size actually chosen", () => {
    // Against the old hard-coded fifty this third page of a hundred rows
    // called itself tasks 101–150: a position in the history that was not
    // where the reader was, and half the rows on screen unaccounted for.
    expect(pageWindow({ page: 2, size: 100 }, 100)).toEqual({ from: 201, to: 300 });
    expect(pageWindow({ page: 3, size: 25 }, 25)).toEqual({ from: 76, to: 100 });
    expect(pageWindow({ page: 0, size: 200 }, 200)).toEqual({ from: 1, to: 200 });
  });

  it("stops at the rows that actually came back", () => {
    // The last page is short. Counting to the full page size would name tasks
    // that are not on the screen.
    expect(pageWindow({ page: 1, size: 50 }, 7)).toEqual({ from: 51, to: 57 });
  });
});
