/**
 * Behaviour tests for what a task row says it did (spec §11.17).
 *
 * The row used to be the operation id and nothing else, so a page of installs
 * read `stack.install` six times over and the history could not answer the one
 * question it exists for: which install was that. The server now derives a
 * subject — the component, the domain — and the row shows it beside the op.
 *
 * The subject is derived on the server precisely so this file never has to
 * touch the task's `input`, which is stored exactly as the caller sent it,
 * passwords included.
 */

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { Task } from "@/lib/api";

import "../i18n";
import { TaskRow, taskSubject } from "./task-drawer";

function task(extra: Partial<Task> & Record<string, unknown> = {}): Task {
  return {
    id: "0d2b6f18-0b9a-4d6b-9b8e-3f0f1f7a1c22",
    op: "stack.install",
    status: "ok",
    progress: 100,
    error_code: null,
    error_detail: null,
    cancellable: false,
    created_at: "2026-09-06T10:00:00Z",
    started_at: null,
    finished_at: null,
    ...extra,
  } as Task;
}

/** The text a reader sees, with the tags taken out. */
function visibleText(row: Task): string {
  return renderToStaticMarkup(<TaskRow task={row} expanded={false} onToggle={() => {}} />)
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ");
}

describe("the subject on a task row", () => {
  it("shows what the task acted on, beside the operation that acted", () => {
    const text = visibleText(task({ subject: "php 8.3" }));
    expect(text).toContain("php 8.3");
    // The op stays: it is what the history's own filter offers and what a
    // support thread quotes.
    expect(text).toContain("stack.install");
  });

  it("tells two rows of the same operation apart", () => {
    expect(visibleText(task({ subject: "php 8.3" }))).toContain("php 8.3");
    expect(visibleText(task({ subject: "redis 7" }))).toContain("redis 7");
  });

  it("falls back to the operation alone when the server named nothing", () => {
    // An op whose input carries only row ids has no honest subject, and a
    // panel that invented one would be worse than one that shows the op.
    const text = visibleText(task({ op: "site.update" }));
    expect(text).toContain("site.update");
    expect(text).not.toContain("undefined");
    expect(text).not.toContain("null");
  });
});

describe("reading the subject off a row", () => {
  it("ignores a row that has no subject, which is every row from an older agent", () => {
    // The field is new. A tab left open across an upgrade, or a panel talking
    // to an agent that has not learned to send it, must render the old row
    // rather than the word "undefined".
    expect(taskSubject(task())).toBeNull();
    expect(taskSubject(task({ subject: null }))).toBeNull();
    expect(taskSubject(task({ subject: "" }))).toBeNull();
    expect(taskSubject(task({ subject: "   " }))).toBeNull();
    expect(taskSubject(task({ subject: 42 }))).toBeNull();
  });

  it("takes the subject when there is one", () => {
    expect(taskSubject(task({ subject: "shop.example.com" }))).toBe("shop.example.com");
    expect(taskSubject(task({ subject: "  php 8.3  " }))).toBe("php 8.3");
  });
});
