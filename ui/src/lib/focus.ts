import { useEffect, useRef, type RefObject } from "react";

/** Everything the browser will hand focus to, in DOM order. */
const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function focusable(container: HTMLElement): HTMLElement[] {
  return [...container.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
    // `offsetParent` is null for anything display:none — a dialog's hidden
    // branches should not swallow the first Tab.
    (element) => element.offsetParent !== null || element === document.activeElement,
  );
}

/**
 * Keep focus inside an overlay while it is open, and give it back afterwards.
 *
 * A layer that sets `aria-modal="true"` is telling assistive technology that
 * everything behind it does not exist. If focus is still back there, a screen
 * reader user tabs through what they have just been told is nothing — so the
 * attribute is not merely decoration, it is a promise this hook keeps.
 *
 * On close, focus returns to whatever opened the layer. Without that, closing a
 * dialog drops the caret on `<body>` and a keyboard user starts the page again
 * from the top.
 */
export function useFocusTrap(active: boolean, ref: RefObject<HTMLElement | null>) {
  const restoreRef = useRef<HTMLElement | null>(null);

  /**
   * Note the control that opened this layer — during render, deliberately.
   *
   * An effect is too late: React applies `autoFocus` while committing, so by
   * the time any effect runs, focus is already on a field inside the overlay
   * and the element worth returning to has been missed. Render happens before
   * the commit, so `document.activeElement` here is still the opener. Listening
   * for `focusin` instead would be no better — a window without system focus
   * does not dispatch those events at all, while `activeElement` stays correct.
   *
   * The read is pure and the write is idempotent, so this is safe to repeat.
   */
  if (active) {
    if (restoreRef.current === null) {
      const current = document.activeElement;
      restoreRef.current =
        current instanceof HTMLElement && current !== document.body ? current : null;
    }
  } else if (restoreRef.current !== null) {
    restoreRef.current = null;
  }

  useEffect(() => {
    if (!active) return;
    const container = ref.current;
    if (!container) return;
    const previous = restoreRef.current;

    // The container itself is the fallback, so an overlay with nothing
    // focusable in it still moves the caret off the page behind. An overlay
    // that has already focused something of its own — an `autoFocus` field —
    // keeps it.
    if (!container.contains(document.activeElement)) {
      (focusable(container)[0] ?? container).focus();
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const items = focusable(container);
      if (items.length === 0) {
        event.preventDefault();
        return;
      }
      const firstItem = items[0]!;
      const lastItem = items[items.length - 1]!;
      const current = document.activeElement;

      // Wrap at both ends rather than letting Tab walk out of the layer.
      if (!event.shiftKey && current === lastItem) {
        event.preventDefault();
        firstItem.focus();
      } else if (event.shiftKey && current === firstItem) {
        event.preventDefault();
        lastItem.focus();
      } else if (current instanceof Node && !container.contains(current)) {
        event.preventDefault();
        firstItem.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      if (!previous?.isConnected) return;
      // Only take focus back if the layer still had it; if something outside
      // deliberately claimed focus, leave it where it is.
      const activeNow = document.activeElement;
      const layerHadIt =
        activeNow === null ||
        activeNow === document.body ||
        (activeNow instanceof Node && container.contains(activeNow));
      if (layerHadIt) previous.focus();
    };
  }, [active, ref]);
}
