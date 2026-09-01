import { useEffect, useRef, useState, type CSSProperties } from "react";

/**
 * The panel's motion helpers.
 *
 * Everything here is hand-rolled on rAF and CSS custom properties on purpose:
 * the panel ships as one binary with no CDN to reach, and an animation library
 * would be the single largest thing in a 350 KB budget (spec §3) to buy motion
 * this small.
 */

/**
 * Does this reader want less motion?
 *
 * Live, not read-once: someone who turns the setting on mid-session should be
 * believed immediately rather than at the next reload.
 */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() =>
    typeof window === "undefined"
      ? false
      : window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  );

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const onChange = () => setReduced(media.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  return reduced;
}

/** How many items still earn a stagger delay before the cascade gets tedious. */
const STAGGER_CAP = 10;

/**
 * The `--i` for a staggered entrance, capped.
 *
 * Past the cap every remaining row shares the last delay, so a 500-row table
 * still lands in under half a second instead of drifting in for a minute.
 *
 * ```tsx
 * <tr className="animate-rise-in stagger" style={staggerStyle(index)}>
 * ```
 */
export function staggerStyle(index: number, cap: number = STAGGER_CAP): CSSProperties {
  return { "--i": Math.min(index, cap) } as CSSProperties;
}

const COUNT_DURATION_MS = 520;

/** The same deceleration as `--ease-out-quint`, evaluated per frame. */
function easeOutQuint(t: number): number {
  return 1 - (1 - t) ** 5;
}

/**
 * A number that travels to its new value instead of snapping to it.
 *
 * The dashboard re-polls every five seconds, so this runs on live data all day:
 * it animates from whatever is currently on screen (not from zero) on every
 * change, which is what makes a CPU graph read as movement rather than as a
 * series of unrelated numbers. Under reduced motion it is the identity function.
 */
export function useCountUp(value: number): number {
  const reduced = usePrefersReducedMotion();
  const [display, setDisplay] = useState(value);
  const fromRef = useRef(value);
  const frameRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (reduced || !Number.isFinite(value)) {
      fromRef.current = value;
      setDisplay(value);
      return;
    }

    const from = fromRef.current;
    if (from === value) return;

    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / COUNT_DURATION_MS);
      const next = from + (value - from) * easeOutQuint(t);
      fromRef.current = next;
      setDisplay(next);
      if (t < 1) frameRef.current = requestAnimationFrame(tick);
      else fromRef.current = value;
    };

    frameRef.current = requestAnimationFrame(tick);
    return () => {
      if (frameRef.current !== undefined) cancelAnimationFrame(frameRef.current);
    };
  }, [value, reduced]);

  return display;
}

/**
 * Has this component been on screen for a frame yet?
 *
 * For animations that must start from a resting state rather than replay on
 * every React render — a meter that fills from zero exactly once, for instance.
 */
export function useMounted(): boolean {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const frame = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(frame);
  }, []);
  return mounted;
}
