import { ChevronRight, Home } from "lucide-react";
import { Fragment } from "react";
import { useTranslation } from "react-i18next";

import { cn } from "@/lib/utils";

/**
 * The path bar. Every ancestor is a button, because "go up two levels" is the
 * single most common navigation in a file manager.
 *
 * The list is forced LTR even on a Farsi page: a Unix path is Latin text with
 * a direction of its own, and mirroring the segments would reverse their
 * meaning (`a/b/c` must never read as `c/b/a`).
 */
export function Breadcrumbs({
  path,
  onNavigate,
}: {
  path: string;
  onNavigate: (path: string) => void;
}) {
  const { t } = useTranslation();
  const segments = path === "" ? [] : path.split("/");

  return (
    <nav aria-label={t("files.title")} dir="ltr" className="min-w-0">
      <ol className="flex flex-wrap items-center gap-0.5 text-sm">
        <li>
          <button
            type="button"
            onClick={() => onNavigate("")}
            className={cn(
              "flex items-center gap-1.5 rounded-lg px-2 py-1 transition-colors",
              segments.length === 0
                ? "font-medium text-ink"
                : "text-ink-muted hover:bg-surface-muted hover:text-ink",
            )}
            aria-current={segments.length === 0 ? "page" : undefined}
          >
            <Home className="h-3.5 w-3.5" aria-hidden />
            {t("files.home")}
          </button>
        </li>
        {segments.map((segment, index) => {
          const target = segments.slice(0, index + 1).join("/");
          const isLast = index === segments.length - 1;
          return (
            <Fragment key={target}>
              <li aria-hidden>
                <ChevronRight className="h-3.5 w-3.5 text-ink-subtle" />
              </li>
              <li className="min-w-0">
                <button
                  type="button"
                  onClick={() => onNavigate(target)}
                  className={cn(
                    "max-w-48 truncate rounded-lg px-2 py-1 font-mono text-[13px] transition-colors",
                    isLast
                      ? "font-medium text-ink"
                      : "text-ink-muted hover:bg-surface-muted hover:text-ink",
                  )}
                  aria-current={isLast ? "page" : undefined}
                >
                  {segment}
                </button>
              </li>
            </Fragment>
          );
        })}
      </ol>
    </nav>
  );
}
