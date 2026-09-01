import { AlertTriangle, CheckCircle2, Info, XCircle } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

type Tone = "info" | "success" | "warning" | "danger";

const TONE: Record<Tone, { box: string; icon: string; Icon: typeof Info }> = {
  info: { box: "border-accent/25 bg-accent-soft/60", icon: "text-accent", Icon: Info },
  success: { box: "border-success/25 bg-success-soft/60", icon: "text-success", Icon: CheckCircle2 },
  warning: { box: "border-warning/30 bg-warning-soft/70", icon: "text-warning", Icon: AlertTriangle },
  danger: { box: "border-danger/30 bg-danger-soft/70", icon: "text-danger", Icon: XCircle },
};

/**
 * A standing message about the state of something.
 *
 * There were four of these in the panel before it existed — the dashboard's
 * offline-agent notice, the firewall's, the mail page's and the stack page's —
 * each with its own border opacity and padding. One component so a warning
 * looks like a warning wherever the operator meets it.
 *
 * `role="alert"` only when the message is a problem: an alert interrupts a
 * screen reader mid-sentence, which is right for "the agent is offline" and
 * rude for "here is how this page works".
 */
export function Callout({
  tone = "info",
  title,
  children,
  action,
  className,
}: {
  tone?: Tone;
  title?: ReactNode;
  children?: ReactNode;
  /** A button or link that resolves the thing being reported. */
  action?: ReactNode;
  className?: string;
}) {
  const { box, icon, Icon } = TONE[tone];
  const urgent = tone === "warning" || tone === "danger";

  return (
    <div
      role={urgent ? "alert" : undefined}
      className={cn(
        "flex animate-rise-in flex-wrap items-start gap-x-3 gap-y-2 rounded-card border px-4 py-3",
        box,
        className,
      )}
    >
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", icon)} aria-hidden />
      <div className="min-w-0 flex-1">
        {title ? <p className="text-sm font-medium text-ink">{title}</p> : null}
        {children ? (
          <div className={cn("text-sm text-ink-muted", title && "mt-0.5")}>{children}</div>
        ) : null}
      </div>
      {action ? <div className="flex shrink-0 items-center gap-2">{action}</div> : null}
    </div>
  );
}
