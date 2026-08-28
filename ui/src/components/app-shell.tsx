import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { Archive, BellRing, Boxes, Clock, Database, FolderOpen, Gauge, Globe, Languages, Layers, ListChecks, LogOut, Monitor, Moon, Network, ShieldCheck, Sun, TerminalSquare, Wallet } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { CommandPalette, type Command } from "@/components/command-palette";
import { TaskDrawer } from "@/components/task-drawer";
import { Button } from "@/components/ui/button";
import { applyLanguage, LANGUAGES } from "@/i18n";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

export function AppShell({ children }: { children: React.ReactNode }) {
  const { t, i18n } = useTranslation();
  const { user, signOut } = useSession();
  const { theme, setTheme } = useTheme();
  const [tasksOpen, setTasksOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const navigate = useNavigate();

  const commands = useMemo<Command[]>(
    () => [
      { id: "tasks", label: t("tasks.title"), hint: "T", run: () => setTasksOpen(true) },
      { id: "go-dashboard", label: t("nav.dashboard"), run: () => void navigate({ to: "/" }) },
      { id: "go-sites", label: t("nav.sites"), run: () => void navigate({ to: "/sites" }) },
      { id: "go-apps", label: t("nav.apps"), run: () => void navigate({ to: "/apps" }) },
      { id: "go-databases", label: t("nav.databases"), run: () => void navigate({ to: "/databases" }) },
      { id: "go-plans", label: t("nav.plans"), run: () => void navigate({ to: "/plans" }) },
      { id: "go-cron", label: t("nav.cron"), run: () => void navigate({ to: "/cron" }) },
      { id: "go-backups", label: t("nav.backups"), run: () => void navigate({ to: "/backups" }) },
      { id: "go-dns", label: t("nav.dns"), run: () => void navigate({ to: "/dns" }) },
      { id: "go-stack", label: t("nav.stack"), run: () => void navigate({ to: "/stack" }) },
      { id: "go-files", label: t("nav.files"), run: () => void navigate({ to: "/files" }) },
      { id: "go-firewall", label: t("nav.firewall"), run: () => void navigate({ to: "/firewall" }) },
      { id: "go-alerts", label: t("nav.alerts"), run: () => void navigate({ to: "/alerts" }) },
      { id: "go-tasks", label: t("nav.tasks"), run: () => void navigate({ to: "/tasks" }) },
      { id: "go-terminal", label: t("nav.terminal"), run: () => void navigate({ to: "/terminal" }) },
      { id: "theme-light", label: `${t("nav.theme")}: ${t("nav.themeLight")}`, run: () => setTheme("light") },
      { id: "theme-dark", label: `${t("nav.theme")}: ${t("nav.themeDark")}`, run: () => setTheme("dark") },
      { id: "theme-system", label: `${t("nav.theme")}: ${t("nav.themeSystem")}`, run: () => setTheme("system") },
      ...LANGUAGES.map((language) => ({
        id: `lang-${language.code}`,
        label: `${t("nav.language")}: ${language.label}`,
        run: () => applyLanguage(language.code),
      })),
      { id: "sign-out", label: t("common.signOut"), run: () => void signOut() },
    ],
    [t, setTheme, signOut, navigate],
  );

  const nav = [
    { to: "/", label: t("nav.dashboard"), icon: Gauge },
    { to: "/sites", label: t("nav.sites"), icon: Globe },
    { to: "/apps", label: t("nav.apps"), icon: Boxes },
    { to: "/databases", label: t("nav.databases"), icon: Database },
    { to: "/files", label: t("nav.files"), icon: FolderOpen },
    { to: "/plans", label: t("nav.plans"), icon: Wallet },
    { to: "/cron", label: t("nav.cron"), icon: Clock },
    { to: "/backups", label: t("nav.backups"), icon: Archive },
    { to: "/dns", label: t("nav.dns"), icon: Network },
    { to: "/firewall", label: t("nav.firewall"), icon: ShieldCheck },
    { to: "/alerts", label: t("nav.alerts"), icon: BellRing },
    { to: "/tasks", label: t("nav.tasks"), icon: ListChecks },
    { to: "/terminal", label: t("nav.terminal"), icon: TerminalSquare },
    { to: "/stack", label: t("nav.stack"), icon: Layers },
  ];

  return (
    <div className="min-h-dvh bg-canvas">
      <header className="sticky top-0 z-30 border-b border-border bg-surface/85 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-4 px-4 sm:px-6">
          <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight text-ink">
            <span
              className="grid h-6 w-6 place-items-center rounded-md bg-accent text-[11px] font-bold text-on-accent"
              aria-hidden
            >
              F
            </span>
            {t("common.appName")}
          </Link>

          {/* Scrolls rather than pushing the page wide: the panel has grown
              past what fits on a phone, and a body that scrolls sideways is
              worse than a nav bar that does. The negative margin plus matching
              padding lets the first and last items sit flush while their focus
              rings still have room. */}
          <nav
            className="-mx-1 flex min-w-0 items-center gap-1 overflow-x-auto px-1"
            aria-label={t("nav.dashboard")}
          >
            {nav.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "shrink-0 rounded-lg px-3 py-1.5 text-sm transition-colors",
                  pathname === item.to
                    ? "bg-surface-muted font-medium text-ink"
                    : "text-ink-muted hover:bg-surface-muted hover:text-ink",
                )}
              >
                {item.label}
              </Link>
            ))}
          </nav>

          <div className="ms-auto flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setPaletteOpen(true)}
              className="hidden gap-2 sm:inline-flex"
              aria-keyshortcuts="Meta+K Control+K"
            >
              {t("common.search")}
              <kbd className="rounded border border-border px-1 font-mono text-[10px] text-ink-subtle">⌘K</kbd>
            </Button>

            <Button
              variant="ghost"
              size="icon"
              onClick={() => setTasksOpen(true)}
              aria-label={t("tasks.title")}
            >
              <ListChecks className="h-4 w-4" />
            </Button>

            <ThemeToggle theme={theme} setTheme={setTheme} />

            <Button
              variant="ghost"
              size="icon"
              aria-label={t("nav.language")}
              onClick={() => {
                const next = i18n.language === "fa" ? "en" : "fa";
                applyLanguage(next);
              }}
            >
              <Languages className="h-4 w-4" />
            </Button>

            <Button
              variant="ghost"
              size="icon"
              onClick={() => void signOut()}
              aria-label={t("common.signOut")}
              title={user?.username}
            >
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6">{children}</main>

      <TaskDrawer open={tasksOpen} onClose={() => setTasksOpen(false)} />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} commands={commands} />
    </div>
  );
}

function ThemeToggle({
  theme,
  setTheme,
}: {
  theme: "light" | "dark" | "system";
  setTheme: (theme: "light" | "dark" | "system") => void;
}) {
  const { t } = useTranslation();
  const next = theme === "light" ? "dark" : theme === "dark" ? "system" : "light";
  const Icon = theme === "light" ? Sun : theme === "dark" ? Moon : Monitor;
  const label =
    theme === "light" ? t("nav.themeLight") : theme === "dark" ? t("nav.themeDark") : t("nav.themeSystem");

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setTheme(next)}
      aria-label={`${t("nav.theme")}: ${label}`}
      title={`${t("nav.theme")}: ${label}`}
    >
      <Icon className="h-4 w-4" />
    </Button>
  );
}
