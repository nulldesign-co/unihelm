import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Archive,
  BellRing,
  Boxes,
  Clock,
  Database,
  FolderOpen,
  Gauge,
  Globe,
  Layers,
  ListChecks,
  LogOut,
  Mail,
  Menu as MenuIcon,
  Monitor,
  Moon,
  Network,
  Palette,
  Search,
  ShieldCheck,
  Sun,
  TerminalSquare,
  Wallet,
  X,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { CommandPalette, type Command } from "@/components/command-palette";
import { TaskDrawer } from "@/components/task-drawer";
import { Button } from "@/components/ui/button";
import { assetUrl, useApplyBranding, useBranding, type PublicBranding } from "@/lib/branding";
import { useSession } from "@/lib/session";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

interface NavGroup {
  label: string | null;
  items: NavItem[];
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const { user, signOut } = useSession();
  const { theme, setTheme } = useTheme();
  const [tasksOpen, setTasksOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const navigate = useNavigate();
  // Branding is data, so the accent colour, the tab title and the favicon
  // follow a save with no reload (spec §11.19).
  const branding = useBranding();
  useApplyBranding(branding);

  // Navigating is what the mobile drawer is for; arriving closes it.
  useEffect(() => {
    setSidebarOpen(false);
  }, [pathname]);

  // Sixteen destinations don't belong in one flat strip. Grouped by what the
  // operator is doing, not by when the feature shipped.
  const groups = useMemo<NavGroup[]>(
    () => [
      { label: null, items: [{ to: "/", label: t("nav.dashboard"), icon: Gauge }] },
      {
        label: t("nav.groupHosting"),
        items: [
          { to: "/sites", label: t("nav.sites"), icon: Globe },
          { to: "/apps", label: t("nav.apps"), icon: Boxes },
          { to: "/databases", label: t("nav.databases"), icon: Database },
          { to: "/files", label: t("nav.files"), icon: FolderOpen },
          { to: "/mail", label: t("nav.mail"), icon: Mail },
          { to: "/dns", label: t("nav.dns"), icon: Network },
        ],
      },
      {
        label: t("nav.groupOperations"),
        items: [
          { to: "/cron", label: t("nav.cron"), icon: Clock },
          { to: "/backups", label: t("nav.backups"), icon: Archive },
          { to: "/tasks", label: t("nav.tasks"), icon: ListChecks },
          { to: "/terminal", label: t("nav.terminal"), icon: TerminalSquare },
          { to: "/stack", label: t("nav.stack"), icon: Layers },
        ],
      },
      {
        label: t("nav.groupSecurity"),
        items: [
          { to: "/firewall", label: t("nav.firewall"), icon: ShieldCheck },
          { to: "/alerts", label: t("nav.alerts"), icon: BellRing },
        ],
      },
      {
        label: t("nav.groupAdmin"),
        items: [
          { to: "/plans", label: t("nav.plans"), icon: Wallet },
          { to: "/branding", label: t("nav.branding"), icon: Palette },
        ],
      },
    ],
    [t],
  );

  const commands = useMemo<Command[]>(
    () => [
      { id: "tasks", label: t("tasks.title"), hint: "T", run: () => setTasksOpen(true) },
      ...groups.flatMap((group) =>
        group.items.map((item) => ({
          id: `go-${item.to}`,
          label: item.label,
          icon: item.icon,
          run: () => void navigate({ to: item.to }),
        })),
      ),
      { id: "theme-light", label: `${t("nav.theme")}: ${t("nav.themeLight")}`, icon: Sun, run: () => setTheme("light") },
      { id: "theme-dark", label: `${t("nav.theme")}: ${t("nav.themeDark")}`, icon: Moon, run: () => setTheme("dark") },
      { id: "theme-system", label: `${t("nav.theme")}: ${t("nav.themeSystem")}`, icon: Monitor, run: () => setTheme("system") },
      { id: "sign-out", label: t("common.signOut"), icon: LogOut, run: () => void signOut() },
    ],
    [t, groups, setTheme, signOut, navigate],
  );

  const sidebar = (
    <SidebarContent
      branding={branding}
      groups={groups}
      pathname={pathname}
      username={user?.username}
      role={user?.role}
      onSearch={() => {
        setSidebarOpen(false);
        setPaletteOpen(true);
      }}
      onTasks={() => {
        setSidebarOpen(false);
        setTasksOpen(true);
      }}
      theme={theme}
      setTheme={setTheme}
      onSignOut={() => void signOut()}
    />
  );

  return (
    <div className="min-h-dvh bg-canvas">
      {/* Mobile top bar: the drawer trigger and the two things worth a thumb's
          reach. Desktop needs none of it — the sidebar is always there. */}
      <header className="sticky top-0 z-30 flex h-14 items-center gap-1 border-b border-border bg-surface/90 px-3 backdrop-blur lg:hidden">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setSidebarOpen(true)}
          aria-label={t("nav.menu")}
          aria-expanded={sidebarOpen}
        >
          <MenuIcon className="h-5 w-5" />
        </Button>
        <Brand branding={branding} className="ms-1" />
        <div className="ms-auto flex items-center gap-1">
          <Button variant="ghost" size="icon" onClick={() => setPaletteOpen(true)} aria-label={t("common.search")}>
            <Search className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" onClick={() => setTasksOpen(true)} aria-label={t("tasks.title")}>
            <ListChecks className="h-4 w-4" />
          </Button>
        </div>
      </header>

      {/* Desktop sidebar: fixed to the start edge, flipped for free by logical
          properties when the document is RTL. */}
      <aside className="fixed inset-y-0 start-0 z-30 hidden w-64 lg:block">{sidebar}</aside>

      {/* Mobile drawer: mounted only while open, so the entrance animation is
          the mount and closing is instant. */}
      {sidebarOpen ? (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label={t("nav.menu")}>
          <div className="absolute inset-0 animate-fade-in bg-black/40" onClick={() => setSidebarOpen(false)} />
          <div className="absolute inset-y-0 start-0 w-72 max-w-[85vw] animate-slide-in-start">
            {sidebar}
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={() => setSidebarOpen(false)}
              aria-label={t("common.close")}
              className="absolute top-3 -end-11 bg-black/30 text-white hover:bg-black/50 hover:text-white"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>
      ) : null}

      <div className="lg:ps-64">
        <main className="mx-auto w-full max-w-screen-xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          {children}
        </main>
      </div>

      <TaskDrawer open={tasksOpen} onClose={() => setTasksOpen(false)} />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} commands={commands} />
    </div>
  );
}

function Brand({ branding, className }: { branding: PublicBranding; className?: string }) {
  const { t } = useTranslation();
  const logo = assetUrl(branding, "logo");
  return (
    <Link
      to="/"
      className={cn("flex min-w-0 items-center gap-2.5 font-semibold tracking-tight text-ink", className)}
    >
      {/* The reseller's mark and name where the product's used to be
          (spec §11.19). Both fall back per field, so a reseller with only a
          logo keeps the product name and vice versa. */}
      {logo ? (
        <img src={logo} alt="" aria-hidden className="h-6 max-w-24 shrink-0 object-contain" />
      ) : (
        <span
          className="grid h-6 w-6 shrink-0 place-items-center rounded-md bg-accent text-[11px] font-bold text-on-accent"
          aria-hidden
        >
          F
        </span>
      )}
      <span className="truncate">{branding.panel_name ?? t("common.appName")}</span>
    </Link>
  );
}

function SidebarContent({
  branding,
  groups,
  pathname,
  username,
  role,
  onSearch,
  onTasks,
  theme,
  setTheme,
  onSignOut,
}: {
  branding: PublicBranding;
  groups: NavGroup[];
  pathname: string;
  username?: string;
  role?: "admin" | "reseller" | "customer";
  onSearch: () => void;
  onTasks: () => void;
  theme: "light" | "dark" | "system";
  setTheme: (theme: "light" | "dark" | "system") => void;
  onSignOut: () => void;
}) {
  const { t } = useTranslation();

  const isActive = (to: string) => (to === "/" ? pathname === "/" : pathname === to || pathname.startsWith(`${to}/`));

  return (
    <div className="flex h-full flex-col border-e border-border bg-surface">
      <div className="flex h-14 shrink-0 items-center px-4">
        <Brand branding={branding} />
      </div>

      <div className="px-3 pb-2">
        <button
          onClick={onSearch}
          aria-keyshortcuts="Meta+K Control+K"
          className="flex h-8 w-full items-center gap-2 rounded-lg border border-border bg-canvas px-2.5 text-sm text-ink-subtle transition-colors hover:border-border-strong hover:text-ink-muted"
        >
          <Search className="h-3.5 w-3.5" aria-hidden />
          <span className="min-w-0 flex-1 truncate text-start">{t("common.search")}</span>
          <kbd className="rounded border border-border bg-surface px-1 font-mono text-[10px] text-ink-subtle">
            ⌘K
          </kbd>
        </button>
      </div>

      <nav className="min-h-0 flex-1 space-y-4 overflow-y-auto px-3 pt-1 pb-3" aria-label={t("nav.menu")}>
        {groups.map((group, index) => (
          <div key={group.label ?? index}>
            {group.label ? (
              <p className="px-2 pb-1 text-[11px] font-medium tracking-wider text-ink-subtle uppercase">
                {group.label}
              </p>
            ) : null}
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const active = isActive(item.to);
                return (
                  <li key={item.to}>
                    <Link
                      to={item.to}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "group flex items-center gap-2.5 rounded-lg px-2 py-1.5 text-sm transition-colors",
                        active
                          ? "bg-accent-soft font-medium text-accent"
                          : "text-ink-muted hover:bg-surface-muted hover:text-ink",
                      )}
                    >
                      <item.icon
                        className={cn(
                          "h-4 w-4 shrink-0",
                          active ? "" : "text-ink-subtle transition-colors group-hover:text-ink-muted",
                        )}
                        aria-hidden
                      />
                      <span className="truncate">{item.label}</span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className="shrink-0 space-y-2 border-t border-border p-3">
        <div className="flex items-center justify-between gap-1">
          <Button variant="ghost" size="icon-sm" onClick={onTasks} aria-label={t("tasks.title")}>
            <ListChecks className="h-4 w-4" />
          </Button>
          <ThemeToggle theme={theme} setTheme={setTheme} />
          <Button variant="ghost" size="icon-sm" onClick={onSignOut} aria-label={t("common.signOut")}>
            <LogOut className="h-4 w-4" />
          </Button>
        </div>

        {username ? (
          <div className="flex items-center gap-2.5 rounded-lg bg-surface-muted/60 px-2 py-1.5">
            <span
              className="grid h-7 w-7 shrink-0 place-items-center rounded-full bg-accent-soft text-xs font-semibold text-accent uppercase"
              aria-hidden
            >
              {username.slice(0, 1)}
            </span>
            <span className="min-w-0">
              <span dir="ltr" className="block truncate text-start text-sm font-medium text-ink">
                {username}
              </span>
              {role ? (
                <span className="block truncate text-xs text-ink-muted">{t(`common.role.${role}`)}</span>
              ) : null}
            </span>
          </div>
        ) : null}
      </div>
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
      size="icon-sm"
      onClick={() => setTheme(next)}
      aria-label={`${t("nav.theme")}: ${label}`}
      title={`${t("nav.theme")}: ${label}`}
    >
      <Icon className="h-4 w-4" />
    </Button>
  );
}
